import assert from 'node:assert/strict';
import test from 'node:test';
import {packReleaseEvidenceTransport} from '../aws/production-release-dispatch-contract.mjs';
import { brokerDigest, assertRegistrationHandoff, assertBrokerAuthorization, assertPolicyPruningHandoff, assertBrokerClosurePlan } from '../aws/stage-b-staged-broker-contract.mjs';
import { createReleaseIdentity, selectReleasePolicyDeletion, createReleaseCoordinatorStore, authenticateReleaseGateRuns,captureReleasePhaseMaterial,hydrateReleasePhaseMaterial,releaseTransitionDispatchInputs,obtainReleaseTransitionAuthorization,readHostedReleaseSource,authenticateHostedStageBImages,HOSTED_RELEASE_ROOT } from '../aws/production-release-coordinator.mjs';
import {requiredWorkflowFiles} from '../github/release-lifecycle-contract.mjs';
import {readReleaseGateEvidence} from '../github/check-required-workflow-gates.mjs';
import {runHostedReleaseCoordinator,hostedReleaseTrainRequest,createHostedReleaseRuntime,readDurableCompletedRegistration,registeredTaskStateFromBytes} from '../aws/run-production-release-coordinator.mjs';
import {deriveStageBToolingInputTreeSha256} from '../aws/validate-stage-b-image-reuse.mjs';

function gateFixture(sourceSha,lifecycle='strict'){
 const files=requiredWorkflowFiles(lifecycle),workflowPayloads={},expectedWorkflowRunIds={};
 files.forEach((file,i)=>{
  const id=i+1,runId=i+100;expectedWorkflowRunIds[file]=String(runId);
  const workflow={id,path:`.github/workflows/${file}`};
  workflowPayloads[file]={workflow,runs:[{id:runId,workflow_id:id,path:workflow.path,head_sha:sourceSha,head_branch:'main',event:lifecycle==='prerequisites'?'push':'workflow_dispatch',run_attempt:1,
   status:'completed',conclusion:'success',created_at:'2026-10-08T12:00:00.000Z',repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'}}]};
 });
 return {sourceSha,lifecycle,workflowPayloads,expectedWorkflowRunIds};
}
import { CURRENT_REGISTRATION_OPERATION, rejectExternalAccess, prepublicationPredecessorFixture, schema3RegistrationPredecessor } from './fixtures/production-release-system.mjs';

const sourceSha = 'e1f92ec31bdb0e40d4aff06ee98e1add817e6e07';
import {createProductionComponentDeploymentState} from '../aws/production-component-deployment-state.mjs';
const component=(name,sha)=>({sourceSha:sha,establishedThroughSha:sha,imageDigest:'sha256:'+'1'.repeat(64),taskDefinitionArn:`arn:aws:ecs:eu-west-2:368992683803:task-definition/${name}:1`,desiredCount:2});
const baseline=createProductionComponentDeploymentState({now:'2026-10-08T00:00:00.000Z',components:{backend:component('backend','9'.repeat(40)),frontend:component('frontend','8'.repeat(40)),database:null,security:null}});

test('hosted source reader authenticates exact main and component ancestry before classification',()=>{
 const item={stateKey:{S:'production#T-ej2003/genuine-scan-main'},generation:{N:String(baseline.generation)},state:{S:JSON.stringify(baseline)}};
 const run=args=>{assert.deepEqual(args.slice(0,2),['dynamodb','get-item']);return JSON.stringify({Item:item});};
 const checkout=()=>({currentHead:sourceSha,originMainHead:sourceSha});
 const seen=[];const git=args=>{seen.push(args);if(args[0]==='merge-base')return '';if(args[0]==='diff')return args[3]==='9'.repeat(40)?'backend/src/services/qrService.ts\n':'src/pages/QrBatches.tsx\n';throw new Error('Unexpected git command');};
 const accepted=readHostedReleaseSource(sourceSha,{run,checkout,git});
 assert.deepEqual(accepted.baseline,baseline);assert.deepEqual(accepted.changedFiles,['backend/src/services/qrService.ts','src/pages/QrBatches.tsx']);
 assert.equal(seen.filter(args=>args[0]==='merge-base').length,2);
 assert.throws(()=>readHostedReleaseSource(sourceSha,{run,checkout:()=>({currentHead:sourceSha,originMainHead:'f'.repeat(40)}),git}));
});
test('hosted coordinator restart rejects a changed deployed baseline before another transition',async()=>{
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'2',
  GITHUB_RUN_ID:'700',GITHUB_SHA:sourceSha,RUNNER_TEMP:'/tmp'};
 const runtime=createHostedReleaseRuntime({sourceSha,ticketId:'current-release',imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),
  requiredGateRunIdsJson:'{}',env,awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>({}),
  sourceReader:()=>({baseline:{...baseline,generation:baseline.generation+1},changedFiles:[]})});
 await assert.rejects(()=>runtime.authenticateSource(sourceSha,{baselineSha256:brokerDigest(baseline),baselineGeneration:baseline.generation}),/baseline changed/);
});
test('hosted adopted registration resumes from its durable result without rematerializing exclusive files',async()=>{
 const releaseId='c'.repeat(64),env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'2',
  GITHUB_RUN_ID:'700',GITHUB_SHA:sourceSha,RUNNER_TEMP:'/tmp'};
 const runtime=createHostedReleaseRuntime({sourceSha,ticketId:'current-release',imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),
  requiredGateRunIdsJson:'{}',env,awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>({}),
  materialize:rejectExternalAccess,refresh:rejectExternalAccess});
 try{
  const inputs=await runtime.materializeInputs({releaseId,sourceSha},{},{phase:'registration',prepared:null,adopted:true});
  assert.equal(inputs.directory,`${HOSTED_RELEASE_ROOT}/${releaseId}/registration`);
  await assert.rejects(()=>runtime.materializeInputs({releaseId,sourceSha},{},{phase:'pruning',prepared:null,adopted:true}));
 }finally{fs.rmSync(path.join(HOSTED_RELEASE_ROOT,releaseId),{recursive:true,force:true});}
});
test('hosted image resolver carries the exact source-bound transport to the canonical verifier',()=>{
 const authorizationJson=JSON.stringify({sourceSha,images:[]}),transportSha256=createHash('sha256').update(authorizationJson).digest('hex');
 let verified=0;
 const evidence=authenticateHostedStageBImages({sourceSha,transportJson:authorizationJson,transportSha256,run:rejectExternalAccess,
  verifyAuthorization:({authorization,sourceSha:actual})=>{verified++;assert.equal(actual,sourceSha);assert.deepEqual(authorization,JSON.parse(authorizationJson));
   return Object.fromEntries(['backend','worker','rls-executor','rls-canary'].map(name=>[name,`example@sha256:${'a'.repeat(64)}`]));}});
 assert.equal(verified,1);assert.equal(evidence.authorizationRawSha256,transportSha256);assert.equal(evidence.sourceSha,sourceSha);
 const packed=packReleaseEvidenceTransport({authorizationJson,authorizationSha256:transportSha256,completedRegistrationSourceSha:'b'.repeat(40)});
 const durable=authenticateHostedStageBImages({sourceSha,transportJson:packed.json,transportSha256:packed.sha256,run:rejectExternalAccess,
  verifyAuthorization:()=>Object.fromEntries(['backend','worker','rls-executor','rls-canary'].map(name=>[name,'fixture-ref']))});
 assert.equal(durable.completedRegistrationSourceSha,'b'.repeat(40));assert.equal(durable.authorizationRawSha256,transportSha256);
 assert.throws(()=>authenticateHostedStageBImages({sourceSha,transportJson:authorizationJson,transportSha256:'0'.repeat(64),run:rejectExternalAccess,
  verifyAuthorization:()=>{assert.fail('Changed transport cannot reach verifier');}}));
});

test('hosted release adopts an independently authenticated terminal broker closure without replaying mutations',async()=>{
 const artifacts=new Map(),steps=new Map();let start,checks=0;
 const store={putArtifact:async(id,value)=>{assert.equal(brokerDigest(value),id);artifacts.set(id,structuredClone(value));},
  getArtifact:async id=>structuredClone(artifacts.get(id)),readStart:async()=>start||null,
  writeStart:async(_request,value)=>{assert.equal(start,undefined);start=structuredClone(value);},
  readStep:async(_id,name)=>steps.get(name)||null,
  writeStep:async value=>{assert.equal(steps.has(value.name),false);steps.set(value.name,structuredClone(value));}};
 const registration={preparation:{sourceSha:'a'.repeat(40)},result:{authorizationSha256:'b'.repeat(64)}};
 const terminal={kind:'STAGED_BROKER_TERMINAL_HANDOFF',sourceSha:'c'.repeat(40)};
 const closure={sourceSha:terminal.sourceSha,terminalSha256:brokerDigest(terminal),closureSha256:'e'.repeat(64),
  registrationTransactionId:registration.result.authorizationSha256};
 const runtime={store,gateLifecycle:'prerequisites',authenticateSource:async()=>({baseline,changedFiles:[]}),
  resolveArtifacts:async()=>({sourceSha}),authenticateArtifacts:async()=>{},resolveGates:async()=>({sourceSha}),
  authenticateGates:async()=>{},findCompletedRegistration:async()=>registration,
  findCompletedBrokerClosure:async()=>closure,authenticateCompletedBrokerClosure:async(_release,entry,candidate)=>{
   checks++;assert.deepEqual(entry,registration);assert.deepEqual(candidate,closure);return terminal;},
  materializeInputs:async()=>assert.fail('Terminal adoption must not create a new Terraform plan'),
  runStageOperation:async()=>assert.fail('Terminal adoption must not replay broker or IAM writes')};
 const request={sourceSha,ticketId:'CHG-20261011-001'};
 const invoke=()=>runHostedReleaseCoordinator({...request,imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),
  requiredGateRunIdsJson:'{}',lifecycle:'prerequisites',completedBrokerClosureSourceSha:closure.sourceSha},
  {runtimeFactory:()=>runtime});
 const first=await invoke();assert.equal(first.status,'PREREQUISITES_CONVERGED');
 assert.equal(first.closureSha256,brokerDigest(terminal));assert.equal(steps.has('BROKER_CLOSURE_CANDIDATE'),true);
 assert.equal(steps.has('registration:prepared'),false);assert.equal(steps.has('cutover:result'),false);
 assert.deepEqual(await invoke(),first);assert.equal(checks,2);
 const saved=structuredClone(steps.get('BROKER_CLOSURE_CANDIDATE'));
 artifacts.set(saved.result,{...closure,closureSha256:'f'.repeat(64)});
 await assert.rejects(invoke,/Release artifact substitution/);
 artifacts.set(saved.result,closure);
 steps.set('registration:prepared',{releaseId:first.releaseId,sourceSha,name:'registration:prepared',result:brokerDigest(closure)});
 await assert.rejects(invoke,/cannot mix coordinator mutations/);
});

test('hosted closure adoption source is explicit and malformed source fails before AWS access',()=>{
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',
  GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:sourceSha,RUNNER_TEMP:'/tmp'};
 assert.throws(()=>createHostedReleaseRuntime({sourceSha,ticketId:'CHG-20261011-001',imageTransportJson:'fixture',
  imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',completedBrokerClosureSourceSha:'wrong',env,
  awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>({})}));
 const workflow=fs.readFileSync('.github/workflows/release-train.yml','utf8');
 assert.match(workflow,/completed_broker_closure_source_sha:/);
 assert.match(workflow,/COMPLETED_BROKER_CLOSURE_SOURCE_SHA: \$\{\{ inputs\.completed_broker_closure_source_sha \}\}/);
 assert.equal(hostedReleaseTrainRequest({COMPLETED_BROKER_CLOSURE_SOURCE_SHA:'c'.repeat(40)}).completedBrokerClosureSourceSha,'c'.repeat(40));
});

test('hosted closure reader callback authenticates current checkout and tooling tree',async()=>{
 const current='e4e7819443bd80964a72cf8099008a6cb054be3f';
 const historical='528c5e733b950d4987345d633702cb2c83a66ff8';
 const registrationSource='2c2d63eaea623c0d9d55c98a949d0a47186fdd2e';
 const tree=deriveStageBToolingInputTreeSha256(current),sentinel=new Error('Closure reader reached after checkout authentication');
 let checkoutCalls=0;
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',
  GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:current,RUNNER_TEMP:'/tmp'};
 const runtime=createHostedReleaseRuntime({sourceSha:current,ticketId:'CHG-20261011-001',imageTransportJson:'fixture',
  imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',completedBrokerClosureSourceSha:historical,
  env,awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>({}),
  protectedCheckout:options=>{checkoutCalls++;assert.equal(options.expectedSourceSha,current);
   assert.equal(options.requireCanonicalRepository,true);return {currentHead:current,originMainHead:current};},
  readClosure:async({sourceSha,readCheckout})=>{assert.equal(sourceSha,historical);
   assert.deepEqual(readCheckout(),{sourceSha:current,treeSha256:tree});throw sentinel;}});
 const registration={preparation:{sourceSha:registrationSource},result:{authorizationSha256:'a'.repeat(64)}};
 const candidate={sourceSha:historical,terminalSha256:'b'.repeat(64),closureSha256:'c'.repeat(64),
  registrationTransactionId:registration.result.authorizationSha256};
 await assert.rejects(()=>runtime.authenticateCompletedBrokerClosure({sourceSha:current},registration,candidate),error=>error===sentinel);
 assert.equal(checkoutCalls,1);
});

test('completed registration adoption reads exact Terraform task bindings from the authenticated state bytes',()=>{
 const address='aws_ecs_task_definition.backend',lineage='4e438e59-8b8b-194d-030c-5ede0c26344a';
 const state={version:4,lineage,serial:126,resources:[{mode:'managed',type:'aws_ecs_task_definition',name:'backend',
  instances:[{attributes:{arn:'arn:aws:ecs:eu-west-2:368992683803:task-definition/example:29',revision:29}}]}]};
 const bytes=Buffer.from(JSON.stringify(state)),expected={lineage,serial:126,stateSha256:createHash('sha256').update(bytes).digest('hex')};
 assert.equal(registeredTaskStateFromBytes(bytes,expected,[address])[address].revision,29);
 assert.throws(()=>registeredTaskStateFromBytes(bytes,{...expected,stateSha256:'0'.repeat(64)},[address]),/state changed/);
 assert.throws(()=>registeredTaskStateFromBytes(bytes,{...expected,serial:125},[address]));
 assert.throws(()=>registeredTaskStateFromBytes(bytes,expected,['aws_ecs_task_definition.worker']),/resource differs/);
 const duplicate=Buffer.from(JSON.stringify({...state,resources:[state.resources[0],state.resources[0]]}));
 assert.throws(()=>registeredTaskStateFromBytes(duplicate,{...expected,stateSha256:createHash('sha256').update(duplicate).digest('hex')},[address]),/resource differs/);
});

test('gate authentication uses the canonical required-workflow contract and exact child identities',()=>{
 const release={sourceSha};assert.equal(authenticateReleaseGateRuns(release,gateFixture(sourceSha)).length,5);
 const retried=gateFixture(sourceSha);
 retried.workflowPayloads['deployment-audit.yml'].runs[0].run_attempt=2;
 assert.equal(authenticateReleaseGateRuns(release,retried).length,5);
 retried.workflowPayloads['deployment-audit.yml'].runs[0].conclusion='failure';
 assert.throws(()=>authenticateReleaseGateRuns(release,retried),/Required exact-source gates are not successful/);
 for(const field of ['head_sha','path','workflow_id','conclusion','repository']){
  const evidence=gateFixture(sourceSha),run=evidence.workflowPayloads['deployment-audit.yml'].runs[0];
  run[field]=field==='repository'?{full_name:'attacker/repo'}:'wrong';
  assert.throws(()=>authenticateReleaseGateRuns(release,evidence));
 }
 for(const attempt of [0,-1,1.5,'2',null]){
  const evidence=gateFixture(sourceSha);
  evidence.workflowPayloads['deployment-audit.yml'].runs[0].run_attempt=attempt;
  assert.throws(()=>authenticateReleaseGateRuns(release,evidence),/Gate attempt identity invalid/);
 }
 const missing=gateFixture(sourceSha);delete missing.workflowPayloads['secret-scan.yml'];assert.throws(()=>authenticateReleaseGateRuns(release,missing));
});
test('hosted gate reader carries exact workflow and child identities into the coordinator verifier',async()=>{
 const fixture=gateFixture(sourceSha),api=async endpoint=>{
  const workflow=/^\/actions\/workflows\/([^/]+)$/.exec(endpoint),run=/^\/actions\/runs\/([1-9][0-9]*)$/.exec(endpoint);
  if(workflow)return fixture.workflowPayloads[decodeURIComponent(workflow[1])]?.workflow;
  if(run)return Object.values(fixture.workflowPayloads).flatMap(value=>value.runs).find(value=>String(value.id)===run[1]);
  throw new Error('Unexpected external access');
 };
 const evidence=await readReleaseGateEvidence({sourceSha,lifecycle:'strict',expectedWorkflowRunIds:fixture.expectedWorkflowRunIds,githubJson:api});
 assert.equal(authenticateReleaseGateRuns({sourceSha},evidence).length,5);
 const missing=await readReleaseGateEvidence({sourceSha,lifecycle:'strict',expectedWorkflowRunIds:{...fixture.expectedWorkflowRunIds,'deployment-audit.yml':'999'},githubJson:api});
 assert.throws(()=>authenticateReleaseGateRuns({sourceSha},missing));
});

test('maximum governed transition dispatch uses references and stays far below GitHub total input limit',()=>{
 const release={sourceSha,releaseId:'b'.repeat(64),ticketId:'T'.repeat(128)};
 for(const phase of ['registration','pruning','policy','publication','cutover']){
  const inputs=releaseTransitionDispatchInputs({release,authorizationRound:Number.MAX_SAFE_INTEGER},phase,'c'.repeat(64));
  const size=Buffer.byteLength(JSON.stringify({ref:'main',inputs}));assert.ok(size<1024);assert.ok(size<65535);
  assert.equal(inputs.preparation_reference,'c'.repeat(64));assert.equal(Object.hasOwn(inputs,'preparation'),false);
 }
 assert.equal(releaseTransitionDispatchInputs({release,authorizationRound:0},'closure','c'.repeat(64)).phase,'closure');
 const successor=releaseTransitionDispatchInputs({release,authorizationRound:0},'cutover','c'.repeat(64),
  {recoveryTooling:{sourceSha:'d'.repeat(40)}});
 assert.equal(successor.source_sha,sourceSha);
 assert.equal(successor.tooling_sha,'d'.repeat(40));
});

test('release identity binds exact source, deployed baseline and deterministic classification', () => {
 const input = { sourceSha, ticketId:'current-release', baseline, changedFiles: ['backend/src/services/qrService.ts'] };
 const release = createReleaseIdentity(input);
 assert.equal(release.sourceSha, sourceSha);
 assert.equal(release.classification.backend, true);
 const {releaseId, ...body} = release;
 assert.equal(releaseId, brokerDigest(body));
 assert.deepEqual(createReleaseIdentity({...input, changedFiles: [...input.changedFiles, ...input.changedFiles]}), release);
 assert.notEqual(createReleaseIdentity({...input, sourceSha: 'a'.repeat(40)}).releaseId, release.releaseId);
 assert.notEqual(createReleaseIdentity({...input, ticketId:'different-release'}).releaseId, release.releaseId);
 assert.notEqual(createReleaseIdentity({...input, baseline: {...baseline, components:{...baseline.components,backend:component('backend','b'.repeat(40))}}}).releaseId, release.releaseId);
});

const inventory = ['v9', 'v10', 'v11', 'v12', 'v13'].map((versionId, i) => ({
 versionId, isDefault: versionId === 'v13', createDate: new Date(Date.UTC(2026, 9, i + 1)).toISOString(), documentSha256: String(i+1).repeat(64),
}));
test('current-release full capacity selects only the unique oldest eligible obsolete non-default', () => {
 assert.equal(selectReleasePolicyDeletion({inventory, protectedVersionIds: ['v9'], obsoleteVersionIds: ['v9', 'v10', 'v11', 'v12']}), 'v10');
 assert.equal(selectReleasePolicyDeletion({inventory: inventory.map(v => v.versionId === 'v12' ? {...v, createDate: inventory[2].createDate} : v), protectedVersionIds: [], obsoleteVersionIds: ['v9','v10','v11','v12']}), 'v9');
});
for (const [name, mutate] of [
 ['oldest tie', xs => xs.map(v => v.versionId === 'v10' ? {...v, createDate: xs[0].createDate} : v)],
 ['duplicate identity', xs => [...xs.slice(0,4), {...xs[4], versionId: 'v9'}]],
 ['two defaults', xs => xs.map(v => v.versionId === 'v9' ? {...v, isDefault: true} : v)],
 ['invalid date', xs => xs.map(v => v.versionId === 'v9' ? {...v, createDate: 'invalid'} : v)],
]) test(`capacity fails closed for ${name}`, () => {
 assert.throws(() => selectReleasePolicyDeletion({inventory: mutate(inventory), protectedVersionIds: [], obsoleteVersionIds: ['v9','v10','v11','v12']}));
});
test('default and active/recoverable transaction versions cannot be selected', () => {
 assert.throws(() => selectReleasePolicyDeletion({inventory, protectedVersionIds: ['v9','v10','v11','v12'], obsoleteVersionIds: inventory.map(v => v.versionId)}));
 assert.throws(() => selectReleasePolicyDeletion({inventory, protectedVersionIds: [], obsoleteVersionIds: ['v13']}));
});
test('fixture carries current operation as immutable provenance, never as a new registration identity', () => {
 assert.equal(CURRENT_REGISTRATION_OPERATION, '1b2f41edaae551cc5785591f78e23ea368abcff3551b207d144cb923fa5b4495');
 const f = prepublicationPredecessorFixture();
 assert.equal(f.imageImpactReport.imageReuseCompatible, false);
 assert.notDeepEqual(f.registrationTaskMap, f.aliasRuntimeTaskMap);
 assert.equal(Object.keys(f.registration.result.definitions).length, 12);
 assert.throws(() => rejectExternalAccess('aws', 'ecs', 'register-task-definition'), /External access forbidden/);
});

// Capacity is an authenticated continuation of the same three-identity predecessor.
// The caller cannot opt into a mismatch outside these exact operations.
import { authenticatePrepublicationPolicyChain, authenticateNormalPolicyPrerequisite } from '../aws/stage-b-staged-broker-executor.mjs';
for (const operation of ['prepare-pruning','authorize-pruning','prune']) test(`mixed-chain predecessor survives ${operation}`, async () => {
 const f = prepublicationPredecessorFixture(), p = schema3RegistrationPredecessor(f);
 const chain = {registration: {preparation: p}, policy: f.policy};
 let authenticated = 0, observed = 0;
 const value = await authenticatePrepublicationPolicyChain({operation, chain, checkout: f.f.release,
  authenticateChain: async actual => { assert.deepEqual(actual, chain); authenticated++; },
  observe: async proof => { assert.equal(authenticated,1); assert.deepEqual(proof,p.registrationPredecessor); observed++; return structuredClone(p.prerequisites); },
 });
 assert.deepEqual(value.prerequisites,p.prerequisites); assert.equal(observed,1);
});
for (const operation of ['prepare-publication','publish','prepare-cutover','cutover']) test(`predecessor exception cannot authorize ${operation}`, async () => {
 const f = prepublicationPredecessorFixture();
 await assert.rejects(() => authenticatePrepublicationPolicyChain({operation, chain: {registration: {preparation: schema3RegistrationPredecessor(f)},policy: f.policy},
  checkout: f.f.release, authenticateChain: rejectExternalAccess, observe: rejectExternalAccess}));
});

import { runReleaseCoordinator } from '../aws/production-release-coordinator.mjs';
import { createPublicRegistrationFixture } from './fixtures/production-release-system.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createPublicKey,verify as verifySignature,constants} from 'node:crypto';
import {brokerAuthorizationMessage} from '../aws/stage-b-staged-broker-authorization.mjs';
import {readBrokerProtectedEnvironmentApproval,readBrokerProtectedEnvironmentAuthorization,verifyBrokerProtectedEnvironmentAuthorization} from '../aws/stage-b-staged-broker-authorization.mjs';
import {PRODUCTION_ENVIRONMENT_APPROVAL,createProductionEnvironmentApprovalEvidence} from '../aws/production-github-environment-approval.mjs';
import JSZip from 'jszip';
import {createHash} from 'node:crypto';
import {readZipCentralDirectory} from '../aws/package-production-green-stage-b-broker.mjs';
import {adoptRegisteredOutputs} from '../aws/stage-b-release-prerequisites.mjs';
import {authorizeReleaseTransition} from '../aws/authorize-production-stage-b-release-transition.mjs';

function hostedApprovalTransport(sourceSha,now,runId){
 const repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
 const environment={id:7,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]};
 const actual={state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'};
 const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:environment,repository,environment:'production',sourceSha,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,eventName:'workflow_dispatch',workflowRunId:String(runId),workflowRunAttempt:'1',executionActor:'operator',observedAt:now.toISOString(),actualApproval:actual});
 return {approval,publish:async authorization=>{
  const zip=new JSZip();zip.file('authorization.json',JSON.stringify(authorization));const archive=await zip.generateAsync({type:'nodebuffer',compression:'DEFLATE',streamFiles:true});
  assert.throws(()=>readZipCentralDirectory(archive),/ZIP metadata is not canonical/);
  const workflow={id:runId,repository:{id:9,full_name:repository},head_repository:{full_name:repository},path:'.github/workflows/authorize-production-stage-b-release-transition.yml',head_sha:sourceSha,event:'workflow_dispatch',status:'completed',conclusion:'success',run_attempt:1,actor:{login:'operator'}};
  const artifact={id:runId+10000,name:'production-stage-b-release-transition-authorization',expired:false,digest:`sha256:${createHash('sha256').update(archive).digest('hex')}`,workflow_run:{id:runId,head_sha:sourceSha,repository_id:9}};
  const payloads={['actions/runs/'+runId]:workflow,['actions/runs/'+runId+'/artifacts']:[{artifacts:[artifact]}],['actions/artifacts/'+artifact.id+'/zip']:archive,['environments/production']:environment,['actions/runs/'+runId+'/approvals']:[{state:'approved',environments:[{id:7,name:'production'}],user:{id:1,login:'operator'}}]};
  const run=args=>{assert.equal(args[0],'api');assert.ok(args[1].startsWith(`repos/${repository}/`));const key=args[1].slice(`repos/${repository}/`.length);assert.ok(Object.hasOwn(payloads,key),'Unexpected external access');return Buffer.isBuffer(payloads[key])?payloads[key]:JSON.stringify(payloads[key]);};
  return a=>verifyBrokerProtectedEnvironmentAuthorization(a,{run});
 }};
}

test('governed workflow producer consumes immutable coordinator preparation and real public authorization without production writes',async()=>{
 const source=prepublicationPredecessorFixture().f.release.sourceSha,ticketId='current-release';
 const release=createReleaseIdentity({sourceSha:source,ticketId,baseline,changedFiles:['backend/src/services/qrService.ts']});
 const directory=path.join(HOSTED_RELEASE_ROOT,release.releaseId,'registration');
 fs.mkdirSync(directory,{recursive:true,mode:0o700});
 const f=await createPublicRegistrationFixture({privateDirectory:directory});
 try{
  const original=await f.run({...f.initialRequest,operation:'prepare-registration'}),store=f.coordinatorStore;
  const materializationSha256=await captureReleasePhaseMaterial({prepared:original,files:f.files,store,repositoryRoot:process.cwd()});
  const prepared={...original,materializationSha256},preparationReference=brokerDigest(prepared);
  for(const value of [baseline,release,prepared])store.putArtifact(brokerDigest(value),value);
  store.writeStart({sourceSha:source,ticketId},{release:brokerDigest(release),baseline:brokerDigest(baseline)});
  store.writeStep({releaseId:release.releaseId,sourceSha:source,name:'registration:prepared',result:preparationReference});
  store.writeStep({releaseId:release.releaseId,sourceSha:source,name:'registration:pending:0',prepared:preparationReference,runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'});
  const transport=hostedApprovalTransport(source,f.now,700),releaseContext={releaseId:release.releaseId,phase:'registration',preparationReference,authorizationRound:0};
  const env={GITHUB_ACTIONS:'true',GITHUB_WORKFLOW_REF:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,GITHUB_REPOSITORY:PRODUCTION_ENVIRONMENT_APPROVAL.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:source,RUNNER_TEMP:'/tmp',RELEASE_ID:release.releaseId,RELEASE_PHASE:'registration',RELEASE_PREPARATION_REFERENCE:preparationReference,RELEASE_AUTHORIZATION_ROUND:'0'};
  const request={sourceSha:source,ticketId,...releaseContext,output:path.join(directory,'authorization.json')};
  const dependencies={env,run:rejectExternalAccess,createStore:()=>store,runRequest:r=>f.run(r,{readProtectedApproval:async()=>({approval:transport.approval,release:releaseContext})})};
  for(const bad of [{...request,preparationReference:'0'.repeat(64)},{...request,phase:'cutover'},{...request,authorizationRound:1},{...request,sourceSha:'f'.repeat(40)}])await assert.rejects(()=>authorizeReleaseTransition(bad,dependencies));
  assert.equal(fs.existsSync(request.output),false);
  const result=await authorizeReleaseTransition(request,dependencies),bytes=fs.readFileSync(result.authorizationPath),authorization=JSON.parse(bytes);
  assert.equal(result.authorizationFileSha256,brokerDigest(bytes));assert.equal(result.authorizationSha256,brokerDigest(authorization));
  assert.deepEqual(authorization.release,releaseContext);
  await assertBrokerAuthorization(authorization,prepared.preparation,{verify:await transport.publish(authorization),now:f.now});
  assert.equal(f.snapshot().registrationApplyCalls,0);assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);assert.equal(f.snapshot().aliasCalls,0);
 }finally{f.dispose();fs.rmSync(path.join(HOSTED_RELEASE_ROOT,release.releaseId),{recursive:true,force:true});}
});

test('hosted runtime authenticates a durable registration result without replaying historical recovery after later phases',async()=>{
 const f=await createPublicRegistrationFixture();
 try{
  const prepared=await f.run({...f.initialRequest,operation:'prepare-registration'});
  const authorization=await f.run({operation:'authorize-registration',preparation:prepared.preparation,planPath:prepared.planPath,makerIdentity:f.maker,humanReviewId:'fixture-hosted-result'});
  const result=await f.run({operation:'register',preparation:prepared.preparation,authorization,planPath:prepared.planPath});
  const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
   GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'2',
   GITHUB_RUN_ID:'700',GITHUB_SHA:f.source,RUNNER_TEMP:'/tmp'};
  const runtime=createHostedReleaseRuntime({sourceSha:f.source,ticketId:'current-release',imageTransportJson:'fixture',
   imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',env,awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,
   createStore:()=>f.coordinatorStore,verifyAuthorization:f.checker.verify,
   readReceipt:({status})=>{assert.equal(status,'TASK_REGISTERED');return result;},runStageOperation:rejectExternalAccess});
  f.advanceClock(31*60*1000);
  await runtime.authenticateCompletedTransition({release:{sourceSha:f.source},inputs:{directory:f.directory}},'registration',prepared,authorization,result);
  assert.equal(f.snapshot().registrationApplyCalls,1);
 }finally{f.dispose();}
});

test('hosted recovery selector trusts native intent absence and presence, not the coordinator marker',async()=>{
 const f=await createPublicRegistrationFixture();
 try{
  const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
   GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'2',
   GITHUB_RUN_ID:'700',GITHUB_SHA:f.source,RUNNER_TEMP:'/tmp'};
  const id='a'.repeat(64),authorization={id};let present=false;
  const runtime=createHostedReleaseRuntime({sourceSha:f.source,ticketId:'current-release',imageTransportJson:'fixture',
   imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',env,awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,
   createStore:()=>f.coordinatorStore,verifyAuthorization:f.checker.verify,
   readReceipt:({id:observed,status})=>{assert.equal(observed,brokerDigest(authorization));assert.equal(status,'TASK_REGISTRATION_INTENT');
    if(!present)throw Object.assign(new Error('absent'),{code:'RECEIPT_ABSENT'});return {savedPlanSha256:id,authorizedAt:f.now.toISOString()};}});
  const context={release:{sourceSha:f.source},inputs:{directory:f.directory}};
  assert.equal(await runtime.classifyNativeAttempt(context,'registration',null,authorization),'PRE_NATIVE');
  present=true;
  assert.equal(await runtime.classifyNativeAttempt(context,'registration',null,authorization),'RECOVER');
 }finally{f.dispose();}
});

test('hosted capacity reader authenticates the five live versions and selects v9 without deleting it',async()=>{
 const fixture=prepublicationPredecessorFixture(),owner=fixture.policy.receiptBoundAdoption.ownership;
 const arn=owner.identity.policyArn,document=fixture.policy.terminal.policy;
 const versions=fixture.policy.receiptBoundAdoption.successorInventory.map(version=>({...version,CreateDate:new Date(Date.UTC(2026,8,Number(version.VersionId.slice(1))-8)).toISOString()}));
 const awsRun=args=>{
  const command=args.slice(0,2).join(' ');
  if(command==='dynamodb get-item')return JSON.stringify({Item:{stateKey:{S:`production#iam-policy-owner#${arn}`},generation:{N:String(owner.identity.generation)},state:{S:JSON.stringify(owner)}}});
  if(command==='iam get-policy')return JSON.stringify({Policy:{Arn:arn,DefaultVersionId:'v13'}});
  if(command==='iam list-policy-versions')return JSON.stringify({Versions:versions});
  if(command==='iam get-policy-version'){const versionId=args[args.indexOf('--version-id')+1];return JSON.stringify({PolicyVersion:{VersionId:versionId,IsDefaultVersion:versionId==='v13',Document:document}});}
  return rejectExternalAccess(args);
 };
 const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
  GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'1',
  GITHUB_RUN_ID:'700',GITHUB_SHA:sourceSha,RUNNER_TEMP:'/tmp'};
 const runtime=createHostedReleaseRuntime({sourceSha,ticketId:'current-release',imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),
  requiredGateRunIdsJson:'{}',env,awsRun,ghRun:rejectExternalAccess,createStore:()=>({})});
 const retention=await runtime.authenticatePolicyRetention();
 assert.equal(selectReleasePolicyDeletion(retention),'v9');
 assert.equal(retention.inventory.filter(version=>version.isDefault)[0].versionId,'v13');
 const taskMap=fixture.registration.result.taskMap;
 assert.equal((await runtime.authenticatePolicyRetention(null,{registration:{result:{taskMap}}})).noOpPolicyCandidate,true);
 const changedMap={...taskMap,[Object.keys(taskMap)[0]]:Object.values(taskMap)[0].replace(/:[1-9][0-9]*$/,':999')};
 assert.equal((await runtime.authenticatePolicyRetention(null,{registration:{result:{taskMap:changedMap}}})).noOpPolicyCandidate,false);
 versions.splice(versions.findIndex(version=>version.VersionId==='v9'),1);
 assert.equal(Object.hasOwn(await runtime.authenticatePolicyRetention(null,{registration:{result:{taskMap}}}),'noOpPolicyCandidate'),false);
});

test('runner replacement hydrates exact public preparation material and rejects substituted members before writing',async()=>{
 const f=await createPublicRegistrationFixture();
 try{
  const prepared=await f.run({...f.initialRequest,operation:'prepare-registration'}),store=f.coordinatorStore;
  const paths={...f.files,plan:prepared.planPath},original=Object.fromEntries(Object.entries(paths).map(([name,file])=>[name,fs.readFileSync(file)]));
  const reference=await captureReleasePhaseMaterial({prepared,files:f.files,store,repositoryRoot:process.cwd()});
  // Only this test's newly generated temporary material is removed.
  for(const file of Object.values(paths)){assert.ok(file.startsWith(f.directory+'/'));fs.rmSync(file);}
  const capsule=store.getArtifact(reference);
  for(const mutate of [c=>c.sourceSha='f'.repeat(40),c=>delete c.members.plan,c=>c.members.plan.sha256='0'.repeat(64)]){
   const bad=structuredClone(capsule);mutate(bad);const badReference=brokerDigest(bad);store.putArtifact(badReference,bad);
   await assert.rejects(()=>hydrateReleasePhaseMaterial({reference:badReference,prepared,files:f.files,planPath:prepared.planPath,store,repositoryRoot:process.cwd()}));
   for(const file of Object.values(paths))assert.equal(fs.existsSync(file),false);
  }
  const recovered=await hydrateReleasePhaseMaterial({reference,prepared,files:f.files,planPath:prepared.planPath,store,repositoryRoot:process.cwd()});
  assert.deepEqual(recovered,prepared);
  for(const [name,file] of Object.entries(paths)){assert.deepEqual(fs.readFileSync(file),original[name]);assert.equal(fs.statSync(file).mode&0o777,0o600);}
  await hydrateReleasePhaseMaterial({reference,prepared,files:f.files,planPath:prepared.planPath,store,repositoryRoot:process.cwd()});
  assert.equal(f.snapshot().registrationApplyCalls,0);assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);assert.equal(f.snapshot().aliasCalls,0);
 }finally{f.dispose();}
});

test('hosted authorization producer uses actual protected approval and rejects unrelated workflow authority',async()=>{
 const now=new Date('2026-10-08T12:00:00.000Z'),repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
 const env={GITHUB_ACTIONS:'true',GITHUB_WORKFLOW_REF:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,GITHUB_SHA:sourceSha,GITHUB_RUN_ATTEMPT:'1',GITHUB_REPOSITORY:repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ID:'700',GITHUB_ACTOR:'operator',GH_TOKEN:'fixture-only',RELEASE_ID:'b'.repeat(64),RELEASE_PHASE:'registration',RELEASE_PREPARATION_REFERENCE:'c'.repeat(64),RELEASE_AUTHORIZATION_ROUND:'0'};
 const environment={id:7,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]};
 const responses={['environments/production']:environment,['actions/runs/700/approvals']:[{state:'approved',environments:[{id:7,name:'production'}],user:{id:1,login:'operator'}}]};
 let reads=0;
 const fetchImpl=async url=>{const prefix=`https://api.github.com/repos/${repository}/`;assert.ok(url.startsWith(prefix));const suffix=url.slice(prefix.length);assert.ok(Object.hasOwn(responses,suffix),'Unexpected external access');reads++;return {ok:true,json:async()=>responses[suffix]};};
 const value=await readBrokerProtectedEnvironmentApproval({sourceSha,env,now,fetchImpl});assert.equal(value.approval.actualApproval.userLogin,'operator');assert.equal(value.release.releaseId,env.RELEASE_ID);assert.equal(reads,2);
 for(const [field,bad] of [['GITHUB_WORKFLOW_REF',PRODUCTION_ENVIRONMENT_APPROVAL.workflowRef],['GITHUB_SHA','a'.repeat(40)],['GITHUB_RUN_ATTEMPT','2']]){
  await assert.rejects(()=>readBrokerProtectedEnvironmentApproval({sourceSha,env:{...env,[field]:bad},now,fetchImpl}));assert.equal(reads,2);
 }
 environment.protection_rules[0].prevent_self_review=true;
 await assert.rejects(()=>readBrokerProtectedEnvironmentApproval({sourceSha,env,now,fetchImpl}),/self-approved/);
});

test('protected approval authenticates exact workflow artifact before public registration and preserves sole-operator truth',async()=>{
 const f=await createPublicRegistrationFixture();
 try{
  const prepared=await f.run({...f.initialRequest,operation:'prepare-registration'}),p=prepared.preparation;
  const repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment={id:7,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]};
  const actual={state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'};
  const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:environment,repository,environment:'production',sourceSha:f.source,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
   eventName:'workflow_dispatch',workflowRunId:'700',workflowRunAttempt:'1',executionActor:'operator',observedAt:f.now.toISOString(),actualApproval:actual});
  const {predecessorReceiptRecovery,...inputs}=f.initialRequest;
  const authorization=await f.run({...inputs,operation:'authorize-registration',preparation:p,planPath:prepared.planPath},{readProtectedApproval:async()=>({approval,release:{releaseId:'b'.repeat(64),phase:'registration',preparationReference:brokerDigest(prepared),authorizationRound:0}})});
  assert.equal(authorization.schemaVersion,2);assert.equal(authorization.preparationSha256,brokerDigest(p));
  assert.equal(authorization.review.checkerIndependent,false);assert.equal(authorization.review.soleOperatorModel,true);
  const zip=new JSZip();zip.file('authorization.json',JSON.stringify(authorization));const archive=await zip.generateAsync({type:'nodebuffer',streamFiles:true});
  const workflow={id:700,repository:{id:9,full_name:repository},head_repository:{full_name:repository},path:'.github/workflows/authorize-production-stage-b-release-transition.yml',head_sha:f.source,event:'workflow_dispatch',status:'completed',conclusion:'success',run_attempt:1,actor:{login:'operator'}};
  const artifact={id:701,name:'production-stage-b-release-transition-authorization',expired:false,digest:`sha256:${createHash('sha256').update(archive).digest('hex')}`,workflow_run:{id:700,head_sha:f.source,repository_id:9}};
  const payloads={['actions/runs/700']:workflow,['actions/runs/700/artifacts']:[{artifacts:[artifact]}],['actions/artifacts/701/zip']:archive,['environments/production']:environment,['actions/runs/700/approvals']:[{state:'approved',environments:[{id:7,name:'production'}],user:{id:1,login:'operator'}}]};
  const run=args=>{assert.equal(args[0],'api');const key=args[1].slice(`repos/${repository}/`.length);assert.ok(Object.hasOwn(payloads,key),'Unexpected GitHub access');return Buffer.isBuffer(payloads[key])?payloads[key]:JSON.stringify(payloads[key]);};
  const retrieved=await readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run});
  assert.deepEqual(retrieved.authorization,authorization);assert.equal(retrieved.workflow.id,700);
  const malformedArchive=Buffer.from(archive),end=malformedArchive.lastIndexOf(Buffer.from([0x50,0x4b,0x05,0x06]));
  malformedArchive.writeUInt16LE(9,malformedArchive.readUInt32LE(end+16)+8);
  const originalDigest=artifact.digest;artifact.digest=`sha256:${createHash('sha256').update(malformedArchive).digest('hex')}`;
  payloads['actions/artifacts/701/zip']=malformedArchive;
  await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/ZIP metadata is not canonical/);
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  const descriptorOffset=archive.readUInt32LE(end+16)-16;
  for(const offset of [0,4,8,12]){
   const corrupted=Buffer.from(archive);corrupted.writeUInt32LE((corrupted.readUInt32LE(descriptorOffset+offset)^1)>>>0,descriptorOffset+offset);
   artifact.digest=`sha256:${createHash('sha256').update(corrupted).digest('hex')}`;
   payloads['actions/artifacts/701/zip']=corrupted;
   assert.throws(()=>readZipCentralDirectory(corrupted,{allowSingleMemberDataDescriptor:true}),/data descriptor is invalid/);
   await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/data descriptor is invalid/);
  }
  for(const [offset,size] of [[8,2],[14,4],[18,4],[22,4]]){
   const corrupted=Buffer.from(archive);if(size===2)corrupted.writeUInt16LE(corrupted.readUInt16LE(offset)^1,offset);else corrupted.writeUInt32LE((corrupted.readUInt32LE(offset)^1)>>>0,offset);
   artifact.digest=`sha256:${createHash('sha256').update(corrupted).digest('hex')}`;
   payloads['actions/artifacts/701/zip']=corrupted;
   await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/local descriptor metadata is invalid/);
  }
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  const directoryOffset=archive.readUInt32LE(end+16);
  const gap=Buffer.concat([archive.subarray(0,directoryOffset),Buffer.from([0]),archive.subarray(directoryOffset)]);
  gap.writeUInt32LE(directoryOffset+1,gap.lastIndexOf(Buffer.from([0x50,0x4b,0x05,0x06]))+16);
  assert.throws(()=>readZipCentralDirectory(gap,{allowSingleMemberDataDescriptor:true}),/data descriptor is invalid/);
  const hiddenBody=Buffer.concat([archive.subarray(0,end),Buffer.from([0x50,0x4b,0x03,0x04]),archive.subarray(end)]);
  artifact.digest=`sha256:${createHash('sha256').update(hiddenBody).digest('hex')}`;
  payloads['actions/artifacts/701/zip']=hiddenBody;
  await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/directory placement is invalid/);
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  const prefixed=Buffer.concat([Buffer.from([0]),archive]);
  assert.throws(()=>readZipCentralDirectory(prefixed,{allowSingleMemberDataDescriptor:true}),/directory placement is invalid/);
  const wrongDisk=Buffer.from(archive);wrongDisk.writeUInt16LE(1,end+4);
  assert.throws(()=>readZipCentralDirectory(wrongDisk,{allowSingleMemberDataDescriptor:true}),/one member on one disk/);
  const wrongMemberDisk=Buffer.from(archive);wrongMemberDisk.writeUInt16LE(1,directoryOffset+34);
  artifact.digest=`sha256:${createHash('sha256').update(wrongMemberDisk).digest('hex')}`;
  payloads['actions/artifacts/701/zip']=wrongMemberDisk;
  await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/member belongs to another disk/);
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  const wrongLocalVersion=Buffer.from(archive);wrongLocalVersion.writeUInt16LE(21,4);
  assert.throws(()=>readZipCentralDirectory(wrongLocalVersion,{allowSingleMemberDataDescriptor:true}),/local header placement is invalid/);
  const zeroFlagArchive=await zip.generateAsync({type:'nodebuffer'});
  assert.equal(readZipCentralDirectory(zeroFlagArchive,{allowSingleMemberDataDescriptor:true}).length,1);
  for(const name of ['../authorization.json','foo/../authorization.json']){
   const unsafeZip=new JSZip();unsafeZip.file(name,JSON.stringify(authorization),{createFolders:false});
   const unsafeArchive=await unsafeZip.generateAsync({type:'nodebuffer',streamFiles:true});
   artifact.digest=`sha256:${createHash('sha256').update(unsafeArchive).digest('hex')}`;
   payloads['actions/artifacts/701/zip']=unsafeArchive;
   await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/Unexpected raw authorization ZIP member/);
  }
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  const deflated=await zip.generateAsync({type:'nodebuffer',compression:'DEFLATE',streamFiles:true});
  const deflatedEnd=deflated.lastIndexOf(Buffer.from([0x50,0x4b,0x05,0x06]));
  const deflatedDirectory=deflated.readUInt32LE(deflatedEnd+16);
  const deflatedEntry=readZipCentralDirectory(deflated,{allowSingleMemberDataDescriptor:true})[0];
  const descriptorStart=deflatedEntry.dataOffset+deflatedEntry.compressedSize;
  const trailingDeflate=Buffer.concat([deflated.subarray(0,descriptorStart),Buffer.from([0]),deflated.subarray(descriptorStart)]);
  trailingDeflate.writeUInt32LE(deflatedDirectory+1,deflatedEnd+17);
  trailingDeflate.writeUInt32LE(deflatedEntry.compressedSize+1,deflatedDirectory+21);
  trailingDeflate.writeUInt32LE(deflatedEntry.compressedSize+1,descriptorStart+9);
  artifact.digest=`sha256:${createHash('sha256').update(trailingDeflate).digest('hex')}`;
  payloads['actions/artifacts/701/zip']=trailingDeflate;
  await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run}),/DEFLATE stream has trailing bytes/);
  artifact.digest=originalDigest;payloads['actions/artifacts/701/zip']=archive;
  await assert.rejects(()=>readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:'f'.repeat(40),run}));
  const verify=a=>verifyBrokerProtectedEnvironmentAuthorization(a,{run});
  await assertBrokerAuthorization(authorization,p,{verify,now:f.now});
  for(const field of ['sourceSha','purpose','preparationSha256']){
   const changed=structuredClone(authorization);changed[field]='wrong';await assert.rejects(()=>assertBrokerAuthorization(changed,p,{verify,now:f.now}));
  }
  const changed=structuredClone(authorization);changed.review.checkerIndependent=true;await assert.rejects(()=>assertBrokerAuthorization(changed,p,{verify,now:f.now}));
  for(const [object,field,value] of [[workflow,'conclusion','failure'],[workflow,'run_attempt',2],[workflow,'head_sha','f'.repeat(40)],[artifact,'digest','sha256:'+'0'.repeat(64)],[artifact,'expired',true]]){
   const prior=object[field];object[field]=value;await assert.rejects(()=>verify(authorization));object[field]=prior;
  }
  const substitute=structuredClone(authorization);substitute.nonce='0'.repeat(64);await assert.rejects(()=>verify(substitute),/substitution/);
  await assert.rejects(()=>assertBrokerAuthorization(authorization,p,{verify,now:new Date(f.now.getTime()+31*60000)}));
  const priorVerify=f.checker.verify;f.checker.verify=a=>a.schemaVersion===2?verify(a):priorVerify(a);
  const result=await f.run({...inputs,operation:'register',preparation:p,authorization,planPath:prepared.planPath});
  assertRegistrationHandoff({preparation:p,authorization,result},{sourceSha:f.source,treeSha256:f.tree});
  assert.equal(f.snapshot().registrationApplyCalls,1);assert.equal(Object.keys(result.definitions).length,12);
  assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);assert.equal(f.snapshot().aliasCalls,0);
 }finally{f.dispose();}
});

test('external coordinator records survive lost create responses and reject replacement without business mutations',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'coordinator-store-'));fs.chmodSync(directory,0o700);
 const objects=new Map(),calls=[];let loseResponse=true;
 const run=args=>{
  calls.push(args.slice(0,2));assert.equal(args[0],'s3api');
  const value=flag=>args[args.indexOf(flag)+1],key=value('--key');
  if(args[1]==='put-object'){
   assert.equal(value('--if-none-match'),'*');assert.equal(value('--server-side-encryption'),'AES256');
   if(objects.has(key))throw Object.assign(new Error('Occupied'),{stderr:'(PreconditionFailed)'});
   objects.set(key,fs.readFileSync(value('--body')));
   if(loseResponse){loseResponse=false;throw new Error('Lost create response');}return '{}';
  }
  assert.equal(args[1],'get-object');
  if(!objects.has(key))throw Object.assign(new Error('Absent'),{stderr:'(NoSuchKey)'});
  const file=args.find(a=>a.startsWith(directory+'/'));assert.ok(file);fs.writeFileSync(file,objects.get(key));return '{}';
 };
 try{
  const store=createReleaseCoordinatorStore({run,directory,repositoryRoot:process.cwd()});
  const request={sourceSha,ticketId:'current-release'},record={release:'1'.repeat(64),baseline:'2'.repeat(64)};
  assert.equal(store.readStart(request),null);store.writeStart(request,record);assert.deepEqual(store.readStart(request),record);
  store.writeStart(request,record);assert.throws(()=>store.writeStart(request,{...record,release:'3'.repeat(64)}));
  const artifact={sourceSha,value:'immutable'};const digest=brokerDigest(artifact);store.putArtifact(digest,artifact);store.putArtifact(digest,artifact);
  assert.deepEqual(store.getArtifact(digest),artifact);assert.throws(()=>store.putArtifact(digest,{...artifact,value:'altered'}));
  const step={releaseId:'4'.repeat(64),sourceSha,name:'registration:attempt',prepared:digest,authorization:'5'.repeat(64)};
  store.writeStep(step);assert.deepEqual(store.readStep(step.releaseId,step.name),step);
  assert.throws(()=>store.writeStep({...step,authorization:'6'.repeat(64)}));assert.equal(objects.size,3);
  store.putArtifact(brokerDigest(null),null);assert.equal(store.getArtifact(brokerDigest(null)),null);
  assert.ok(calls.every(([service,operation])=>service==='s3api'&&['get-object','put-object'].includes(operation)));
 }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('current completed operation retains its real signed identity and all twelve successor bindings offline',async()=>{
 const {publicKey,...entry}=JSON.parse(fs.readFileSync(new URL('../../documents/ops/iam/MSCQRProductionStageBCompletedRegistration-2026-10-08.json',import.meta.url)));
 const key=createPublicKey({key:Buffer.from(publicKey,'base64'),format:'der',type:'spki'});
 const verify=a=>verifySignature('sha256',brokerAuthorizationMessage(a),{key,padding:constants.RSA_PKCS1_PSS_PADDING,saltLength:32},Buffer.from(a.signature.signatureBase64,'base64'));
 const release={sourceSha:entry.preparation.sourceSha,treeSha256:entry.preparation.treeSha256};
 assertRegistrationHandoff(entry,release);
 assert.equal(await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify,now:new Date(entry.result.authorizedAt)}),CURRENT_REGISTRATION_OPERATION);
 assert.equal(Object.keys(entry.result.definitions).length,12);
 assert.equal(entry.result.authorizationSha256,CURRENT_REGISTRATION_OPERATION);
 const descendant={sourceSha:'d'.repeat(40),treeSha256:'e'.repeat(64)};
 const plan={errored:false,variables:{tooling_sha:{value:descendant.sourceSha}},resource_changes:Object.entries(entry.result.definitions).map(([address,d])=>{
  const state={...structuredClone(d.desired),arn:d.arn,revision:d.revision};
  return {address,mode:'managed',change:{actions:['no-op'],before:state,after:structuredClone(state),after_unknown:{}}};
 })};
 const impact={imageReleaseSha:release.sourceSha,toolingSha:descendant.sourceSha,toolingInputTreeSha256:descendant.treeSha256,imageReuseCompatible:true,newImagesRequired:false,imageAffectingFiles:[]};
 const adopted=adoptRegisteredOutputs(entry,descendant,plan,impact);
 assert.equal(adopted.adoption.transaction.authorizationSha256,CURRENT_REGISTRATION_OPERATION);
 assert.deepEqual(adopted.result,entry.result);assert.deepEqual(adopted.preparation,entry.preparation);
 const changed=structuredClone(entry.authorization);changed.sourceSha='a'.repeat(40);
 await assert.rejects(()=>assertBrokerAuthorization(changed,entry.preparation,{verify,now:new Date(entry.result.authorizedAt)}));
 const altered=structuredClone(entry);const d=Object.values(altered.result.definitions)[0];d.arn=d.arn.replace(/:\d+$/,':999');
 assert.throws(()=>adoptRegisteredOutputs(altered,descendant,plan,impact));
 assert.throws(()=>adoptRegisteredOutputs(entry,descendant,plan,{...impact,imageReuseCompatible:false,newImagesRequired:true}));
});

async function seedDurableRegistration(store,entry,ticketId='current-release'){
 const release=createReleaseIdentity({sourceSha:entry.preparation.sourceSha,ticketId,baseline,changedFiles:[]});
 const put=async value=>{const hash=brokerDigest(value);await store.putArtifact(hash,value);return hash;};
 await store.writeStart({sourceSha:release.sourceSha,ticketId},{release:await put(release),baseline:await put(baseline)});
 await store.writeStep({releaseId:release.releaseId,sourceSha:release.sourceSha,name:'registration:result',
  prepared:await put({preparation:entry.preparation}),authorization:await put(entry.authorization),result:await put(entry.result)});
 return release;
}

for(const lostResponse of [null,'prerequisites-only','prerequisites-only-overlap','normal-predecessor','adopt-registration','adopt-current-registration','full-capacity-noop-policy','full-capacity-change-policy','full-capacity-second-plan-change','adopt-descendant-registration','hosted-runner-replacement','proved-no-policy-write','no-prune-policy-lost','github-approval','approval-boundary','approval-timed-out','approval-journal-timeout','approval-record-response-lost','authorization-response-lost','approval-expired-before-consumption','source-advance','register','prune','converge-policy','publish','cutover','reconcile','cutover-expired-before-closure','closure-alias-changed','closure-cas-substituted','expired-register','expired-prune','expired-converge-policy','expired-publish','pre-intent-register','post-intent-register','reservation-register','pre-intent-prune','owner-prune','post-intent-prune','pre-intent-converge-policy','owner-converge-policy','post-intent-converge-policy','pre-intent-publish','post-intent-publish','reservation-publish','pre-intent-cutover','expired-pre-intent-reconcile','post-intent-cutover','reservation-cutover','pre-intent-reconcile','post-intent-reconcile','inventory-drift','default-drift','ownership-drift','alias-drift']) test(`one public coordinator entry closes full-capacity prerequisites; lost response: ${lostResponse}`, async () => {
 const hostedClosureRelease=lostResponse===null?createReleaseIdentity({sourceSha:prepublicationPredecessorFixture().f.release.sourceSha,
  ticketId:'current-release',baseline,changedFiles:['backend/src/services/qrService.ts']}):null;
 const f=await createPublicRegistrationFixture({completedRegistration:lostResponse==='adopt-registration',currentCompletedRegistration:['adopt-current-registration','full-capacity-noop-policy','full-capacity-change-policy','full-capacity-second-plan-change'].includes(lostResponse),descendantCompletedRegistration:['adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse),normalPredecessor:lostResponse==='normal-predecessor',
  ...(hostedClosureRelease?{privateDirectory:path.join(HOSTED_RELEASE_ROOT,hostedClosureRelease.releaseId,'cutover')}:{})});
 if(lostResponse==='no-prune-policy-lost')f.changeLiveInventory(xs=>xs.filter(v=>v.VersionId!=='v9'));
 const priorRegistrationCalls=f.snapshot().registeredTaskDefinitionCalls,priorApplyCalls=f.snapshot().registrationApplyCalls;
 const steps=new Map(),calls=[],materializedPruningPhases=new Set();let interrupted=false,approvalDispatches=0,noOpPolicyEvidence=true,noOpPolicyPlan=lostResponse!=='full-capacity-change-policy',noOpPolicyIdentityChanged=false,policyPlanCalls=0;const lostOperation=lostResponse==='hosted-runner-replacement'?'prune':lostResponse==='no-prune-policy-lost'?'converge-policy':lostResponse?.replace(/^expired-/,'');const drift=lostResponse?.endsWith('-drift');
 const copy=value=>JSON.parse(JSON.stringify(value));
 const hostedVerifiers=new Map(),priorVerify=f.checker.verify;
 const hostedApproval=lostResponse===null||lostResponse?.startsWith('prerequisites-only')||['github-approval','approval-boundary','approval-record-response-lost','adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement','approval-expired-before-consumption'].includes(lostResponse);
 if(hostedApproval)f.checker.verify=a=>a.schemaVersion===2?hostedVerifiers.get(a.nonce)?.(a)||false:priorVerify(a);
 const runtime={
  store:{...f.coordinatorStore,
   writeStep:async value=>{f.coordinatorStore.writeStep(value);const key=`${value.releaseId}/${value.name}`;assert.ok(!steps.has(key));steps.set(key,copy(value));if(lostResponse==='authorization-response-lost'&&value.name==='registration:authorized:0'&&!interrupted){interrupted=true;assert.equal(f.snapshot().registrationApplyCalls,0);f.advanceClock(31*60*1000);throw new Error('Lost completed mutation response');}if(lostResponse==='approval-record-response-lost'&&value.name==='registration:pending:0')throw new Error('Lost completed mutation response');}},
  authenticateSource:async source=>{
   assert.equal(source,f.source);
   return readHostedReleaseSource(source,{checkout:()=>({currentHead:source,originMainHead:source}),
    run:args=>{assert.deepEqual(args.slice(0,2),['dynamodb','get-item']);return JSON.stringify({Item:{stateKey:{S:'production#T-ej2003/genuine-scan-main'},
     generation:{N:String(baseline.generation)},state:{S:JSON.stringify(baseline)}}});},
    git:args=>args[0]==='merge-base'?'':args[0]==='diff'&&args[3]==='9'.repeat(40)?'backend/src/services/qrService.ts\n':args[0]==='diff'?'':rejectExternalAccess(args)});
  },
  resolveArtifacts:async release=>({sourceSha:release.sourceSha,fixturePackageSha256:brokerDigest(f.files.package)}),
  authenticateArtifacts:async(release,evidence)=>assert.equal(evidence.sourceSha,release.sourceSha),
  gateLifecycle:lostResponse?.startsWith('prerequisites-only')?'prerequisites':'strict',
  resolveGates:async release=>{
   const fixture=gateFixture(release.sourceSha,runtime.gateLifecycle);
   return readReleaseGateEvidence({sourceSha:release.sourceSha,lifecycle:fixture.lifecycle,expectedWorkflowRunIds:fixture.expectedWorkflowRunIds,
    githubJson:async endpoint=>{
     const workflow=/^\/actions\/workflows\/([^/]+)$/.exec(endpoint),run=/^\/actions\/runs\/([1-9][0-9]*)$/.exec(endpoint);
     if(workflow)return fixture.workflowPayloads[decodeURIComponent(workflow[1])]?.workflow;
     if(run)return Object.values(fixture.workflowPayloads).flatMap(value=>value.runs).find(value=>String(value.id)===run[1]);
     return rejectExternalAccess(endpoint);
    }});
  },
  authenticateGates:async(release,evidence)=>authenticateReleaseGateRuns(release,evidence),
  materializeInputs:async(release,artifacts,{phase,prepared})=>{
   assert.equal(release.sourceSha,f.source);assert.equal(artifacts.sourceSha,f.source);
   if(prepared)assert.equal(prepared.preparation.sourceSha,release.sourceSha);
   if(lostResponse==='full-capacity-noop-policy'&&phase.startsWith('pruning')){
    assert.ok(!materializedPruningPhases.has(phase),'Stage A input would be overwritten on approval polling');
    materializedPruningPhases.add(phase);
   }
   if(phase==='registration')return f.initialRequest;
   const {predecessorReceiptRecovery,...inputs}=f.initialRequest;return inputs;
  },
  capturePreparation:async(context,name,prepared)=>{
   if(lostResponse==='full-capacity-noop-policy'&&name==='policy')return prepared;
   const materializationSha256=await captureReleasePhaseMaterial({prepared,files:f.files,store:f.coordinatorStore,repositoryRoot:process.cwd()});
   return {...prepared,materializationSha256};
  },
  hydratePreparation:async(context,name,prepared)=>{
   if(lostResponse==='full-capacity-noop-policy'&&name==='policy')return;
   await hydrateReleasePhaseMaterial({reference:prepared.materializationSha256,prepared,files:f.files,planPath:prepared.planPath,store:f.coordinatorStore,repositoryRoot:process.cwd()});
  },
  findCompletedRegistration:async release=>{
   if(lostResponse!=='adopt-descendant-registration')return f.completedRegistration||null;
   await seedDurableRegistration(f.coordinatorStore,f.completedRegistration);
   const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
    GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:f.source,RUNNER_TEMP:'/tmp'};
   const hosted=createHostedReleaseRuntime({sourceSha:f.source,ticketId:'current-release',
    imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',env,
    awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>f.coordinatorStore,verifyAuthorization:f.checker.verify,
    imageReader:()=>({sourceSha:f.source,completedRegistrationSourceSha:f.completedRegistration.preparation.sourceSha}),
    readReceipt:({id,status})=>{assert.equal(id,brokerDigest(f.completedRegistration.authorization));assert.equal(status,'TASK_REGISTERED');return f.completedRegistration.result;},
    imageImpact:({imageReleaseSha,toolingSha})=>{assert.equal(imageReleaseSha,f.completedRegistration.preparation.sourceSha);assert.equal(toolingSha,f.source);return {imageReuseCompatible:true,newImagesRequired:false};}});
   return hosted.findCompletedRegistration(release);
  },
  authenticateRegistration:async(release,entry,_inputs,{predecessorAdvanced}={})=>{
   if(entry.adoption){
    assertRegistrationHandoff(entry,{sourceSha:release.sourceSha,treeSha256:f.tree});
    assert.equal(await f.checker.verify(entry.authorization),true);
    if(!predecessorAdvanced){
     const observed=await f.run({...f.initialRequest,predecessorReceiptRecovery:undefined,operation:'prepare-registration-adoption',
      prerequisiteChain:{registration:{preparation:entry.preparation,authorization:entry.authorization,result:entry.result}}});
     assert.deepEqual(observed.prerequisiteChain.registration,entry);
    }else assert.equal(f.snapshot().registeredTaskDefinitionCalls,12);
   }else{assert.equal(entry.preparation.sourceSha,release.sourceSha);await f.authenticateRegistration(entry);}
  },
  runStageOperation:async request=>{calls.push(request.operation);if(['full-capacity-noop-policy','full-capacity-change-policy','full-capacity-second-plan-change'].includes(lostResponse)&&request.operation==='prepare-policy'){const policyAttempt=++policyPlanCalls;return {preparation:{sourceSha:f.source,state:f.snapshot().liveState,policyNoOp:true,artifactSetSha256:policyAttempt===1?'a'.repeat(64):'b'.repeat(64),configuration:noOpPolicyIdentityChanged?'changed':'original'},mutationAddresses:noOpPolicyPlan&&!(lostResponse==='full-capacity-second-plan-change'&&policyAttempt===2)?[]:['aws_iam_policy.broker'],planPath:path.join(f.initialRequest.directory,'noop-policy.tfplan')};}if(lostResponse==='proved-no-policy-write'){if(request.operation==='prune'&&!interrupted){interrupted=true;throw new Error('Lost completed mutation response');}if(request.operation==='recover-policy')return {status:'RECOVERED_NO_WRITE'};}if(drift&&!interrupted&&request.operation===(lostResponse==='alias-drift'?'cutover':'prune')){interrupted=true;if(lostResponse==='inventory-drift')f.changeLiveInventory(xs=>xs.map(v=>v.VersionId==='v10'?{...v,VersionId:'v99'}:v));if(lostResponse==='default-drift')f.changeLiveDefault('v12');if(lostResponse==='ownership-drift')f.changeOwnership(owner=>({...owner,identity:{...owner.identity,operationIdentity:'0'.repeat(64)}}));if(lostResponse==='alias-drift')f.changeLiveAlias(alias=>({...alias,RevisionId:'unapproved-revision'}));}const result=await f.run(request);
   if(request.operation==='cutover'&&lostResponse==='cutover-expired-before-closure')f.advanceClock(31*60*1000);
   if(request.operation==='cutover'&&lostResponse==='closure-alias-changed')f.changeLiveAlias(alias=>({...alias,RevisionId:'unapproved-revision'}));
   if(request.operation==='cutover'&&lostResponse==='closure-cas-substituted')return {...result,alias:{...result.alias,RevisionId:'substituted-revision'}};
   if(request.operation===lostOperation&&!interrupted){interrupted=true;if(lostResponse?.startsWith('expired-'))f.advanceClock(31*60*1000);throw new Error('Lost completed mutation response');}return result;},
  classifyNativeAttempt:async(_context,name,_prepared,authorization)=>{
   const id=brokerDigest(authorization),status={registration:'TASK_REGISTRATION_INTENT',pruning:'BROKER_POLICY_PRUNING_INTENT',policy:'BROKER_POLICY_INTENT',publication:'PUBLICATION_INTENT',cutover:'CUTOVER_INTENT',closure:'STATE_REFRESH_INTENT'}[name];
   const snapshot=f.snapshot();
   return snapshot.receipts.some(r=>r[0]===id&&r[1]===status)||(['pruning','policy'].includes(name)&&snapshot.owner?.identity?.operationIdentity===id)?'RECOVER':'PRE_NATIVE';
  },
  readRecoveredTransition:async(context,name,prepared,authorization,result)=>{if(lostResponse==='proved-no-policy-write'&&result.status==='RECOVERED_NO_WRITE'){f.advanceClock(31*60*1000);return {status:'RECOVERED_NO_WRITE',authorizationSha256:brokerDigest(authorization)};}return f.recoveredReceipt(name,authorization,result);},
  now:()=>f.now,
  authenticateAuthorization:(p,a)=>assertBrokerAuthorization(a,p,{verify:f.checker.verify,now:new Date(a.issuedAt)}),
  authenticateCompletedTransition:async(context,name,prepared,authorization,result)=>{
   const p=prepared.preparation;
   await assertBrokerAuthorization(authorization,p,{verify:f.checker.verify,now:new Date(result.stateAuthorizedAt||result.authorizedAt||f.now)});
   if(name==='registration'){
    assertRegistrationHandoff({preparation:p,authorization,result},{sourceSha:f.source,treeSha256:f.tree});
    assert.equal(Object.keys(result.definitions).length,12);
    assert.deepEqual(f.snapshot().receipts.find(r=>r[1]==='TASK_REGISTERED')[2],result);
   } else if(name==='pruning')assertPolicyPruningHandoff({preparation:p,authorization,result},p.prerequisiteChain);
   else if(name==='cutover')assert.deepEqual(f.snapshot().receipts.find(r=>r[0]===brokerDigest(authorization)&&r[1]==='CUTOVER_COMMITTED_STATE_PENDING')?.[2],result);
   else if(name==='closure')assertBrokerClosurePlan(result.closurePlan,p);
   else {assert.equal(result.preparationSha256,brokerDigest(p));assert.equal(result.authorizationSha256,brokerDigest(authorization));}
  },
  authenticateClosure:async(context,packages,chain)=>{
   assertBrokerClosurePlan(packages.closure.result.closurePlan,packages.cutover.prepared.preparation);
   assert.deepEqual(f.snapshot().liveAlias,packages.cutover.result.alias);
   assert.deepEqual(chain.policy.result.policy,f.snapshot().policySnapshot.policy);
   assert.ok(f.snapshot().receipts.some(r=>r[1]==='STAGED_BROKER_TERMINAL_HANDOFF'));
   return packages.closure.result;
  },
  authenticatePolicyRetention:async()=>({inventory:f.snapshot().policySnapshot.versions.map(v=>({versionId:v.VersionId,isDefault:v.IsDefaultVersion,createDate:new Date(Date.UTC(2026,8,['v9','v10','v11','v12','v13'].indexOf(v.VersionId)+1)).toISOString(),documentSha256:brokerDigest(f.fixture.policy.terminal.policy)})),protectedVersionIds:['v12','v13'],obsoleteVersionIds:['v9','v10','v11'],...(['full-capacity-noop-policy','full-capacity-change-policy','full-capacity-second-plan-change'].includes(lostResponse)?{noOpPolicyCandidate:noOpPolicyEvidence}:{})}),
  obtainAuthorization:async(context,phase,prepared,digest)=>{
   if((lostResponse==='full-capacity-noop-policy'&&phase==='policy'||lostResponse==='full-capacity-change-policy'&&phase==='pruning'))return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};
   assert.equal(brokerDigest(prepared),digest);
   const cutover=phase==='closure'?steps.get(`${context.release.releaseId}/cutover:result`):null;
   const predecessor=cutover?{cutoverPreparation:f.coordinatorStore.getArtifact(cutover.prepared).preparation,
    cutoverAuthorization:f.coordinatorStore.getArtifact(cutover.authorization),casResult:f.coordinatorStore.getArtifact(cutover.result)}:{};
   if(lostResponse==='approval-journal-timeout'&&phase==='registration'&&context.authorizationRound===0){
    assert.equal(context.pendingApproval,null);
    if(!interrupted){
     interrupted=true;approvalDispatches++;
     const workflow='authorize-production-stage-b-release-transition.yml';
     await runtime.store.writeStep({releaseId:context.release.releaseId,sourceSha:f.source,name:'registration:dispatch:0',
      dispatch:{identity:{repository:'T-ej2003/genuine-scan-main',workflow,workflowPath:`.github/workflows/${workflow}`,
       workflowId:8,ref:'main',targetSha:f.source,inputs:releaseTransitionDispatchInputs(context,'registration',digest)},beforeRunIds:[]}});
     throw new Error('Lost approval child response before pending marker');
    }
    return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   }
   if(['approval-boundary','approval-timed-out','approval-record-response-lost'].includes(lostResponse)&&phase==='registration'&&context.authorizationRound===0){
    if(!context.pendingApproval){approvalDispatches++;return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};}
    assert.equal(context.pendingApproval.runId,'700');assert.equal(context.pendingApproval.prepared,digest);
    if(lostResponse==='approval-timed-out')return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   }
   if(hostedApproval){
    const transport=hostedApprovalTransport(f.source,f.now,context.pendingApproval?Number(context.pendingApproval.runId):900+hostedVerifiers.size);
    const operation={registration:'authorize-registration',pruning:'authorize-pruning',policy:'authorize-policy',publication:'authorize-publication',cutover:'authorize-cutover',closure:'authorize-closure'}[phase];
    const approvalContext={releaseId:context.release.releaseId,phase,preparationReference:digest,authorizationRound:context.authorizationRound};
    const authorization=lostResponse===null&&phase==='closure'
     ?await (async()=>{
      const output=path.join(HOSTED_RELEASE_ROOT,context.release.releaseId,'closure','authorization.json');
      fs.mkdirSync(path.dirname(output),{recursive:true,mode:0o700});
      const env={GITHUB_ACTIONS:'true',GITHUB_WORKFLOW_REF:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
       GITHUB_REPOSITORY:PRODUCTION_ENVIRONMENT_APPROVAL.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',
       GITHUB_RUN_ID:String(900+hostedVerifiers.size),GITHUB_SHA:f.source,RUNNER_TEMP:'/tmp',RELEASE_ID:context.release.releaseId,
       RELEASE_PHASE:phase,RELEASE_PREPARATION_REFERENCE:digest,RELEASE_AUTHORIZATION_ROUND:String(context.authorizationRound)};
      const signed=await authorizeReleaseTransition({sourceSha:f.source,ticketId:context.release.ticketId,...approvalContext,output},
       {env,run:rejectExternalAccess,createStore:()=>f.coordinatorStore,
        runRequest:r=>f.run(r,{readProtectedApproval:async()=>({approval:transport.approval,release:approvalContext})})});
      assert.equal(signed.authorizationPath,output);return JSON.parse(fs.readFileSync(output,'utf8'));
     })()
     :await f.run({operation,preparation:prepared.preparation,planPath:prepared.planPath,...predecessor},
      {readProtectedApproval:async()=>({approval:transport.approval,release:approvalContext})});
    hostedVerifiers.set(authorization.nonce,await transport.publish(authorization));
    if(lostResponse==='approval-expired-before-consumption'&&phase==='registration'&&context.authorizationRound===0){assert.equal(f.snapshot().registrationApplyCalls,0);f.advanceClock(31*60*1000);}
    return {status:'AUTHORIZED',authorization};
   }
   if(phase==='registration') {
    assert.equal(prepared.preparation.schemaVersion,lostResponse==='normal-predecessor'?2:3);
    if(lostResponse!=='normal-predecessor')assert.deepEqual(prepared.preparation.registrationPolicyPredecessor,f.fixture.policy);
    const authorization=await f.run({operation:'authorize-registration',preparation:prepared.preparation,planPath:prepared.planPath,makerIdentity:f.maker,humanReviewId:'fixture-production-approval'});
    return {status:'AUTHORIZED',authorization};
   }
   const operation={pruning:'authorize-pruning',policy:'authorize-policy',publication:'authorize-publication',cutover:'authorize-cutover',closure:'authorize-closure'}[phase];
   assert.ok(operation);
   if(phase==='pruning')assert.equal(prepared.preparation.target.versionId,'v9');
   const authorization=await f.run({operation,preparation:prepared.preparation,planPath:prepared.planPath,...predecessor,
    makerIdentity:f.maker,humanReviewId:`fixture-production-${phase}-approval`});
   return {status:'AUTHORIZED',authorization};
  },
 };
 try {
  const request={sourceSha:f.source,ticketId:'current-release'};
  if(lostResponse==='full-capacity-change-policy'){
   const waiting=await runReleaseCoordinator(request,runtime);
   assert.equal(waiting.status,'WAITING_FOR_APPROVAL');assert.equal(waiting.phase,'pruning');
   assert.ok(![...steps.keys()].some(key=>key.endsWith('/pruning:skipped')));
   assert.equal(f.snapshot().registrationApplyCalls,priorApplyCalls);
   assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);
   return;
  }
  if(lostResponse==='full-capacity-second-plan-change'){
   await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Full-capacity policy preparation is no longer a no-op/);
   assert.ok([...steps.keys()].some(key=>key.endsWith('/pruning:skipped')));
   assert.ok(![...steps.keys()].some(key=>key.endsWith('/policy:prepared')));
   assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);
   assert.equal(f.snapshot().registrationApplyCalls,priorApplyCalls);
   return;
  }
  if(lostResponse==='full-capacity-noop-policy'){
   for(let attempt=0;attempt<2;attempt++){
    const waiting=await runReleaseCoordinator(request,runtime);
    assert.equal(waiting.status,'WAITING_FOR_APPROVAL');assert.equal(waiting.phase,'policy');
    assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);
    assert.equal(f.snapshot().registrationApplyCalls,priorApplyCalls);
   }
   assert.ok([...steps.keys()].some(key=>key.endsWith('/pruning:skipped')));
   noOpPolicyIdentityChanged=true;
   await assert.rejects(()=>runReleaseCoordinator(request,runtime),/No-op policy preparation changed/);
   noOpPolicyIdentityChanged=false;
   noOpPolicyPlan=false;
   await assert.rejects(()=>runReleaseCoordinator(request,runtime),/no longer a no-op/);
   noOpPolicyPlan=true;noOpPolicyEvidence=false;
   await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Unpruned inventory changed/);
   assert.equal(f.snapshot().policyDeletes,0);assert.equal(f.snapshot().policyCreates,0);
   return;
  }
  if(drift){await assert.rejects(()=>runReleaseCoordinator(request,runtime));const before=f.snapshot();assert.equal(before.registrationApplyCalls,1);assert.equal(before.policyDeletes,lostResponse==='alias-drift'?1:0);assert.equal(before.policyCreates,lostResponse==='alias-drift'?1:0);assert.equal(before.aliasCalls,0);await assert.rejects(()=>runReleaseCoordinator(request,runtime));const after=f.snapshot();for(const count of ['registrationApplyCalls','policyDeletes','policyCreates','publicationCalls','aliasCalls'])assert.equal(after[count],before[count]);return;}
  if(['closure-alias-changed','closure-cas-substituted'].includes(lostResponse)){
   await assert.rejects(()=>runReleaseCoordinator(request,runtime));
   assert.equal(f.snapshot().aliasCalls,1);assert.equal(f.snapshot().refreshCalls,0);
   assert.equal([...steps.keys()].filter(k=>k.endsWith('closure:authorized:0')).length,0);
   return;
  }
  if(['approval-boundary','approval-timed-out'].includes(lostResponse)){const waiting=await runReleaseCoordinator(request,runtime);assert.equal(waiting.status,'WAITING_FOR_APPROVAL');assert.equal(waiting.runId,'700');assert.equal(f.snapshot().registrationApplyCalls,0);}
  if(lostResponse==='approval-journal-timeout')await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Lost approval child response/);
  const nativeOperation=lostResponse?.replace(/^(expired-)?(pre|post)-intent-|^(reservation|owner)-/,'');
  if(lostResponse?.includes('pre-intent-'))f.injectNativeFault({kind:'checkout',operation:nativeOperation});
  if(lostResponse?.startsWith('post-intent-'))f.injectNativeFault({kind:'after-intent',status:{register:'TASK_REGISTRATION_INTENT',prune:'BROKER_POLICY_PRUNING_INTENT','converge-policy':'BROKER_POLICY_INTENT',publish:'PUBLICATION_INTENT',cutover:'CUTOVER_INTENT',reconcile:'STATE_REFRESH_INTENT'}[nativeOperation]});
  if(lostResponse?.startsWith('reservation-'))f.injectNativeFault({kind:'before-intent',status:{register:'TASK_REGISTRATION_INTENT',publish:'PUBLICATION_INTENT',cutover:'CUTOVER_INTENT'}[nativeOperation]});
  if(lostResponse?.startsWith('owner-'))f.injectNativeFault({kind:'before-intent',status:{prune:'BROKER_POLICY_PRUNING_INTENT','converge-policy':'BROKER_POLICY_INTENT'}[nativeOperation]});
  if(lostResponse?.startsWith('post-intent-')||lostResponse?.startsWith('owner-')){
   await assert.rejects(()=>runReleaseCoordinator(request,runtime));
   const before=f.snapshot();await assert.rejects(()=>runReleaseCoordinator(request,runtime));
   assert.ok(calls.includes({register:'recover-registration',prune:'recover-policy','converge-policy':'recover-policy',publish:'recover-publication',cutover:'recover-cutover',reconcile:'recover-reconciliation'}[nativeOperation]));
   if(nativeOperation==='register')assert.equal(calls.filter(call=>call==='recover-registration').length,1);
   const after=f.snapshot();for(const count of ['registrationApplyCalls','policyDeletes','policyCreates','publicationCalls','aliasCalls','refreshCalls'])assert.equal(after[count],before[count]);return;
  }
  if(lostResponse?.includes('pre-intent-')){
   await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Injected pre-native checkout failure/);
   if(lostResponse.startsWith('expired-'))f.advanceClock(31*60*1000);
  }
  else if(lostResponse?.startsWith('reservation-'))await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Injected reservation-only failure/);
  else if(lostResponse&&!['prerequisites-only','prerequisites-only-overlap','normal-predecessor','adopt-registration','adopt-current-registration','adopt-descendant-registration','source-advance','github-approval','approval-boundary','approval-timed-out','approval-journal-timeout','approval-expired-before-consumption','cutover-expired-before-closure'].includes(lostResponse))await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Lost completed mutation response/);
  if(lostResponse==='hosted-runner-replacement'){
   const workflow=fs.readFileSync('.github/workflows/release-train.yml','utf8');
   for(const binding of ['needs: gates','TARGET_SHA: ${{ needs.gates.outputs.target_sha }}',
    'RELEASE_TICKET_ID: ${{ inputs.ticket_id }}','NORMAL_IMAGE_AUTHORIZATION_JSON: ${{ inputs.normal_image_authorization_json }}',
    'REQUIRED_GATE_RUN_IDS_JSON: ${{ needs.gates.outputs.gate_run_ids_json }}'])
    assert.ok(workflow.includes(binding),`Release Train omitted hosted transport binding: ${binding}`);
   const hostedAction=fs.readFileSync('.github/actions/converge-stage-b-prerequisites/action.yml','utf8');
   assert.ok(workflow.includes('uses: ./.github/actions/converge-stage-b-prerequisites'));
   assert.ok(hostedAction.includes('node scripts/aws/run-production-release-coordinator.mjs'));
   assert.ok(hostedAction.includes('AWS_CREDENTIAL_EXPIRATION: ${{ fromJSON(steps.credentials.outputs.aws-expiration) }}'));
   assert.ok(workflow.indexOf('  gates:')<workflow.indexOf('  orchestrate:'));
   assert.ok(workflow.slice(workflow.indexOf('  orchestrate:')).includes('environment: production'));
   assert.ok(workflow.indexOf('Wait for required workflow gates')<workflow.indexOf('Converge exact Stage B prerequisites'));
   assert.ok(workflow.indexOf('Converge exact Stage B prerequisites')<workflow.indexOf('Trigger final Release Gate'));
   assert.ok(workflow.includes("if: needs.gates.outputs.target_ref == 'main'"));
   assert.ok(workflow.includes('git merge-base --is-ancestor "$TARGET_SHA" origin/main'));
  }
  const invoke=()=>['prerequisites-only','prerequisites-only-overlap','adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse)
   ? runHostedReleaseCoordinator(hostedReleaseTrainRequest({TARGET_SHA:request.sourceSha,RELEASE_TICKET_ID:request.ticketId,
      NORMAL_IMAGE_AUTHORIZATION_JSON:'fixture-transport',NORMAL_IMAGE_AUTHORIZATION_SHA256:'0'.repeat(64),
      REQUIRED_GATE_RUN_IDS_JSON:'{}',RELEASE_LIFECYCLE:runtime.gateLifecycle}),{runtimeFactory:()=>({...runtime})})
   : runReleaseCoordinator(request,runtime);
  const result=await invoke();
  assert.equal(result.status,'PREREQUISITES_CONVERGED');
  if(lostResponse==='normal-predecessor'){
   const record=steps.get(`${result.releaseId}/policy:result`),get=f.coordinatorStore.getArtifact;
   const policy={preparation:get(record.prepared).preparation,authorization:get(record.authorization),result:get(record.result)};
   const chain={registration:policy.preparation.prerequisiteChain.registration,policy};
   let checks=0;const verifyPruning=async predecessor=>{
    checks++;const entry=predecessor.pruning;assertPolicyPruningHandoff(entry,predecessor);
    await assertBrokerAuthorization(entry.authorization,entry.preparation,{verify:f.checker.verify,now:new Date(entry.result.authorizedAt)});
    assert.deepEqual(f.snapshot().receipts.find(r=>r[0]===brokerDigest(entry.authorization)&&r[1]==='BROKER_POLICY_PRUNED')?.[2],entry.result);
   };
   await authenticateNormalPolicyPrerequisite(chain,{sourceSha:f.source,treeSha256:f.tree},verifyPruning);assert.equal(checks,1);
   const ordinary=structuredClone(chain);delete ordinary.policy.preparation.prerequisiteChain.pruning;
   await authenticateNormalPolicyPrerequisite(ordinary,{},async()=>{throw new Error('Unexpected pruning authentication');});
   await assert.rejects(()=>authenticateNormalPolicyPrerequisite(chain,{},undefined));
   await assert.rejects(()=>authenticateNormalPolicyPrerequisite(chain,{},async()=>{throw new Error('Missing native pruning intent');}),/Missing native pruning intent/);
   for(const alter of [c=>{c.registration.result.sourceSha='f'.repeat(40);},c=>{c.policy.preparation.prerequisiteChain.pruning.result.authorizationSha256='0'.repeat(64);},c=>{c.policy.preparation.prerequisiteChain.pruning.authorization.nonce='f'.repeat(64);},c=>{c.policy.preparation.prerequisiteChain.unapproved={};}]){
    const wrong=structuredClone(chain);alter(wrong);await assert.rejects(()=>authenticateNormalPolicyPrerequisite(wrong,{},verifyPruning));
   }
  }
  const cutoverApproval=f.coordinatorStore.getArtifact(steps.get(`${result.releaseId}/cutover:result`).authorization);
  const closureApproval=f.coordinatorStore.getArtifact(steps.get(`${result.releaseId}/closure:result`).authorization);
  const closurePrepared=f.coordinatorStore.getArtifact(steps.get(`${result.releaseId}/closure:result`).prepared);
  const cutoverResult=f.coordinatorStore.getArtifact(steps.get(`${result.releaseId}/cutover:result`).result);
  assert.notEqual(brokerDigest(cutoverApproval),brokerDigest(closureApproval));
  assert.equal(closureApproval.purpose,'STAGE_B_BROKER_STATE_REFRESH');
  assert.equal(closureApproval.preparationSha256,brokerDigest(closurePrepared.preparation));
  assert.equal(closurePrepared.preparation.cutover.authorizationSha256,brokerDigest(cutoverApproval));
  assert.equal(closurePrepared.preparation.cutover.resultSha256,brokerDigest(cutoverResult));
  const expected=['prepare-registration','register','prepare-pruning','prune','prepare-policy','converge-policy','prepare-publication','publish','prepare-cutover','cutover','reconcile'];
  if(lostResponse==='no-prune-policy-lost')expected.splice(expected.indexOf('prepare-pruning'),2);
  if(['adopt-registration','adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse))expected.splice(0,2);
  if(['adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse))expected.unshift('prepare-registration-adoption');
  if(lostResponse==='hosted-runner-replacement')expected.splice(expected.indexOf('prune')+1,0,'recover-policy');
  else if(lostResponse==='proved-no-policy-write')expected.splice(expected.indexOf('prune')+1,0,'prune');
  else if(lostResponse?.includes('pre-intent-')||lostResponse?.startsWith('reservation-'))expected.splice(expected.indexOf(nativeOperation)+1,0,nativeOperation);
  else if(lostResponse&&!['prerequisites-only','prerequisites-only-overlap','normal-predecessor','adopt-registration','adopt-current-registration','adopt-descendant-registration','proved-no-policy-write','authorization-response-lost','source-advance','github-approval','approval-boundary','approval-timed-out','approval-journal-timeout','approval-record-response-lost','approval-expired-before-consumption','cutover-expired-before-closure'].includes(lostResponse))expected.splice(expected.indexOf(lostOperation)+1,0,{register:'recover-registration',prune:'recover-policy','converge-policy':'recover-policy',publish:'recover-publication',cutover:'recover-cutover',reconcile:'recover-reconciliation'}[lostOperation]);
  assert.deepEqual(calls,expected);
  if(['pre-intent-register','expired-pre-intent-register','reservation-register'].includes(lostResponse))assert.equal(calls.filter(call=>call==='recover-registration').length,0);
  if(lostResponse==='expired-pre-intent-register')assert.ok([...steps.keys()].some(key=>key.endsWith('registration:authorized:1')));
  assert.equal(f.snapshot().registrationApplyCalls,1);assert.equal(f.snapshot().policyDeletes,lostResponse==='no-prune-policy-lost'?0:1);assert.equal(f.snapshot().policyCreates,1);assert.equal(f.snapshot().publicationCalls,1);assert.equal(f.snapshot().aliasCalls,1);assert.equal(f.snapshot().refreshCalls,1);
  if(lostResponse==='reconcile')assert.equal(f.snapshot().receipts.filter(r=>r[1]==='STAGED_BROKER_TERMINAL_HANDOFF').length,1);
  assert.equal(f.snapshot().registeredTaskDefinitionCalls,12);
  if(['adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse)){assert.equal(result.registrationTransactionId,CURRENT_REGISTRATION_OPERATION);assert.equal(f.snapshot().registeredTaskDefinitionCalls-priorRegistrationCalls,0);}
  if(['approval-boundary','approval-timed-out','approval-journal-timeout','approval-record-response-lost'].includes(lostResponse))assert.equal(approvalDispatches,1);
  if(lostResponse==='approval-timed-out')assert.ok([...steps.keys()].some(key=>key.endsWith('registration:approval-timeout:0')));
  if(lostResponse==='approval-journal-timeout'){
   assert.ok(steps.has(`${result.releaseId}/registration:dispatch:0`));
   assert.ok(steps.has(`${result.releaseId}/registration:approval-timeout:0`));
   assert.equal(steps.has(`${result.releaseId}/registration:pending:0`),false);
   assert.ok(steps.has(`${result.releaseId}/registration:authorized:1`));
  }
  if(lostResponse==='expired-pre-intent-reconcile'){
   assert.ok(steps.has(`${result.releaseId}/closure:authorized:1`));
   assert.equal(f.snapshot().aliasCalls,1);assert.equal(f.snapshot().refreshCalls,1);
  }
  if(lostResponse==='cutover-expired-before-closure'){
   assert.ok(Date.parse(cutoverApproval.expiresAt)<=f.now.getTime());
   assert.ok(Date.parse(closureApproval.expiresAt)>f.now.getTime());
   assert.equal(f.snapshot().aliasCalls,1);assert.equal(f.snapshot().refreshCalls,1);
  }
  if(lostResponse==='approval-expired-before-consumption'){assert.equal(hostedVerifiers.size,7);assert.equal([...steps.keys()].filter(k=>k.endsWith('registration:authorized:0')||k.endsWith('registration:authorized:1')).length,2);}
  assert.ok(steps.has(`${result.releaseId}/${lostResponse?.startsWith('prerequisites-only')?'PREREQUISITE_GATES_PASSED':'GATES_PASSED'}`));
  if(lostResponse==='source-advance')runtime.authenticateSource=async(source,frozen)=>{assert.equal(source,request.sourceSha);assert.equal(frozen.releaseId,result.releaseId);return {baseline:{...baseline,generation:baseline.generation+1},changedFiles:['frontend/src/app.ts']};};
  await invoke();
  assert.deepEqual(calls,expected);
  if(lostResponse?.startsWith('prerequisites-only')){
   const prior=structuredClone(steps.get(`${result.releaseId}/PREREQUISITE_GATES_PASSED`));
   runtime.gateLifecycle=lostResponse==='prerequisites-only-overlap'?'authenticated-initial-overlap':'strict';
   await invoke();assert.ok(steps.has(`${result.releaseId}/GATES_PASSED`));assert.deepEqual(calls,expected);
   assert.deepEqual(steps.get(`${result.releaseId}/PREREQUISITE_GATES_PASSED`),prior);
  }
  if(lostResponse==='authorization-response-lost'){assert.ok(steps.has(`${result.releaseId}/registration:authorized:0`));assert.ok(steps.has(`${result.releaseId}/registration:authorized:1`));}
  assert.equal(f.snapshot().registrationApplyCalls,1);assert.equal(f.snapshot().policyDeletes,lostResponse==='no-prune-policy-lost'?0:1);assert.equal(f.snapshot().policyCreates,1);assert.equal(f.snapshot().publicationCalls,1);assert.equal(f.snapshot().aliasCalls,1);assert.equal(f.snapshot().refreshCalls,1);
 }finally{f.dispose();if(hostedClosureRelease)fs.rmSync(path.join(HOSTED_RELEASE_ROOT,hostedClosureRelease.releaseId),{recursive:true,force:true});}
});


test('governed approval dispatch resumes its exact child at the human boundary without a second POST',async()=>{
 const release={sourceSha,releaseId:'b'.repeat(64),ticketId:'current-release'},prepared={preparation:{sourceSha}},reference=brokerDigest(prepared);
 const workflow='authorize-production-stage-b-release-transition.yml',repository='T-ej2003/genuine-scan-main';
 let recorded,posts=0,reads=0,lose=true;
 const child={id:701,workflow_id:8,path:`.github/workflows/${workflow}`,head_sha:sourceSha,head_branch:'main',event:'workflow_dispatch',run_attempt:1,status:'waiting',repository:{full_name:repository},head_repository:{full_name:repository}};
 const store={readStep:async()=>recorded||null,writeStep:async value=>{assert.equal(recorded,undefined);recorded=structuredClone(value);}};
 const run=args=>{
  const suffix=args[1].slice(`repos/${repository}/`.length);
  if(suffix==='branches/main')return JSON.stringify({protected:true,commit:{sha:sourceSha}});
  if(suffix==='actions/runs/701')return JSON.stringify(child);
  if(suffix==='actions/runs/701/pending_deployments')return JSON.stringify([{environment:{id:9,name:'production'}}]);
  throw new Error('Unexpected approval read '+suffix);
 };
 const fetchImpl=async(url,options)=>{
  let body;
  if(url.endsWith(`/workflows/${workflow}`))body={id:8,path:child.path};
  else if(url.includes('/runs?')){reads++;body={total_count:reads===1?0:1,workflow_runs:reads===1?[]:[child]};}
  else if(options?.method==='POST'){posts++;if(lose){lose=false;throw new Error('Lost approval dispatch response');}body={workflow_run_id:701};}
  else throw new Error('Unexpected approval API '+url);
  return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});
 };
 const context={release,authorizationRound:0,store};
 const deps={token:'fixture-only',run,fetchImpl,sleep:rejectExternalAccess,attempts:1};
 await assert.rejects(()=>obtainReleaseTransitionAuthorization(context,'pruning',prepared,reference,deps),/Lost approval dispatch/);
 const boundary=await obtainReleaseTransitionAuthorization(context,'pruning',prepared,reference,deps);
 assert.equal(boundary.status,'WAITING_FOR_APPROVAL');assert.equal(boundary.runId,'701');assert.equal(posts,1);
 const pending={runId:boundary.runId,prepared:reference};
 assert.deepEqual(await obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps),boundary);assert.equal(posts,1);
 child.status='completed';child.conclusion='timed_out';
 assert.deepEqual(await obtainReleaseTransitionAuthorization(context,'pruning',prepared,reference,deps),
  {status:'APPROVAL_TIMED_OUT',runId:'701'});assert.equal(posts,1);
 assert.deepEqual(await obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps),
  {status:'APPROVAL_TIMED_OUT',runId:'701'});assert.equal(posts,1);
 child.conclusion='failure';await assert.rejects(()=>obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps),/Exact approval child failed/);assert.equal(posts,1);
 child.head_sha='f'.repeat(40);await assert.rejects(()=>obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps));assert.equal(posts,1);
 await assert.rejects(()=>obtainReleaseTransitionAuthorization(context,'pruning',prepared,reference,deps));assert.equal(posts,1);
});

test('successor approval dispatch executes from protected descendant without relabeling the release',async()=>{
 const toolingSha='d'.repeat(40),release={sourceSha,releaseId:'b'.repeat(64),ticketId:'current-release'};
 const prepared={preparation:{sourceSha,recoveryTooling:{sourceSha:toolingSha}}},reference=brokerDigest(prepared);
 const repository='T-ej2003/genuine-scan-main',workflow='authorize-production-stage-b-release-transition.yml';
 const child={id:702,workflow_id:8,path:`.github/workflows/${workflow}`,head_sha:toolingSha,head_branch:'main',
  event:'workflow_dispatch',run_attempt:1,status:'waiting',repository:{full_name:repository},head_repository:{full_name:repository}};
 let posted;
 const run=args=>{const suffix=args[1].slice(`repos/${repository}/`.length);
  if(suffix==='branches/main')return JSON.stringify({protected:true,commit:{sha:toolingSha}});
  if(suffix==='actions/runs/702')return JSON.stringify(child);
  if(suffix==='actions/runs/702/pending_deployments')return JSON.stringify([{environment:{id:9,name:'production'}}]);
  throw new Error(`Unexpected approval read ${suffix}`);};
 const fetchImpl=async(url,options)=>{let body;
  if(url.endsWith(`/workflows/${workflow}`))body={id:8,path:child.path};
  else if(url.endsWith('/actions/runs/702'))body=child;
  else if(url.includes('/runs?'))body={total_count:posted?1:0,workflow_runs:posted?[child]:[]};
  else if(options?.method==='POST'){posted=JSON.parse(options.body);body={workflow_run_id:702};}
  else throw new Error(`Unexpected approval API ${url}`);
  return new Response(JSON.stringify(body),{status:200,headers:{'content-type':'application/json'}});};
 const context={release,authorizationRound:0,store:{readStep:async()=>null,writeStep:async()=>{}}};
 const result=await obtainReleaseTransitionAuthorization(context,'cutover',prepared,reference,
  {token:'fixture-only',run,fetchImpl,sleep:rejectExternalAccess,attempts:1});
 assert.equal(result.status,'WAITING_FOR_APPROVAL');assert.equal(posted.ref,'main');
 assert.equal(posted.inputs.source_sha,sourceSha);assert.equal(posted.inputs.tooling_sha,toolingSha);
 child.head_sha=sourceSha;
 await assert.rejects(()=>obtainReleaseTransitionAuthorization({...context,pendingApproval:{runId:'702',prepared:reference}},
  'cutover',prepared,reference,{token:'fixture-only',run,fetchImpl,sleep:rejectExternalAccess,attempts:1}));
});

 test('prerequisite CI cannot substitute dispatch, branch, source, repository or deployment gate evidence',()=>{
  const valid=gateFixture(sourceSha,'prerequisites');
  assert.equal(authenticateReleaseGateRuns({sourceSha},valid).length,5);
  for(const [field,value] of [['event','workflow_dispatch'],['head_branch','attacker'],['head_sha','a'.repeat(40)],['conclusion','failure']]){
   const evidence=structuredClone(valid);evidence.workflowPayloads['quality-gate.yml'].runs[0][field]=value;
   assert.throws(()=>authenticateReleaseGateRuns({sourceSha},evidence));
  }
  assert.throws(()=>authenticateReleaseGateRuns({sourceSha},{...valid,lifecycle:'strict'}));
  assert.throws(()=>createHostedReleaseRuntime({sourceSha,ticketId:'ticket',lifecycle:'prerequisites',env:{},awsRun:rejectExternalAccess,ghRun:rejectExternalAccess}),/explicit prerequisite-only/);
 });


test('durable registration selector rejects missing, substituted and cross-release authority without registration',async()=>{
 const f=await createPublicRegistrationFixture({descendantCompletedRegistration:true});
 try{
  const sourceSha=f.completedRegistration.preparation.sourceSha,ticketId='current-release',priorCalls=f.snapshot().registrationApplyCalls;
  const query={store:f.coordinatorStore,sourceSha,ticketId};
  await assert.rejects(()=>readDurableCompletedRegistration(query),/Missing predecessor/);
  const release=await seedDurableRegistration(f.coordinatorStore,f.completedRegistration);
  assert.deepEqual(await readDurableCompletedRegistration(query),f.completedRegistration);
  await assert.rejects(()=>readDurableCompletedRegistration({...query,ticketId:'wrong-ticket'}),/Missing predecessor/);
  await assert.rejects(()=>readDurableCompletedRegistration({...query,sourceSha:'f'.repeat(40)}),/Missing predecessor/);
  await assert.rejects(()=>readDurableCompletedRegistration({...query,store:{...f.coordinatorStore,readStep:()=>null}}),/Missing completed/);
  for(const change of [x=>({...x,sourceSha:'f'.repeat(40)}),x=>({...x,releaseId:'f'.repeat(64)}),x=>({...x,name:'publication:result'})]){
   await assert.rejects(()=>readDurableCompletedRegistration({...query,store:{...f.coordinatorStore,readStep:(...args)=>change(f.coordinatorStore.readStep(...args))}}));
  }
  await assert.rejects(()=>readDurableCompletedRegistration({...query,store:{...f.coordinatorStore,getArtifact:hash=>({...f.coordinatorStore.getArtifact(hash),tampered:true})}}),/substitution/);
  const record=f.coordinatorStore.readStep(release.releaseId,'registration:result');
  const incomplete=structuredClone(f.completedRegistration.result);delete incomplete.definitions[Object.keys(incomplete.definitions)[0]];
  const incompleteHash=brokerDigest(incomplete);
  await assert.rejects(()=>readDurableCompletedRegistration({...query,store:{...f.coordinatorStore,
   readStep:()=>({...record,result:incompleteHash}),getArtifact:hash=>hash===incompleteHash?incomplete:f.coordinatorStore.getArtifact(hash)}}),/Incomplete predecessor/);
  assert.equal(release.sourceSha,sourceSha);assert.equal(f.snapshot().registrationApplyCalls,priorCalls);
 }finally{f.dispose();}
});

test('hosted durable selection authenticates signature/native receipt and binds the predecessor across retries',async()=>{
 const f=await createPublicRegistrationFixture({descendantCompletedRegistration:true});
 try{
  await seedDurableRegistration(f.coordinatorStore,f.completedRegistration);
  const sourceSha=f.source,predecessor=f.completedRegistration.preparation.sourceSha;
  const env={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REPOSITORY:'T-ej2003/genuine-scan-main',
   GITHUB_WORKFLOW_REF:'T-ej2003/genuine-scan-main/.github/workflows/release-train.yml@refs/heads/main',GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:sourceSha,RUNNER_TEMP:'/tmp'};
  const options={sourceSha,ticketId:'current-release',imageTransportJson:'fixture',imageTransportSha256:'0'.repeat(64),requiredGateRunIdsJson:'{}',env,
   awsRun:rejectExternalAccess,ghRun:rejectExternalAccess,createStore:()=>f.coordinatorStore,verifyAuthorization:f.checker.verify,
   imageReader:()=>({sourceSha,completedRegistrationSourceSha:predecessor}),readReceipt:()=>f.completedRegistration.result,imageImpact:()=>({imageReuseCompatible:true,newImagesRequired:false})};
  const runtime=createHostedReleaseRuntime(options),release={sourceSha,releaseId:'b'.repeat(64)};
  assert.deepEqual(await runtime.findCompletedRegistration(release),f.completedRegistration);
  await assert.rejects(()=>createHostedReleaseRuntime({...options,verifyAuthorization:()=>false}).findCompletedRegistration(release));
  await assert.rejects(()=>createHostedReleaseRuntime({...options,readReceipt:()=>({...f.completedRegistration.result,sourceSha:'f'.repeat(40)})}).findCompletedRegistration(release));
  await assert.rejects(()=>createHostedReleaseRuntime({...options,imageImpact:()=>({imageReuseCompatible:false,newImagesRequired:true})}).findCompletedRegistration(release),/incompatible/);
  const artifacts=await runtime.resolveArtifacts();
  assert.equal(artifacts.completedRegistrationSourceSha,predecessor);
  await assert.rejects(()=>runtime.authenticateArtifacts(release,{...artifacts,completedRegistrationSourceSha:'f'.repeat(40)}));
 }finally{f.dispose();}
});


test('public schema2 cross-source adoption keeps IAM predecessor separate and never re-registers completed definitions',async()=>{
 const original=await createPublicRegistrationFixture({normalPredecessor:true,completedRegistration:true});
 const entry=structuredClone(original.completedRegistration),verifyOriginal=original.checker.verify;original.dispose();
 const current=await createPublicRegistrationFixture({ordinaryCompletedRegistration:entry});
 try{
  const verifyCurrent=current.checker.verify;current.checker.verify=authorization=>authorization.preparationSha256===brokerDigest(entry.preparation)?verifyOriginal(authorization):verifyCurrent(authorization);
  const before=current.snapshot();assert.equal(entry.preparation.schemaVersion,2);assert.notEqual(current.source,entry.preparation.sourceSha);
  const adopted=await current.run({...current.initialRequest,predecessorReceiptRecovery:undefined,operation:'prepare-registration-adoption',prerequisiteChain:{registration:entry}});
  assert.equal(adopted.status,'REGISTERED_OUTPUTS_ADOPTED_NONTERMINAL');assert.equal(adopted.sourceSha,current.source);
  assert.deepEqual(adopted.prerequisiteChain.registration.result,entry.result);
  assert.deepEqual(adopted.prerequisiteChain.registration.preparation.prerequisites.taskMap,entry.preparation.prerequisites.taskMap);
  assert.deepEqual(adopted.prerequisiteChain.registration.result.taskMap,entry.result.taskMap);
  const after=current.snapshot();assert.equal(after.registeredTaskDefinitionCalls,before.registeredTaskDefinitionCalls);assert.equal(after.policyDeletes,0);assert.equal(after.policyCreates,0);assert.equal(after.aliasCalls,0);assert.equal(after.refreshCalls,0);
  let chain=adopted.prerequisiteChain;
  const {predecessorReceiptRecovery,...inputs}=current.initialRequest;
  for(const [prepare,authorize,execute] of [['prepare-pruning','authorize-pruning','prune'],['prepare-policy','authorize-policy','converge-policy'],['prepare-publication','authorize-publication','publish']]){
   const prepared=await current.run({...inputs,operation:prepare,prerequisiteChain:chain,...(execute==='prune'?{versionId:'v9'}:{})});
   const authorization=await current.run({...inputs,operation:authorize,preparation:prepared.preparation,planPath:prepared.planPath,makerIdentity:current.maker,humanReviewId:'schema2-publication-regression'});
   const result=await current.run({...inputs,operation:execute,preparation:prepared.preparation,authorization,planPath:prepared.planPath});
   const entry={preparation:prepared.preparation,authorization,result};
   if(execute==='prune')chain={...chain,pruning:entry};
   if(execute==='converge-policy')chain={registration:chain.registration,policy:entry};
  }
  const published=current.snapshot();assert.equal(published.registeredTaskDefinitionCalls,before.registeredTaskDefinitionCalls);assert.equal(published.policyDeletes,1);assert.equal(published.policyCreates,1);assert.equal(published.publicationCalls,1);assert.equal(published.aliasCalls,0);assert.equal(published.refreshCalls,0);
 }finally{current.dispose();}
});

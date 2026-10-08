import assert from 'node:assert/strict';
import test from 'node:test';
import { brokerDigest, assertRegistrationHandoff, assertBrokerAuthorization, assertPolicyPruningHandoff, assertBrokerClosurePlan } from '../aws/stage-b-staged-broker-contract.mjs';
import { createReleaseIdentity, selectReleasePolicyDeletion, createReleaseCoordinatorStore, authenticateReleaseGateRuns,captureReleasePhaseMaterial,hydrateReleasePhaseMaterial,releaseTransitionDispatchInputs,obtainReleaseTransitionAuthorization,readHostedReleaseSource,authenticateHostedStageBImages,HOSTED_RELEASE_ROOT } from '../aws/production-release-coordinator.mjs';
import {requiredWorkflowFiles} from '../github/release-lifecycle-contract.mjs';
import {readReleaseGateEvidence} from '../github/check-required-workflow-gates.mjs';
import {runHostedReleaseCoordinator,hostedReleaseTrainRequest,createHostedReleaseRuntime} from '../aws/run-production-release-coordinator.mjs';

function gateFixture(sourceSha){
 const files=requiredWorkflowFiles('strict'),workflowPayloads={},expectedWorkflowRunIds={};
 files.forEach((file,i)=>{
  const id=i+1,runId=i+100;expectedWorkflowRunIds[file]=String(runId);
  const workflow={id,path:`.github/workflows/${file}`};
  workflowPayloads[file]={workflow,runs:[{id:runId,workflow_id:id,path:workflow.path,head_sha:sourceSha,head_branch:'main',event:'workflow_dispatch',run_attempt:1,
   status:'completed',conclusion:'success',created_at:'2026-10-08T12:00:00.000Z',repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'}}]};
 });
 return {sourceSha,lifecycle:'strict',workflowPayloads,expectedWorkflowRunIds};
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
 assert.throws(()=>authenticateHostedStageBImages({sourceSha,transportJson:authorizationJson,transportSha256:'0'.repeat(64),run:rejectExternalAccess,
  verifyAuthorization:()=>{assert.fail('Changed transport cannot reach verifier');}}));
});

test('gate authentication uses the canonical required-workflow contract and exact child identities',()=>{
 const release={sourceSha};assert.equal(authenticateReleaseGateRuns(release,gateFixture(sourceSha)).length,5);
 for(const field of ['head_sha','path','workflow_id','conclusion','repository','run_attempt']){
  const evidence=gateFixture(sourceSha),run=evidence.workflowPayloads['deployment-audit.yml'].runs[0];
  run[field]=field==='repository'?{full_name:'attacker/repo'}:field==='run_attempt'?2:'wrong';
  assert.throws(()=>authenticateReleaseGateRuns(release,evidence));
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
 assert.throws(()=>releaseTransitionDispatchInputs({release,authorizationRound:0},'closure','c'.repeat(64)));
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
import { authenticatePrepublicationPolicyChain } from '../aws/stage-b-staged-broker-executor.mjs';
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
import {adoptRegisteredOutputs} from '../aws/stage-b-release-prerequisites.mjs';
import {authorizeReleaseTransition} from '../aws/authorize-production-stage-b-release-transition.mjs';

function hostedApprovalTransport(sourceSha,now,runId){
 const repository=PRODUCTION_ENVIRONMENT_APPROVAL.repository;
 const environment={id:7,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]};
 const actual={state:'approved',environmentId:7,environmentName:'production',userId:1,userLogin:'operator'};
 const approval=createProductionEnvironmentApprovalEvidence({environmentConfig:environment,repository,environment:'production',sourceSha,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,eventName:'workflow_dispatch',workflowRunId:String(runId),workflowRunAttempt:'1',executionActor:'operator',observedAt:now.toISOString(),actualApproval:actual});
 return {approval,publish:async authorization=>{
  const zip=new JSZip();zip.file('authorization.json',JSON.stringify(authorization));const archive=await zip.generateAsync({type:'nodebuffer'});
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
  const zip=new JSZip();zip.file('authorization.json',JSON.stringify(authorization));const archive=await zip.generateAsync({type:'nodebuffer'});
  const workflow={id:700,repository:{id:9,full_name:repository},head_repository:{full_name:repository},path:'.github/workflows/authorize-production-stage-b-release-transition.yml',head_sha:f.source,event:'workflow_dispatch',status:'completed',conclusion:'success',run_attempt:1,actor:{login:'operator'}};
  const artifact={id:701,name:'production-stage-b-release-transition-authorization',expired:false,digest:`sha256:${createHash('sha256').update(archive).digest('hex')}`,workflow_run:{id:700,head_sha:f.source,repository_id:9}};
  const payloads={['actions/runs/700']:workflow,['actions/runs/700/artifacts']:[{artifacts:[artifact]}],['actions/artifacts/701/zip']:archive,['environments/production']:environment,['actions/runs/700/approvals']:[{state:'approved',environments:[{id:7,name:'production'}],user:{id:1,login:'operator'}}]};
  const run=args=>{assert.equal(args[0],'api');const key=args[1].slice(`repos/${repository}/`.length);assert.ok(Object.hasOwn(payloads,key),'Unexpected GitHub access');return Buffer.isBuffer(payloads[key])?payloads[key]:JSON.stringify(payloads[key]);};
  const retrieved=await readBrokerProtectedEnvironmentAuthorization({workflowRunId:'700',sourceSha:f.source,run});
  assert.deepEqual(retrieved.authorization,authorization);assert.equal(retrieved.workflow.id,700);
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

for(const lostResponse of [null,'normal-predecessor','adopt-registration','adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement','proved-no-policy-write','no-prune-policy-lost','github-approval','approval-boundary','approval-timed-out','approval-record-response-lost','authorization-response-lost','approval-expired-before-consumption','source-advance','register','prune','converge-policy','publish','cutover','expired-register','expired-prune','expired-converge-policy','expired-publish','pre-intent-register','expired-pre-intent-register','post-intent-register','reservation-register','pre-intent-prune','owner-prune','post-intent-prune','pre-intent-converge-policy','owner-converge-policy','post-intent-converge-policy','pre-intent-publish','post-intent-publish','reservation-publish','pre-intent-cutover','post-intent-cutover','reservation-cutover','pre-intent-reconcile','post-intent-reconcile','inventory-drift','default-drift','ownership-drift','alias-drift']) test(`one public coordinator entry closes full-capacity prerequisites; lost response: ${lostResponse}`, async () => {
 const f=await createPublicRegistrationFixture({completedRegistration:lostResponse==='adopt-registration',currentCompletedRegistration:lostResponse==='adopt-current-registration',descendantCompletedRegistration:['adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse),normalPredecessor:lostResponse==='normal-predecessor'});
 if(lostResponse==='no-prune-policy-lost')f.changeLiveInventory(xs=>xs.filter(v=>v.VersionId!=='v9'));
 const priorRegistrationCalls=f.snapshot().registeredTaskDefinitionCalls;
 const steps=new Map(),calls=[];let interrupted=false,approvalDispatches=0;const lostOperation=lostResponse==='hosted-runner-replacement'?'prune':lostResponse==='no-prune-policy-lost'?'converge-policy':lostResponse?.replace(/^expired-/,'');const drift=lostResponse?.endsWith('-drift');
 const copy=value=>JSON.parse(JSON.stringify(value));
 const hostedVerifiers=new Map(),priorVerify=f.checker.verify;
 const hostedApproval=['github-approval','approval-boundary','approval-record-response-lost','adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement','approval-expired-before-consumption'].includes(lostResponse);
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
  resolveGates:async release=>{
   const fixture=gateFixture(release.sourceSha);
   return readReleaseGateEvidence({sourceSha:release.sourceSha,lifecycle:'strict',expectedWorkflowRunIds:fixture.expectedWorkflowRunIds,
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
   if(phase==='registration')return f.initialRequest;
   const {predecessorReceiptRecovery,...inputs}=f.initialRequest;return inputs;
  },
  capturePreparation:async(context,name,prepared)=>{
   const materializationSha256=await captureReleasePhaseMaterial({prepared,files:f.files,store:f.coordinatorStore,repositoryRoot:process.cwd()});
   return {...prepared,materializationSha256};
  },
  hydratePreparation:async(context,name,prepared)=>{
   await hydrateReleasePhaseMaterial({reference:prepared.materializationSha256,prepared,files:f.files,planPath:prepared.planPath,store:f.coordinatorStore,repositoryRoot:process.cwd()});
  },
  findCompletedRegistration:async()=>f.completedRegistration||null,
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
  runStageOperation:async request=>{calls.push(request.operation);if(lostResponse==='proved-no-policy-write'){if(request.operation==='prune'&&!interrupted){interrupted=true;throw new Error('Lost completed mutation response');}if(request.operation==='recover-policy')return {status:'RECOVERED_NO_WRITE'};}if(drift&&!interrupted&&request.operation===(lostResponse==='alias-drift'?'cutover':'prune')){interrupted=true;if(lostResponse==='inventory-drift')f.changeLiveInventory(xs=>xs.map(v=>v.VersionId==='v10'?{...v,VersionId:'v99'}:v));if(lostResponse==='default-drift')f.changeLiveDefault('v12');if(lostResponse==='ownership-drift')f.changeOwnership(owner=>({...owner,identity:{...owner.identity,operationIdentity:'0'.repeat(64)}}));if(lostResponse==='alias-drift')f.changeLiveAlias(alias=>({...alias,RevisionId:'unapproved-revision'}));}const result=await f.run(request);if(request.operation===lostOperation&&!interrupted){interrupted=true;if(lostResponse?.startsWith('expired-'))f.advanceClock(31*60*1000);throw new Error('Lost completed mutation response');}return result;},
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
   await assertBrokerAuthorization(authorization,p,{verify:f.checker.verify,now:new Date(result.authorizedAt||f.now)});
   if(name==='registration'){
    assertRegistrationHandoff({preparation:p,authorization,result},{sourceSha:f.source,treeSha256:f.tree});
    assert.equal(Object.keys(result.definitions).length,12);
    assert.deepEqual(f.snapshot().receipts.find(r=>r[1]==='TASK_REGISTERED')[2],result);
   } else if(name==='pruning')assertPolicyPruningHandoff({preparation:p,authorization,result},p.prerequisiteChain);
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
  authenticatePolicyRetention:async()=>({inventory:f.snapshot().policySnapshot.versions.map(v=>({versionId:v.VersionId,isDefault:v.IsDefaultVersion,createDate:new Date(Date.UTC(2026,8,['v9','v10','v11','v12','v13'].indexOf(v.VersionId)+1)).toISOString(),documentSha256:brokerDigest(f.fixture.policy.terminal.policy)})),protectedVersionIds:['v12','v13'],obsoleteVersionIds:['v9','v10','v11']}),
  obtainAuthorization:async(context,phase,prepared,digest)=>{
   assert.equal(brokerDigest(prepared),digest);
   if(['approval-boundary','approval-timed-out','approval-record-response-lost'].includes(lostResponse)&&phase==='registration'&&context.authorizationRound===0){
    if(!context.pendingApproval){approvalDispatches++;return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};}
    assert.equal(context.pendingApproval.runId,'700');assert.equal(context.pendingApproval.prepared,digest);
    if(lostResponse==='approval-timed-out')return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   }
   if(hostedApproval){
    const transport=hostedApprovalTransport(f.source,f.now,context.pendingApproval?Number(context.pendingApproval.runId):900+hostedVerifiers.size);
    const operation={registration:'authorize-registration',pruning:'authorize-pruning',policy:'authorize-policy',publication:'authorize-publication',cutover:'authorize-cutover'}[phase];
    const authorization=await f.run({operation,preparation:prepared.preparation,planPath:prepared.planPath},{readProtectedApproval:async()=>({approval:transport.approval,release:{releaseId:context.release.releaseId,phase,preparationReference:digest,authorizationRound:context.authorizationRound}})});
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
   const operation={pruning:'authorize-pruning',policy:'authorize-policy',publication:'authorize-publication',cutover:'authorize-cutover'}[phase];
   assert.ok(operation);
   if(phase==='pruning')assert.equal(prepared.preparation.target.versionId,'v9');
   const authorization=await f.run({operation,preparation:prepared.preparation,planPath:prepared.planPath,makerIdentity:f.maker,humanReviewId:`fixture-production-${phase}-approval`});
   return {status:'AUTHORIZED',authorization};
  },
 };
 try {
  const request={sourceSha:f.source,ticketId:'current-release'};
  if(drift){await assert.rejects(()=>runReleaseCoordinator(request,runtime));const before=f.snapshot();assert.equal(before.registrationApplyCalls,1);assert.equal(before.policyDeletes,lostResponse==='alias-drift'?1:0);assert.equal(before.policyCreates,lostResponse==='alias-drift'?1:0);assert.equal(before.aliasCalls,0);await assert.rejects(()=>runReleaseCoordinator(request,runtime));const after=f.snapshot();for(const count of ['registrationApplyCalls','policyDeletes','policyCreates','publicationCalls','aliasCalls'])assert.equal(after[count],before[count]);return;}
  if(['approval-boundary','approval-timed-out'].includes(lostResponse)){const waiting=await runReleaseCoordinator(request,runtime);assert.equal(waiting.status,'WAITING_FOR_APPROVAL');assert.equal(waiting.runId,'700');assert.equal(f.snapshot().registrationApplyCalls,0);}
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
  else if(lostResponse&&!['normal-predecessor','adopt-registration','adopt-current-registration','adopt-descendant-registration','source-advance','github-approval','approval-boundary','approval-timed-out','approval-expired-before-consumption'].includes(lostResponse))await assert.rejects(()=>runReleaseCoordinator(request,runtime),/Lost completed mutation response/);
  if(lostResponse==='hosted-runner-replacement'){
   const workflow=fs.readFileSync('.github/workflows/release-train.yml','utf8');
   for(const binding of ['needs: gates','TARGET_SHA: ${{ needs.gates.outputs.target_sha }}',
    'RELEASE_TICKET_ID: ${{ inputs.ticket_id }}','NORMAL_IMAGE_AUTHORIZATION_JSON: ${{ inputs.normal_image_authorization_json }}',
    'REQUIRED_GATE_RUN_IDS_JSON: ${{ needs.gates.outputs.gate_run_ids_json }}'])
    assert.ok(workflow.includes(binding),`Release Train omitted hosted transport binding: ${binding}`);
   const hostedAction=fs.readFileSync('.github/actions/converge-stage-b-prerequisites/action.yml','utf8');
   assert.ok(workflow.includes('uses: ./.github/actions/converge-stage-b-prerequisites'));
   assert.ok(hostedAction.includes('node scripts/aws/run-production-release-coordinator.mjs'));
   assert.ok(hostedAction.includes('AWS_CREDENTIAL_EXPIRATION: ${{ steps.credentials.outputs.aws-expiration }}'));
   assert.ok(workflow.indexOf('  gates:')<workflow.indexOf('  orchestrate:'));
   assert.ok(workflow.slice(workflow.indexOf('  orchestrate:')).includes('environment: production'));
   assert.ok(workflow.indexOf('Wait for required workflow gates')<workflow.indexOf('Converge exact Stage B prerequisites'));
   assert.ok(workflow.indexOf('Converge exact Stage B prerequisites')<workflow.indexOf('Trigger final Release Gate'));
   assert.ok(workflow.includes("if: needs.gates.outputs.target_ref == 'main'"));
   assert.ok(workflow.includes('git merge-base --is-ancestor "$TARGET_SHA" origin/main'));
  }
  const invoke=()=>['adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse)
   ? runHostedReleaseCoordinator(hostedReleaseTrainRequest({TARGET_SHA:request.sourceSha,RELEASE_TICKET_ID:request.ticketId,
      NORMAL_IMAGE_AUTHORIZATION_JSON:'fixture-transport',NORMAL_IMAGE_AUTHORIZATION_SHA256:'0'.repeat(64),
      REQUIRED_GATE_RUN_IDS_JSON:'{}',RELEASE_LIFECYCLE:'strict'}),{runtimeFactory:()=>({...runtime})})
   : runReleaseCoordinator(request,runtime);
  const result=await invoke();
  assert.equal(result.status,'PREREQUISITES_CONVERGED');
  const expected=['prepare-registration','register','prepare-pruning','prune','prepare-policy','converge-policy','prepare-publication','publish','prepare-cutover','cutover','reconcile'];
  if(lostResponse==='no-prune-policy-lost')expected.splice(expected.indexOf('prepare-pruning'),2);
  if(['adopt-registration','adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse))expected.splice(0,2);
  if(['adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse))expected.unshift('prepare-registration-adoption');
  if(lostResponse==='hosted-runner-replacement')expected.splice(expected.indexOf('prune')+1,0,'recover-policy');
  else if(lostResponse==='proved-no-policy-write')expected.splice(expected.indexOf('prune')+1,0,'prune');
  else if(lostResponse?.includes('pre-intent-')||lostResponse?.startsWith('reservation-'))expected.splice(expected.indexOf(nativeOperation)+1,0,nativeOperation);
  else if(lostResponse&&!['normal-predecessor','adopt-registration','adopt-current-registration','adopt-descendant-registration','proved-no-policy-write','authorization-response-lost','source-advance','github-approval','approval-boundary','approval-timed-out','approval-record-response-lost','approval-expired-before-consumption'].includes(lostResponse))expected.splice(expected.indexOf(lostOperation)+1,0,{register:'recover-registration',prune:'recover-policy','converge-policy':'recover-policy',publish:'recover-publication',cutover:'recover-cutover'}[lostOperation]);
  assert.deepEqual(calls,expected);
  if(['pre-intent-register','expired-pre-intent-register','reservation-register'].includes(lostResponse))assert.equal(calls.filter(call=>call==='recover-registration').length,0);
  if(lostResponse==='expired-pre-intent-register')assert.ok([...steps.keys()].some(key=>key.endsWith('registration:authorized:1')));
  assert.equal(f.snapshot().registrationApplyCalls,1);assert.equal(f.snapshot().policyDeletes,lostResponse==='no-prune-policy-lost'?0:1);assert.equal(f.snapshot().policyCreates,1);assert.equal(f.snapshot().publicationCalls,1);assert.equal(f.snapshot().aliasCalls,1);
  assert.equal(f.snapshot().registeredTaskDefinitionCalls,12);
  if(['adopt-current-registration','adopt-descendant-registration','hosted-runner-replacement'].includes(lostResponse)){assert.equal(result.registrationTransactionId,CURRENT_REGISTRATION_OPERATION);assert.equal(f.snapshot().registeredTaskDefinitionCalls-priorRegistrationCalls,0);}
  if(['approval-boundary','approval-timed-out','approval-record-response-lost'].includes(lostResponse))assert.equal(approvalDispatches,1);
  if(lostResponse==='approval-timed-out')assert.ok([...steps.keys()].some(key=>key.endsWith('registration:approval-timeout:0')));
  if(lostResponse==='approval-expired-before-consumption'){assert.equal(hostedVerifiers.size,6);assert.equal([...steps.keys()].filter(k=>k.endsWith('registration:authorized:0')||k.endsWith('registration:authorized:1')).length,2);}
  assert.ok(steps.has(`${result.releaseId}/GATES_PASSED`));
  if(lostResponse==='source-advance')runtime.authenticateSource=async(source,frozen)=>{assert.equal(source,request.sourceSha);assert.equal(frozen.releaseId,result.releaseId);return {baseline:{...baseline,generation:baseline.generation+1},changedFiles:['frontend/src/app.ts']};};
  await invoke();
  assert.deepEqual(calls,expected);
  if(lostResponse==='authorization-response-lost'){assert.ok(steps.has(`${result.releaseId}/registration:authorized:0`));assert.ok(steps.has(`${result.releaseId}/registration:authorized:1`));}
  assert.equal(f.snapshot().registrationApplyCalls,1);assert.equal(f.snapshot().policyDeletes,lostResponse==='no-prune-policy-lost'?0:1);assert.equal(f.snapshot().policyCreates,1);assert.equal(f.snapshot().publicationCalls,1);assert.equal(f.snapshot().aliasCalls,1);
 }finally{f.dispose();}
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
 assert.deepEqual(await obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps),
  {status:'APPROVAL_TIMED_OUT',runId:'701'});assert.equal(posts,1);
 child.conclusion='failure';await assert.rejects(()=>obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps),/Exact approval child failed/);assert.equal(posts,1);
 child.head_sha='f'.repeat(40);await assert.rejects(()=>obtainReleaseTransitionAuthorization({...context,pendingApproval:pending},'pruning',prepared,reference,deps));assert.equal(posts,1);
});

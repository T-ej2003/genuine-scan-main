import assert from 'node:assert/strict';
import { brokerDigest,brokerExecutionCheckout,assertBrokerPreparation,prepareBrokerStateRefresh } from './stage-b-staged-broker-contract.mjs';
import { assertProductionComponentDeploymentState } from './production-component-deployment-state.mjs';
import { classifyProductionChanges } from './production-deployment-classification.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {randomUUID,createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {canonicalJson} from './production-green-stage-b-contract.mjs';
import {STAGE_B_TERRAFORM_BACKEND,stageBApplyAttemptS3Key} from './stage-b-terraform-backend-contract.mjs';
import {readProductionReceiptObject} from './production-receipt-read.mjs';
import {reserveStageBSharedApplyAttempt} from '../apply-production-green-stage-b.mjs';
import {ensureStageBPrivateDirectory,assertStageBPrivateFile,writeStageBPrivateFileAtomic} from './stage-b-artifact-contract.mjs';
import {stagedBrokerArtifactSet} from './stage-b-staged-broker-executor.mjs';
import {requiredWorkflowFiles} from '../github/release-lifecycle-contract.mjs';
import {buildGateEntries,evaluateGateState,parseExpectedWorkflowRunIds} from '../github/check-required-workflow-gates.mjs';
import {readStageBProtectedMainCheckout} from './stage-b-deployment-identity.mjs';
import {createProductionComponentDeploymentStateClient} from './production-component-deployment-state.mjs';
import {unpackReleaseEvidenceTransport} from './production-release-dispatch-contract.mjs';
import {verifyProductionReleaseImageAuthorization} from './verify-production-release-image-authorization.mjs';
import {verifyImageEvidenceSignature} from './production-green-stage-b-image-evidence.mjs';
export const HOSTED_RELEASE_ROOT='/tmp/mscqr-production-release';

export function authenticateReleaseGateRuns(release,evidence) {
 assert.equal(evidence.sourceSha,release.sourceSha,'Gate source substitution');
 const required=requiredWorkflowFiles(evidence.lifecycle);
 assert.deepEqual(Object.keys(evidence.workflowPayloads).sort(),required.slice().sort());
 const expected=parseExpectedWorkflowRunIds(JSON.stringify(evidence.expectedWorkflowRunIds),required);
 assert.ok(expected,'Exact gate run identities are required');
 for(const file of required){
  const workflow=evidence.workflowPayloads[file].workflow;
  assert.equal(workflow.path,`.github/workflows/${file}`);assert.ok(Number.isSafeInteger(workflow.id)&&workflow.id>0);
 }
 const entries=buildGateEntries({requiredWorkflowFiles:required,workflowPayloads:evidence.workflowPayloads,targetSha:release.sourceSha,
  targetEvents:['push','workflow_dispatch'],expectedWorkflowRunIds:expected});
 for(const {run} of entries){
  assert.ok(run,'Missing exact-source required gate');
  assert.equal(run.repository?.full_name,'T-ej2003/genuine-scan-main');assert.equal(run.head_repository?.full_name,'T-ej2003/genuine-scan-main');
  assert.equal(String(run.run_attempt),'1','Gate attempt identity changed');
 }
 assert.equal(evaluateGateState(entries).ok,true,'Required exact-source gates are not successful');
 return entries.map(({workflowFile,run})=>({workflowFile,runId:String(run.id),sourceSha:run.head_sha}));
}

export function releaseTransitionDispatchInputs({release,authorizationRound},phase,preparationReference,preparation){
 assert.match(release.sourceSha||'',/^[a-f0-9]{40}$/);assert.match(release.releaseId||'',/^[a-f0-9]{64}$/);
 assert.match(release.ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);assert.match(preparationReference||'',/^[a-f0-9]{64}$/);
 assert.ok(['registration','pruning','policy','publication','cutover','closure'].includes(phase));assert.ok(Number.isSafeInteger(authorizationRound)&&authorizationRound>=0);
 const executionSourceSha=preparation?brokerExecutionCheckout(preparation).sourceSha:release.sourceSha;
 const inputs={source_sha:release.sourceSha,...(executionSourceSha!==release.sourceSha?{tooling_sha:executionSourceSha}:{}),ticket_id:release.ticketId,release_id:release.releaseId,phase,preparation_reference:preparationReference,authorization_round:String(authorizationRound)};
 assert.ok(Buffer.byteLength(JSON.stringify({ref:'main',inputs}))<60*1024,'Release approval dispatch exceeds safe transport size');return inputs;
}

// The Release Train owns this child. Resume authenticates the recorded dispatch
// attempt/run rather than dispatching another approval after an interrupted POST.
export async function obtainReleaseTransitionAuthorization(context,phase,prepared,preparationReference,
 {token,run,fetchImpl=fetch,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms)),attempts=20}={}) {
 const {dispatchSourceBoundWorkflow}=await import('../github/dispatch-source-bound-workflow.mjs');
 const {readBrokerProtectedEnvironmentAuthorization,verifyBrokerProtectedEnvironmentAuthorization}=await import('./stage-b-staged-broker-authorization.mjs');
 const {release,authorizationRound,pendingApproval,store}=context;
 const inputs=releaseTransitionDispatchInputs({release,authorizationRound},phase,preparationReference,prepared.preparation);
 assert.equal(brokerDigest(prepared),preparationReference);assert.equal(prepared.preparation.sourceSha,release.sourceSha);
 const executionSourceSha=brokerExecutionCheckout(prepared.preparation).sourceSha;
 assert.equal(typeof run,'function');assert.ok(Number.isSafeInteger(attempts)&&attempts>0&&attempts<=120);
 const repository='T-ej2003/genuine-scan-main',workflow='authorize-production-stage-b-release-transition.yml';
 const api=suffix=>JSON.parse(run(['api',`repos/${repository}/${suffix}`],{encoding:'utf8',maxBuffer:8*1024*1024}));
 const name=`${phase}:dispatch:${authorizationRound}`;
 const prior=await store.readStep(release.releaseId,name);
 if(prior){assert.equal(prior.releaseId,release.releaseId);assert.equal(prior.sourceSha,release.sourceSha);assert.equal(prior.name,name);}
 let workflowRunId=pendingApproval?.runId;
 if(pendingApproval){assert.equal(pendingApproval.prepared,preparationReference);assert.match(String(workflowRunId),/^[1-9][0-9]*$/);}
 if(!workflowRunId){
  if(!prior){const main=api('branches/main');assert.equal(main.protected,true);assert.equal(main.commit.sha,executionSourceSha,'Protected main advanced before approval dispatch');}
  const child=await dispatchSourceBoundWorkflow({repository,token,workflow,ref:'main',targetSha:executionSourceSha,inputs,fetchImpl,sleep,
   dispatchJournal:{read:async()=>prior?.dispatch||null,write:async dispatch=>store.writeStep({releaseId:release.releaseId,sourceSha:release.sourceSha,name,dispatch})}});
  workflowRunId=String(child.id);
 }
 for(let attempt=0;attempt<attempts;attempt++){
  const child=api(`actions/runs/${workflowRunId}`);
  assert.equal(String(child.id),String(workflowRunId));assert.equal(child.head_sha,executionSourceSha);
  assert.equal(child.path,`.github/workflows/${workflow}`);assert.equal(child.head_branch,'main');assert.equal(child.event,'workflow_dispatch');assert.equal(String(child.run_attempt),'1');
  assert.equal(child.repository?.full_name,repository);assert.equal(child.head_repository?.full_name,repository);
  if(child.status==='completed'){
   if(child.conclusion==='timed_out')return {status:'APPROVAL_TIMED_OUT',runId:String(workflowRunId)};
   assert.equal(child.conclusion,'success','Exact approval child failed');
   const {authorization}=await readBrokerProtectedEnvironmentAuthorization({workflowRunId,sourceSha:release.sourceSha,workflowSourceSha:executionSourceSha,run});
   await assertReleaseTransitionApproval(authorization);
   return {status:'AUTHORIZED',authorization};
  }
  const pending=api(`actions/runs/${workflowRunId}/pending_deployments`);assert.ok(Array.isArray(pending));
  const production=pending.filter(x=>x.environment?.name==='production');
  assert.ok(production.length<=1,'Ambiguous production approval boundary');
  if(production.length)return {status:'WAITING_FOR_APPROVAL',runId:String(workflowRunId),runUrl:`https://github.com/${repository}/actions/runs/${workflowRunId}`};
  if(attempt+1<attempts)await sleep(1500);
 }
 throw new Error('Exact approval child has not completed or reached its human approval boundary');
 async function assertReleaseTransitionApproval(authorization){
  assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,preparationReference,authorizationRound});
  const {assertBrokerAuthorization}=await import('./stage-b-staged-broker-contract.mjs');
  await assertBrokerAuthorization(authorization,prepared.preparation,{verify:a=>verifyBrokerProtectedEnvironmentAuthorization(a,{run}),now:new Date(authorization.issuedAt)});
 }
}

// Reuse the existing conditional, encrypted Stage-B receipt namespace. These
// records are coordinator references, never authority to bypass native journals.
export function createReleaseCoordinatorStore({run,directory,repositoryRoot}) {
 ensureStageBPrivateDirectory({directory,repositoryRoot,create:false});
 assert.equal(typeof run,'function');
 const id=(kind,key)=>brokerDigest({kind:`PRODUCTION_RELEASE_COORDINATOR_${kind}`,key});
 const read=(kind,key)=>{
  const file=path.join(directory,`coordinator-read-${randomUUID()}.json`);
  try {
   if(!readProductionReceiptObject({run,bucket:STAGE_B_TERRAFORM_BACKEND.bucketName,key:stageBApplyAttemptS3Key(id(kind,key)),file}))return undefined;
   const value=JSON.parse(fs.readFileSync(file));
   assert.deepEqual(Object.keys(value).sort(),['key','kind','value']);
   assert.equal(value.kind,`PRODUCTION_RELEASE_COORDINATOR_${kind}`);assert.deepEqual(value.key,key);
   return value.value;
  }finally{fs.rmSync(file,{force:true});}
 };
 const write=(kind,key,value)=>{
  const bytes=Buffer.from(canonicalJson({kind:`PRODUCTION_RELEASE_COORDINATOR_${kind}`,key,value}));
  try {reserveStageBSharedApplyAttempt({artifactSetIdentity:id(kind,key),bytes,privateDirectory:directory,run});}
  catch(error){
   // A lost create response or repeated content-addressed write is safe only
   // after exact readback. Neither condition authorizes an AWS business write.
   const existing=read(kind,key);if(existing===undefined)throw error;assert.deepEqual(existing,value,'Immutable coordinator record conflict');
  }
 };
 return {
  readStart:request=>read('START',request)??null,writeStart:(request,value)=>write('START',request,value),
  readStep:(releaseId,name)=>read('STEP',{releaseId,name})??null,
  writeStep:value=>write('STEP',{releaseId:value.releaseId,name:value.name},value),
  putArtifact:(sha256,value)=>{assert.equal(brokerDigest(value),sha256);write('ARTIFACT',{sha256},value);},
  getArtifact:sha256=>{assert.match(sha256||'',/^[a-f0-9]{64}$/);const value=read('ARTIFACT',{sha256});assert.ok(value!==undefined,'Missing release artifact');assert.equal(brokerDigest(value),sha256);return value;},
 };
}

// Saved plans and package bytes survive runner replacement. Paths are supplied
// by the trusted runtime; external artifacts cannot choose filesystem targets.
export async function captureReleasePhaseMaterial({prepared,files,store,repositoryRoot}) {
 const p=prepared.preparation;assertBrokerPreparation(p);assert.equal(stagedBrokerArtifactSet(files,repositoryRoot,p,p.successorReconciliation?p.sourceSha:undefined),p.artifactSetSha256);
 const successorFiles=p.successorReconciliation?Object.fromEntries(['historicalStatePath','currentStatePath','bindingReportPath','imageEvidencePath','imageSignaturePath']
  .map(name=>[name,p.successorReconciliation[name]])):{};
 const materialFiles={...files,plan:prepared.planPath,...successorFiles};
 assert.equal(new Set(Object.values(materialFiles)).size,Object.keys(materialFiles).length,'Phase material paths overlap');
 const members={};
 for(const [name,filePath] of Object.entries(materialFiles)){
  assertStageBPrivateFile({filePath,repositoryRoot,label:`Release ${name}`});const bytes=fs.readFileSync(filePath);
  assert.ok(bytes.length<=64*1024*1024,'Oversized phase material');
  const artifact={kind:'PRODUCTION_RELEASE_BINARY',sha256:brokerDigest(bytes),base64:bytes.toString('base64')},reference=brokerDigest(artifact);
  if(name==='plan')assert.equal(artifact.sha256,p.savedPlanSha256);
  if(name in successorFiles)assert.equal(artifact.sha256,p.successorReconciliation[name.replace(/Path$/,'Sha256')],`Successor ${name} changed before capture`);
  await store.putArtifact(reference,artifact);members[name]={sha256:artifact.sha256,reference};
 }
 const capsule={kind:'PRODUCTION_RELEASE_PHASE_MATERIAL',sourceSha:p.sourceSha,preparationSha256:brokerDigest(p),members};
 const reference=brokerDigest(capsule);await store.putArtifact(reference,capsule);return reference;
}

export async function hydrateReleasePhaseMaterial({reference,prepared,files,planPath,store,repositoryRoot}) {
 const capsule=await store.getArtifact(reference),p=prepared.preparation;
 assertBrokerPreparation(p);
 assert.equal(brokerDigest(capsule),reference);assert.deepEqual(Object.keys(capsule).sort(),['kind','members','preparationSha256','sourceSha']);
 assert.equal(capsule.kind,'PRODUCTION_RELEASE_PHASE_MATERIAL');assert.equal(capsule.sourceSha,p.sourceSha);assert.equal(capsule.preparationSha256,brokerDigest(p));
 assert.deepEqual(Object.keys(files).sort(),['backendMetadata','package','packageManifest','tfvars']);
 const successorFiles=p.successorReconciliation?Object.fromEntries(['historicalStatePath','currentStatePath','bindingReportPath','imageEvidencePath','imageSignaturePath']
  .map(name=>[name,p.successorReconciliation[name]])):{};
 const materialFiles={...files,plan:planPath,...successorFiles};
 assert.equal(new Set(Object.values(materialFiles)).size,Object.keys(materialFiles).length,'Phase material paths overlap');
 assert.deepEqual(Object.keys(capsule.members).sort(),Object.keys(materialFiles).sort());
 const contents={};
 for(const [name,member] of Object.entries(capsule.members)){
  assert.deepEqual(Object.keys(member).sort(),['reference','sha256']);
  const artifact=await store.getArtifact(member.reference);assert.equal(brokerDigest(artifact),member.reference);
  assert.deepEqual(Object.keys(artifact).sort(),['base64','kind','sha256']);assert.equal(artifact.kind,'PRODUCTION_RELEASE_BINARY');
  assert.equal(typeof artifact.base64,'string');assert.ok(artifact.base64.length<=Math.ceil(64*1024*1024/3)*4);
  const bytes=Buffer.from(artifact.base64,'base64');assert.equal(bytes.toString('base64'),artifact.base64);
  assert.equal(brokerDigest(bytes),member.sha256);assert.equal(artifact.sha256,member.sha256);contents[name]=bytes;
 }
 assert.equal(brokerDigest(Object.fromEntries(Object.keys(files).map(name=>[name,brokerDigest(contents[name])]))),p.artifactSetSha256);
 assert.equal(brokerDigest(contents.plan),p.savedPlanSha256);
 for(const name of Object.keys(successorFiles))assert.equal(brokerDigest(contents[name]),p.successorReconciliation[name.replace(/Path$/,'Sha256')],`Successor ${name} differs from preparation`);
 // Validate the complete content binding before writing even one local member.
 for(const [name,filePath] of Object.entries(materialFiles)){
  ensureStageBPrivateDirectory({directory:path.dirname(filePath),repositoryRoot,create:true});
  if(fs.existsSync(filePath)){assertStageBPrivateFile({filePath,repositoryRoot,label:`Release ${name}`});assert.equal(brokerDigest(fs.readFileSync(filePath)),brokerDigest(contents[name]),'Existing material differs');}
  else writeStageBPrivateFileAtomic({filePath,bytes:contents[name],repositoryRoot,label:`Release ${name}`});
 }
 assert.equal(stagedBrokerArtifactSet(files,repositoryRoot,p,p.successorReconciliation?p.sourceSha:undefined),p.artifactSetSha256);
 return {...prepared,planPath};
}

// A release stays bound to this source and deployed baseline even when main advances.
export function createReleaseIdentity({sourceSha, ticketId, baseline, changedFiles}) {
 assert.match(sourceSha || '', /^[a-f0-9]{40}$/);
 assert.match(ticketId || '', /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 assertProductionComponentDeploymentState(baseline);
 const body = {schemaVersion: 1, sourceSha, ticketId, baselineSha256:brokerDigest(baseline), baselineGeneration:baseline.generation,
  classification: classifyProductionChanges(changedFiles)};
 return {...body, releaseId: brokerDigest(body)};
}

// The deployed component state is the release baseline. Every component range
// must be an ancestor of the immutable source; source advances cannot silently
// replace the baseline selected at release start.
export function readHostedReleaseSource(sourceSha,{run,checkout=readStageBProtectedMainCheckout,git=(args)=>execFileSync('git',args,{encoding:'utf8'})}={}){
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.equal(typeof run,'function');
 const identity=checkout({cwd:path.resolve(fileURLToPath(new URL('../..',import.meta.url))),fetchOriginMain:true,expectedSourceSha:sourceSha,requireCanonicalRepository:true});
 assert.equal(identity.currentHead,sourceSha);assert.equal(identity.originMainHead,sourceSha);
 const baseline=createProductionComponentDeploymentStateClient({run}).read();assert.ok(baseline,'Missing deployed-component baseline');
 const paths=new Set();
 for(const previous of new Set(Object.values(baseline.components).filter(Boolean).map(value=>value.establishedThroughSha||value.sourceSha))){
  assert.match(previous,/^[a-f0-9]{40}$/);
  git(['merge-base','--is-ancestor',previous,sourceSha]);
  for(const file of git(['diff','--name-only','--diff-filter=ACDMRT',previous,sourceSha]).split('\n').filter(Boolean))paths.add(file);
 }
 return {baseline,changedFiles:[...paths].sort()};
}

export function authenticateHostedStageBImages({sourceSha,transportJson,transportSha256,run,
  verifyAuthorization=verifyProductionReleaseImageAuthorization,verifyEvidence=verifyImageEvidenceSignature}={}){
 assert.match(sourceSha||'',/^[a-f0-9]{40}$/);assert.equal(typeof transportJson,'string');
 assert.match(transportSha256||'',/^[a-f0-9]{64}$/);assert.equal(typeof run,'function');
 const transport=unpackReleaseEvidenceTransport({json:transportJson,sha256:transportSha256});
 assert.equal(createHash('sha256').update(transport.authorizationJson).digest('hex'),transport.authorizationSha256);
 const authorization=JSON.parse(transport.authorizationJson);
 const refs=verifyAuthorization({authorization,sourceSha,verifyImageEvidence:options=>verifyEvidence({...options,run})});
 assert.deepEqual(Object.keys(refs).sort(),['backend','rls-canary','rls-executor','worker']);
 return {sourceSha,authorization,authorizationJson:transport.authorizationJson,refs,authorizationRawSha256:transport.authorizationSha256,
  transportSha256,historicalRuntimeTransportSha256:transport.historicalRuntimeSha256||null};
}

// Eligibility comes from authenticated retention/transaction evidence, not version numbering.
export function selectReleasePolicyDeletion({inventory, protectedVersionIds, obsoleteVersionIds}) {
 assert.ok(Array.isArray(inventory) && inventory.length === 5, 'Capacity handling requires the complete five-version inventory');
 const ids = new Set();
 for (const v of inventory) {
  assert.match(v.versionId || '', /^v[1-9][0-9]*$/);
  assert.ok(!ids.has(v.versionId), 'Duplicate IAM version identity'); ids.add(v.versionId);
  assert.equal(typeof v.isDefault, 'boolean');
  assert.match(v.documentSha256 || '', /^[a-f0-9]{64}$/);
  assert.equal(typeof v.createDate, 'string');
  assert.ok(Number.isFinite(Date.parse(v.createDate)), 'Invalid IAM CreateDate');
 }
 assert.equal(inventory.filter(v => v.isDefault).length, 1, 'Exactly one default must be authenticated');
 for (const list of [protectedVersionIds, obsoleteVersionIds]) {
  assert.ok(Array.isArray(list)); assert.equal(new Set(list).size, list.length);
  assert.ok(list.every(id => ids.has(id)), 'Retention evidence references an unknown IAM version');
 }
 const protectedIds = new Set(protectedVersionIds), obsoleteIds = new Set(obsoleteVersionIds);
 const eligible = inventory.filter(v => !v.isDefault && !protectedIds.has(v.versionId) && obsoleteIds.has(v.versionId));
 assert.ok(eligible.length, 'No eligible obsolete non-default policy version');
 const minimum = Math.min(...eligible.map(v => Date.parse(v.createDate)));
 const oldest = eligible.filter(v => Date.parse(v.createDate) === minimum);
 assert.equal(oldest.length, 1, 'Ambiguous oldest eligible policy version');
 return oldest[0].versionId;
}

const transitions = Object.freeze([
 ['registration', 'prepare-registration', 'register', 'recover-registration'],
 ['pruning', 'prepare-pruning', 'prune', 'recover-policy'],
 ['policy', 'prepare-policy', 'converge-policy', 'recover-policy'],
 ['publication', 'prepare-publication', 'publish', 'recover-publication'],
 ['cutover', 'prepare-cutover', 'cutover', 'recover-cutover'],
 ['closure', null, 'reconcile', 'recover-reconciliation'],
]);

// The runtime supplies authenticated external reads, durable conditional storage
// and the existing Stage-B public operation. Callers cannot supply phase order.
export async function runReleaseCoordinator(request, runtime) {
 assert.deepEqual(Object.keys(request).sort(), ['sourceSha', 'ticketId']);
 assert.match(request.sourceSha || '', /^[a-f0-9]{40}$/);
 assert.match(request.ticketId || '', /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 const store = runtime.store;
 const put = async value => {
  const sha256 = brokerDigest(value); await store.putArtifact(sha256, value); return sha256;
 };
 const get = async sha256 => {
  assert.match(sha256 || '', /^[a-f0-9]{64}$/);
  const value = await store.getArtifact(sha256); assert.equal(brokerDigest(value), sha256, 'Release artifact substitution'); return value;
 };
 const start=await store.readStart(request);
 let release;
 if(start){
  assert.deepEqual(Object.keys(start).sort(),['baseline','release']);
  release=await get(start.release);
  assert.equal(release.sourceSha,request.sourceSha);assert.equal(release.ticketId,request.ticketId);
  const baseline=await get(start.baseline);assertProductionComponentDeploymentState(baseline);
  assert.equal(brokerDigest(baseline),release.baselineSha256);assert.equal(baseline.generation,release.baselineGeneration);
  const {releaseId,...identity}=release;assert.equal(releaseId,brokerDigest(identity));
  // Reauthenticate eligibility without replacing the deployed baseline chosen
  // at release start. A later main or component-state generation is not a new release.
  await runtime.authenticateSource(request.sourceSha,release);
 }else{
  const accepted=await runtime.authenticateSource(request.sourceSha);
  release=createReleaseIdentity({sourceSha:request.sourceSha,ticketId:request.ticketId,baseline:accepted.baseline,changedFiles:accepted.changedFiles});
  await store.writeStart(request,{release:await put(release),baseline:await put(accepted.baseline)});
 }
 const readStep = async name => {
  const record = await store.readStep(release.releaseId, name);
  if (record) { assert.equal(record.releaseId, release.releaseId); assert.equal(record.sourceSha, release.sourceSha); assert.equal(record.name, name); }
  return record;
 };
 const record = async (name, value) => store.writeStep({releaseId: release.releaseId, sourceSha: release.sourceSha, name, ...value});
 const once = async (name, produce) => {
  const existing = await readStep(name);
  if (existing) return get(existing.result);
  const result = await produce(); await record(name, {result: await put(result)}); return result;
 };
 const original = await once('SOURCE_ACCEPTED', async () => release);
 assert.equal(brokerDigest(original), brokerDigest(release), 'Release source/baseline cannot be rebound');
 const artifacts = await once('ARTIFACTS_RESOLVED', async () => {
  const value=await runtime.resolveArtifacts(release);await runtime.authenticateArtifacts(release,value);return value;
 });
 await runtime.authenticateArtifacts(release, artifacts);
 const gates = await once('GATES_PASSED', async () => {
  const value=await runtime.resolveGates(release);await runtime.authenticateGates(release,value);return value;
 });
 await runtime.authenticateGates(release, gates);
 const completedRegistration = await once('REGISTRATION_CANDIDATE', () => runtime.findCompletedRegistration(release));
 const adoptedRegistration=completedRegistration&&await readStep('REGISTRATION_ADOPTED');
 const registrationResult=await readStep('registration:result'),registrationPrepared=await readStep('registration:prepared');
 const {predecessorReceiptRecovery, ...initialInputs} = await runtime.materializeInputs(release, artifacts,{phase:'registration',chain:null,
  adopted:Boolean(adoptedRegistration),prepared:registrationResult?await get(registrationResult.prepared):registrationPrepared?await get(registrationPrepared.result):null});
 let chain;
 const context = {release, artifacts, gates, store, inputs:initialInputs};
 const assertReleaseApproval=(phase,prepared,authorization,round=authorization.release?.authorizationRound)=>{
  if(authorization.schemaVersion===2)assert.deepEqual(authorization.release,{releaseId:release.releaseId,phase,
   preparationReference:brokerDigest(prepared),authorizationRound:round},'Authorization substituted release/phase identity');
 };
 const packages = {};
 for (const [name, prepare, execute, recover] of transitions) {
  if (name === 'registration' && completedRegistration) {
   const adopted = await once('REGISTRATION_ADOPTED', async () => {
    if (completedRegistration.preparation.sourceSha === release.sourceSha) {
     await runtime.authenticateRegistration(release, completedRegistration);
     return {status:'REGISTERED_OUTPUTS_ADOPTED_NONTERMINAL',sourceSha:release.sourceSha,
      prerequisiteChain:{registration:completedRegistration}};
    }
    return runtime.runStageOperation({...initialInputs, predecessorReceiptRecovery:undefined, operation:'prepare-registration-adoption',
     prerequisiteChain:{registration:completedRegistration}});
   });
   assert.equal(adopted.status,'REGISTERED_OUTPUTS_ADOPTED_NONTERMINAL'); assert.equal(adopted.sourceSha,release.sourceSha);
   chain = adopted.prerequisiteChain;
   await runtime.authenticateRegistration(release, chain.registration, initialInputs,{predecessorAdvanced:true});
   continue;
  }
  const done = await readStep(`${name}:result`);
  const savedPreparation=await readStep(`${name}:prepared`);
  // An earlier Terraform transition advances serial/bindings. Build fresh
  // planning material only for a new preparation; hydrate immutable captured
  // material when resuming an existing preparation/attempt.
  const inputs=name==='registration'?initialInputs:await runtime.materializeInputs(release,artifacts,{phase:name,chain,
   prepared:done?await get(done.prepared):savedPreparation?await get(savedPreparation.result):name==='closure'?packages.cutover.prepared:null});
  assert.equal(inputs.predecessorReceiptRecovery,undefined,'Historical predecessor selection belongs only to registration preparation');
  context.inputs=inputs;
  if (name === 'pruning') {
   const skipped = await readStep('pruning:skipped');
   if (skipped) {
    assert.equal(done,null,'Pruning cannot be both skipped and completed');
    assert.equal(savedPreparation,null,'Pruning cannot be both skipped and prepared');
    const retention=await get(skipped.result);
    assert.equal(retention.inventory.length,4,'Only four-version capacity may skip pruning');
    const policyAttempted=(await Promise.all(Array.from({length:20},(_,round)=>readStep(`policy:attempt:${round}`)))).some(Boolean);
    if (!policyAttempted) assert.deepEqual(await runtime.authenticatePolicyRetention(context,chain),retention,'Unpruned inventory changed before policy convergence');
    continue;
   }
   if (!done) {
    if (savedPreparation) context.versionId = (await get(savedPreparation.result)).preparation.target.versionId;
    else {
     const retention = await runtime.authenticatePolicyRetention(context, chain);
     if (retention.inventory.length < 5) {
      assert.equal(retention.inventory.length,4,'Policy capacity changed outside the supported predecessor');
      await record('pruning:skipped',{result:await put(retention)});
      continue;
     }
     context.versionId = selectReleasePolicyDeletion(retention);
    }
   }
  }
  let prepared, authorization, result;
  if (done) {
   prepared = await get(done.prepared); authorization = await get(done.authorization); result = await get(done.result);
   await runtime.hydratePreparation(context,name,prepared);
   assertReleaseApproval(name,prepared,authorization);
   await runtime.authenticateCompletedTransition(context, name, prepared, authorization, result);
  } else {
   const prepareRequest = {...inputs, operation:prepare, ...(chain ? {prerequisiteChain:chain} : {})};
   if (name === 'registration' && predecessorReceiptRecovery) prepareRequest.predecessorReceiptRecovery=predecessorReceiptRecovery;
   if (name === 'pruning') prepareRequest.versionId = context.versionId;
   if (name === 'cutover') Object.assign(prepareRequest, {publicationPreparation:packages.publication.prepared.preparation,
    publicationAuthorization:packages.publication.authorization, publicationResult:packages.publication.result});
   prepared = await once(`${name}:prepared`, async () => {
    if(name==='closure')return runtime.capturePreparation(context,name,{...packages.cutover.prepared,preparation:prepareBrokerStateRefresh({
     preparation:packages.cutover.prepared.preparation,authorization:packages.cutover.authorization,casResult:packages.cutover.result})});
    const value = await runtime.runStageOperation(prepareRequest);
    return runtime.capturePreparation(context,name,value);
   });
   assert.ok(prepared?.preparation, `Expected ${name} preparation`);
   assert.equal(prepared.preparation.sourceSha, release.sourceSha, 'Preparation changed release source');
   await runtime.hydratePreparation(context,name,prepared);
   const preparedDigest = await put(prepared);
   for(let round=0;;round++){
    assert.ok(round<20,'Repeated no-write or expired approvals require a new governed release');
    const attempt=await readStep(`${name}:attempt:${round}`);
    const authenticatedDispatch=async()=>{
     const journal=await readStep(`${name}:dispatch:${round}`),identity=journal?.dispatch?.identity;
     assert.ok(identity,'Timed-out approval lacks an authenticated dispatch');
     assert.equal(identity.repository,'T-ej2003/genuine-scan-main');
     assert.equal(identity.workflow,'authorize-production-stage-b-release-transition.yml');
     assert.equal(identity.workflowPath,'.github/workflows/authorize-production-stage-b-release-transition.yml');
     assert.equal(identity.ref,'main');assert.equal(identity.targetSha,brokerExecutionCheckout(prepared.preparation).sourceSha);
     assert.deepEqual(identity.inputs,releaseTransitionDispatchInputs({release,authorizationRound:round},name,preparedDigest,prepared.preparation));
    };
    {
     const timedOut=await readStep(`${name}:approval-timeout:${round}`);
     if(timedOut){
      assert.equal(attempt,null);assert.equal(await readStep(`${name}:authorized:${round}`),null);
      const pending=await readStep(`${name}:pending:${round}`);
      assert.equal(timedOut.prepared,preparedDigest);
      assert.match(timedOut.runId,/^[1-9][0-9]*$/);
      if(pending)assert.equal(timedOut.runId,pending.runId);
      else await authenticatedDispatch();
      continue;
     }
     const signed=await readStep(`${name}:authorized:${round}`);
     if(signed){
      assert.equal(signed.prepared,preparedDigest);
      authorization=await get(signed.authorization);
      await runtime.authenticateAuthorization(prepared.preparation,authorization);
      assertReleaseApproval(name,prepared,authorization,round);
      if(!attempt&&Date.parse(authorization.expiresAt)<=(runtime.now?.()||new Date()).getTime())continue;
     }else{
      assert.equal(attempt,null,'An attempt cannot lack its authenticated approval');
      const pendingApproval=await readStep(`${name}:pending:${round}`);
      if(pendingApproval)assert.equal(pendingApproval.prepared,preparedDigest);
      const approval=await runtime.obtainAuthorization({...context,authorizationRound:round,pendingApproval},name,prepared,preparedDigest);
      if(approval.status==='APPROVAL_TIMED_OUT'){
       assert.equal(attempt,null);
       assert.match(String(approval.runId),/^[1-9][0-9]*$/);
       if(pendingApproval)assert.equal(String(approval.runId),pendingApproval.runId,'Timed-out child differs from the recorded approval');
       else await authenticatedDispatch();
       await record(`${name}:approval-timeout:${round}`,{prepared:preparedDigest,runId:String(approval.runId)});
       continue;
      }
      if(approval.status==='WAITING_FOR_APPROVAL'){
       assert.match(String(approval.runId),/^[1-9][0-9]*$/);
       assert.equal(approval.runUrl,`https://github.com/T-ej2003/genuine-scan-main/actions/runs/${approval.runId}`);
       if(pendingApproval){assert.equal(String(approval.runId),pendingApproval.runId);assert.equal(approval.runUrl,pendingApproval.runUrl);}
       else await record(`${name}:pending:${round}`,{prepared:preparedDigest,runId:String(approval.runId),runUrl:approval.runUrl});
       return {status:'WAITING_FOR_APPROVAL',releaseId:release.releaseId,sourceSha:release.sourceSha,
        phase:name,authorizationRound:round,runId:String(approval.runId),runUrl:approval.runUrl};
      }
      assert.equal(approval.status,'AUTHORIZED');authorization=approval.authorization;
      if(pendingApproval){assert.equal(authorization.schemaVersion,2,'Recorded workflow approval requires protected artifact authority');
       assert.equal(authorization.protectedEnvironmentApprovalEvidence.workflowRunId,pendingApproval.runId,'Approval substituted the recorded child run');}
      await runtime.authenticateAuthorization(prepared.preparation,authorization);
      assertReleaseApproval(name,prepared,authorization,round);
      await record(`${name}:authorized:${round}`,{prepared:preparedDigest,authorization:await put(authorization)});
      if(Date.parse(authorization.expiresAt)<=(runtime.now?.()||new Date()).getTime())continue;
     }
    }
    const authorizationDigest=await put(authorization);
    assertReleaseApproval(name,prepared,authorization);
    // The coordinator invocation is not a native mutation intent. Only the
    // native journal (or held policy ownership) can select native recovery.
    const nativeState=attempt?await runtime.classifyNativeAttempt(context,name,prepared,authorization):'PRE_NATIVE';
    assert.ok(['PRE_NATIVE','RECOVER'].includes(nativeState),'Unknown native recovery state');
    if(nativeState==='PRE_NATIVE'&&Date.parse(authorization.expiresAt)<=(runtime.now?.()||new Date()).getTime())continue;
    const operationRequest={...inputs,operation:nativeState==='RECOVER'?recover:execute,preparation:prepared.preparation,authorization,planPath:prepared.planPath};
    if(name==='closure')Object.assign(operationRequest,{casResult:packages.cutover.result,
     cutoverPreparation:packages.cutover.prepared.preparation,cutoverAuthorization:packages.cutover.authorization});
    if(attempt){
     assert.equal(attempt.prepared,preparedDigest);assert.equal(attempt.authorization,authorizationDigest);
     result=await runtime.runStageOperation(operationRequest);
     if(nativeState==='RECOVER')result=await runtime.readRecoveredTransition(context,name,prepared,authorization,result);
    }else{
     await record(`${name}:attempt:${round}`,{prepared:preparedDigest,authorization:authorizationDigest});
     result=await runtime.runStageOperation(operationRequest);
    }
    if((name==='pruning'||name==='policy')&&result.status==='RECOVERED_NO_WRITE'){
     const noWrite=await readStep(`${name}:no-write:${round}`);
     const proof={prepared:preparedDigest,authorization:authorizationDigest,result:await put(result)};
     if(noWrite){assert.equal(noWrite.prepared,proof.prepared);assert.equal(noWrite.authorization,proof.authorization);assert.equal(noWrite.result,proof.result);}
     else await record(`${name}:no-write:${round}`,proof);
     continue;
    }
    await runtime.authenticateCompletedTransition(context,name,prepared,authorization,result);
    await record(`${name}:result`,{prepared:preparedDigest,authorization:authorizationDigest,result:await put(result)});
    break;
   }
  }
  packages[name]={prepared,authorization,result};
  if (name === 'registration') chain={registration:{preparation:prepared.preparation,authorization,result}};
  if (name === 'pruning') chain={...chain,pruning:{preparation:prepared.preparation,authorization,result}};
  if (name === 'policy') chain={registration:chain.registration,policy:{preparation:prepared.preparation,authorization,result}};
 }
 const closure = await runtime.authenticateClosure(context, packages, chain);
 const result={status:'PREREQUISITES_CONVERGED', releaseId:release.releaseId, sourceSha:release.sourceSha,
  registrationTransactionId:chain.registration.result.authorizationSha256,
  closureSha256:await put(closure), artifactsSha256:await put(artifacts), gatesSha256:await put(gates)};
 assert.deepEqual(await once('PREREQUISITES_CONVERGED', async()=>result),result,'Terminal prerequisite closure changed');
 return result;
}

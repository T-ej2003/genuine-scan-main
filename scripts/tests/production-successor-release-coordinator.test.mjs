import assert from 'node:assert/strict';
import test from 'node:test';
import {assertBrokerPreparation,brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {runSuccessorReleaseCoordinator,assertSuccessorRecoveryRequest} from '../aws/production-successor-release-coordinator.mjs';
import {runHostedSuccessorReleaseCoordinator} from '../aws/run-production-successor-release-coordinator.mjs';
import {authorizeReleaseTransition} from '../aws/authorize-production-stage-b-release-transition.mjs';
import {HOSTED_RELEASE_ROOT} from '../aws/production-release-coordinator.mjs';
import {authenticateFailedReleaseTransitionAttempt,releaseTransitionDispatchInputs} from '../aws/production-release-coordinator.mjs';
import {PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {execFileSync} from 'node:child_process';
import yaml from 'js-yaml';
import {ensureStageBPrivateDirectory} from '../aws/stage-b-artifact-contract.mjs';
import {rig,ready} from './fixtures/staged-broker-runtime.mjs';

const A='a'.repeat(40),C='c'.repeat(40),D='d'.repeat(40);
test('protected authorization installs dependencies and selects the direct production Terraform workspace',()=>{
 const workflow=fs.readFileSync(new URL('../../.github/workflows/authorize-production-stage-b-release-transition.yml',import.meta.url),'utf8');
 const install=workflow.indexOf('npm --prefix backend ci --ignore-scripts --no-audit --no-fund');
 const authorize=workflow.indexOf('node scripts/aws/authorize-production-stage-b-release-transition.mjs');
 assert.ok(install>0&&authorize>install);
 assert.match(workflow,/^    env:\n(?:      [^\n]*\n)*      TF_WORKSPACE: default$/m);
});
test('hosted cutover and closure setup creates every private authorization directory',()=>{
 const workflow=yaml.load(fs.readFileSync(new URL('../../.github/workflows/authorize-production-stage-b-release-transition.yml',import.meta.url),'utf8'));
 const steps=workflow.jobs.authorize.steps;
 const setup=steps.find(step=>step.name==='Authenticate exact protected source and private phase paths').run;
 const initialize=steps.find(step=>step.name==='Initialize exact provider schemas without applying or accessing the backend').run;
 for(const phase of ['cutover','closure']) for(const existing of [false,true]) {
  const sandbox=fs.mkdtempSync(path.join(os.tmpdir(),'stage-b-authorization-permissions-'));
  try {
   const root=path.join(sandbox,'evidence'),releaseId='1'.repeat(64),operation=path.join(root,releaseId);
   const bin=path.join(sandbox,'bin');fs.mkdirSync(bin);
   const commands={git:'case "$1" in rev-parse) printf "%s\\n" "$TOOLING_SHA";; esac',
    gh:'case "$*" in *protected*) echo true;; *) echo "$TOOLING_SHA";; esac',
    terraform:'touch "$TF_DATA_DIR/terraform.tfstate"'};
   for(const [name,body] of Object.entries(commands)) fs.writeFileSync(path.join(bin,name),'#!/bin/bash\n'+body+'\n',{mode:0o700});
   if(existing) for(const relative of ['', 'cutover','cutover/terraform','closure']) {
    const directory=path.join(operation,relative);fs.mkdirSync(directory,{recursive:true});fs.chmodSync(directory,0o755);
   }
   const environment=path.join(sandbox,'github-env');
   const env={...process.env,PATH:bin+path.delimiter+process.env.PATH,SOURCE_SHA:A,TOOLING_SHA:C,
    RELEASE_ID:releaseId,RELEASE_PREPARATION_REFERENCE:'2'.repeat(64),RELEASE_PHASE:phase,
    RELEASE_AUTHORIZATION_ROUND:'0',GITHUB_RUN_ATTEMPT:'1',GITHUB_SHA:C,
    GITHUB_REPOSITORY:'test/repository',GITHUB_ENV:environment};
   execFileSync('bash',['-c',setup.replaceAll(HOSTED_RELEASE_ROOT,root)],{env});
   const variables=Object.fromEntries(fs.readFileSync(environment,'utf8').trim().split('\n').map(line=>line.split('=')));
   assert.equal(variables.TF_DATA_DIR,path.join(operation,'cutover/terraform'));
   assert.equal(variables.AUTHORIZATION_OUTPUT,path.join(operation,phase,'authorization.json'));
   execFileSync('bash',['-e','-c',initialize],{env:{...env,...variables}});
   assert.equal(fs.existsSync(path.join(variables.TF_DATA_DIR,'terraform.tfstate')),false);
   for(const directory of [root,operation,path.join(operation,'cutover'),variables.TF_DATA_DIR,path.dirname(variables.AUTHORIZATION_OUTPUT)])
    assert.equal(ensureStageBPrivateDirectory({directory,repositoryRoot:process.cwd()}),directory);
   fs.chmodSync(path.join(operation,'cutover'),0o755);
   assert.throws(()=>ensureStageBPrivateDirectory({directory:path.join(operation,'cutover'),repositoryRoot:process.cwd()}),/0700/);
  } finally { fs.rmSync(sandbox,{recursive:true,force:true}); }
 }
});
const request={kind:'STAGE_B_SUCCESSOR_CUTOVER_REQUEST',releaseSourceSha:A,recoveryToolingSha:C,
 recoveryId:'2'.repeat(64),ticketId:'MSCQR-RECOVER',brokerVersion:'13',expectedAliasVersion:'12',expectedAliasRevision:'revision-before',
 historicalImportReference:'3'.repeat(64),currentStateSha256:'4'.repeat(64),
 publicationResultSha256:'5'.repeat(64),imageEvidenceReference:'6'.repeat(64),imageSignatureReference:'7'.repeat(64)};

async function fixture({approval='AUTHORIZED',lostResponse=false,lostNativeResponse=false,expireFirstApproval=false,
 expireEvidenceBeforeExecution=false,expireBeforeClosure=false}={}) {
 const original=rig({sourceSha:A}),r=await ready(original),p=structuredClone(r.p);
 // The published prerequisite chain, not the reviewed predecessor's runtime map,
 // authenticates the post-registration IAM task revisions during successor preparation.
 const successorMap=Object.fromEntries(Object.entries(original.p.prerequisites.taskMap)
  .map(([mode,arn])=>[mode,arn.replace(/:([0-9]+)$/,(_,revision)=>`:${Number(revision)+4}`)]));
 original.p.prerequisiteChain={registration:{result:{taskMap:successorMap}}};
 p.recoveryTooling={sourceSha:C,treeSha256:'8'.repeat(64),publicationResultSha256:brokerDigest(p.publication)};
 const selected={...request,publicationResultSha256:brokerDigest(p.publication)};
 let clock=Date.now();
 const successorEvidence=()=>{
  const value={operationId:'',historicalStatePath:'/tmp/historical',historicalStateSha256:'1'.repeat(64),
   currentStatePath:'/tmp/current',currentStateSha256:p.state.stateSha256,bindingReportPath:'/tmp/binding',
   bindingReportSha256:'2'.repeat(64),imageEvidencePath:'/tmp/images',imageEvidenceSha256:'3'.repeat(64),
   imageSignaturePath:'/tmp/signature',imageSignatureSha256:'4'.repeat(64),
   publicationResultSha256:brokerDigest(p.publication),outputChanges:[],createdAt:new Date(clock).toISOString(),
   expiresAt:new Date(clock+30*60_000).toISOString()};
  value.operationId=brokerDigest({purpose:p.purpose,sourceSha:p.sourceSha,recoveryTooling:p.recoveryTooling,
   publicationResultSha256:value.publicationResultSha256,historicalStateSha256:value.historicalStateSha256,
   currentStateSha256:value.currentStateSha256,alias:p.alias,target:p.target,bindingReportSha256:value.bindingReportSha256,
   imageEvidenceSha256:value.imageEvidenceSha256,imageSignatureSha256:value.imageSignatureSha256,outputChanges:[]});
  return value;
 };
 p.successorReconciliation=successorEvidence();
 const reference=brokerDigest(selected),artifacts=new Map([[reference,selected]]),steps=new Map(),starts=new Map();
 const releaseId=brokerDigest({schemaVersion:2,sourceSha:A,ticketId:selected.ticketId,recoveryReference:reference,toolingSha:C});
 const counts={registration:0,pruning:0,policy:0,publication:0,prepare:0,cutover:0,closure:0,approval:0};
 let nativeCutover;
 const store={putArtifact:(id,value)=>{assert.equal(id,brokerDigest(value));const prior=artifacts.get(id);
  if(prior)assert.deepEqual(prior,value);else artifacts.set(id,structuredClone(value));},
  getArtifact:id=>{assert.ok(artifacts.has(id));return structuredClone(artifacts.get(id));},
  readStart:key=>starts.get(JSON.stringify(key))||null,
  writeStart:(key,value)=>{const id=JSON.stringify(key);if(starts.has(id))assert.deepEqual(starts.get(id),value);else starts.set(id,structuredClone(value));},
  readStep:(id,name)=>steps.get(`${id}/${name}`)||null,
  writeStep:value=>{const id=`${value.releaseId}/${value.name}`;if(steps.has(id))assert.deepEqual(steps.get(id),value);
   else steps.set(id,structuredClone(value));if(lostResponse&&value.name==='cutover:attempt:0')throw new Error('Lost attempt response');}};
 const runtime={store,now:()=>clock,authenticateRequest:async value=>assert.deepEqual(value,selected),
  authenticatePublication:async()=>({preparation:original.p,authorization:original.auth,result:p.publication}),
  materializeInputs:async({phase})=>({phase,files:{},directory:'/tmp',terraformDataDir:'/tmp',successorRecovery:{}}),
  runStageOperation:async input=>{
   if(input.operation==='prepare-successor-cutover'){
    assert.deepEqual(input.prerequisiteChain,original.p.prerequisiteChain);
    counts.prepare++;
    if(counts.prepare>1){p.savedPlanSha256='e'.repeat(64);p.successorReconciliation=successorEvidence();}
    return {preparation:p,planPath:'/tmp/plan.tfplan'};
   }
   if(input.operation==='cutover'){counts.cutover++;nativeCutover={status:'CUTOVER_COMMITTED_STATE_PENDING',
    preparationSha256:brokerDigest(input.preparation),authorizationSha256:brokerDigest(input.authorization),
    alias:{...p.alias,FunctionVersion:'13',RevisionId:'after'},authorizedAt:new Date().toISOString()};
    if(expireBeforeClosure)clock+=31*60_000;
    if(lostNativeResponse)throw new Error('Lost native cutover response');return nativeCutover;}
   if(input.operation==='recover-cutover'){assert.ok(nativeCutover);return nativeCutover;}
   if(input.operation==='reconcile'){counts.closure++;return {status:'RECONCILED_PENDING_RELEASE_CAS',
    preparationSha256:brokerDigest(input.preparation),authorizationSha256:brokerDigest(input.authorization),
    closurePlan:{},stateAuthorizedAt:new Date().toISOString()};}
   throw new Error(`Unexpected operation ${input.operation}`);
  },
  capturePreparation:async(_context,_phase,value)=>({...value,materializationSha256:'9'.repeat(64)}),
  hydratePreparation:async()=>{},authenticateAuthorization:async()=>{},
  obtainAuthorization:async(context,phase,prepared,preparationReference)=>{counts.approval++;
   if(approval==='UNRECORDED_TIMEOUT')return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   if(approval==='APPROVAL_TIMED_OUT_TWICE'&&phase==='cutover'&&context.authorizationRound<2){
    const runId=String(700+context.authorizationRound);
    if(!context.pendingApproval)return {status:'WAITING_FOR_APPROVAL',runId,
     runUrl:`https://github.com/T-ej2003/genuine-scan-main/actions/runs/${runId}`};
    clock+=31*60_000;return {status:'APPROVAL_TIMED_OUT',runId};
   }
   if(['WAITING_FOR_APPROVAL','APPROVAL_TIMED_OUT','APPROVAL_TIMED_OUT_STILL_VALID'].includes(approval)&&counts.approval===1)
    return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};
   if(['APPROVAL_TIMED_OUT','APPROVAL_TIMED_OUT_STILL_VALID'].includes(approval)&&counts.approval===2){
    if(approval==='APPROVAL_TIMED_OUT')clock+=31*60_000;
    return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   }
   if(expireEvidenceBeforeExecution&&context.authorizationRound===0)clock+=31*60_000;
   return {status:'AUTHORIZED',authorization:{schemaVersion:2,issuedAt:new Date(clock).toISOString(),
    expiresAt:new Date(clock+(expireFirstApproval&&context.authorizationRound===0?-1000:20*60_000)).toISOString(),
    ...(context.pendingApproval?{protectedEnvironmentApprovalEvidence:{workflowRunId:context.pendingApproval.runId}}:{}),
    release:{releaseId:context.release.releaseId,
     phase,preparationReference,authorizationRound:context.authorizationRound}}};},
  classifyNativeAttempt:async(_context,phase)=>phase==='cutover'&&nativeCutover?'RECOVER':'PRE_NATIVE',
  authenticateCompletedTransition:async()=>{},authenticateClosure:async()=>({status:'CLOSED',sourceSha:A})};
 return {runtime,reference,store,steps,counts,releaseId,advanceClock:ms=>{clock+=ms;}};
}

test('hosted successor coordinator records preparation and governs cutover then closure without replaying prerequisites',async()=>{
 const f=await fixture(),execute=()=>runHostedSuccessorReleaseCoordinator({recoveryReference:f.reference},
  {runtimeFactory:()=>f.runtime}),result=await execute();
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');assert.equal(result.sourceSha,A);assert.equal(result.toolingSha,C);
 assert.equal(f.steps.get(`${f.releaseId}/cutover:prepared`).name,'cutover:prepared');
 assert.equal(f.steps.get(`${f.releaseId}/closure:prepared`).name,'closure:prepared');
 assert.deepEqual(f.counts,{registration:0,pruning:0,policy:0,publication:0,prepare:1,cutover:1,closure:1,approval:2});
 const again=await execute();
 assert.deepEqual(again,result);assert.equal(f.counts.cutover,1);assert.equal(f.counts.closure,1);
});

test('lost native alias response adopts its authenticated result without a second CAS',async()=>{
 const f=await fixture({lostNativeResponse:true});
 await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),/Lost native cutover response/);
 assert.equal(f.counts.cutover,1);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');assert.equal(f.counts.cutover,1);
});

test('protected authorization pending boundary resumes the same immutable preparation',async()=>{
 const f=await fixture({approval:'WAITING_FOR_APPROVAL'});
 const first=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(first.status,'WAITING_FOR_APPROVAL');assert.equal(first.phase,'cutover');assert.equal(f.counts.cutover,0);
 const second=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(second.status,'BROKER_CLOSURE_COMPLETE');assert.equal(f.counts.cutover,1);
});

test('timed-out protected child records round zero and authorizes a fresh round without replay',async()=>{
 const f=await fixture({approval:'APPROVAL_TIMED_OUT'});
 const first=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(first.status,'WAITING_FOR_APPROVAL');assert.equal(first.authorizationRound,0);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.equal(f.steps.get(`${f.releaseId}/cutover:approval-timeout:0`).runId,'700');
 assert.ok(f.steps.has(`${f.releaseId}/cutover:authorized:1`));
 assert.equal(f.counts.prepare,2);
 assert.notEqual(f.steps.get(`${f.releaseId}/cutover:prepared`).result,
  f.steps.get(`${f.releaseId}/cutover:prepared:1`).result);
 assert.equal(f.counts.cutover,1);
});

test('timed-out approval retains still-valid preparation in the next authorization round',async()=>{
 const f=await fixture({approval:'APPROVAL_TIMED_OUT_STILL_VALID'});
 await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.equal(f.counts.prepare,1);
 assert.equal(f.steps.get(`${f.releaseId}/cutover:prepared`).result,
  f.steps.get(`${f.releaseId}/cutover:prepared:1`).result);
});

test('expired pre-native authorization advances round without replacing still-valid evidence',async()=>{
 const f=await fixture({expireFirstApproval:true});
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.ok(f.steps.has(`${f.releaseId}/cutover:authorized:0`));
 assert.ok(f.steps.has(`${f.releaseId}/cutover:authorized:1`));
 assert.equal(f.counts.prepare,1);
 assert.equal(f.steps.get(`${f.releaseId}/cutover:authorized:0`).prepared,
  f.steps.get(`${f.releaseId}/cutover:authorized:1`).prepared);
 assert.equal(f.counts.cutover,1);
});

test('successor evidence expiring after approval is retired before alias intent and re-prepared',async()=>{
 const f=await fixture({expireEvidenceBeforeExecution:true});
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.deepEqual(f.steps.get(`${f.releaseId}/cutover:retired:0`).reason,'EVIDENCE_EXPIRED');
 assert.equal(f.counts.prepare,2);assert.equal(f.counts.cutover,1);
});

test('protected authorization entrypoint rejects a late old round and cross-round preparation substitution',async()=>{
 const f=await fixture({approval:'APPROVAL_TIMED_OUT'});
 await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 const first=f.steps.get(`${f.releaseId}/cutover:prepared`).result;
 const directory=path.join(HOSTED_RELEASE_ROOT,f.releaseId,'cutover');
 const env={GITHUB_ACTIONS:'true',GITHUB_WORKFLOW_REF:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
  GITHUB_REPOSITORY:PRODUCTION_ENVIRONMENT_APPROVAL.repository,GITHUB_EVENT_NAME:'workflow_dispatch',
  GITHUB_RUN_ATTEMPT:'1',GITHUB_RUN_ID:'700',GITHUB_SHA:C,RUNNER_TEMP:'/tmp',RELEASE_ID:f.releaseId,
  RELEASE_PHASE:'cutover',RELEASE_PREPARATION_REFERENCE:first,RELEASE_AUTHORIZATION_ROUND:'0'};
 try{
  const authorizationRequest={sourceSha:A,ticketId:request.ticketId,releaseId:f.releaseId,phase:'cutover',
   preparationReference:first,authorizationRound:0,output:path.join(directory,'authorization.json')};
  await assert.rejects(()=>authorizeReleaseTransition(authorizationRequest,{env,createStore:()=>f.store,run:()=>assert.fail('No AWS call')}),
   /retired|timed out/);
  const newer=f.steps.get(`${f.releaseId}/cutover:prepared:1`).result;
  assert.notEqual(first,newer);
  await assert.rejects(()=>authorizeReleaseTransition({...authorizationRequest,authorizationRound:1},
   {env:{...env,RELEASE_AUTHORIZATION_ROUND:'1'},createStore:()=>f.store,run:()=>assert.fail('No AWS call')}));
 }finally{fs.rmSync(path.join(HOSTED_RELEASE_ROOT,f.releaseId),{recursive:true,force:true});}
});

test('pending approval is retired when its evidence expires before the child completes',async()=>{
 const f=await fixture({approval:'WAITING_FOR_APPROVAL'});
 const pending=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(pending.status,'WAITING_FOR_APPROVAL');
 f.advanceClock(31*60_000);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.equal(f.steps.get(`${f.releaseId}/cutover:retired:0`).reason,'EVIDENCE_EXPIRED');
 assert.equal(f.counts.prepare,2);assert.equal(f.counts.cutover,1);
});

test('two consecutive timeouts preserve each historical round and authorize only fresh evidence',async()=>{
 const f=await fixture({approval:'APPROVAL_TIMED_OUT_TWICE'});
 assert.equal((await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime)).authorizationRound,0);
 assert.equal((await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime)).authorizationRound,1);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');assert.equal(f.counts.prepare,3);
 for(let round=0;round<2;round++)assert.equal(f.steps.get(`${f.releaseId}/cutover:approval-timeout:${round}`).runId,String(700+round));
 const approved=f.steps.get(`${f.releaseId}/cutover:authorized:2`).prepared;
 assert.equal(approved,f.steps.get(`${f.releaseId}/cutover:prepared:2`).result);
 assert.notEqual(approved,f.steps.get(`${f.releaseId}/cutover:prepared:1`).result);
 assert.equal(f.counts.cutover,1);
});

test('closure retains completed cutover evidence after its pre-CAS validity window',async()=>{
 const f=await fixture({expireBeforeClosure:true});
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.equal(f.counts.cutover,1);assert.equal(f.counts.closure,1);
 assert.equal(f.counts.prepare,1);
});

test('rejected and cancelled approvals stop without advancing preparation or mutating the alias',async()=>{
 for(const status of ['REJECTED','CANCELLED','FAILED']){
  const f=await fixture();
  f.runtime.obtainAuthorization=async()=>{throw new Error(`Exact approval child ${status}`);};
  await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),
   new RegExp(status));
  assert.equal(f.counts.prepare,1);assert.equal(f.counts.cutover,0);
  assert.equal(f.steps.has(`${f.releaseId}/cutover:prepared:1`),false);
 }
});

test('protected-main tooling advance invalidates a pending operation without rewriting its history',async()=>{
 const f=await fixture({approval:'WAITING_FOR_APPROVAL'});
 const pending=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(pending.status,'WAITING_FOR_APPROVAL');
 const historical=structuredClone(f.steps.get(`${f.releaseId}/cutover:prepared`));
 f.runtime.authenticateRequest=async()=>{throw new Error('Protected main advanced beyond operation tooling');};
 await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),
  /Protected main advanced/);
 assert.deepEqual(f.steps.get(`${f.releaseId}/cutover:prepared`),historical);
 assert.equal(f.counts.cutover,0);assert.equal(f.counts.prepare,1);
});

test('an unrecorded timed-out approval cannot authorize another child',async()=>{
 const f=await fixture({approval:'UNRECORDED_TIMEOUT'});
 await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),
  /authenticated dispatch/);
 assert.equal(f.counts.cutover,0);
 assert.equal(f.steps.has(`${f.releaseId}/cutover:approval-timeout:0`),false);
});

test('lost coordinator attempt response resumes only after native intent absence is authenticated',async()=>{
 const f=await fixture({lostResponse:true});
 await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),/Lost attempt response/);
 assert.equal(f.counts.cutover,0);
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');assert.equal(f.counts.cutover,1);
});

test('successor routing rejects missing, mixed or malformed evidence before any operation',async()=>{
 for(const mutate of [v=>{delete v.historicalImportReference;},v=>{v.releaseSourceSha=v.recoveryToolingSha;},
  v=>{v.brokerVersion=v.expectedAliasVersion;},v=>{v.imageSignatureReference='wrong';},
  v=>{v.expectedAliasRevision='';}]){
  const value=structuredClone(request);mutate(value);
  assert.throws(()=>assertSuccessorRecoveryRequest(value));
 }
 const f=await fixture();f.runtime.authenticateRequest=async()=>{throw new Error('Wrong protected-main tooling');};
 await assert.rejects(()=>runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime),/Wrong protected-main tooling/);
 assert.equal(f.counts.cutover,0);
});

test('post-CAS tooling continuation retires the failed historical approval and closes without replaying alias CAS',async()=>{
 const f=await fixture();
 const capture=f.runtime.capturePreparation;
 f.runtime.capturePreparation=async(context,phase,value)=>capture(context,phase,{...value,
  planPath:path.join(HOSTED_RELEASE_ROOT,f.releaseId,'cutover','reconcile.tfplan')});
 f.runtime.obtainAuthorization=async(context,phase,prepared,preparationReference)=>{
  f.counts.approval++;
  if(phase==='closure')return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};
  return {status:'AUTHORIZED',authorization:{schemaVersion:2,expiresAt:new Date(Date.now()+20*60_000).toISOString(),
   release:{releaseId:context.release.releaseId,phase,preparationReference,authorizationRound:context.authorizationRound}}};
 };
 const pending=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(pending.phase,'closure');assert.equal(pending.authorizationRound,0);assert.equal(f.counts.cutover,1);
 const old=f.steps.get(`${f.releaseId}/closure:prepared`),oldPrepared=f.store.getArtifact(old.result);
 const release={releaseId:f.releaseId,sourceSha:A,ticketId:request.ticketId};
 const identity={repository:'T-ej2003/genuine-scan-main',workflow:'authorize-production-stage-b-release-transition.yml',
  workflowPath:'.github/workflows/authorize-production-stage-b-release-transition.yml',workflowId:77,ref:'main',targetSha:C,
  inputs:releaseTransitionDispatchInputs({release,authorizationRound:0},'closure',old.result,oldPrepared.preparation)};
 f.store.writeStep({releaseId:f.releaseId,sourceSha:A,name:'closure:dispatch:0',dispatch:{identity,beforeRunIds:['699']}});
 f.runtime.authenticateRequest=async()=>({currentTooling:{sourceSha:D,treeSha256:'d'.repeat(64)},
  supersededAuthorization:{runId:'700',toolingSha:C,conclusion:'failure',preparationReference:old.result,authorizationRound:0}});
 f.runtime.obtainAuthorization=async(context,phase,prepared,preparationReference)=>{
  f.counts.approval++;
  return {status:'AUTHORIZED',authorization:{schemaVersion:2,issuedAt:new Date().toISOString(),expiresAt:new Date(Date.now()+20*60_000).toISOString(),
   protectedEnvironmentApprovalEvidence:{workflowRunId:'701'},release:{releaseId:context.release.releaseId,phase,preparationReference,authorizationRound:context.authorizationRound}}};
 };
 const closed=await runHostedSuccessorReleaseCoordinator({recoveryReference:f.reference},{runtimeFactory:()=>f.runtime});
 assert.equal(closed.status,'BROKER_CLOSURE_COMPLETE');assert.equal(closed.sourceSha,A);assert.equal(closed.toolingSha,C);assert.equal(closed.closureToolingSha,D);
 assert.equal(f.counts.cutover,1);assert.equal(f.counts.closure,1);
 const retired=f.steps.get(`${f.releaseId}/closure:retired:0`);
 assert.equal(retired.prepared,old.result);assert.equal(retired.reason,'TOOLING_ADVANCED_AFTER_CAS');assert.equal(retired.runId,'700');
 const next=f.steps.get(`${f.releaseId}/closure:prepared:1`),nextPrepared=f.store.getArtifact(next.result);
 assertBrokerPreparation(nextPrepared.preparation);
 assert.equal(nextPrepared.preparation.sourceSha,A);
 assert.equal(nextPrepared.preparation.recoveryTooling.sourceSha,C);
 assert.equal(nextPrepared.preparation.closureContinuation.currentTooling.sourceSha,D);
 const tampered=structuredClone(nextPrepared.preparation);tampered.closureContinuation.operationId='f'.repeat(64);
 assert.throws(()=>assertBrokerPreparation(tampered),/Closure continuation identity is invalid/);
 const mixed=structuredClone(nextPrepared.preparation);mixed.closureContinuation.currentTooling.sourceSha=C;
 mixed.closureContinuation.operationId=brokerDigest(Object.fromEntries(Object.entries(mixed.closureContinuation).filter(([key])=>key!=='operationId')));
 assert.throws(()=>assertBrokerPreparation(mixed));
 assert.equal(f.steps.get(`${f.releaseId}/closure:authorized:1`).prepared,next.result);
 const output=path.join(HOSTED_RELEASE_ROOT,f.releaseId,'closure','authorization.json');
 const env={GITHUB_ACTIONS:'true',GITHUB_WORKFLOW_REF:PRODUCTION_ENVIRONMENT_APPROVAL.stageBReleaseTransitionWorkflowRef,
  GITHUB_REPOSITORY:PRODUCTION_ENVIRONMENT_APPROVAL.repository,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',
  GITHUB_RUN_ID:'701',GITHUB_SHA:D,RUNNER_TEMP:'/tmp',RELEASE_ID:f.releaseId,RELEASE_PHASE:'closure',
  RELEASE_PREPARATION_REFERENCE:next.result,RELEASE_AUTHORIZATION_ROUND:'1'};
 try{
  ensureStageBPrivateDirectory({directory:path.dirname(output),repositoryRoot:process.cwd(),create:true});
  const auth=await authorizeReleaseTransition({sourceSha:A,ticketId:request.ticketId,releaseId:f.releaseId,phase:'closure',
   preparationReference:next.result,authorizationRound:1,output},{env,createStore:()=>f.store,hydrateMaterial:async()=>{},
   run:()=>assert.fail('Authorization fixture must not access AWS'),
   ghRun:args=>{
    if(args[1].endsWith('/actions/runs/700'))return JSON.stringify({id:700,workflow_id:77,repository:{full_name:'T-ej2003/genuine-scan-main'},
     head_repository:{full_name:'T-ej2003/genuine-scan-main'},head_sha:C,head_branch:'main',
     path:'.github/workflows/authorize-production-stage-b-release-transition.yml',event:'workflow_dispatch',run_attempt:1,status:'completed',conclusion:'failure'});
    if(args[1].endsWith('/artifacts'))return JSON.stringify([{artifacts:[]}]);
    assert.fail(`Unexpected GitHub read ${args.join(' ')}`);
   },
   runRequest:async value=>{
    assert.equal(value.operation,'authorize-closure');assert.equal(value.preparation.sourceSha,A);
    assert.equal(value.preparation.closureContinuation.currentTooling.sourceSha,D);
    return {schemaVersion:2,preparationSha256:brokerDigest(value.preparation),protectedEnvironmentApprovalEvidence:{workflowRunId:'701'}};
   }});
  assert.equal(auth.authorizationSha256,brokerDigest(JSON.parse(fs.readFileSync(output,'utf8'))));
 }finally{fs.rmSync(path.join(HOSTED_RELEASE_ROOT,f.releaseId),{recursive:true,force:true});}
});

test('failed authorization attempt with an artifact cannot be superseded',()=>{
 const calls=[];
 const run=args=>{calls.push(args);return args[1].endsWith('/artifacts')?JSON.stringify([{artifacts:[{
  name:'production-stage-b-release-transition-authorization',workflow_run:{id:700}}]}]):JSON.stringify({id:700,workflow_id:77,
   repository:{full_name:'T-ej2003/genuine-scan-main'},head_repository:{full_name:'T-ej2003/genuine-scan-main'},head_sha:C,
   head_branch:'main',path:'.github/workflows/authorize-production-stage-b-release-transition.yml',event:'workflow_dispatch',
   run_attempt:1,status:'completed',conclusion:'failure'});};
 assert.throws(()=>authenticateFailedReleaseTransitionAttempt({run,runId:'700',toolingSha:C,workflowId:77,beforeRunIds:['699']}),/produced an authorization artifact/);
 assert.equal(calls.length,2);
});

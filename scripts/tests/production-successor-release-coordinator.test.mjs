import assert from 'node:assert/strict';
import test from 'node:test';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {runSuccessorReleaseCoordinator,assertSuccessorRecoveryRequest} from '../aws/production-successor-release-coordinator.mjs';
import {runHostedSuccessorReleaseCoordinator} from '../aws/run-production-successor-release-coordinator.mjs';
import {rig,ready} from './fixtures/staged-broker-runtime.mjs';

const A='a'.repeat(40),C='c'.repeat(40);
const request={kind:'STAGE_B_SUCCESSOR_CUTOVER_REQUEST',releaseSourceSha:A,recoveryToolingSha:C,
 recoveryId:'2'.repeat(64),ticketId:'MSCQR-RECOVER',brokerVersion:'13',expectedAliasVersion:'12',expectedAliasRevision:'revision-before',
 historicalImportReference:'3'.repeat(64),currentStateSha256:'4'.repeat(64),
 publicationResultSha256:'5'.repeat(64),imageEvidenceReference:'6'.repeat(64),imageSignatureReference:'7'.repeat(64)};

async function fixture({approval='AUTHORIZED',lostResponse=false,lostNativeResponse=false,expireFirstApproval=false}={}) {
 const original=rig({sourceSha:A}),r=await ready(original),p=structuredClone(r.p);
 p.recoveryTooling={sourceSha:C,treeSha256:'8'.repeat(64),publicationResultSha256:brokerDigest(p.publication)};
 const selected={...request,publicationResultSha256:brokerDigest(p.publication)};
 const reference=brokerDigest(selected),artifacts=new Map([[reference,selected]]),steps=new Map(),starts=new Map();
 const releaseId=brokerDigest({schemaVersion:2,sourceSha:A,ticketId:selected.ticketId,recoveryReference:reference,toolingSha:C});
 const counts={registration:0,pruning:0,policy:0,publication:0,cutover:0,closure:0,approval:0};
 let nativeCutover;
 const store={putArtifact:(id,value)=>{assert.equal(id,brokerDigest(value));const prior=artifacts.get(id);
  if(prior)assert.deepEqual(prior,value);else artifacts.set(id,structuredClone(value));},
  getArtifact:id=>{assert.ok(artifacts.has(id));return structuredClone(artifacts.get(id));},
  readStart:key=>starts.get(JSON.stringify(key))||null,
  writeStart:(key,value)=>{const id=JSON.stringify(key);if(starts.has(id))assert.deepEqual(starts.get(id),value);else starts.set(id,structuredClone(value));},
  readStep:(id,name)=>steps.get(`${id}/${name}`)||null,
  writeStep:value=>{const id=`${value.releaseId}/${value.name}`;if(steps.has(id))assert.deepEqual(steps.get(id),value);
   else steps.set(id,structuredClone(value));if(lostResponse&&value.name==='cutover:attempt:0')throw new Error('Lost attempt response');}};
 const runtime={store,authenticateRequest:async value=>assert.deepEqual(value,selected),
  authenticatePublication:async()=>({preparation:original.p,authorization:original.auth,result:p.publication}),
  materializeInputs:async({phase})=>({phase,files:{},directory:'/tmp',terraformDataDir:'/tmp',successorRecovery:{}}),
  runStageOperation:async input=>{
   if(input.operation==='prepare-successor-cutover')return {preparation:p,planPath:'/tmp/plan.tfplan'};
   if(input.operation==='cutover'){counts.cutover++;nativeCutover={status:'CUTOVER_COMMITTED_STATE_PENDING',
    preparationSha256:brokerDigest(input.preparation),authorizationSha256:brokerDigest(input.authorization),
    alias:{...p.alias,FunctionVersion:'13',RevisionId:'after'},authorizedAt:new Date().toISOString()};
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
   if(['WAITING_FOR_APPROVAL','APPROVAL_TIMED_OUT'].includes(approval)&&counts.approval===1)
    return {status:'WAITING_FOR_APPROVAL',runId:'700',runUrl:'https://github.com/T-ej2003/genuine-scan-main/actions/runs/700'};
   if(approval==='APPROVAL_TIMED_OUT'&&counts.approval===2)return {status:'APPROVAL_TIMED_OUT',runId:'700'};
   return {status:'AUTHORIZED',authorization:{schemaVersion:2,issuedAt:new Date().toISOString(),
    expiresAt:new Date(Date.now()+(expireFirstApproval&&context.authorizationRound===0?-1000:20*60_000)).toISOString(),
    ...(context.pendingApproval?{protectedEnvironmentApprovalEvidence:{workflowRunId:context.pendingApproval.runId}}:{}),
    release:{releaseId:context.release.releaseId,
     phase,preparationReference,authorizationRound:context.authorizationRound}}};},
  classifyNativeAttempt:async(_context,phase)=>phase==='cutover'&&nativeCutover?'RECOVER':'PRE_NATIVE',
  authenticateCompletedTransition:async()=>{},authenticateClosure:async()=>({status:'CLOSED',sourceSha:A})};
 return {runtime,reference,store,steps,counts,releaseId};
}

test('hosted successor coordinator records preparation and governs cutover then closure without replaying prerequisites',async()=>{
 const f=await fixture(),execute=()=>runHostedSuccessorReleaseCoordinator({recoveryReference:f.reference},
  {runtimeFactory:()=>f.runtime}),result=await execute();
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');assert.equal(result.sourceSha,A);assert.equal(result.toolingSha,C);
 assert.equal(f.steps.get(`${f.releaseId}/cutover:prepared`).name,'cutover:prepared');
 assert.equal(f.steps.get(`${f.releaseId}/closure:prepared`).name,'closure:prepared');
 assert.deepEqual(f.counts,{registration:0,pruning:0,policy:0,publication:0,cutover:1,closure:1,approval:2});
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
 assert.equal(f.counts.cutover,1);
});

test('expired pre-native authorization advances round while keeping the preparation',async()=>{
 const f=await fixture({expireFirstApproval:true});
 const result=await runSuccessorReleaseCoordinator({recoveryReference:f.reference},f.runtime);
 assert.equal(result.status,'BROKER_CLOSURE_COMPLETE');
 assert.ok(f.steps.has(`${f.releaseId}/cutover:authorized:0`));
 assert.ok(f.steps.has(`${f.releaseId}/cutover:authorized:1`));
 assert.equal(f.counts.cutover,1);
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

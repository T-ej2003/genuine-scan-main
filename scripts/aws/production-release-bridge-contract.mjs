import assert from 'node:assert/strict';
import {brokerDigest} from './stage-b-staged-broker-contract.mjs';
import {assertProductionEnvironmentApprovalIdentity,assertProductionEnvironmentApprovalFreshness,PRODUCTION_ENVIRONMENT_APPROVAL} from './production-github-environment-approval.mjs';

const SHA40=/^[a-f0-9]{40}$/;
const SHA256=/^[a-f0-9]{64}$/;
const RUN_ID=/^[1-9][0-9]*$/;
const ROTATION=/^rotation-[a-z0-9-]+$/;
export const BRIDGE_OPERATION='PREPARE_OVERLAP_LEGACY';

export function bridgeOperationId({releaseId,sourceSha,rotationId}) {
 assert.match(releaseId||'',SHA256);assert.match(sourceSha||'',SHA40);assert.match(rotationId||'',ROTATION);
 return brokerDigest({kind:'PRODUCTION_RELEASE_BRIDGE_OPERATION_V1',releaseId,sourceSha,rotationId});
}

export function createBridgeRequest({releaseId,sourceSha,ticketId,rotationId,manifestSha256,environmentApprovalSha256,workflowRunId,workflowRunAttempt,authorizationRound=0,issuedAt,expiresAt}) {
 const operationId=bridgeOperationId({releaseId,sourceSha,rotationId});
 assert.match(ticketId||'',/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/);
 assert.match(manifestSha256||'',SHA256);assert.match(environmentApprovalSha256||'',SHA256);assert.match(String(workflowRunId||''),RUN_ID);
 assert.match(String(workflowRunAttempt||''),RUN_ID);
 assert.ok(Number.isSafeInteger(authorizationRound)&&authorizationRound>=0&&authorizationRound<32,'Bridge authorization round is invalid');
 const start=Date.parse(issuedAt),end=Date.parse(expiresAt);
 assert.ok(Number.isSafeInteger(start)&&Number.isSafeInteger(end)&&end>start&&end-start<=30*60*1000,'Bridge request authorization window is invalid');
 const body={kind:'PRODUCTION_RELEASE_TRUSTED_TERMINAL_REQUEST_V1',schemaVersion:1,operationId,operation:BRIDGE_OPERATION,
  releaseId,sourceSha,ticketId,rotationId,manifestSha256,environmentApprovalSha256,workflowRunId:String(workflowRunId),workflowRunAttempt:String(workflowRunAttempt),authorizationRound,issuedAt,expiresAt};
 return Object.freeze({...body,requestSha256:brokerDigest(body)});
}

export function assertBridgeRequest(value,{releaseId,sourceSha,ticketId,rotationId,manifestSha256,now=Date.now(),allowExpired=false}={}) {
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'Bridge request is missing');
 assert.deepEqual(Object.keys(value).sort(),['authorizationRound','issuedAt','environmentApprovalSha256','expiresAt','kind','manifestSha256','operation','operationId','releaseId','requestSha256','rotationId','schemaVersion','sourceSha','ticketId','workflowRunAttempt','workflowRunId'].sort());
 const expected=createBridgeRequest(value);
 assert.deepEqual(value,expected,'Bridge request was changed');
 assert.equal(value.releaseId,releaseId);assert.equal(value.sourceSha,sourceSha);assert.equal(value.ticketId,ticketId);
 assert.equal(value.rotationId,rotationId);assert.equal(value.manifestSha256,manifestSha256);
 assert.ok(allowExpired||now>=Date.parse(value.issuedAt)&&now<Date.parse(value.expiresAt),'Bridge request is expired or not yet valid');
 return value;
}

export async function claimBridgeRequest(store,request,{now=Date.now()}={}) {
 assertBridgeRequest(request,{releaseId:request.releaseId,sourceSha:request.sourceSha,ticketId:request.ticketId,rotationId:request.rotationId,manifestSha256:request.manifestSha256,now});
 const phase=`BRIDGE:REQUEST:${request.workflowRunId}:${request.workflowRunAttempt}`;
 const existing=await store.readOperation(request.operationId,phase);
 if(existing)assert.deepEqual(existing,request,'Bridge request conflicts with existing authorization');
 else{
  assert.equal(await store.claimOperation(request.operationId,phase,request),true,'Bridge request ownership was not confirmed');
  assert.deepEqual(await store.readOperation(request.operationId,phase),request,'Bridge request readback differs');
 }
 const owner={operationId:request.operationId,requestSha256:request.requestSha256,workflowRunId:request.workflowRunId,workflowRunAttempt:request.workflowRunAttempt,authorizationRound:request.authorizationRound};
 const ownerPhase=`BRIDGE:REQUEST:ROUND:${request.authorizationRound}`;
 const priorOwner=await store.readOperation(request.operationId,ownerPhase);
 if(priorOwner)assert.deepEqual(priorOwner,owner,'Another workflow owns the immutable bridge operation');
 else{
  assert.equal(await store.claimOperation(request.operationId,ownerPhase,owner),true,'Bridge request ownership was not confirmed');
  assert.deepEqual(await store.readOperation(request.operationId,ownerPhase),owner);
 }
 return !existing;
}

export async function requestTrustedTerminalCutover({store,sourceSha,ticketId,rotationId,manifestSha256,approval,workflowRunId,workflowRunAttempt,verifyCompletedSign,now=Date.now()}) {
 const start=await store.readStart({sourceSha,ticketId});
 assert.ok(start,'Release coordinator has no authenticated start');
 const release=await store.getArtifact(start.release);
 assert.equal(release.releaseId,brokerDigest(Object.fromEntries(Object.entries(release).filter(([name])=>name!=='releaseId'))));
 assert.equal(release.sourceSha,sourceSha);assert.equal(release.ticketId,ticketId);
 const closure=await store.readStep(release.releaseId,'PREREQUISITE_PREPARATION_CONVERGED');
 assert.ok(closure&&closure.sourceSha===sourceSha&&closure.releaseId===release.releaseId,'Release prerequisites are incomplete');
 const result=await store.getArtifact(closure.result);
 assert.equal(result.status,'PREREQUISITES_CONVERGED');assert.equal(result.releaseId,release.releaseId);
 const operationId=bridgeOperationId({releaseId:release.releaseId,sourceSha,rotationId});
 const operator=await store.readOperation(operationId,'BRIDGE:OPERATOR:DISPATCH');
 let authorizationRound=0;
 for(;authorizationRound<32;authorizationRound++){
  const owner=await store.readOperation(operationId,`BRIDGE:REQUEST:ROUND:${authorizationRound}`);
  if(!owner)break;
  const prior=await store.readOperation(operationId,`BRIDGE:REQUEST:${owner.workflowRunId}:${owner.workflowRunAttempt}`);
  assert.ok(prior,'Owned bridge request is missing; reconcile before retry');
  assertBridgeRequest(prior,{releaseId:release.releaseId,sourceSha,ticketId,rotationId,manifestSha256,allowExpired:true});
  assert.equal(prior.requestSha256,owner.requestSha256);
  if(await store.readOperation(operationId,'BRIDGE:CUTOVER:COMPLETED'))return prior;
  if(now<Date.parse(prior.expiresAt))return prior;
  if(operator?.requestSha256===prior.requestSha256)return prior;
  if(operator)continue;
  for(const phase of ['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR']){
   const prefix=`BRIDGE:SIGN:${phase}`,dispatch=await store.readOperation(operationId,`${prefix}:DISPATCH`);
   if(!dispatch||dispatch.requestSha256!==prior.requestSha256)continue;
   const result=await store.readOperation(operationId,`${prefix}:RESULT`);
   assert.ok(result,`${phase} Sign outcome is unknown; reauthorization is forbidden`);
   assert.ok(Date.parse(dispatch.claimedAt)>=Date.parse(prior.issuedAt)&&Date.parse(dispatch.claimedAt)<Date.parse(prior.expiresAt),`${phase} Sign was not claimed during its authorization`);
   assert.equal(typeof verifyCompletedSign,'function','Independent native Sign verification is required before reauthorization');
   assert.equal(await verifyCompletedSign({phase,dispatch,result,request:prior}),true,`${phase} native Sign could not be authenticated`);
   let completed=await store.readOperation(operationId,`${prefix}:COMPLETED`);
   if(!completed){
    completed={dispatch,resultSha256:brokerDigest(result)};
    await store.writeOperation(operationId,`${prefix}:COMPLETED`,completed);
    assert.deepEqual(await store.readOperation(operationId,`${prefix}:COMPLETED`),completed,`${phase} Sign completion readback differs`);
   }
   assert.equal(classifyBridgeNativeResult({dispatch,result,completion:completed}),'COMPLETED');
  }
  const root=await store.readOperation(operationId,'BRIDGE:SIGN:ROOT_DROP:DISPATCH');
  if(root){
   const rootResult=await store.readOperation(operationId,'BRIDGE:SIGN:ROOT_DROP:RESULT');
   const rootCompletion=await store.readOperation(operationId,'BRIDGE:SIGN:ROOT_DROP:COMPLETED');
   assert.equal(classifyBridgeNativeResult({dispatch:root,result:rootResult,completion:rootCompletion}),'COMPLETED','Root Sign outcome is unknown');
   const rootIssued=Date.parse(root.phaseTimestamp);
   assert.ok(Number.isSafeInteger(rootIssued)&&now>=rootIssued&&now-rootIssued<780000,'Root freshness reserve is exhausted; separate recovery is required');
  }
 }
 assert.ok(!operator,'Operator claim has no authenticated authorization owner');
 assert.ok(authorizationRound<32,'Bridge authorization rounds exhausted');
 assertProductionEnvironmentApprovalIdentity(approval,{sourceSha,repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository});
 assertProductionEnvironmentApprovalFreshness(approval,{now:new Date(now)});
 assert.equal(approval.workflowRef,PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef);
 assert.equal(approval.workflowRunId,String(workflowRunId));assert.equal(approval.workflowRunAttempt,String(workflowRunAttempt));
 assert.equal(approval.schemaVersion,3,'Actual protected-environment review is required');
 await store.putArtifact(brokerDigest(approval),approval);
 const request=createBridgeRequest({releaseId:release.releaseId,sourceSha,ticketId,rotationId,manifestSha256,
  environmentApprovalSha256:brokerDigest(approval),workflowRunId,workflowRunAttempt,authorizationRound,
  issuedAt:new Date(now).toISOString(),expiresAt:new Date(Math.min(now+30*60*1000,Date.parse(approval.observedAt)+PRODUCTION_ENVIRONMENT_APPROVAL.maxAgeMs)).toISOString()});
 await claimBridgeRequest(store,request,{now});return request;
}

export function classifyBridgeNativeResult({dispatch,result,completion}={}) {
 if(!dispatch)return 'NOT_STARTED';
 if(!result||!completion)return 'OUTCOME_UNKNOWN';
 assert.deepEqual(result.dispatch,dispatch,'Bridge native result belongs to a different dispatch');
 assert.deepEqual(completion.dispatch,dispatch,'Bridge native completion belongs to a different dispatch');
 assert.equal(completion.resultSha256,brokerDigest(result),'Bridge native result differs from completion');
 return 'COMPLETED';
}

export async function bridgeRequestForSign({store,operationId,dispatch,releaseId,sourceSha,ticketId,rotationId,manifestSha256}={}){
 assert.equal(dispatch?.operationId,operationId);
 let owner;
 for(let round=0;round<32;round++){
  const candidate=await store.readOperation(operationId,`BRIDGE:REQUEST:ROUND:${round}`);
  if(!candidate)break;
  assert.equal(candidate.operationId,operationId);assert.equal(candidate.authorizationRound,round);
  if(candidate.requestSha256===dispatch.requestSha256){owner=candidate;break;}
 }
 assert.ok(owner,'Sign has no owned authorization request');
 const request=await store.readOperation(operationId,`BRIDGE:REQUEST:${owner.workflowRunId}:${owner.workflowRunAttempt}`);
 assertBridgeRequest(request,{releaseId,sourceSha,ticketId,rotationId,manifestSha256,allowExpired:true});
 assert.equal(request.requestSha256,dispatch.requestSha256);
 assert.equal(request.authorizationRound,owner.authorizationRound);
 const claimed=Date.parse(dispatch.claimedAt);
 assert.ok(Number.isSafeInteger(claimed)&&claimed>=Date.parse(request.issuedAt)&&claimed<Date.parse(request.expiresAt),
  'Sign dispatch was not claimed during its exact authorization');
 return request;
}

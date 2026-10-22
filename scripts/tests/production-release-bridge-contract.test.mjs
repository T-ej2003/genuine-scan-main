import assert from 'node:assert/strict';
import test from 'node:test';
import {bridgeOperationId,createBridgeRequest,assertBridgeRequest,claimBridgeRequest,classifyBridgeNativeResult,requestTrustedTerminalCutover,bridgeRequestForSign} from '../aws/production-release-bridge-contract.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';
import {createProductionEnvironmentApprovalEvidence,PRODUCTION_ENVIRONMENT_APPROVAL} from '../aws/production-github-environment-approval.mjs';
import {authenticateBridgeEnvironmentApproval} from '../aws/verify-production-release-terminal-bridge.mjs';

const input={releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'CHG-1',rotationId:'rotation-20260913011819-98b062c4',manifestSha256:'c'.repeat(64),environmentApprovalSha256:'e'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',issuedAt:'2026-10-22T10:00:00.000Z',expiresAt:'2026-10-22T10:30:00.000Z'};
const now=Date.parse('2026-10-22T10:01:00.000Z');

test('bridge request binds one source, rotation, exact manifest, run and authorization window',()=>{
 const request=createBridgeRequest(input);
 assert.equal(request.operationId,bridgeOperationId(input));
 assert.equal(assertBridgeRequest(request,{...input,now}),request);
 for(const field of ['sourceSha','rotationId','manifestSha256','workflowRunId','workflowRunAttempt']){
  assert.throws(()=>assertBridgeRequest({...request,[field]:field==='workflowRunId'?'124':'d'.repeat(field==='sourceSha'?40:64)},{...input,now}));
 }
 assert.throws(()=>assertBridgeRequest(request,{...input,now:Date.parse(input.expiresAt)}),/expired/);
 assert.throws(()=>createBridgeRequest({...input,expiresAt:'2026-10-22T10:31:00.000Z'}),/window/);
});

test('claim is write once and conflicting replacement fails closed',async()=>{
 const request=createBridgeRequest(input),records=new Map();
 const store={readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,claimOperation:async(id,phase,value)=>{const key=`${id}:${phase}`;if(records.has(key))throw Error('occupied');records.set(key,value);return true;}};
 // The claim itself always validates current freshness; keep test time current.
 const fresh=createBridgeRequest({...input,issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()});
 assert.equal(await claimBridgeRequest(store,fresh),true);
 assert.equal(await claimBridgeRequest(store,fresh),false);
 assert.equal(records.size,2);
 assert.ok(request.requestSha256!==fresh.requestSha256);
 await assert.rejects(()=>claimBridgeRequest(store,{...fresh,manifestSha256:'d'.repeat(64)}));
});

test('a dispatched native operation without a captured result remains unknown',()=>{
 const dispatch={operationId:'a'.repeat(64),phase:'ROOT_DROP',requestSha256:'b'.repeat(64)};
 const result={dispatch,response:{Signature:'c'}};
 assert.equal(classifyBridgeNativeResult({}),'NOT_STARTED');
 assert.equal(classifyBridgeNativeResult({dispatch}),'OUTCOME_UNKNOWN');
 assert.equal(classifyBridgeNativeResult({dispatch,result}),'OUTCOME_UNKNOWN');
 assert.equal(classifyBridgeNativeResult({dispatch,result,completion:{dispatch,resultSha256:brokerDigest(result)}}),'COMPLETED');
 assert.throws(()=>classifyBridgeNativeResult({dispatch,result:{...result,dispatch:{...dispatch,phase:'OTHER'}},completion:{dispatch,resultSha256:brokerDigest(result)}}));
 assert.throws(()=>classifyBridgeNativeResult({dispatch,result,completion:{dispatch,resultSha256:'0'.repeat(64)}}));
});

test('hosted request requires durable prerequisite closure and actual protected review',async()=>{
 const identity={schemaVersion:1,sourceSha:input.sourceSha,ticketId:input.ticketId,baselineSha256:'0'.repeat(64),baselineGeneration:1,changedFiles:[]};
 const release={...identity,releaseId:brokerDigest(identity)};
 const approval=createProductionEnvironmentApprovalEvidence({repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',
  sourceSha:input.sourceSha,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef,eventName:'workflow_dispatch',
  workflowRunId:'123',workflowRunAttempt:'1',executionActor:'operator',observedAt:new Date(now-15*60*1000).toISOString(),
  actualApproval:{state:'approved',environmentId:10,environmentName:'production',userId:1,userLogin:'operator'},
  environmentConfig:{id:10,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]}});
 const records=new Map(),artifacts=new Map();let complete=false,operatorCommit;
 const store={readStart:async()=>({release:brokerDigest(release)}),getArtifact:async id=>artifacts.get(id)|| (id===brokerDigest(release)?release:{status:'PREREQUISITES_CONVERGED',releaseId:release.releaseId}),
  readStep:async()=>complete?{releaseId:release.releaseId,sourceSha:input.sourceSha,result:'f'.repeat(64)}:null,
  putArtifact:async(id,value)=>{artifacts.set(id,value);},readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,
  readOperationCommittedAt:async()=>operatorCommit,
  claimOperation:async(id,phase,value)=>{records.set(`${id}:${phase}`,value);return true;}};
 const params={store,sourceSha:input.sourceSha,ticketId:input.ticketId,rotationId:input.rotationId,manifestSha256:input.manifestSha256,approval,workflowRunId:'123',workflowRunAttempt:'1',now};
 await assert.rejects(()=>requestTrustedTerminalCutover(params),/prerequisites/);
 complete=true;
 const request=await requestTrustedTerminalCutover(params);
 assert.equal(request.expiresAt,new Date(now+15*60*1000).toISOString(),'Sign request cannot outlive its observed protected approval');
 assert.equal(request.environmentApprovalSha256,brokerDigest(approval));
 assert.equal(request.releaseId,release.releaseId);
 assert.equal(await authenticateBridgeEnvironmentApproval({store,request,observeApproval:async()=>approval}),approval);
 await assert.rejects(()=>authenticateBridgeEnvironmentApproval({store,request,observeApproval:async()=>({...approval,actualApproval:{...approval.actualApproval,userLogin:'forged'}})}),/approval changed/);
 records.set(`${request.operationId}:BRIDGE:OPERATOR:DISPATCH`,{requestSha256:request.requestSha256,operationId:request.operationId,
  inputSha256:'a'.repeat(64),claimedAt:new Date(Date.parse(request.expiresAt)-1000).toISOString(),
  executionContract:'S3_COMMIT_BEFORE_NATIVE_V2'});
 operatorCommit=request.expiresAt;
 const later=now+31*60*1000;
 const nextApproval=createProductionEnvironmentApprovalEvidence({repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',
  sourceSha:input.sourceSha,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef,eventName:'workflow_dispatch',
  workflowRunId:'124',workflowRunAttempt:'1',executionActor:'operator',observedAt:new Date(later).toISOString(),
  actualApproval:{state:'approved',environmentId:10,environmentName:'production',userId:1,userLogin:'operator'},
  environmentConfig:{id:10,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]}});
 const renewed=await requestTrustedTerminalCutover({...params,approval:nextApproval,workflowRunId:'124',now:later});
 assert.equal(renewed.authorizationRound,1);
 assert.equal(records.get(`${request.operationId}:BRIDGE:OPERATOR:DISPATCH`).requestSha256,request.requestSha256);
 const dispatch={operationId:renewed.operationId,phase:'ROOT_DROP',requestSha256:renewed.requestSha256,
  phaseTimestamp:new Date(later+29*60*1000).toISOString(),claimedAt:new Date(later+29*60*1000).toISOString()};
 records.set(`${renewed.operationId}:BRIDGE:SIGN:ROOT_DROP:DISPATCH`,dispatch);
 await assert.rejects(()=>requestTrustedTerminalCutover({...params,approval:nextApproval,workflowRunId:'124',now:later+31*60*1000}),/outcome is unknown/);
 assert.equal(records.has(`${renewed.operationId}:BRIDGE:REQUEST:ROUND:2`),false);
});

test('expired request preserves captured root and adoption while requiring a fresh authorization for each pending Sign',async()=>{
 const identity={schemaVersion:1,sourceSha:input.sourceSha,ticketId:input.ticketId,baselineSha256:'0'.repeat(64),baselineGeneration:1,changedFiles:[]};
 const release={...identity,releaseId:brokerDigest(identity)},records=new Map(),artifacts=new Map();
 const operationId=bridgeOperationId({...input,releaseId:release.releaseId});
 const store={readStart:async()=>({release:brokerDigest(release)}),getArtifact:async id=>artifacts.get(id)||
  (id===brokerDigest(release)?release:{status:'PREREQUISITES_CONVERGED',releaseId:release.releaseId}),
  readStep:async()=>({releaseId:release.releaseId,sourceSha:input.sourceSha,result:'f'.repeat(64)}),
  putArtifact:async(id,value)=>{artifacts.set(id,value);},
  readOperation:async(_id,phase)=>records.get(phase)||null,
  claimOperation:async(_id,phase,value)=>{assert.equal(records.has(phase),false);records.set(phase,value);return true;},
  writeOperation:async(_id,phase,value)=>{assert.equal(records.has(phase),false);records.set(phase,value);return true;}};
 const approvalFor=(runId,at)=>createProductionEnvironmentApprovalEvidence({repository:PRODUCTION_ENVIRONMENT_APPROVAL.repository,environment:'production',
  sourceSha:input.sourceSha,workflowRef:PRODUCTION_ENVIRONMENT_APPROVAL.releaseTrainWorkflowRef,eventName:'workflow_dispatch',
  workflowRunId:String(runId),workflowRunAttempt:'1',executionActor:'operator',observedAt:new Date(at).toISOString(),
  actualApproval:{state:'approved',environmentId:10,environmentName:'production',userId:1,userLogin:'operator'},
  environmentConfig:{id:10,name:'production',can_admins_bypass:false,protection_rules:[{type:'required_reviewers',prevent_self_review:false,reviewers:[{type:'User',reviewer:{id:1,login:'operator'}}]}]}});
 const requestAt=(runId,at,verifyCompletedSign=()=>true)=>requestTrustedTerminalCutover({store,sourceSha:input.sourceSha,ticketId:input.ticketId,
  rotationId:input.rotationId,manifestSha256:input.manifestSha256,approval:approvalFor(runId,at),workflowRunId:String(runId),workflowRunAttempt:'1',
  verifyCompletedSign,now:at});
 const captured=(phase,request,at)=>{
  const dispatch={operationId,phase,requestSha256:request.requestSha256,claimedAt:new Date(at).toISOString(),
   phaseTimestamp:new Date(at).toISOString()};
  const result={dispatch,response:{KeyId:'key',Signature:'c2ln'}};
  records.set(`BRIDGE:SIGN:${phase}:DISPATCH`,dispatch);
  records.set(`BRIDGE:SIGN:${phase}:RESULT`,result);
  records.set(`BRIDGE:SIGN:${phase}:COMPLETED`,{dispatch,resultSha256:brokerDigest(result)});
  return dispatch;
 };
 const first=await requestAt(1,now);
 const rootAt=now+29*60*1000;
 const root=captured('ROOT_DROP',first,rootAt);
 records.delete('BRIDGE:SIGN:ROOT_DROP:COMPLETED'); // Native response persisted; completion-marker acknowledgement was lost.
 assert.equal((await bridgeRequestForSign({store,operationId,dispatch:root,...input,releaseId:release.releaseId})).requestSha256,first.requestSha256);
 let verified=0;
 const second=await requestAt(2,now+31*60*1000,({phase})=>{assert.equal(phase,'ROOT_DROP');verified++;return true;});
 assert.equal(second.authorizationRound,1);assert.equal(verified,1);
 assert.equal(records.get('BRIDGE:SIGN:ROOT_DROP:COMPLETED').resultSha256,brokerDigest(records.get('BRIDGE:SIGN:ROOT_DROP:RESULT')));
 assert.equal(records.get('BRIDGE:SIGN:ROOT_DROP:DISPATCH'),root,'Root Sign must not be replaced');
 assert.equal(await requestAt(3,now+32*60*1000),second,'Active renewed authorization must be reused');
 assert.equal(records.has('BRIDGE:REQUEST:ROUND:2'),false);
 await assert.rejects(()=>requestAt(4,now+62*60*1000),/Root freshness reserve is exhausted/);
 assert.equal(records.has('BRIDGE:REQUEST:ROUND:2'),false,'Expired root cannot mint another signing round');
 await assert.rejects(()=>bridgeRequestForSign({store,operationId,dispatch:{...root,claimedAt:new Date(now+31*60*1000).toISOString()},
  ...input,releaseId:release.releaseId}),/not claimed during/);
 await assert.rejects(()=>requestTrustedTerminalCutover({store,sourceSha:'d'.repeat(40),ticketId:input.ticketId,rotationId:input.rotationId,
  manifestSha256:input.manifestSha256,approval:approvalFor(4,now+32*60*1000),workflowRunId:'4',workflowRunAttempt:'1',now:now+32*60*1000}),
 /Expected values to be strictly equal/);
});

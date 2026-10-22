import assert from 'node:assert/strict';
import test from 'node:test';
import {reserveBridgeOperator} from '../aws/run-production-release-terminal-bridge.mjs';
import {createBridgeRequest} from '../aws/production-release-bridge-contract.mjs';

test('lost operator response never authorizes a second native cutover',async()=>{
 const records=new Map(),commits=new Map();
 const store={readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,
  readOperationCommittedAt:async(id,phase)=>commits.get(`${id}:${phase}`),
  claimOperation:async(id,phase,value)=>{const key=`${id}:${phase}`;if(records.has(key))throw Error('duplicate');records.set(key,value);commits.set(key,value.claimedAt);return true;}};
 const request=createBridgeRequest({releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
  manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
  issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
 const operationId=request.operationId;
 const input={store,request,configSha256:'c'.repeat(64),commands:['--mode','prepare-overlap'],now:()=>29*60*1000};
 assert.equal(await reserveBridgeOperator(input),'EXECUTE');
 assert.equal(await reserveBridgeOperator(input),'RECONCILE');
 await assert.rejects(()=>reserveBridgeOperator({...input,configSha256:'d'.repeat(64)}),/different inputs/);
 assert.equal(records.size,1);
 await assert.rejects(()=>reserveBridgeOperator({...input,now:()=>31*60*1000,store:{...store,readOperation:async()=>null}}),/REAUTHORIZATION_REQUIRED/);
});

test('a timely operator claim remains executable when its readback crosses request expiry',async()=>{
 const request=createBridgeRequest({releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
  manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
  issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
 let calls=0,claimed;
 const store={readOperation:async()=>claimed||null,readOperationCommittedAt:async()=>claimed.claimedAt,
  claimOperation:async(_id,_phase,value)=>{claimed=value;return true;}};
 assert.equal(await reserveBridgeOperator({store,request,configSha256:'c'.repeat(64),commands:['operator'],
  now:()=>++calls<=2?29*60*1000:31*60*1000}),'EXECUTE');
 assert.equal(claimed.requestSha256,request.requestSha256);
 assert.equal(calls,1,'claim initiation and its immutable time use one authorization decision');
});

test('a claim committed after expiry cannot borrow its earlier client timestamp',async()=>{
 const request=createBridgeRequest({releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
  manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
  issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
 let claimed;
 const store={readOperation:async()=>claimed||null,readOperationCommittedAt:async()=>new Date(30*60*1000).toISOString(),
  claimOperation:async(_id,_phase,value)=>{claimed=value;return true;}};
 await assert.rejects(()=>reserveBridgeOperator({store,request,configSha256:'c'.repeat(64),commands:['operator'],
  now:()=>29*60*1000}),/REAUTHORIZATION_REQUIRED/);
 assert.equal(claimed.requestSha256,request.requestSha256,'ambiguous claim remains immutable for reconciliation');
 assert.equal(claimed.executionContract,'S3_COMMIT_BEFORE_NATIVE_V2');
 await assert.rejects(()=>reserveBridgeOperator({store,request,configSha256:'c'.repeat(64),commands:['operator'],
  now:()=>31*60*1000}),/REAUTHORIZATION_REQUIRED/);
});

test('a renewed round preserves the late claim and owns a distinct atomic operator claim',async()=>{
 const release={releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
  manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64)};
 const first=createBridgeRequest({...release,workflowRunId:'123',workflowRunAttempt:'1',authorizationRound:0,
  issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
 const second=createBridgeRequest({...release,workflowRunId:'124',workflowRunAttempt:'1',authorizationRound:1,
  issuedAt:new Date(31*60*1000).toISOString(),expiresAt:new Date(60*60*1000).toISOString()});
 const records=new Map(),commits=new Map();
 const store={readOperation:async(_id,phase)=>records.get(phase)||null,
  readOperationCommittedAt:async(_id,phase)=>commits.get(phase),
  claimOperation:async(_id,phase,value)=>{assert.equal(records.has(phase),false);records.set(phase,value);
   commits.set(phase,value.claimedAt);return true;}};
 const old='BRIDGE:OPERATOR:DISPATCH';
 // Model S3 committing the old claim after the old request expired.
 records.set(old,{requestSha256:first.requestSha256,operationId:first.operationId,inputSha256:'f'.repeat(64),
  claimedAt:new Date(29*60*1000).toISOString(),executionContract:'S3_COMMIT_BEFORE_NATIVE_V2'});
 commits.set(old,new Date(30*60*1000).toISOString());
 const action=await reserveBridgeOperator({store,request:second,configSha256:'c'.repeat(64),commands:['operator'],
  now:()=>32*60*1000});
 assert.equal(action,'EXECUTE');
 assert.equal(records.get(old).requestSha256,first.requestSha256);
 assert.equal(records.get('BRIDGE:OPERATOR:DISPATCH:ROUND:1').requestSha256,second.requestSha256);
});

import assert from 'node:assert/strict';
import test from 'node:test';
import {reserveBridgeOperator} from '../aws/run-production-release-terminal-bridge.mjs';
import {createBridgeRequest} from '../aws/production-release-bridge-contract.mjs';

test('lost operator response never authorizes a second native cutover',async()=>{
 const records=new Map();
 const store={readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,
  claimOperation:async(id,phase,value)=>{const key=`${id}:${phase}`;if(records.has(key))throw Error('duplicate');records.set(key,value);return true;}};
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

test('authorization expiring during durable operator claim never starts native mutation',async()=>{
 const request=createBridgeRequest({releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
  manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
  issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
 let calls=0,claimed;
 const store={readOperation:async()=>claimed||null,claimOperation:async(_id,_phase,value)=>{claimed=value;return true;}};
 await assert.rejects(()=>reserveBridgeOperator({store,request,configSha256:'c'.repeat(64),commands:['operator'],
  now:()=>++calls<=2?29*60*1000:31*60*1000}),/OUTCOME_UNKNOWN/);
 assert.equal(claimed.requestSha256,request.requestSha256);
});

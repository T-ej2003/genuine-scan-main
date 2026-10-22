import test from 'node:test';
import assert from 'node:assert/strict';
import {waitForTerminalCutover} from '../aws/run-hosted-production-release-bridge.mjs';
import {createBridgeRequest} from '../aws/production-release-bridge-contract.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';

const request=createBridgeRequest({releaseId:'a'.repeat(64),sourceSha:'b'.repeat(40),ticketId:'ticket',rotationId:'rotation-test',
 manifestSha256:'c'.repeat(64),environmentApprovalSha256:'d'.repeat(64),workflowRunId:'123',workflowRunAttempt:'1',
 issuedAt:new Date(0).toISOString(),expiresAt:new Date(30*60*1000).toISOString()});
const dispatch={operationId:request.operationId,phase:'ROOT_DROP',requestSha256:request.requestSha256};
const native={dispatch,response:{Signature:'c2ln'}};
const signs={
 'BRIDGE:SIGN:ROOT_DROP:DISPATCH':dispatch,'BRIDGE:SIGN:ROOT_DROP:RESULT':native,
 'BRIDGE:SIGN:ROOT_DROP:COMPLETED':{dispatch,resultSha256:brokerDigest(native)}};
const operator={operationId:request.operationId,requestSha256:request.requestSha256,inputSha256:'e'.repeat(64),claimedAt:new Date(29*60*1000).toISOString()};
const input=(records,clock=()=>31*60*1000)=>({verify:async()=>null,ensureCredentials:async()=>{},store:{readOperation:async(_id,phase)=>records[phase]||null,
 readOperationCommittedAt:async()=>operator.claimedAt},
 request,now:clock,wait:async()=>{},maxPolls:2});

test('expired completed signatures without an operator claim reauthorize immediately',async()=>{
 let checks=0;
 await assert.rejects(waitForTerminalCutover({...input(signs),verify:async()=>{checks++;return null;}}),/REAUTHORIZATION_REQUIRED/);
 assert.equal(checks,1);
});

test('expired request with an authenticated matching operator claim can reconcile native work',async()=>{
 let checks=0;
 const completion={readinessSha256:'a'.repeat(64)};
 const result=await waitForTerminalCutover({...input({...signs,'BRIDGE:OPERATOR:DISPATCH':operator}),
  verify:async()=>++checks===2?completion:null});
 assert.equal(result,completion);
});

test('mismatched, late and unbound operator claims fail closed',async()=>{
 for(const claim of [{...operator,requestSha256:'f'.repeat(64)},
  {...operator,claimedAt:new Date(31*60*1000).toISOString()},
  {...operator,inputSha256:'not-a-hash'}]){
  await assert.rejects(waitForTerminalCutover(input({...signs,'BRIDGE:OPERATOR:DISPATCH':claim})),/Operator claim/);
 }
});

test('expired request with unknown KMS dispatch fails closed before reauthorization',async()=>{
 await assert.rejects(waitForTerminalCutover(input({'BRIDGE:SIGN:ROOT_DROP:DISPATCH':dispatch})),/OUTCOME_UNKNOWN/);
});

test('request expiry before any privileged dispatch requires reauthorization',async()=>{
 await assert.rejects(waitForTerminalCutover(input({})),/REAUTHORIZATION_REQUIRED/);
});

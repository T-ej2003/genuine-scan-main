import test from 'node:test';
import assert from 'node:assert/strict';
import {waitForTerminalCutover} from '../aws/run-hosted-production-release-bridge.mjs';
import {brokerDigest} from '../aws/stage-b-staged-broker-contract.mjs';

test('captured signatures remain observable after request expiry while the operator is in flight',async()=>{
 let minute=29,checks=0;
 const completion={readinessSha256:'a'.repeat(64)};
 const dispatch={operationId:'operation',phase:'ROOT_DROP',requestSha256:'request'};
 const native={dispatch,response:{Signature:'c2ln'}};
 const result=await waitForTerminalCutover({verify:async()=>++checks===3?completion:null,
  ensureCredentials:async()=>{},store:{readOperation:async(_operation,phase)=>({
   'BRIDGE:SIGN:ROOT_DROP:DISPATCH':dispatch,'BRIDGE:SIGN:ROOT_DROP:RESULT':native,
   'BRIDGE:SIGN:ROOT_DROP:COMPLETED':{dispatch,resultSha256:brokerDigest(native)},
   'BRIDGE:OPERATOR:DISPATCH':{requestSha256:'request'}})[phase]||null},
  operationId:'operation',requestSha256:'request',expiresAt:new Date(30*60*1000).toISOString(),now:()=>minute*60*1000,
  wait:async()=>{minute++;},maxPolls:4});
 assert.equal(result,completion);assert.equal(checks,3);assert.ok(minute>30);
});

test('expired request without a Sign and bounded unknown outcome fail closed',async()=>{
 const input={verify:async()=>null,ensureCredentials:async()=>{},operationId:'operation',
  requestSha256:'request',expiresAt:new Date(30*60*1000).toISOString(),now:()=>31*60*1000,wait:async()=>{},maxPolls:2};
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async()=>null}}),/expired before a native Sign/);
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async(_id,phase)=>phase.endsWith(':DISPATCH')?{requestSha256:'request'}:null}}),/OUTCOME_UNKNOWN/);
 const dispatch={operationId:'operation',phase:'ROOT_DROP',requestSha256:'earlier-round'};
 const native={dispatch,response:{Signature:'c2ln'}};
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async(_id,phase)=>({
  'BRIDGE:SIGN:ROOT_DROP:DISPATCH':dispatch,'BRIDGE:SIGN:ROOT_DROP:RESULT':native,
  'BRIDGE:SIGN:ROOT_DROP:COMPLETED':{dispatch,resultSha256:brokerDigest(native)}})[phase]||null}}),/REAUTHORIZATION_REQUIRED/);
});

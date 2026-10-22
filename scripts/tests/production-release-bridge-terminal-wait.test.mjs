import test from 'node:test';
import assert from 'node:assert/strict';
import {waitForTerminalCutover} from '../aws/run-hosted-production-release-bridge.mjs';

test('late native Sign keeps one request observable after its authorization window closes',async()=>{
 let minute=29,checks=0;
 const completion={readinessSha256:'a'.repeat(64)};
 const result=await waitForTerminalCutover({verify:async()=>++checks===3?completion:null,
  ensureCredentials:async()=>{},store:{readOperation:async(_operation,phase)=>phase.endsWith('ROOT_DROP:DISPATCH')?{requestSha256:'request'}:null},
  operationId:'operation',requestSha256:'request',expiresAt:new Date(30*60*1000).toISOString(),now:()=>minute*60*1000,
  wait:async()=>{minute++;},maxPolls:4});
 assert.equal(result,completion);assert.equal(checks,3);assert.ok(minute>30);
});

test('expired request without a Sign and bounded unknown outcome fail closed',async()=>{
 const input={verify:async()=>null,ensureCredentials:async()=>{},operationId:'operation',
  requestSha256:'request',expiresAt:new Date(30*60*1000).toISOString(),now:()=>31*60*1000,wait:async()=>{},maxPolls:2};
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async()=>null}}),/expired before a native Sign/);
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async()=>({requestSha256:'earlier-round'})}}),/expired before a native Sign/);
 await assert.rejects(waitForTerminalCutover({...input,store:{readOperation:async()=>({requestSha256:'request'})}}),/outcome remains unknown/);
});

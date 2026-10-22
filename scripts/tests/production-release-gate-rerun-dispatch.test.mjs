import assert from 'node:assert/strict';
import test from 'node:test';
import {requestNormalGateRerun} from '../aws/run-hosted-production-release-bridge.mjs';

const sourceSha='a'.repeat(40);
const marker={runId:'123',runAttempt:1,sourceSha,releaseTrainRunId:'456'};
const make=()=>{
 const records=new Map();let posts=0;
 const store={
  readOperation:async(id,phase)=>records.get(`${id}:${phase}`)||null,
  claimOperation:async(id,phase,value)=>{
   const key=`${id}:${phase}`;assert.ok(!records.has(key),'duplicate claim');records.set(key,value);return true;
  },
  writeOperation:async(id,phase,value)=>{
   const key=`${id}:${phase}`;assert.ok(!records.has(key),'duplicate result');records.set(key,value);return true;
  },
 };
 const base={store,operationId:'release',...marker,requireMain:async()=>{},token:'test',
  fetchRun:async()=>({id:123,head_sha:sourceSha,path:'.github/workflows/release-gate.yml',
   event:'workflow_dispatch',repository:{full_name:'T-ej2003/genuine-scan-main'},run_attempt:1})};
 return {base,records,fetchStatus:status=>async()=>{posts++;return {status};},postCount:()=>posts};
};

test('definitive rejected rerun is durable and the next invocation can retry exactly once',async()=>{
 const f=make();
 await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:f.fetchStatus(403)}),/rejected.*403/);
 assert.equal(f.postCount(),1);
 assert.equal(await requestNormalGateRerun({...f.base,fetchImpl:f.fetchStatus(201)}),'WAIT');
 assert.equal(f.postCount(),2);
 assert.equal(await requestNormalGateRerun({...f.base,fetchImpl:async()=>assert.fail('completed dispatch replayed')}),'WAIT');
 assert.equal(f.postCount(),2);
});

test('lost rerun response remains ambiguous until GitHub proves the next attempt',async()=>{
 const f=make();
 await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:async()=>{throw Error('network timeout');}}),/network timeout/);
 await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:async()=>assert.fail('ambiguous dispatch replayed')}),/OUTCOME_UNKNOWN/);
 assert.equal(await requestNormalGateRerun({...f.base,fetchRun:async()=>({id:123,head_sha:sourceSha,
  path:'.github/workflows/release-gate.yml',event:'workflow_dispatch',
  repository:{full_name:'T-ej2003/genuine-scan-main'},run_attempt:2}),
  fetchImpl:async()=>assert.fail('observed dispatch replayed')}),'WAIT');
});

test('server error and request timeout cannot authorize a duplicate rerun',async()=>{
 for(const status of [500,408,429]){
  const f=make();
  await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:f.fetchStatus(status)}),/OUTCOME_UNKNOWN/);
  await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:async()=>assert.fail('ambiguous response replayed')}),/OUTCOME_UNKNOWN/);
  assert.equal(f.postCount(),1);
 }
});

test('conflicting ownership and lost result write fail closed',async()=>{
 const f=make();
 await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:f.fetchStatus(403)}),/rejected/);
 await assert.rejects(requestNormalGateRerun({...f.base,sourceSha:'b'.repeat(40),
  fetchImpl:async()=>assert.fail('conflicted dispatch replayed')}),/Conflicting/);
 const g=make();
 await assert.rejects(requestNormalGateRerun({...g.base,fetchImpl:g.fetchStatus(201),
  store:{...g.base.store,writeOperation:async()=>{throw Error('S3 timeout');}}}),/S3 timeout/);
 await assert.rejects(requestNormalGateRerun({...g.base,fetchImpl:async()=>assert.fail('uncommitted result replayed')}),/OUTCOME_UNKNOWN/);
});

test('concurrent recovery does not submit a second rerun',async()=>{
 const f=make();let complete,posts=0;
 const first=requestNormalGateRerun({...f.base,fetchImpl:async()=>{posts++;return new Promise(resolve=>{complete=resolve;});}});
 while(!complete)await new Promise(resolve=>setImmediate(resolve));
 await assert.rejects(requestNormalGateRerun({...f.base,fetchImpl:async()=>assert.fail('duplicate POST')}),/OUTCOME_UNKNOWN/);
 complete({status:201});assert.equal(await first,'WAIT');
 assert.equal(posts,1);
});

test('protected-main drift fails before creating a rerun claim',async()=>{
 const f=make();
 await assert.rejects(requestNormalGateRerun({...f.base,requireMain:async()=>{throw Error('source drift');},
  fetchImpl:async()=>assert.fail('source drift reached POST')}),/source drift/);
 assert.equal(f.records.size,0);
});

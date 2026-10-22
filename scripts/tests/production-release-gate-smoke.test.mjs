import test from 'node:test';
import assert from 'node:assert/strict';
import {runCli,runJournaledSmoke,smokeOperationId} from '../aws/run-production-release-gate-smoke.mjs';

test('strict normal Gate keeps its existing smoke path when only a parent run ID is supplied',async()=>{
 let calls=0;
 await runCli({env:{RELEASE_TRAIN_RUN_ID:'42'},runSmoke:()=>{calls++;return 'healthy';}});
 assert.equal(calls,1);
});

test('smoke receipt loss is recovered by a fresh read-only smoke without an AWS mutation',async()=>{
 const sourceSha='a'.repeat(40),rotationId='rotation-test',releaseTrainRunId='42';
 const operationId=smokeOperationId({sourceSha,rotationId,releaseTrainRunId});
 const intent={operationId,sourceSha,rotationId,releaseTrainRunId,childRunId:'91',runAttempt:'1'};
 const records=new Map();let reads=0,smokes=0;
 const store={readOperation:async(_,phase)=>records.get(phase)||null,
  writeOperation:async(_,phase,value)=>{records.set(phase,value);throw Error('S3 receipt response lost');}};
 const services={backend:{taskDefinition:'backend:1'},frontend:{taskDefinition:'frontend:1'}};
 const input={store,operationId,intent,readServices:async()=>{reads++;return services;},
  smoke:async()=>{smokes++;return 'Verified https://www.mscqr.com returned HTTP 200';},
  now:()=> '2026-10-22T00:00:00.000Z'};
 await assert.rejects(runJournaledSmoke(input),/response lost/);
 assert.equal((await runJournaledSmoke(input)).intent.childRunId,'91');
 assert.equal(smokes,2);assert.ok(reads>=3);
 await assert.rejects(runJournaledSmoke({...input,intent:{...intent,sourceSha:'0'.repeat(40)}}),/identity changed/);
 await assert.rejects(runJournaledSmoke({...input,readServices:async()=>({...services,frontend:{taskDefinition:'attacker:3'}})}),
  /service changed/);
});

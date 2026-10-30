import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { WORKER_COMMITTED as C, WORKER_REFLECTION, committedWorkerExecutionReference, workerReflectionHash as hash } from '../aws/stage-b-worker-policy-reflection.mjs';
import { assertVerifiedWorkerHistory, assertAuthenticatedWorkerReflectionSuccessor } from '../aws/production-green-stage-b-state-reconciliation-evidence.mjs';
import { prepublicationPolicyCorroboratedState } from '../aws/stage-b-staged-broker-executor.mjs';
const r=C.verifiedRecovery,now=new Date('2026-10-30T22:00:00.000Z');
const state=()=>({historicalState:structuredClone(C.predecessorState),currentState:structuredClone(C.successorState)});
for(const phase of ['PREPARATION','REGISTRATION']) test(`${phase} bridges only the authenticated exact worker successor`,async()=>{
  const s=state(),copy=structuredClone(s);let calls=0;
  const actual=await prepublicationPolicyCorroboratedState({...s,phase,predecessorOnly:true,authenticatedBindingTransition:false,authenticateWorkerSuccessor:async()=>{calls++;return true;}});
  assert.deepEqual(actual,s.historicalState);assert.deepEqual(s,copy);assert.equal(calls,1);
  for(const authenticateWorkerSuccessor of [undefined,async()=>false,async()=>{throw Error('unavailable authenticated receipt');}])
    await assert.rejects(()=>prepublicationPolicyCorroboratedState({...s,phase,predecessorOnly:true,authenticateWorkerSuccessor}));
});
test('unrelated states and phases cannot use the worker exception',async()=>{
  for(const change of [s=>s.currentState.serial=150,s=>s.currentState.lineage='other',s=>s.currentState.stateSha256='0'.repeat(64),s=>s.historicalState.serial=147,s=>s.historicalState.stateSha256='0'.repeat(64),s=>s.currentState.extra=true]){
    const s=state();change(s);let calls=0;
    const actual=await prepublicationPolicyCorroboratedState({...s,phase:'PREPARATION',predecessorOnly:true,authenticateWorkerSuccessor:async()=>{calls++;return true;}});
    assert.deepEqual(actual,s.currentState);assert.equal(calls,0);
  }
  for(const options of [{phase:'PUBLICATION',predecessorOnly:true},{phase:'POLICY',predecessorOnly:true},{phase:'PREPARATION',predecessorOnly:false}]){
    const s=state();assert.deepEqual(await prepublicationPolicyCorroboratedState({...s,...options,authenticateWorkerSuccessor:()=>{throw Error('must not authenticate');}}),s.currentState);
  }
});
test('existing authenticated binding-transition and recovery cases retain their original authority',async()=>{
  for(const options of [{phase:'PREPARATION',authenticatedBindingTransition:true},{phase:'REGISTRATION_RECOVERY'},{phase:'ADOPTION'}]){
    const s=state();s.currentState.serial=151;
    assert.deepEqual(await prepublicationPolicyCorroboratedState({...s,...options,predecessorOnly:true}),s.historicalState);
  }
});
function history(){
  const policies=JSON.parse(fs.readFileSync('scripts/tests/fixtures/worker-smtp-policy-reflection.json')).after.map(p=>({name:p.name,policy:typeof p.policy==='string'?JSON.parse(p.policy):p.policy})).sort((a,b)=>a.name.localeCompare(b.name));
  const body={sourceSha:r.sourceSha,observedAt:now.toISOString(),stateIdentity:structuredClone(C.successorState),invariantStateSha256:WORKER_REFLECTION.invariantStateSha256,
    roleStateSha256:'a'.repeat(64),boundImages:Object.fromEntries(['backend','worker','executor','canary','read_only_canary'].map(k=>[k,`368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-${k==='worker'?'worker':'backend'}@sha256:${'b'.repeat(64)}`])),
    sourcePolicySha256:hash(policies.find(p=>p.name===WORKER_REFLECTION.policyName).policy),livePolicies:policies,committedExecution:committedWorkerExecutionReference(r.sourceSha)};
  return {preparationRunId:r.preparationRunId,authorizationRunId:r.authorizationRunId,executionRunId:r.executionRunId,expectedResultArtifactId:r.resultArtifactId,expectedResultArtifactDigest:r.resultArtifactDigest,expectedResultSha256:r.resultByteSha256,now,
    preparation:{sourceSha:r.sourceSha,reconciliationMode:WORKER_REFLECTION.mode,predecessorState:structuredClone(C.successorState),refreshOnlyPlanSha256:r.planSha256,refreshOnlyPlanJsonSha256:r.planJsonSha256},authorization:{authorizationSha256:r.authorizationSha256},
    result:{schemaVersion:3,kind:'PRODUCTION_GREEN_STAGE_B_WORKER_REFLECTION_RESULT',reconciliationMode:WORKER_REFLECTION.mode,status:'recovered-complete',sourceSha:r.sourceSha,authorizationSha256:r.authorizationSha256,
      predecessorState:structuredClone(C.successorState),successorState:structuredClone(C.successorState),successorEvidence:{...body,evidenceSha256:hash(body)},recoveredExecution:committedWorkerExecutionReference(r.sourceSha),remoteResourceMutationCount:0,terraformStateMutationCount:0}};
}
test('the recorded verification-only receipt semantics are accepted but are not self-authenticating',()=>{
  assert.doesNotThrow(()=>assertVerifiedWorkerHistory(history()));
  assert.throws(()=>assertAuthenticatedWorkerReflectionSuccessor({currentProtectedMainSha:r.sourceSha,recovery:r,predecessorState:C.predecessorState,successorState:C.successorState},{sourceSha:r.sourceSha,predecessorState:C.predecessorState,successorState:C.successorState}),/not authenticated/);
});
for(const [name,mutate] of Object.entries({preparation:h=>h.preparationRunId='1',authorization:h=>h.authorizationRunId='1',execution:h=>h.executionRunId=C.executionRunId,artifact:h=>h.expectedResultArtifactId='1',archive:h=>h.expectedResultArtifactDigest='sha256:'+'0'.repeat(64),bytes:h=>h.expectedResultSha256='0'.repeat(64),source:h=>h.preparation.sourceSha='0'.repeat(40),plan:h=>h.preparation.refreshOnlyPlanSha256='0'.repeat(64),planJson:h=>h.preparation.refreshOnlyPlanJsonSha256='0'.repeat(64),approval:h=>h.authorization.authorizationSha256='0'.repeat(64),serial:h=>h.result.successorState.serial=150,predecessor:h=>h.preparation.predecessorState.serial=148,stateWrite:h=>h.result.terraformStateMutationCount=1,remoteWrite:h=>h.result.remoteResourceMutationCount=1,incomplete:h=>h.result.status='state-write-completed-postverify-failed',missing:h=>delete h.result.successorEvidence,forged:h=>h.result.successorEvidence.evidenceSha256='0'.repeat(64),extra:h=>h.result.untrusted=true,expired:h=>h.now=new Date(now.getTime()+1800001),substituted:h=>h.result.recoveredExecution.executionRunId='1'}))
  test(`verified worker completion rejects ${name}`,()=>{const h=history();mutate(h);assert.throws(()=>assertVerifiedWorkerHistory(h));});

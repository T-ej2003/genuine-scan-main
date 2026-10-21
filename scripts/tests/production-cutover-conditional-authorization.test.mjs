import assert from 'node:assert/strict';
import fs from 'node:fs';
import {constants,verify} from 'node:crypto';
import test from 'node:test';
import {conditionalFixture,memoryConditionalStore,h} from './fixtures/conditional-cutover.mjs';
import {assertConditionalDerivation,authenticateConditionalBundle,verifyConditionalKmsEnvelope,parseConditionalJson,assertConditionalProductionEnabled,CONDITIONAL_LANE_ENABLED} from '../aws/production-cutover-conditional-authorization.mjs';
import {createConditionalConsumptionJournal,assertNoConditionalCutoverConflict} from '../aws/production-cutover-consumption-journal.mjs';
import {rehearseConditionalContinuation,runConditionalProductionContinuation} from '../aws/production-cutover-conditional-continuation.mjs';
import {renderConditionalRuntime,assertConditionalRuntimeBytes} from '../aws/production-cutover-runtime-materialization.mjs';
import {authenticateConditionalWorkflowArtifact} from '../aws/production-cutover-conditional-workflow.mjs';
import {canonicalJson} from '../aws/production-green-stage-b-contract.mjs';

test('conditional JSON rejects duplicate, escaped-duplicate, prototype, malformed and unbounded input',()=>{
  for(const bytes of ['{"a":1,"a":2}','{"a":1,"\\u0061":2}','{"__proto__":{}}','{"a":undefined}','{} trailing','[1,]','"unterminated']) assert.throws(()=>parseConditionalJson(bytes));
  assert.throws(()=>parseConditionalJson('{\"n\":1e999}'));
  assert.throws(()=>parseConditionalJson(' '.repeat(1024*1024+1)));
  assert.throws(()=>parseConditionalJson('['.repeat(65)+'0'+']'.repeat(65)));
  assert.deepEqual(parseConditionalJson('{"a":[1,true,null,"x"]}'),{a:[1,true,null,'x']});
});

test('four independently authenticated phase authorities bind exact derivation and real signatures',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const binding=authenticateConditionalBundle({...f,now:f.now()}); assert.equal(binding.derivationSha256,h(f.d));
  for(const phase of ['ROOT_DROP','INVENTORY_ADOPTION','ROTATION_SUCCESSOR']) {
    const tampered=structuredClone(f.envelopes[phase]);tampered.payload.derivationSha256='0'.repeat(64);
    assert.throws(()=>verifyConditionalKmsEnvelope(tampered,{...f,phase,now:f.now()}));
    const substituted=structuredClone(f.envelopes[phase]);substituted.signatureBase64=f.envelopes[phase==='ROOT_DROP'?'INVENTORY_ADOPTION':'ROOT_DROP'].signatureBase64;
    assert.throws(()=>verifyConditionalKmsEnvelope(substituted,{...f,phase,now:f.now()}));
  }
  const forged={...f.workflowArtifact}; assert.throws(()=>authenticateConditionalBundle({...f,workflowArtifact:forged,now:f.now()}),/authentication required/);
  const incomplete={...f.envelopes};delete incomplete.ROTATION_SUCCESSOR;
  assert.throws(()=>authenticateConditionalBundle({...f,envelopes:incomplete,now:f.now()}));
});

test('unknown fields, cross-release reuse, wrong source, key alias policy and mutated predecessor fail closed',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const mutate of [d=>{d.extra=true;},d=>{d.toolingSourceSha='0'.repeat(40);},d=>{d.historicalReleaseSha='0'.repeat(40);},d=>{d.rotationId='rotation-unrelated';},d=>{d.backendImageDigest=`sha256:${'0'.repeat(64)}`;},d=>{d.predecessor.stateSha256='0'.repeat(64);},d=>{d.inventory.completionReceiptSha256='0'.repeat(64);},d=>{d.keys.root.policySha256='0'.repeat(64);}]) {
    const d=structuredClone(f.d);mutate(d);assert.throws(()=>authenticateConditionalBundle({...f,d,now:f.now()}));
  }
  const trust=structuredClone(f.trust);trust.root.publicKeyDerBase64=trust.checker.publicKeyDerBase64;
  assert.throws(()=>authenticateConditionalBundle({...f,trust,now:f.now()}));
  assert.throws(()=>assertConditionalDerivation({...f.d,files:[...f.d.files,...f.d.files]}));
});

test('workflow receipt is authenticated through API metadata, ZIP digest, source and actual independent approval',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  for(const mutate of [()=>{f.run.head_sha='0'.repeat(40);},()=>{f.run.run_attempt=2;},()=>{f.artifact.digest=`sha256:${'0'.repeat(64)}`;},()=>{f.artifact.expired=true;}]) {
    const run={...f.run},artifact={...f.artifact};mutate();
    await assert.rejects(authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',fetchImpl:f.fetchImpl,now:f.now()}));
    Object.assign(f.run,run);Object.assign(f.artifact,artifact);
  }
  await assert.rejects(authenticateConditionalWorkflowArtifact({d:f.d,runId:'101',artifactId:'102',token:'fixture',fetchImpl:async url=>url.endsWith('/approvals')?{ok:true,json:async()=>[]} : f.fetchImpl(url),now:f.now()}),/approval event/);
});

test('mocked historical continuation uses actual QR/root, adoption, successor and readiness consumers without post-root approval',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);t.mock.timers.enable({apis:['Date'],now:f.now()});
  const store=memoryConditionalStore(),journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  const result=await rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now});
  assert.equal(result.readiness.ecsUpdateServiceCount,0);assert.equal(f.prompts(),1);
  assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'COMPLETED_CONFIRMED');
  assert.equal(await journal.status('PREPARE_OVERLAP','REGISTER_TASK_DEFINITION'),'COMPLETED_CONFIRMED');
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}),/claim conflict/);
  await assert.rejects(assertNoConditionalCutoverConflict({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256}),/legacy execution is forbidden/);
  const other=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:'f'.repeat(64)});
  await assert.rejects(other.claimExecution({...authenticateConditionalBundle({...f,now:f.now()})}),/authenticated phase authorities/);
});

test('runtime byte substitution and immutable file drift are rejected',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const rootBytes=await f.adapters.root({nativeSign:async(request,invoke)=>invoke()});
  const input={d:f.d,rootBytes,qr:f.qr,taskDefinition:f.taskDefinition,secretMetadata:f.metadata,now:f.now(),verifyRootSignature:f.verifyBytes};
  const result=renderConditionalRuntime(input);
  assert.throws(()=>assertConditionalRuntimeBytes(Buffer.from('{}'),result.bytes));
  assert.throws(()=>renderConditionalRuntime({...input,secretMetadata:{...f.metadata,VersionIdsToStages:{other:['AWSCURRENT']}}}));
  fs.writeFileSync(f.d.files[0].path,'changed');assert.throws(()=>renderConditionalRuntime(input),/Immutable file changed/);
});

test('root and QR TTL checks remain effective, including expiry during work and pre-dispatch TOCTOU',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const rootBytes=await f.adapters.root({nativeSign:async(request,invoke)=>invoke()});
  const input={d:f.d,rootBytes,qr:f.qr,taskDefinition:f.taskDefinition,secretMetadata:f.metadata,now:f.now(),verifyRootSignature:f.verifyBytes};
  assert.throws(()=>renderConditionalRuntime({...input,now:f.now()+900001}),/stale/);
  const store=memoryConditionalStore(),journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  const original=f.adapters.observe; let checks=0;
  f.adapters.observe=async()=>{const value=await original();if(++checks===4)value.broker.version='22';return value;};
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}),/Live broker differs/);
  assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'NOT_DISPATCHED');
  f.advance(1_800_000);assert.throws(()=>authenticateConditionalBundle({...f,now:f.now()}),/window/);
});

test('lost KMS response burns native attempt and never generates a replacement signature',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);let calls=0;
  const store=memoryConditionalStore(),journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  const root=f.adapters.root;
  f.adapters.root=async({nativeSign})=>root({nativeSign:(request)=>nativeSign(request,()=>{calls++;throw new Error('response lost');})});
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}),/outcome unknown/);
  assert.equal(calls,1);assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'OUTCOME_UNKNOWN');
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}));assert.equal(calls,1);
});

test('confirmed claim required: lost claim response and racing executors cannot dispatch',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const binding=authenticateConditionalBundle({...f,now:f.now()});
  const store=memoryConditionalStore(),options={store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256};
  const first=createConditionalConsumptionJournal(options),second=createConditionalConsumptionJournal(options);
  const results=await Promise.allSettled([first.claimExecution(binding),second.claimExecution(binding)]);
  assert.equal(results.filter(result=>result.status==='fulfilled').length,1);
  const lost=memoryConditionalStore(),claim=lost.claimOperation;lost.claimOperation=(...args)=>{claim(...args);throw new Error('lost claim response');};
  const uncertain=createConditionalConsumptionJournal({...options,store:lost});
  await assert.rejects(uncertain.claimExecution(binding),/lost claim response/);
  await assert.rejects(uncertain.claimPhase({},'ROOT_DROP',{}),/ownership/);
});

test('failed result persistence and invalid signature cannot be marked completed',async t=>{
  const f=await conditionalFixture();t.after(f.cleanup);
  const store=memoryConditionalStore(),write=store.writeOperation;
  store.writeOperation=(id,name,value)=>{if(name.includes('RESULT:KMS_SIGN'))throw new Error('storage failed');return write(id,name,value);};
  const journal=createConditionalConsumptionJournal({store,rotationId:f.d.rotationId,predecessorStateSha256:f.d.predecessor.stateSha256});
  await assert.rejects(rehearseConditionalContinuation({...f,journal,now:f.now,monotonic:f.now}),/outcome unknown/);
  assert.equal(await journal.status('ROOT_DROP','KMS_SIGN'),'OUTCOME_UNKNOWN');
});

test('production remains disabled despite env switches and injected executable adapters',async()=>{
  assert.equal(CONDITIONAL_LANE_ENABLED,false);
  process.env.MSCQR_CONDITIONAL_LANE_ENABLED='true';
  try {assert.throws(assertConditionalProductionEnabled,/disabled/);await assert.rejects(runConditionalProductionContinuation({adapters:{}}),/disabled/);}finally{delete process.env.MSCQR_CONDITIONAL_LANE_ENABLED;}
});

test('strict JSON preserves ordinary text and rejects lossy integers or malformed Unicode',()=>{
 assert.deepEqual(parseConditionalJson('{"label":"undefined is ordinary text"}'),{label:'undefined is ordinary text'});
 assert.throws(()=>parseConditionalJson('{"number":9007199254740993}'),/unsafe/);
 assert.throws(()=>parseConditionalJson('"\\ud800"'),/Unicode/);
 assert.equal(parseConditionalJson('"\\ud83d\\ude80"'),'🚀');
});

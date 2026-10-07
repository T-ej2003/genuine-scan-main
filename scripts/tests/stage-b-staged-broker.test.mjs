import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { canonicalBrokerPolicy, resolvedBrokerEnvironment } from './fixtures/staged-broker.mjs';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from '../aws/production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_FUNCTION, BROKER_ALIAS, brokerDigest, brokerTargetIdentity,
 assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan, assertBrokerAuthorization,
 assertBrokerPreparation, assertTerminalPolicyHandoff, createTerminalPolicySuccessorAdoption, assertTerminalPolicySuccessorState,
 } from '../aws/stage-b-staged-broker-contract.mjs';
import { executeBrokerPublication as publish, prepareBrokerCutover, executeBrokerAliasCas as cutover, reconcileBrokerAlias as reconcile, brokerTransitionRequired } from '../aws/stage-b-staged-broker.mjs';
import { BROKER_POLICY_CONVERGENCE, TASK_REGISTRATION, deriveBrokerPolicy } from '../aws/stage-b-release-prerequisites.mjs';
const phaseInput = r => Object.hasOwn(r, 'p') ? { ...r, preparation: r.p, authorization: r.auth } : r;
const executeBrokerPublication = (r, d) => publish(phaseInput(r), d);
const executeBrokerAliasCas = (r, d) => cutover(phaseInput(r), d);
const reconcileBrokerAlias = (r, d) => reconcile(phaseInput(r), d);
const clone = structuredClone;
import { rig, ready, configuration, preparation, authorization, cutoverPlan, publicationPlan, envelope, change, tfFn, tfAlias, alias, state, env, prerequisites, sourceSha, oldSha, packageSha256, now, target } from './fixtures/staged-broker-runtime.mjs';

function terminalPolicyFixture() {
 const treeSha256='9'.repeat(64), historicalState={...state,serial:117,stateSha256:'d'.repeat(64)}, release={sourceSha,treeSha256};
 const registrationPreparation={purpose:TASK_REGISTRATION,sourceSha:oldSha,treeSha256:'8'.repeat(64)}, registrationAuthorization={schemaVersion:1};
 const historicalRegistration={preparation:registrationPreparation,authorization:registrationAuthorization,result:{sourceSha:oldSha,treeSha256:registrationPreparation.treeSha256,
   preparationSha256:brokerDigest(registrationPreparation),authorizationSha256:brokerDigest(registrationAuthorization),taskMap:clone(prerequisites.taskMap),definitions:{}}};
 const p=preparation(); p.schemaVersion=2;p.purpose=BROKER_POLICY_CONVERGENCE;p.sourceSha=oldSha;p.treeSha256='7'.repeat(64);p.state={...state,serial:110};p.publication=null;
 p.prerequisites={...clone(prerequisites),policyVersion:'v12'};p.target={policy:deriveBrokerPolicy(p.prerequisites.policy,historicalRegistration.result.taskMap)};
 p.prerequisiteChain={registration:historicalRegistration};
 const auth=authorization(p);auth.purpose=p.purpose;auth.sourceSha=oldSha;auth.preparationSha256=brokerDigest(p);
 const result={status:'BROKER_POLICY_CONVERGED_NONTERMINAL',sourceSha:oldSha,treeSha256:p.treeSha256,preparationSha256:brokerDigest(p),authorizationSha256:brokerDigest(auth),savedPlanSha256:p.savedPlanSha256,policy:clone(p.target.policy),authorizedAt:now.toISOString()};
 const owner={policyArn:prerequisites.policyArn,operationIdentity:brokerDigest(auth),sourceSha:oldSha,owner:'owner-1',generation:1};
 const terminal={...clone(result),owner,successorIdentity:{policyVersion:'v13'}};
 const inventory=[{VersionId:'v13',IsDefaultVersion:true}];
 const entry=createTerminalPolicySuccessorAdoption({preparation:p,authorization:auth,result,terminal},release,historicalState,inventory);
 const ownership={identity:owner,status:'RELEASED',terminal:{outcome:'SUCCEEDED',receiptSha256:brokerDigest(terminal)},mutation:{intentSha256:'e'.repeat(64)}};
 const live={policyArn:prerequisites.policyArn,version:'v13',policy:clone(terminal.policy),versions:inventory};
 return {entry,release,state:historicalState,ownership,live};
}
function publicationWithTerminalPolicyAdoption(f=terminalPolicyFixture()) {
 const currentRegistrationPreparation={purpose:TASK_REGISTRATION,sourceSha,treeSha256:f.release.treeSha256};
 const currentRegistrationAuthorization={schemaVersion:1};
 const currentRegistration={preparation:currentRegistrationPreparation,authorization:currentRegistrationAuthorization,result:{sourceSha,treeSha256:f.release.treeSha256,
  preparationSha256:brokerDigest(currentRegistrationPreparation),authorizationSha256:brokerDigest(currentRegistrationAuthorization),taskMap:clone(prerequisites.taskMap),definitions:{}}};
 const p=preparation();p.schemaVersion=2;p.sourceSha=sourceSha;p.treeSha256=f.release.treeSha256;p.state=clone(f.state);
 p.prerequisites={...clone(prerequisites),policyVersion:'v13',policy:clone(f.entry.terminal.policy)};
 p.prerequisiteChain={registration:currentRegistration,policy:f.entry};
 return p;
}

test('terminal policy successor adoption preserves historical provenance and binds exact current release/state',()=>{
 const f=terminalPolicyFixture();assertTerminalPolicyHandoff(f.entry,f.release);
 assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy:f.entry.terminal.policy}});
 const sameSource=clone(f.entry);sameSource.adoption=undefined;
 assertTerminalPolicyHandoff(sameSource,{sourceSha:oldSha,treeSha256:sameSource.preparation.treeSha256});
 const p=publicationWithTerminalPolicyAdoption(f);assertBrokerPreparation(p);
 assertBrokerPublicationPlan(publicationPlan(),p);
});

for(const [name,mutate] of [
 ['historical preparation source',f=>f.entry.preparation.sourceSha=sourceSha],
 ['adoption consumer source',f=>f.entry.adoption.consumerSourceSha=oldSha],
 ['authorization binding',f=>f.entry.authorization.signature.signatureBase64='dGFtcGVy'],
 ['terminal receipt',f=>f.entry.terminal.policy.Statement[0].Effect='Deny'],
 ['successor version',f=>f.entry.adoption.successorVersion='v12'],
 ['successor document hash',f=>f.entry.adoption.successorDocumentSha256='0'.repeat(64)],
 ['successor inventory',f=>f.entry.adoption.successorInventory[0].IsDefaultVersion=false],
 ['caller-selected historical source',f=>f.entry.adoption.historicalSourceSha='c'.repeat(40)],
 ['unsupported pruning purpose',f=>{f.entry.preparation.purpose='STAGE_B_BROKER_POLICY_PRUNING';f.entry.authorization.purpose=f.entry.preparation.purpose;}],
 ['transaction replayability',f=>f.entry.adoption.transactionReplayable=true],
]) test(`terminal policy adoption rejects tampered ${name}`,()=>{
 const f=terminalPolicyFixture();mutate(f);assert.throws(()=>assertTerminalPolicyHandoff(f.entry,f.release));
});

for(const [name,mutate] of [
 ['wrong live policy version',f=>f.live.version='v12'],
 ['wrong live policy document',f=>f.live.policy.Statement[0].Effect='Deny'],
 ['wrong Terraform serial',f=>f.state.serial++],
 ['wrong Terraform state hash',f=>f.state.stateSha256='0'.repeat(64)],
 ['held ownership',f=>f.ownership.status='HELD'],
 ['nonterminal transaction',f=>f.ownership.terminal.outcome='RECOVERED_NO_WRITE'],
]) test(`terminal policy adoption rejects ${name}`,()=>{
 const f=terminalPolicyFixture();mutate(f);assert.throws(()=>assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy:f.entry.terminal.policy}}));
});
test('terminal policy adoption rejects a mismatched Terraform policy document',()=>{
 const f=terminalPolicyFixture(),policy=clone(f.entry.terminal.policy);policy.Statement[0].Effect='Deny';
 assert.throws(()=>assertTerminalPolicySuccessorState(f.entry,f.release,{ownership:f.ownership,live:f.live,terraform:{...f.state,policyArn:prerequisites.policyArn,policy}}));
});

test('terminal policy adoption is not reusable by a later release SHA',()=>{
 const f=terminalPolicyFixture();assert.throws(()=>assertTerminalPolicyHandoff(f.entry,{sourceSha:'f'.repeat(40),treeSha256:f.release.treeSha256}));
});
test('four phases preserve alias before independent cutover and stop short of release CAS', async () => {
 const r = await ready(); assert.deepEqual(r.calls, ['publish']); assert.deepEqual(await r.deps.getAlias(), alias);
 const casResult = await executeBrokerAliasCas(r, r.deps); assert.equal(r.calls[1].RevisionId, alias.RevisionId); assert.equal(r.calls[1].FunctionVersion, '13');
 const record = await reconcileBrokerAlias({ ...r, casResult }, r.deps); assert.equal(record.status, 'RECONCILED_PENDING_RELEASE_CAS'); assert.deepEqual(record.mutationAddresses.sort(), [BROKER_ALIAS, BROKER_FUNCTION].sort());
 assert.equal(r.calls.at(-1), 'refresh-only');
});
for (const [name, mutate] of [
 ['alias action', p => p.resource_changes.push(change(BROKER_ALIAS, tfAlias, { ...tfAlias, function_version: '13' }, ['update']))],
 ['IAM action', p => p.resource_changes.push(change('aws_iam_policy.broker', {}, {}, ['update']))],
 ['unknown mutation', p => p.resource_changes.push(change('aws_lambda_function.other', {}, {}, ['create']))],
 ['role drift', p => p.resource_changes[0].change.after.role = 'bad'],
 ['task map drift', p => p.resource_changes[0].change.after.environment[0].variables.BROKER_TASK_DEFINITIONS_JSON = '{}'],
 ['code drift', p => p.resource_changes[0].change.after.source_code_hash = 'bad'],
 ['timeout drift', p => { p.resource_changes[0].change.before.timeout = 30; }],
 ['duplicate function', p => p.resource_changes.push(clone(p.resource_changes[0]))],
 ['wrong source', p => p.variables.tooling_sha.value = oldSha],
 ['unrelated config', p => p.resource_changes[0].change.after.environment[0].variables.UNRELATED = 'new'],
]) test(`publication rejects ${name}`, () => { const plan = publicationPlan(); mutate(plan); assert.throws(() => assertBrokerPublicationPlan(plan, preparation())); });
for (const [name, mutate] of [
 ['missing authorization', r => r.auth = null], ['expired authorization', r => r.auth.expiresAt = now.toISOString()],
 ['different plan', r => r.p.savedPlanSha256 = '0'.repeat(64)], ['different phase', r => r.auth.purpose = BROKER_CUTOVER],
 ['unsigned authorization', r => r.deps.verifyAuthorization = async () => false],
 ['policy drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), policy: {} })],
 ['role drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), role: { Arn: 'wrong' } })],
 ['task map drift', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), taskMap: {} })],
 ['traffic unknown', r => r.deps.readPrerequisites = async () => ({ ...clone(prerequisites), traffic: {} })],
 ['state drift', r => r.deps.readStateIdentity = async () => ({ ...state, serial: 999 })],
 ['checkout drift', r => r.deps.readCheckout = async () => ({ sourceSha: oldSha, treeSha256: r.p.treeSha256 })],
]) test(`publication blocks ${name} before mutation`, async () => { const r = rig(); mutate(r); await assert.rejects(() => executeBrokerPublication(r, r.deps)); assert.deepEqual(r.calls, []); });
for (const [name, mutate] of [
 ['predecessor version', a => a.FunctionVersion = '99'], ['predecessor revision', a => a.RevisionId = 'concurrent'], ['routing', a => a.RoutingConfig.AdditionalVersionWeights['99'] = .5], ['wrong alias', a => a.Name = 'other'],
]) test(`cutover blocks changed ${name}`, async () => { const r = await ready(), a = clone(alias); mutate(a); r.setAlias(a); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(r.calls.length, 1); });
for (const name of ['PreconditionFailedException', 'TimeoutError']) test(`${name} consumes approval, records diagnosis and never retries`, async () => {
 const r = await ready(); let count = 0; r.deps.updateAlias = async () => { count++; throw Object.assign(new Error(name), { name }); };
 await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(count, 1);
 assert.ok(r.entries.some(e => e[1] === (name === 'TimeoutError' ? 'CUTOVER_UNKNOWN' : 'CUTOVER_CONFLICT')));
});
test('publication authorization replay fails', async () => { const r = rig(); await executeBrokerPublication(r, r.deps); r.deps.readStateIdentity = async () => state; await assert.rejects(() => executeBrokerPublication(r, r.deps)); assert.equal(r.calls.length, 1); });
test('cutover approval replay fails', async () => { const r = await ready(); await executeBrokerAliasCas(r, r.deps); await assert.rejects(() => executeBrokerAliasCas(r, r.deps)); assert.equal(r.calls.length, 2); });
for (const [name, mutate] of [
 ['absent approval', r => r.auth = null],
 ['expired approval', r => r.auth.expiresAt = now.toISOString()],
 ['publication authority', r => r.auth.purpose = BROKER_PUBLICATION],
 ['unverified signature', r => r.deps.verifyAuthorization = async () => false],
 ['different approved target', r => r.p.target.version = '99'],
 ['different approved predecessor', r => r.p.alias.RevisionId = 'substituted'],
 ['missing publication result', r => r.p.publication = null],
]) test(`cutover rejects ${name} before alias mutation`, async () => {
 const r = await ready(); mutate(r);
 await assert.rejects(() => executeBrokerAliasCas(r, r.deps));
 assert.deepEqual(r.calls, ['publish']);
});
test('latest orphan cannot substitute for publication result', async () => { const r = rig(); r.deps.getVersion = async () => configuration('99'); await assert.rejects(async () => { const pub = await executeBrokerPublication(r, r.deps); assert.equal(pub.target.version, '13'); }); });
for (const [name, mutate] of [ ['code', c => c.CodeSha256 = 'x'], ['configuration', c => c.Environment.Variables.UNRELATED = 'x'], ['runtime', c => c.RuntimeVersionConfig = {}], ['unready', c => c.LastUpdateStatus = 'InProgress'] ]) test(`published target ${name} mismatch blocks`, async () => { const r = rig(); r.deps.getVersion = async () => { const c = configuration(); mutate(c); return c; }; await assert.rejects(() => executeBrokerPublication(r, r.deps)); });
for (const [name, mutate] of [ ['missing alias', p => p.resource_changes.pop()], ['extra mutation', p => p.resource_changes.push(change('aws_iam_policy.broker', {}, {}, ['update']))], ['wrong target', p => p.resource_changes[1].change.after.function_version = '99'], ['function mutation', p => p.resource_changes[0].change.actions = ['update']], ['unknown no-op', p => p.resource_changes.push(change('aws_lambda_alias.other', {}, {}))] ]) test(`cutover plan rejects ${name}`, async () => { const r = await ready(), p = cutoverPlan(); mutate(p); assert.throws(() => assertBrokerCutoverPlan(p, r.p)); });
for (const [name, mutate] of [ ['remote mutation', p => p.resource_changes.push(change(BROKER_ALIAS, tfAlias, tfAlias, ['update']))], ['wrong target', p => p.resource_drift[0].change.after.function_version = '99'], ['extra drift', p => p.resource_drift.push(clone(p.resource_drift[0]))], ['wrong identity', p => { p.resource_drift[0].change.before.arn = 'wrong'; p.resource_drift[0].change.after.arn = 'wrong'; }], ['output drift', p => p.output_changes = { unknown: { actions: ['update'] } }] ]) test(`refresh rejects ${name}`, async () => { const r = await ready(); const p = (await r.deps.captureRefreshOnlyPlan()).plan; mutate(p); assert.throws(() => assertBrokerRefreshPlan(p, r.p, { ...alias, FunctionVersion: '13', RevisionId: 'after' })); });
test('normal post-reconciliation alias action blocks closure', async () => { const r = await ready(); assert.throws(() => assertBrokerClosurePlan(cutoverPlan(), r.p)); });
test('new publication blocks reconciliation rather than selecting latest', async () => { const r = await ready(); const casResult = await executeBrokerAliasCas(r, r.deps); r.deps.readTerraformFunctionVersion = async () => '99'; await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps)); assert.ok(!r.calls.includes('refresh-only')); });
test('app-only unchanged broker skips staged work', () => assert.equal(brokerTransitionRequired({ desiredConfiguration: env, liveConfiguration: clone(env) }), false));
test('parallel CAS has exactly one winner', async () => { const r = await ready(); const outcomes = await Promise.allSettled([executeBrokerAliasCas(r, r.deps), executeBrokerAliasCas(r, r.deps)]); assert.equal(outcomes.filter(x => x.status === 'fulfilled').length, 1); assert.equal(r.calls.filter(x => typeof x === 'object').length, 1); });
test('uncertain state-only reconciliation cannot reuse approval with a different binary', async () => {
 const r = await ready(), casResult = await executeBrokerAliasCas(r, r.deps); let writes=0;
 r.deps.applyRefreshOnlyPlan = async () => { writes++; throw new Error('Uncertain state write'); };
 await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps));
 const capture = r.deps.captureRefreshOnlyPlan; r.deps.captureRefreshOnlyPlan = async () => ({ ...(await capture()), bytes: Buffer.from('different-refresh-binary') });
 await assert.rejects(() => reconcileBrokerAlias({ ...r, casResult }, r.deps)); assert.equal(writes,1);
});

import { signBrokerAuthorization } from '../aws/stage-b-staged-broker-authorization.mjs';
for (const purpose of ['publication', 'cutover']) test(`${purpose} signing authenticates the maker before KMS Sign`, async () => {
  const r = purpose === 'cutover' ? await ready() : { p: preparation() };
  const maker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/authenticated-maker';
  const checker = 'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/authenticated-checker';
  let signs = 0, makerReads = 0;
  const options = { makerIdentity: maker, humanReviewId: 'review-123', makerCaller: async () => { makerReads++; return { Account: '368992683803', Arn: maker }; }, caller: async () => ({ Arn: checker }), sign: async () => { signs++; return 'c2ln'; }, verify: async () => true, now };
  for (const mutate of [
    x => x.makerIdentity = maker.replace('authenticated-maker', 'invented-maker'),
    x => delete x.makerCaller,
    x => x.makerCaller = async () => ({ Account: 'other', Arn: maker }),
    x => x.makerCaller = async () => ({ Account: '368992683803', Arn: checker }),
  ]) { const bad = { ...options }; mutate(bad); await assert.rejects(() => signBrokerAuthorization(r.p, bad)); }
  assert.equal(signs, 0);
  const signed = await signBrokerAuthorization(r.p, options);
  assert.equal(signed.review.makerIdentity, maker); assert.equal(signs, 1); assert.ok(makerReads >= 2);
});

import { recoverBrokerPublication, recoverBrokerAliasCas, recoverBrokerReconciliation } from '../aws/stage-b-staged-broker.mjs';
import { authenticateBrokerAliasCasEvent } from '../aws/stage-b-broker-writer-session.mjs';
function recoveryReaders(r) {
  r.deps.authenticateRecoveryIntent = async (status, expected) => {
    const entry = r.entries.find(e => e[1] === status); assert.ok(entry);
    const { authorizedAt, ...fields } = entry[2]; assert.deepEqual(fields, expected);
    const id = await assertBrokerAuthorization(r.auth, r.p, { verify: r.deps.verifyAuthorization, now: new Date(authorizedAt) });
    assert.equal(id, entry[0]); return { id, authorizedAt };
  };
  r.deps.readRecoveryReceipt = async (id, status) => r.entries.find(e => e[0] === id && e[1] === status)?.[2] || null;
  r.deps.readRecoveryStateIntent = async () => r.entries.find(e => e[1] === 'STATE_REFRESH_INTENT')?.[2];
}
function receiptCrash(r, status) {
  const original = r.deps.record; let failed=false;
  r.deps.record = async (...args) => { if(args[1] === status && !failed){failed=true;throw Error('external commit before durable receipt');} return original(...args); };
}
async function publicationRecovery() {
  const r=rig();receiptCrash(r,'PUBLISHED');await assert.rejects(()=>executeBrokerPublication(r,r.deps));recoveryReaders(r);
  r.deps.authenticatePublicationRecoveryState=async plan=>assert.deepEqual(plan,publicationPlan());
  return {...r,recover:()=>recoverBrokerPublication({preparation:r.p,authorization:r.auth},r.deps)};
}
function casEvent(r, observed) {
  return {eventID:'a1111111-1111-4111-8111-111111111111',eventTime:now.toISOString(),eventSource:'lambda.amazonaws.com',eventName:'UpdateAlias20150331',awsRegion:'eu-west-2',recipientAccountId:STAGE_B.account,
    userAgent:`aws-cli/2 exec-env/mscqr-broker-cutover-${brokerDigest(r.auth)}`,
    userIdentity:{sessionContext:{sessionIssuer:{arn:'arn:aws:iam::368992683803:role/mscqr-production-release-deployer'}}},
    requestParameters:{functionName:STAGE_B.brokerFunctionArn,name:r.p.alias.Name,functionVersion:r.p.target.version,revisionId:r.p.alias.RevisionId,description:r.p.alias.Description,routingConfig:{additionalVersionWeights:{}}},
    responseElements:{aliasArn:observed.AliasArn,name:observed.Name,functionVersion:observed.FunctionVersion,revisionId:observed.RevisionId,description:observed.Description,routingConfig:{additionalVersionWeights:{}}}};
}
async function casRecovery() {
  const r=await ready();receiptCrash(r,'CUTOVER_COMMITTED_STATE_PENDING');await assert.rejects(()=>executeBrokerAliasCas(r,r.deps));recoveryReaders(r);
  const events=[casEvent(r,await r.deps.getAlias())];r.deps.authenticateAliasCasRecovery=async value=>authenticateBrokerAliasCasEvent(events,value);
  return {...r,events,recover:()=>recoverBrokerAliasCas({preparation:r.p,authorization:r.auth},r.deps)};
}
async function reconciliationRecovery(status='RECONCILED_PENDING_RELEASE_CAS') {
  const r=await ready(),casResult=await executeBrokerAliasCas(r,r.deps);receiptCrash(r,status);
  if(status==='HANDOFF'){let failed=false; r.deps.publishTerminalHandoff=async()=>{if(!failed){failed=true;throw Error('handoff absent');}};}
  await assert.rejects(()=>reconcileBrokerAlias({...r,casResult},r.deps));recoveryReaders(r);
  return {...r,casResult,recover:()=>recoverBrokerReconciliation({preparation:r.p,authorization:r.auth,casResult},r.deps)};
}
for(const [phase,fixture] of [['publication',publicationRecovery],['alias CAS',casRecovery],['refresh reconciliation',reconciliationRecovery]]) {
  test(`${phase} recovers post-commit missing receipt read-only and remains idempotent`,async()=>{
    const r=await fixture(),calls=structuredClone(r.calls);r.deps.now=()=>new Date(now.getTime()+3600000);
    const result=await r.recover();assert.ok(result);assert.deepEqual(r.calls,calls);assert.deepEqual(await r.recover(),result);assert.deepEqual(r.calls,calls);
  });
  for(const [name,mutate] of [
    ['wrong source',r=>r.deps.readCheckout=async()=>({sourceSha:'f'.repeat(40),treeSha256:r.p.treeSha256})],
    ['wrong target code',r=>r.deps.getVersion=async v=>({...configuration(v),CodeSha256:'bad'})],
    ['role/policy drift',r=>r.deps.readPrerequisites=async()=>({...prerequisites,policy:{}})],
  ]) test(`${phase} recovery rejects ${name} without replay`,async()=>{const r=await fixture(),calls=structuredClone(r.calls);mutate(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);});
}
test('publication recovery rejects wrong persisted Terraform identity',async()=>{const r=await publicationRecovery();r.deps.authenticatePublicationRecoveryState=async()=>{throw Error('unexpected state');};await assert.rejects(r.recover);assert.deepEqual(r.calls,['publish']);});
test('publication recovery rejects unchanged predecessor or unrelated state version',async()=>{for(const version of ['12','99']){const r=await publicationRecovery();r.deps.readPublicationResult=async()=>({version,savedPlanSha256:r.p.savedPlanSha256,authorizationSha256:brokerDigest(r.auth)});if(version==='99')r.deps.getVersion=async()=>configuration('13');await assert.rejects(r.recover);assert.deepEqual(r.calls,['publish']);}});
for(const [name,mutate] of [
 ['wrong operation marker',r=>r.events[0].userAgent='aws-cli/2 exec-env/mscqr-broker-cutover-'+ 'f'.repeat(64)],['missing operation marker',r=>delete r.events[0].userAgent],
 ['missing event',r=>r.events.length=0],['ambiguous duplicate events',r=>r.events.push(structuredClone(r.events[0]))],
 ['omitted RevisionId',r=>delete r.events[0].requestParameters.revisionId],['wrong RevisionId',r=>r.events[0].requestParameters.revisionId='wrong'],
 ['wrong target',r=>r.events[0].requestParameters.functionVersion='99'],['AWS failure',r=>r.events[0].errorCode='PreconditionFailedException'],
 ['wrong actor',r=>r.events[0].userIdentity.sessionContext.sessionIssuer.arn+='-wrong'],['wrong response',r=>r.events[0].responseElements.revisionId='wrong'],
 ['unavailable AWS response',r=>r.events[0].responseElements=null],['wrong region',r=>r.events[0].awsRegion='eu-west-1'],
 ['event after approval expiry',r=>r.events[0].eventTime=r.auth.expiresAt],
]) test(`alias recovery rejects ${name}; never calls UpdateAlias again`,async()=>{const r=await casRecovery(),calls=structuredClone(r.calls);mutate(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);});
test('reconciliation recovery resumes missing handoff without another refresh apply',async()=>{const r=await reconciliationRecovery('HANDOFF');const calls=structuredClone(r.calls);await r.recover();assert.deepEqual(r.calls,calls);});
test('reconciliation recovery rejects state/live drift and normal-plan alias mutation',async()=>{
 for(const modify of [r=>r.deps.authenticateTerraformState=async()=>{throw Error('wrong state');},r=>r.deps.captureNormalPlan=async()=>({bytes:Buffer.from('wrong'),plan:cutoverPlan()})]){const r=await reconciliationRecovery(),calls=structuredClone(r.calls);modify(r);await assert.rejects(r.recover);assert.deepEqual(r.calls,calls);}
});
for (const [phase, fixture, status] of [['publication',publicationRecovery,'PUBLISHED'],['alias CAS',casRecovery,'CUTOVER_COMMITTED_STATE_PENDING'],['reconciliation',reconciliationRecovery,'RECONCILED_PENDING_RELEASE_CAS']]) {
 test(`${phase} receipt write commits then response is lost: recovery authenticates persisted result once`,async()=>{
  const r=await fixture(),record=r.deps.record;let lost=false;
  r.deps.record=async(...args)=>{await record(...args);if(args[1]===status&&!lost){lost=true;throw Error('receipt response lost');}};
  const calls=structuredClone(r.calls);await assert.rejects(r.recover);const result=await r.recover();assert.ok(result);
  assert.equal(r.entries.filter(e=>e[1]===status).length,1);assert.deepEqual(r.calls,calls);
 });
 test(`${phase} concurrent read-only recoveries cannot substitute or duplicate the immutable receipt`,async()=>{
  const r=await fixture(),record=r.deps.record;r.deps.record=async(...args)=>{assert.ok(!r.entries.some(e=>e[0]===args[0]&&e[1]===args[1]),'conditional occupied');await record(...args);};
  const calls=structuredClone(r.calls),results=await Promise.allSettled([r.recover(),r.recover()]);
  assert.ok(results.some(v=>v.status==='fulfilled'));assert.equal(r.entries.filter(e=>e[1]===status).length,1);await r.recover();assert.deepEqual(r.calls,calls);
 });
}
test('native alias success with uncertain API response recovers from authenticated CAS event, not another mutation',async()=>{
 const r=await ready(),update=r.deps.updateAlias;r.deps.updateAlias=async input=>{await update(input);throw Error('lost AWS response');};
 await assert.rejects(()=>executeBrokerAliasCas(r,r.deps));recoveryReaders(r);
 const events=[casEvent(r,await r.deps.getAlias())];r.deps.authenticateAliasCasRecovery=value=>authenticateBrokerAliasCasEvent(events,value);
 const before=structuredClone(r.calls);await recoverBrokerAliasCas({preparation:r.p,authorization:r.auth},r.deps);assert.deepEqual(r.calls,before);
});
test('refresh-only apply commits then throws: recovery only reads and persists exact state closure',async()=>{
 const r=await ready(),casResult=await executeBrokerAliasCas(r,r.deps),apply=r.deps.applyRefreshOnlyPlan;
 r.deps.applyRefreshOnlyPlan=async bytes=>{await apply(bytes);throw Error('state commit response lost');};
 await assert.rejects(()=>reconcileBrokerAlias({...r,casResult},r.deps));recoveryReaders(r);
 const before=structuredClone(r.calls);await recoverBrokerReconciliation({preparation:r.p,authorization:r.auth,casResult},r.deps);assert.deepEqual(r.calls,before);
});

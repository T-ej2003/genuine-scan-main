import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { canonicalBrokerPolicy, resolvedBrokerEnvironment } from './fixtures/staged-broker.mjs';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from '../aws/production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_FUNCTION, BROKER_ALIAS, brokerDigest, brokerTargetIdentity,
 assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan, assertBrokerAuthorization,
 } from '../aws/stage-b-staged-broker-contract.mjs';
import { executeBrokerPublication as publish, prepareBrokerCutover, executeBrokerAliasCas as cutover, reconcileBrokerAlias as reconcile, brokerTransitionRequired } from '../aws/stage-b-staged-broker.mjs';
const phaseInput = r => Object.hasOwn(r, 'p') ? { ...r, preparation: r.p, authorization: r.auth } : r;
const executeBrokerPublication = (r, d) => publish(phaseInput(r), d);
const executeBrokerAliasCas = (r, d) => cutover(phaseInput(r), d);
const reconcileBrokerAlias = (r, d) => reconcile(phaseInput(r), d);
const clone = structuredClone;
import { rig, ready, configuration, preparation, authorization, cutoverPlan, publicationPlan, envelope, change, tfFn, tfAlias, alias, state, env, prerequisites, sourceSha, oldSha, packageSha256, now, target } from './fixtures/staged-broker-runtime.mjs';
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

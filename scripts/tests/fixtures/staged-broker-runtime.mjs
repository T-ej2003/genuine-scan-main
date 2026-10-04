import assert from 'node:assert/strict';
import fs from 'node:fs';
import { canonicalBrokerPolicy, resolvedBrokerEnvironment } from './staged-broker.mjs';
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, canonicalJson } from '../../aws/production-green-stage-b-contract.mjs';
import { BROKER_PUBLICATION, BROKER_CUTOVER, BROKER_FUNCTION, BROKER_ALIAS, brokerDigest, brokerTargetIdentity,
 assertBrokerPublicationPlan, assertBrokerCutoverPlan, assertBrokerRefreshPlan, assertBrokerClosurePlan, assertBrokerAuthorization,
 } from '../../aws/stage-b-staged-broker-contract.mjs';
import { executeBrokerPublication as publish, prepareBrokerCutover, executeBrokerAliasCas as cutover, reconcileBrokerAlias as reconcile, brokerTransitionRequired } from '../../aws/stage-b-staged-broker.mjs';
const phaseInput = r => Object.hasOwn(r, 'p') ? { ...r, preparation: r.p, authorization: r.auth } : r;
const executeBrokerPublication = (r, d) => publish(phaseInput(r), d);
const executeBrokerAliasCas = (r, d) => cutover(phaseInput(r), d);
const reconcileBrokerAlias = (r, d) => reconcile(phaseInput(r), d);
const clone = structuredClone;
const sourceSha = 'a'.repeat(40), oldSha = 'b'.repeat(40), packageSha256 = 'e'.repeat(64);
const alias = { AliasArn: STAGE_B.brokerAliasArn, Name: 'reviewed', FunctionVersion: '12', RevisionId: 'revision-before', Description: '', RoutingConfig: { AdditionalVersionWeights: {} } };
const state = { lineage: '4e438e59-8b8b-194d-030c-5ede0c26344a', serial: 110, stateSha256: 'c'.repeat(64) };
const env = resolvedBrokerEnvironment();
const prerequisites = { policyArn: 'arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime', policyVersion: 'v12', policy: canonicalBrokerPolicy(), role: { Arn: STAGE_B.brokerRoleArn, RoleId: 'AROATESTROLE', trust: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }] }, attachedPolicies: ['arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime'], inlinePolicies: [], permissionsBoundary: null }, taskMap: JSON.parse(env.BROKER_TASK_DEFINITIONS_JSON), traffic: { reviewedAliasOnly: true, unqualifiedRoutes: [], otherVersionRoutes: [], functionUrls: [], eventSourceMappings: [] } };
function configuration(version = '13') {
 const raw = JSON.parse(fs.readFileSync(new URL('./production-stage-b-broker-get-function-configuration.json', import.meta.url)));
 const variables = clone(env); if (version === '12') variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(variables.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: oldSha });
 return { ...raw, Version: version, FunctionArn: `${STAGE_B.brokerFunctionArn}:${version}`, Environment: { Variables: variables } };
}
const target = brokerTargetIdentity(configuration(), packageSha256);
const tfAlias = { arn: alias.AliasArn, function_name: 'mscqr-production-rls-approval-broker', name: 'reviewed', description: '', routing_config: [], function_version: '12' };
const tfFn = { function_name: 'mscqr-production-rls-approval-broker', role: STAGE_B.brokerRoleArn, publish: true, timeout: 180, source_code_hash: target.codeSha256, code_sha256: target.codeSha256, version: '12', source_code_size: 100, last_modified: 'yesterday', qualified_arn: `${STAGE_B.brokerFunctionArn}:12`, qualified_invoke_arn: `${STAGE_B.brokerFunctionArn}:12`, environment: [{ variables: clone(env) }] };
const change = (address, before, after, actions = ['no-op'], after_unknown = {}) => ({ address, mode: 'managed', type: address.split('.')[0], change: { actions, before, after, after_unknown } });
const envelope = changes => ({ variables: { tooling_sha: { value: sourceSha } }, errored: false, complete: true, resource_changes: changes });
function publicationPlan() {
 const before = clone(tfFn), after = clone(tfFn);
 before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(env.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: oldSha });
 const unknown = {};
 for (const key of ['code_sha256', 'source_code_size', 'last_modified', 'qualified_arn', 'qualified_invoke_arn', 'version']) { delete after[key]; unknown[key] = true; }
 return { ...envelope([change(BROKER_FUNCTION, before, after, ['update'], unknown)]), complete: false };
}
function preparation() {
 return { schemaVersion: 1, purpose: BROKER_PUBLICATION, sourceSha, treeSha256: '1'.repeat(64), savedPlanSha256: brokerDigest(Buffer.from('publication')), logicalPlanSha256: brokerDigest(publicationPlan()), artifactSetSha256: '2'.repeat(64), state: clone(state), packageSha256, alias: clone(alias), prerequisites: clone(prerequisites), configuration: clone(env), canonicalAddresses: [BROKER_ALIAS, BROKER_FUNCTION], publication: null, target: null };
}
const now = new Date('2026-10-04T12:00:00.000Z');
function authorization(p) { return { schemaVersion: 1, purpose: p.purpose, preparationSha256: brokerDigest(p), sourceSha, nonce: '3'.repeat(64), issuedAt: now.toISOString(), expiresAt: new Date(now.getTime()+600000).toISOString(), review: { makerIdentity: 'arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/operator', checkerIdentity: 'arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/reviewer', humanReviewId: 'review-1' }, signature: { keyArn: STAGE_B.approvalKmsKeyArn, algorithm: STAGE_B_APPROVAL_ALGORITHM, signatureBase64: 'c2lnbmVk' } }; }
function cutoverPlan() {
 const fn = { ...clone(tfFn), version: '13', qualified_arn: target.versionArn };
 return envelope([change(BROKER_FUNCTION, fn, clone(fn)), change(BROKER_ALIAS, clone(tfAlias), { ...clone(tfAlias), function_version: '13' }, ['update'])]);
}
function rig() {
 let liveAlias = clone(alias), currentState = clone(state); const calls = [], entries = [], reservations = new Set();
 const p = preparation(), auth = authorization(p);
 const deps = { now: () => now, verifyAuthorization: async () => true, readCheckout: async () => ({ sourceSha, treeSha256: p.treeSha256 }), readPrerequisites: async () => clone(prerequisites), readStateIdentity: async () => clone(currentState), getAlias: async () => clone(liveAlias), getVersion: async version => configuration(version),
 readPlan: async () => ({ plan: publicationPlan(), bytes: Buffer.from('publication'), artifactSetSha256: p.artifactSetSha256 }),
 reserve: async id => { assert.ok(!reservations.has(id), 'Already reserved'); reservations.add(id); }, record: async (...e) => { entries.push(e); },
 applyPublication: async () => { calls.push('publish'); currentState.serial++; }, readPublicationResult: async () => ({ version: '13', savedPlanSha256: p.savedPlanSha256, authorizationSha256: brokerDigest(auth) }),
 authenticatePublicationResult: async result => assert.ok(entries.some(e => e[1] === 'PUBLISHED' && canonicalJson(e[2]) === canonicalJson(result))),
 updateAlias: async input => { calls.push(clone(input)); assert.equal(input.RevisionId, liveAlias.RevisionId); liveAlias = { ...liveAlias, FunctionVersion: input.FunctionVersion, RevisionId: 'revision-after' }; return clone(liveAlias); },
 authenticateCasResult: async result => assert.ok(entries.some(e => e[1] === result.status && canonicalJson(e[2]) === canonicalJson(result))),
 readTerraformFunctionVersion: async () => '13', captureRefreshOnlyPlan: async () => ({ bytes: Buffer.from('refresh'), plan: { ...envelope([]), resource_drift: [change(BROKER_ALIAS, clone(tfAlias), { ...clone(tfAlias), function_version: '13' }, ['update'])] } }), applyRefreshOnlyPlan: async () => { calls.push('refresh-only'); currentState.serial++; },
 captureNormalPlan: async () => { const plan = cutoverPlan(); const a = plan.resource_changes[1]; a.change = { actions: ['no-op'], before: clone(a.change.after), after: clone(a.change.after), after_unknown: {} }; return { bytes: Buffer.from('normal'), plan }; }, publishTerminalHandoff: async value => { assert.equal(value.record.status, "RECONCILED_PENDING_RELEASE_CAS"); }, authenticateTerraformState: async (t, a) => { assert.equal(t.version, liveAlias.FunctionVersion); assert.equal(a.RevisionId, liveAlias.RevisionId); } };
 return { p, auth, deps, calls, entries, state: () => clone(currentState), setAlias: value => { liveAlias = value; } };
}
async function ready(r = rig()) {
 const publicationResult = await executeBrokerPublication({ preparation: r.p, authorization: r.auth }, r.deps);
 const plan = cutoverPlan(), bytes = Buffer.from('cutover');
 const p = await prepareBrokerCutover({ publicationPreparation: r.p, publicationAuthorization: r.auth, publicationResult, plan, bytes, state: r.state(), artifactSetSha256: '4'.repeat(64) }, r.deps);
 r.deps.readPlan = async () => ({ plan, bytes, artifactSetSha256: p.artifactSetSha256 });
 return { ...r, p, auth: authorization(p) };
}

export { rig, ready, configuration, preparation, authorization, cutoverPlan, publicationPlan, envelope, change, tfFn, tfAlias, alias, state, env, prerequisites, sourceSha, oldSha, packageSha256, now, target };

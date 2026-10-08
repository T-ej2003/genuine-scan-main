import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runStagedBrokerRequest } from '../aws/run-stage-b-staged-broker.mjs';
import test from 'node:test';
import { taskChange, rotationVariables } from './fixtures/stage-b-task-rotation.mjs';
import { canonicalBrokerPolicy } from './fixtures/staged-broker.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, assertPrerequisitePlan, authenticateRegisteredDefinition, assertRegisteredTaskDefinitionState, assertRegistrationRecoveryIdentity, taskMapFromRegisteredDefinitions, executeTaskRegistration, deriveBrokerPolicy, assertBrokerPolicyReconciliation, assertBrokerPolicyPruningPlan, adoptRegisteredOutputs, authenticateRegistrationHandoffEvidence } from '../aws/stage-b-release-prerequisites.mjs';
import { brokerDigest, assertBrokerPublicationPlan, assertRegistrationHandoff } from '../aws/stage-b-staged-broker-contract.mjs';
import { preparation as brokerPreparation, publicationPlan, rig as brokerRig, configuration, authorization as brokerAuthorization, cutoverPlan } from './fixtures/staged-broker-runtime.mjs';
import { executeBrokerPublication, prepareBrokerCutover, executeBrokerAliasCas, reconcileBrokerAlias } from '../aws/stage-b-staged-broker.mjs';
function rig(character = 'a', revision = 17) {
  const sourceSha = character.repeat(40), variables = structuredClone(rotationVariables);
  variables.tooling_sha = { value: sourceSha }; variables.image_release_sha.value = sourceSha;
  for (const [name, input] of Object.entries(variables)) if (name.endsWith('_image')) input.value = input.value.replace(/sha256:.+$/, `sha256:${character.repeat(64)}`);
  const plan = { complete: false, errored: false, variables, resource_changes: TASK_REGISTRATION_ADDRESSES.map((address, i) => {
    const c = taskChange(address, i + 1, variables); c.change.before.skip_destroy = true; c.change.after.skip_destroy = true;
    c.change.after.arn = null; c.change.after.revision = null; c.change.after_unknown = { arn: true, revision: true }; return c;
  }) };
  const bytes = Buffer.from(`saved-${character}`), p = { purpose: TASK_REGISTRATION, sourceSha, treeSha256: character.repeat(64),
    savedPlanSha256: brokerDigest(bytes), logicalPlanSha256: brokerDigest(plan), artifactSetSha256: '0'.repeat(64), canonicalAddresses: [...TASK_REGISTRATION_ADDRESSES] };
  const states = Object.fromEntries(plan.resource_changes.map(c => [c.address, { ...structuredClone(c.change.after),
    arn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/${c.change.after.family}:${revision}`, revision }]));
  let applied = false, writes = 0; const receipts = [], reserved = new Set();
  const describe = arn => {
    const s = Object.values(states).find(s => s.arn === arn); assert.ok(s);
    return { taskDefinitionArn: arn, revision: s.revision, status: 'ACTIVE', family: s.family, taskRoleArn: s.task_role_arn,
      executionRoleArn: s.execution_role_arn, networkMode: s.network_mode, cpu: s.cpu, memory: s.memory,
      runtimePlatform: { operatingSystemFamily: s.runtime_platform.operating_system_family, cpuArchitecture: s.runtime_platform.cpu_architecture }, volumes: s.volume.map(({ name }) => ({ name })),
      requiresCompatibilities: s.requires_compatibilities, containerDefinitions: JSON.parse(s.container_definitions), tags: Object.entries(s.tags).map(([key, value]) => ({ key, value })) };
  };
  const deps = { authenticatePrerequisiteAuthorization: async () => brokerDigest({ sourceSha }), readPlan: async () => ({ plan, bytes, artifactSetSha256: p.artifactSetSha256 }),
    reserve: async id => { assert.ok(!reserved.has(id)); reserved.add(id); }, record: async (...entry) => receipts.push(entry),
    applyTaskRegistration: async () => { applied = true; writes++; }, readRegisteredTaskDefinition: async address => { assert.ok(applied); return states[address]; },
    describeTaskDefinition: async arn => describe(arn) };
  return { p, plan, states, deps, describe, receipts, writes: () => writes };
}
test('successive arbitrary protected-main releases authenticate nonconsecutive returned revisions with unchanged framework', async () => {
  let policy = canonicalBrokerPolicy();
  for (const [character, revision] of [['a', 17], ['b', 42], ['c', 103]]) {
    const r = rig(character, revision), result = await executeTaskRegistration({ preparation: r.p, authorization: {} }, r.deps);
    assert.equal(r.writes(), 1); assert.equal(result.sourceSha, character.repeat(40));
    assert.ok(Object.values(result.taskMap).every(arn => arn.endsWith(`:${revision}`)));
    policy = deriveBrokerPolicy(policy, result.taskMap);
    assert.deepEqual(policy.Statement[0].Resource, Object.keys(result.taskMap).sort().map(mode => result.taskMap[mode]));
    assert.equal(result.status, 'REGISTERED_NONTERMINAL');
    const p = brokerPreparation(), plan = publicationPlan();
    p.configuration.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(result.taskMap); p.prerequisites.taskMap = result.taskMap; p.prerequisites.policy = policy;
    p.configuration.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(p.configuration.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: r.p.sourceSha });
    p.sourceSha = r.p.sourceSha; p.packageSha256 = character.repeat(64);
    p.prerequisiteChain = { registration: { result }, policy: { result: { policy } } };
    plan.variables.tooling_sha.value = r.p.sourceSha; plan.resource_changes[0].change.after.environment[0].variables = p.configuration;
    plan.resource_changes[0].change.after.source_code_hash = Buffer.from(p.packageSha256, 'hex').toString('base64');
    // The A predecessor must also have a different source, just as B/C do.
    plan.resource_changes[0].change.before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(p.configuration.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: 'd'.repeat(40) });
    assertBrokerPublicationPlan(plan, p);
  }
});
for (const [name, mutate] of [
  ['wrong source', r => r.plan.variables.tooling_sha.value = 'f'.repeat(40)],
  ['wrong digest', r => { const c = JSON.parse(r.plan.resource_changes[0].change.after.container_definitions); c[0].image = c[0].image.replace(/sha256:.+/, `sha256:${'f'.repeat(64)}`); r.plan.resource_changes[0].change.after.container_definitions = JSON.stringify(c); }],
  ['unexpected role', r => r.plan.resource_changes[0].change.after.task_role_arn += '-wrong'],
  ['unknown template', r => r.plan.resource_changes[0].change.after.family += '-wrong'],
  ['unexpected environment', r => { const c = JSON.parse(r.plan.resource_changes[0].change.after.container_definitions); c[0].environment.push({ name: 'UNKNOWN', value: 'bad' }); r.plan.resource_changes[0].change.after.container_definitions = JSON.stringify(c); }],
  ...['aws_ecs_service.production', 'aws_ecs_task.launch', 'aws_lambda_alias.reviewed', 'aws_iam_policy.broker'].map(address => [address, r => r.plan.resource_changes.push({ address, mode: 'managed', change: { actions: ['update'] } })]),
]) test(`registration rejects ${name} before any write`, async () => { const r = rig(); mutate(r); await assert.rejects(() => executeTaskRegistration({ preparation: r.p, authorization: {} }, r.deps)); assert.equal(r.writes(), 0); });
test('registration replay is denied and uncertain apply cannot retry', async () => {
  const r = rig(); r.deps.applyTaskRegistration = async () => { throw new Error('uncertain'); };
  await assert.rejects(() => executeTaskRegistration({ preparation: r.p, authorization: {} }, r.deps));
  await assert.rejects(() => executeTaskRegistration({ preparation: r.p, authorization: {} }, r.deps));
  assert.equal(r.receipts.filter(e => e[1] === 'TASK_REGISTRATION_INTENT').length, 1);
});
test('A/B/C prerequisite outputs feed the same governed publication, alias CAS and reconciliation code', async () => {
  let previousAlias, previousEnvironment, previousPolicy;
  for (const [character, revision, publishedVersion] of [['a', 17, '13'], ['b', 42, '29'], ['c', 103, '77']]) {
    const registration = rig(character, revision), registered = await executeTaskRegistration({ preparation: registration.p, authorization: {} }, registration.deps);
    const r = brokerRig(), p = r.p; p.schemaVersion = 2; p.sourceSha = registration.p.sourceSha;
    if (previousAlias) { p.alias = structuredClone(previousAlias); r.setAlias(previousAlias); p.prerequisites.policy = previousPolicy; p.prerequisites.taskMap = JSON.parse(previousEnvironment.BROKER_TASK_DEFINITIONS_JSON); }
    const registrationPreparation = { ...structuredClone(p), purpose: TASK_REGISTRATION, target: null, publication: null, prerequisiteChain: null };
    const registrationAuthorization = { ...brokerAuthorization(registrationPreparation), sourceSha: p.sourceSha };
    registered.sourceSha = p.sourceSha; registered.treeSha256 = p.treeSha256;
    registered.preparationSha256 = brokerDigest(registrationPreparation); registered.authorizationSha256 = brokerDigest(registrationAuthorization);
    const policy = deriveBrokerPolicy(p.prerequisites.policy, registered.taskMap);
    const policyPreparation = { ...structuredClone(p), purpose: 'STAGE_B_BROKER_POLICY_CONVERGENCE', target: { policy }, publication: null,
      prerequisiteChain: { registration: { preparation: registrationPreparation, authorization: registrationAuthorization, result: registered } } };
    const policyAuthorization = { ...brokerAuthorization(policyPreparation), sourceSha: p.sourceSha };
    p.prerequisiteChain = { registration: policyPreparation.prerequisiteChain.registration,
      policy: { preparation: policyPreparation, authorization: policyAuthorization,
        result: { sourceSha: p.sourceSha, treeSha256: p.treeSha256, policy, preparationSha256: brokerDigest(policyPreparation), authorizationSha256: brokerDigest(policyAuthorization) } } };
    p.prerequisites.taskMap = registered.taskMap; p.prerequisites.policy = policy;
    p.configuration.BROKER_TASK_DEFINITIONS_JSON = JSON.stringify(registered.taskMap);
    p.configuration.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(p.configuration.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: p.sourceSha });
    const plan = publicationPlan(); plan.variables.tooling_sha.value = p.sourceSha;
    plan.resource_changes[0].change.after.environment[0].variables = structuredClone(p.configuration);
    plan.resource_changes[0].change.before.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON = JSON.stringify({ ...JSON.parse(p.configuration.BROKER_APPROVAL_EXPECTED_JSON), releaseSha: 'd'.repeat(40) });
    plan.resource_changes[0].change.before.version = p.alias.FunctionVersion;
    if (previousEnvironment) plan.resource_changes[0].change.before.environment[0].variables = structuredClone(previousEnvironment);
    p.logicalPlanSha256 = brokerDigest(plan);
    r.deps.readCheckout = async () => ({ sourceSha: p.sourceSha, treeSha256: p.treeSha256 });
    r.deps.readPrerequisites = async () => structuredClone(p.prerequisites);
    r.deps.authenticatePrerequisiteChain = async chain => assert.deepEqual(chain, p.prerequisiteChain);
    r.deps.readPlan = async () => ({ plan, bytes: Buffer.from('publication'), artifactSetSha256: p.artifactSetSha256 });
    r.deps.getVersion = async version => {
      const c = configuration(version); c.Environment.Variables = structuredClone(version === p.alias.FunctionVersion ? plan.resource_changes[0].change.before.environment[0].variables : p.configuration); return c;
    };
    const auth = { ...brokerAuthorization(p), sourceSha: p.sourceSha };
    r.deps.readPublicationResult = async () => ({ version: publishedVersion, savedPlanSha256: p.savedPlanSha256, authorizationSha256: brokerDigest(auth) });
    const publication = await executeBrokerPublication({ preparation: p, authorization: auth }, r.deps);
    const cutover = cutoverPlan(); cutover.variables.tooling_sha.value = p.sourceSha;
    for (const v of [cutover.resource_changes[0].change.before, cutover.resource_changes[0].change.after]) { v.version = publishedVersion; v.qualified_arn = `${v.qualified_arn.split(':').slice(0, -1).join(':')}:${publishedVersion}`; }
    cutover.resource_changes[1].change.before.function_version = p.alias.FunctionVersion; cutover.resource_changes[1].change.after.function_version = publishedVersion;
    r.deps.readTerraformFunctionVersion = async () => publishedVersion;
    cutover.resource_changes[0].change.before.environment[0].variables = structuredClone(p.configuration);
    cutover.resource_changes[0].change.after.environment[0].variables = structuredClone(p.configuration);
    const cp = await prepareBrokerCutover({ publicationPreparation: p, publicationAuthorization: auth, publicationResult: publication,
      plan: cutover, bytes: Buffer.from('cutover'), state: r.state(), artifactSetSha256: '4'.repeat(64) }, r.deps);
    const ca = { ...brokerAuthorization(cp), sourceSha: cp.sourceSha };
    r.deps.readPlan = async () => ({ plan: cutover, bytes: Buffer.from('cutover'), artifactSetSha256: cp.artifactSetSha256 });
    r.deps.updateAlias = async input => {
      const current = await r.deps.getAlias(); assert.equal(input.RevisionId, current.RevisionId); r.calls.push(structuredClone(input));
      const next = { ...current, FunctionVersion: input.FunctionVersion, RevisionId: `revision-${character}` }; r.setAlias(next); return next;
    };
    const cas = await executeBrokerAliasCas({ preparation: cp, authorization: ca }, r.deps);
    r.deps.captureNormalPlan = async () => {
      const normal = structuredClone(cutover), a = normal.resource_changes[1];
      a.change = { actions: ['no-op'], before: structuredClone(a.change.after), after: structuredClone(a.change.after), after_unknown: {} }; return { bytes: Buffer.from('normal'), plan: normal };
    };
    r.deps.captureRefreshOnlyPlan = async () => ({ bytes: Buffer.from('refresh'), plan: { variables: { tooling_sha: { value: cp.sourceSha } }, complete: true, errored: false, resource_changes: [],
      resource_drift: [{ ...structuredClone(cutover.resource_changes[1]), change: { ...structuredClone(cutover.resource_changes[1].change), after_unknown: {} } }] } });
    const reconciled = await reconcileBrokerAlias({ preparation: cp, authorization: ca, casResult: cas }, r.deps);
    assert.equal(reconciled.status, 'RECONCILED_PENDING_RELEASE_CAS'); assert.equal(r.calls[1].RevisionId, p.alias.RevisionId);
    assert.deepEqual(reconciled.mutationAddresses.sort(), ['aws_lambda_function.broker', 'aws_lambda_alias.reviewed'].sort());
    previousAlias = await r.deps.getAlias(); previousEnvironment = structuredClone(p.configuration); previousPolicy = structuredClone(policy);
  }
});
for (const field of ['revision', 'taskRoleArn', 'executionRoleArn', 'cpu', 'containerDefinitions']) test(`readback rejects changed ${field}`, () => {
  const r = rig(), address = TASK_REGISTRATION_ADDRESSES[0], state = r.states[address], observed = r.describe(state.arn);
  observed[field] = field === 'containerDefinitions' ? [] : 'wrong';
  assert.throws(() => authenticateRegisteredDefinition({ address, desired: r.plan.resource_changes[0].change.after, observed, state }));
});
function policyReconciliation() {
  const beforePolicy = canonicalBrokerPolicy(), targetPolicy = structuredClone(beforePolicy); targetPolicy.Statement[0].Resource = targetPolicy.Statement[0].Resource.map(arn => arn.replace(/:1$/, ':42'));
  const p = { sourceSha: 'a'.repeat(40), canonicalAddresses: ['aws_iam_policy.broker'], prerequisites: { policy: beforePolicy }, target: { policy: targetPolicy } };
  const before = { arn: 'arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime', policy: JSON.stringify(beforePolicy) }, after = { ...before, policy: JSON.stringify(targetPolicy) };
  const noop = { address: 'aws_iam_policy.broker', type: 'aws_iam_policy', mode: 'managed', change: { actions: ['no-op'], before: after, after } };
  const normal = { variables: { tooling_sha: { value: p.sourceSha } }, complete: false, errored: false, resource_changes: [noop] };
  const refresh = { ...structuredClone(normal), resource_drift: [{ ...noop, change: { actions: ['update'], before, after } }] };
  return { p, refresh, normal };
}
test('IAM reconciliation is state-only and proves the exact declarative target', () => { const r = policyReconciliation(); assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p); });
test('Terraform refresh-only reconciliation accepts omitted resource_changes and authenticates the exact policy drift', () => {
  const r = policyReconciliation();
  r.refresh.format_version = '1.2'; r.refresh.terraform_version = '1.15.8'; r.refresh.applyable = true;
  delete r.refresh.resource_changes;
  assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p);
});
for (const [name, mutate] of [
  ['remote mutation', r => r.refresh.resource_changes[0].change.actions = ['update']],
  ['unknown drift', r => r.refresh.resource_drift.push(structuredClone(r.refresh.resource_drift[0]))],
  ['wrong successor', r => r.refresh.resource_drift[0].change.after.policy = JSON.stringify(canonicalBrokerPolicy())],
  ['normal pending mutation', r => r.normal.resource_changes[0].change.actions = ['update']],
  ['unknown address', r => r.normal.resource_changes[0].address += '_other'],
  ['unknown value', r => r.normal.resource_changes[0].change.after_unknown = { policy: true }],
  ['wrong source', r => r.normal.variables.tooling_sha.value = 'b'.repeat(40)],
]) test(`IAM reconciliation rejects ${name}`, () => { const r = policyReconciliation(); mutate(r); assert.throws(() => assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p)); });
for (const malformed of [null, {}]) test(`IAM reconciliation rejects malformed refresh resource_changes ${JSON.stringify(malformed)}`, () => {
  const r = policyReconciliation(); r.refresh.resource_changes = malformed;
  assert.throws(() => assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p));
});
test('IAM reconciliation rejects an omitted-property plan with a wrong predecessor policy', () => {
  const r = policyReconciliation(); delete r.refresh.resource_changes;
  r.refresh.resource_drift[0].change.before.policy = JSON.stringify(r.p.target.policy);
  assert.throws(() => assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p));
});
test('pruning approval binds one exact nondefault version and policy inventory', () => {
  const plan = { purpose: BROKER_POLICY_PRUNING, sourceSha: 'a'.repeat(40), policyArn: 'arn:aws:iam::368992683803:policy/mscqr-production-rls-approval-broker-runtime',
    defaultVersionId: 'v12', versionId: 'v9', inventory: [{ VersionId: 'v9', IsDefaultVersion: false }, { VersionId: 'v12', IsDefaultVersion: true }], mutation: 'iam:DeletePolicyVersion' };
  const p = { purpose: BROKER_POLICY_PRUNING, sourceSha: plan.sourceSha, prerequisites: { policyVersion: 'v12' }, target: { versionId: 'v9', inventory: plan.inventory } };
  assertBrokerPolicyPruningPlan(plan, p);
  for (const changed of [{ ...plan, policyArn: `${plan.policyArn}-other` }, { ...plan, versionId: 'v12' }, { ...plan, mutation: 'iam:SetDefaultPolicyVersion' }]) assert.throws(() => assertBrokerPolicyPruningPlan(changed, p));
});

test('IAM reconciliation rejects unapproved output-state changes', () => {
  const r = policyReconciliation();
  r.refresh.output_changes = { target: { actions: ['update'], before: 'approved', after: 'another' } };
  assert.throws(() => assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p));
});

import { recoverTaskRegistration } from '../aws/stage-b-release-prerequisites.mjs';
async function registrationRecoveryFixture() {
  const r = rig('b', 42), authorization = { sourceSha: r.p.sourceSha };
  r.p.state = { lineage: '4e438e59-8b8b-194d-030c-5ede0c26344a', serial: 1, stateSha256: 'c'.repeat(64) };
  r.p.alias = { identity: 'unchanged' }; r.p.prerequisites = { identity: 'unchanged' };
  const record = r.deps.record; let fail = true;
  r.deps.record = async (...args) => { if (args[1] === 'TASK_REGISTERED' && fail) { fail = false; throw Error('after external commit before receipt'); } return record(...args); };
  await assert.rejects(() => executeTaskRegistration({ preparation: r.p, authorization }, r.deps));
  r.deps.readCheckout = async () => ({ sourceSha: r.p.sourceSha, treeSha256: r.p.treeSha256 });
  r.deps.authenticateRegistrationRecoveryIdentity = async prior => prior || ({ mode: 'READ_ONLY_EXACT_SUCCESSOR', transaction: await r.deps.readCheckout(), tooling: { sourceSha: 'd'.repeat(40), treeSha256: 'd'.repeat(64) } });
  r.deps.getAlias = async () => structuredClone(r.p.alias); r.deps.readPrerequisites = async () => structuredClone(r.p.prerequisites);
  r.deps.readStateIdentity = async () => ({ ...r.p.state, serial: 2, stateSha256: 'd'.repeat(64) });
  r.deps.authenticateRecoveryIntent = async (status, expected) => {
    const entry = r.receipts.find(e => e[1] === status); assert.ok(entry);
    assert.equal(entry[0], brokerDigest(authorization));
    const { authorizedAt, ...fields } = entry[2]; assert.deepEqual(fields, expected); return { id: entry[0], authorizedAt };
  };
  r.deps.authenticateRegistrationState = async () => {
    for (const c of r.plan.resource_changes) {
      const state = r.states[c.address]; assert.ok(state); assert.notEqual(state.arn, c.change.before.arn);
      assert.deepEqual({ ...state, arn: c.change.after.arn, revision: c.change.after.revision }, c.change.after);
    }
  };
  r.deps.readRecoveryReceipt = async (id, status) => r.receipts.find(e => e[0] === id && e[1] === status)?.[2] || null;
  return { ...r, authorization, recover: () => recoverTaskRegistration({ preparation: r.p, authorization }, r.deps) };
}
test('completed registration recovers the exact normal receipt without registering or applying again', async () => {
  const r = await registrationRecoveryFixture(), result = await r.recover();
  assert.equal(r.writes(), 1); assert.equal(result.status, 'REGISTERED_NONTERMINAL');
  const normal = rig('b', 42); Object.assign(normal.p, { state: r.p.state, alias: r.p.alias, prerequisites: r.p.prerequisites });
  normal.deps.now = () => new Date(result.authorizedAt);
  const ordinary = await executeTaskRegistration({ preparation: normal.p, authorization: r.authorization }, normal.deps);
  const { recovery, ...transaction } = result; assert.deepEqual(transaction, ordinary); assert.equal(recovery.transaction.sourceSha, r.p.sourceSha); assert.equal(recovery.tooling.sourceSha, "d".repeat(40)); assert.deepEqual(await r.recover(), result);
  await assert.rejects(() => executeTaskRegistration({ preparation: r.p, authorization: r.authorization }, r.deps)); assert.equal(r.writes(), 1);
});
for (const [name, change] of [
  ['wrong Terraform state', r => r.states[TASK_REGISTRATION_ADDRESSES[0]].cpu = '999'],
  ['wrong live definition', r => { const describe = r.deps.describeTaskDefinition; r.deps.describeTaskDefinition = async arn => ({ ...await describe(arn), cpu: '999' }); }],
  ['wrong image', r => { const s = r.states[TASK_REGISTRATION_ADDRESSES[0]], defs = JSON.parse(s.container_definitions); defs[0].image += '-wrong'; s.container_definitions = JSON.stringify(defs); }],
  ['wrong source', r => r.deps.readCheckout = async () => ({ sourceSha: 'e'.repeat(40), treeSha256: r.p.treeSha256 })],
  ['wrong tree', r => r.deps.readCheckout = async () => ({ sourceSha: r.p.sourceSha, treeSha256: 'e'.repeat(64) })],
  ['partial registration', r => { const s=r.states[TASK_REGISTRATION_ADDRESSES[0]]; s.arn=r.plan.resource_changes[0].change.before.arn; }],
  ['wrong returned revision', r => r.states[TASK_REGISTRATION_ADDRESSES[0]].revision = 99],
  ['wrong intent', r => r.receipts[0][2].savedPlanSha256 = 'e'.repeat(64)],
  ['exact predecessor state', r => r.deps.readStateIdentity = async () => r.p.state],
  ['alias drift', r => r.deps.getAlias = async () => ({ identity: 'changed' })],
]) test(`registration recovery rejects ${name} without mutation`, async () => { const r=await registrationRecoveryFixture(); change(r); await assert.rejects(r.recover); assert.equal(r.writes(),1); });
test('unrelated newer registration is never queried or substituted', async () => {
  const r=await registrationRecoveryFixture(), describe=r.deps.describeTaskDefinition, queried=[];
  r.deps.describeTaskDefinition=async arn=>{queried.push(arn);assert.ok(arn.endsWith(':42'));return describe(arn);};
  const result=await r.recover(); assert.equal(queried.length,TASK_REGISTRATION_ADDRESSES.length); assert.ok(Object.values(result.taskMap).every(arn=>arn.endsWith(':42'))); assert.equal(r.writes(),1);
});
test('registration receipt commits before lost response: exact receipt is reused and authorization stays consumed',async()=>{
 const r=await registrationRecoveryFixture(),record=r.deps.record;let lost=false;
 r.deps.record=async(...args)=>{await record(...args);if(args[1]==='TASK_REGISTERED'&&!lost){lost=true;throw Error('receipt response lost');}};
 await assert.rejects(r.recover);const recovered=await r.recover();assert.ok(recovered);assert.equal(r.writes(),1);
 await assert.rejects(()=>executeTaskRegistration({preparation:r.p,authorization:r.auth},r.deps));assert.equal(r.writes(),1);
});

function fixture(address = TASK_REGISTRATION_ADDRESSES[0], revision = 42) {
  const desired = taskChange(address, 1).change.after;
  desired.arn = null; desired.revision = null; desired.ipc_mode = null; desired.pid_mode = null;
  desired.container_definitions = JSON.stringify([{ ...JSON.parse(desired.container_definitions)[0],
    environment: [{ name: 'ONE', value: '1' }, { name: 'TWO', value: '2' }],
    secrets: [{ name: 'ONE', valueFrom: 'approved-one' }, { name: 'TWO', valueFrom: 'approved-two' }],
    command: ['run', 'one'], entryPoint: ['node'], mountPoints: null }]);
  const identity = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${desired.family}`;
  const state = { ...structuredClone(desired), arn: `${identity}:${revision}`, arn_without_revision: identity, id: desired.family, revision,
    enable_fault_injection: false, ipc_mode: '', pid_mode: '', volume: desired.volume.map(v => ({ ...v, configure_at_launch: false })) };
  const containers = JSON.parse(state.container_definitions);
  for (const c of containers) Object.assign(c, { mountPoints: [], portMappings: [], systemControls: [], volumesFrom: [] });
  state.container_definitions = JSON.stringify(containers);
  const observed = { taskDefinitionArn: state.arn, revision, status: 'ACTIVE', family: desired.family,
    taskRoleArn: desired.task_role_arn, executionRoleArn: desired.execution_role_arn, networkMode: desired.network_mode,
    cpu: desired.cpu, memory: desired.memory, requiresCompatibilities: desired.requires_compatibilities,
    runtimePlatform: { operatingSystemFamily: desired.runtime_platform.operating_system_family, cpuArchitecture: desired.runtime_platform.cpu_architecture },
    volumes: desired.volume.map(v => ({ name: v.name, host: {} })), containerDefinitions: structuredClone(containers),
    tags: Object.entries(desired.tags).map(([key, value]) => ({ key, value })), enableFaultInjection: false };
  for (const c of observed.containerDefinitions) { c.cpu = 0; c.environment.reverse(); c.secrets.reverse(); }
  return { address, desired, state, observed, after_unknown: { arn: true, arn_without_revision: true, id: true, revision: true,
    enable_fault_injection: true, requires_compatibilities: [false], runtime_platform: [{}], tags: {},
    volume: desired.volume.map(() => ({ configure_at_launch: true, docker_volume_configuration: [] })) } };
}
const normal = r => authenticateRegisteredDefinition(r);
const recoveryState = r => assertRegisteredTaskDefinitionState(r.desired, r.state, r.after_unknown);
for (const address of TASK_REGISTRATION_ADDRESSES) test(`normal and recovery share bounded provider equivalences: ${address}`, () => {
  const r = fixture(address); normal(r); recoveryState(r);
  const absent = structuredClone(r); absent.observed.volumes.forEach(v => delete v.host); absent.observed.containerDefinitions.forEach(c => delete c.cpu);
  normal(absent);
});

const containerChange = (r, field, value) => {
  const c = JSON.parse(r.state.container_definitions); c[0][field] = value;
  r.state.container_definitions = JSON.stringify(c); r.observed.containerDefinitions[0][field] = value;
};
const volumeChange = (r, tf, aws) => { Object.assign(r.state.volume[0], tf); Object.assign(r.observed.volumes[0], aws); };
const negatives = [
  ['host sourcePath', r => volumeChange(r, { host_path: '/tmp/anything' }, { host: { sourcePath: '/tmp/anything' } })],
  ['unknown host field', r => volumeChange(r, { unknown: true }, { host: { unknown: true } })],
  ['EFS', r => volumeChange(r, { efs_volume_configuration: [{ file_system_id: 'other' }] }, { efsVolumeConfiguration: { fileSystemId: 'other' } })],
  ['Docker', r => volumeChange(r, { docker_volume_configuration: [{ scope: 'shared' }] }, { dockerVolumeConfiguration: { scope: 'shared' } })],
  ['FSx', r => volumeChange(r, { fsx_windows_file_server_volume_configuration: [{}] }, { fsxWindowsFileServerVolumeConfiguration: {} })],
  ['S3 files', r => volumeChange(r, { s3files_volume_configuration: [{}] }, { s3filesVolumeConfiguration: {} })],
  ['configure at launch', r => volumeChange(r, { configure_at_launch: true }, { configureAtLaunch: true })],
  ['unexpected volume', r => { r.state.volume[0].name = 'other'; r.observed.volumes[0].name = 'other'; }],
  ['missing volume', r => { r.state.volume = []; r.observed.volumes = []; }],
  ['duplicate volume', r => { r.state.volume.push(structuredClone(r.state.volume[0])); r.observed.volumes.push(structuredClone(r.observed.volumes[0])); }],
  ['enabled fault injection', r => { r.state.enable_fault_injection = true; r.observed.enableFaultInjection = true; }],
  ['nonboolean fault injection', r => r.state.enable_fault_injection = 'false'],
  ['ipc mode', r => { r.state.ipc_mode = 'host'; r.observed.ipcMode = 'host'; }],
  ['pid mode', r => { r.state.pid_mode = 'host'; r.observed.pidMode = 'host'; }],
  ['image digest', r => containerChange(r, 'image', 'registry/image@sha256:' + 'e'.repeat(64))],
  ['command', r => containerChange(r, 'command', ['different'])],
  ['command order', r => containerChange(r, 'command', ['one', 'run'])],
  ['entrypoint', r => containerChange(r, 'entryPoint', ['different'])],
  ['environment', r => containerChange(r, 'environment', [{ name: 'ONE', value: 'different' }])],
  ['duplicate environment', r => containerChange(r, 'environment', [{ name: 'ONE', value: '1' }, { name: 'ONE', value: '2' }])],
  ['secrets', r => containerChange(r, 'secrets', [{ name: 'ONE', valueFrom: 'different' }])],
  ['mount', r => containerChange(r, 'mountPoints', [{ sourceVolume: 'other', containerPath: '/etc' }])],
  ['privileged', r => containerChange(r, 'privileged', true)],
  ['container CPU', r => containerChange(r, 'cpu', 100)],
  ['unknown container field', r => containerChange(r, 'unknownProviderField', [])],
  ['execution role', r => { r.state.execution_role_arn += '-other'; r.observed.executionRoleArn += '-other'; }],
  ['task role', r => { r.state.task_role_arn += '-other'; r.observed.taskRoleArn += '-other'; }],
  ['unknown provider field', r => { r.state.unknownProviderField = false; r.after_unknown.unknownProviderField = true; }],
  ['unknown computed security field', r => r.after_unknown.container_definitions = true],
  ['unknown nested computed field', r => r.after_unknown.volume[0].host_path = true],
  ['wrong identity output', r => r.state.arn_without_revision += '-other'],
];
for (const [name, mutate] of negatives) for (const [mode, verify] of [['normal', normal], ['recovery', recoveryState]]) {
  if (mode === 'normal' && name.startsWith('unknown computed') || mode === 'normal' && name === 'unknown nested computed field') continue;
  test(`${mode} rejects ${name}`, () => { const r = fixture(); mutate(r); assert.throws(() => verify(r)); });
}
for (const host of [{ sourcePath: '' }, [], null, { unknown: null }]) test(`ECS host must be structurally empty: ${JSON.stringify(host)}`, () => {
  const r = fixture(); r.observed.volumes[0].host = host; assert.throws(() => normal(r));
});

function recoverRows(rows, full) {
  const authorization = { test: 'original-consumed-authority' }, id = brokerDigest(authorization), authorizedAt = '2026-01-01T00:00:00.000Z';
  const plan = full?.plan || { complete: false, errored: false, variables: { tooling_sha: { value: 'a'.repeat(40) } }, resource_changes: rows.map(r => ({ address: r.address, type: 'aws_ecs_task_definition', mode: 'managed', change: { before: { ...r.desired, skip_destroy: true, arn: r.state.arn.replace(/:[0-9]+$/, ':1') }, after: { ...r.desired, skip_destroy: true }, actions: ['create', 'delete'], after_unknown: r.after_unknown } })) };
  // Real/synthetic approved-plan validation is exercised by assertPrerequisitePlan
  // in existing tests. Recovery uses the original complete plan when provided.
  const p = { purpose: 'STAGE_B_TASK_REGISTRATION', sourceSha: plan.variables.tooling_sha.value, treeSha256: full?.transaction?.treeSha256 || 'b'.repeat(64),
    savedPlanSha256: brokerDigest(Buffer.from('original-saved-plan')), logicalPlanSha256: brokerDigest(plan), artifactSetSha256: 'c'.repeat(64),
    canonicalAddresses: plan.resource_changes.map(c => c.address), state: { lineage: 'original', serial: 1 }, alias: {}, prerequisites: {} };
  let receipt; const deps = { authenticateRecoveryIntent: async () => ({ id, authorizedAt }),
    readPlan: async () => ({ plan, bytes: Buffer.from('original-saved-plan'), artifactSetSha256: p.artifactSetSha256 }),
    authenticateRegistrationRecoveryIdentity: async prior => prior || ({ mode: 'READ_ONLY_EXACT_SUCCESSOR', transaction: { sourceSha: p.sourceSha, treeSha256: p.treeSha256 }, tooling: full?.tooling || { sourceSha: 'd'.repeat(40), treeSha256: 'd'.repeat(64) } }),
    readCheckout: async () => ({ sourceSha: p.sourceSha, treeSha256: p.treeSha256 }), getAlias: async () => p.alias, readPrerequisites: async () => p.prerequisites,
    readStateIdentity: async () => ({ lineage: 'original', serial: 2 }), authenticateRegistrationState: async () => rows.forEach(recoveryState),
    readRegisteredTaskDefinition: async address => rows.find(r => r.address === address).state,
    describeTaskDefinition: async arn => rows.find(r => r.state.arn === arn).observed,
    readRecoveryReceipt: async () => receipt || null, record: async (key, status, value) => { assert.equal(key, id); assert.equal(status, 'TASK_REGISTERED'); receipt = value; },
    applyTaskRegistration: async () => assert.fail('Recovery must not apply or register') };
  return recoverTaskRegistration({ preparation: p, authorization }, deps);
}

const realPath = process.env.MSCQR_REGISTRATION_VERIFIER_FIXTURE;
test('twelve captured production successors authenticate normally and in read-only recovery', { skip: !realPath }, async () => {
  const full = JSON.parse(fs.readFileSync(realPath)); assert.equal(full.rows.length, 12);
  const normalDefinitions = Object.fromEntries(full.rows.map(r => [r.address, normal(r)])); full.rows.forEach(recoveryState);
  const result = await recoverRows(full.rows, full);
  if(full.transaction){assert.deepEqual(result.recovery.transaction,full.transaction);assert.deepEqual(result.recovery.tooling,full.tooling);assert.equal(result.sourceSha,full.transaction.sourceSha);}
  assert.deepEqual(result.definitions, normalDefinitions);
  assert.deepEqual(result.taskMap, taskMapFromRegisteredDefinitions(normalDefinitions));
});

for (const [name, change] of [
  ['omitted recovery identity', r => delete r.deps.authenticateRegistrationRecoveryIdentity],
  ['omitted recovery mode', r => r.deps.authenticateRegistrationRecoveryIdentity = async () => ({ transaction: { sourceSha: r.p.sourceSha, treeSha256: r.p.treeSha256 }, tooling: { sourceSha: 'd'.repeat(40), treeSha256: 'd'.repeat(64) } })],
  ['tooling substituted for transaction', r => r.deps.authenticateRegistrationRecoveryIdentity = async () => ({ mode: 'READ_ONLY_EXACT_SUCCESSOR', transaction: { sourceSha: 'd'.repeat(40), treeSha256: 'd'.repeat(64) }, tooling: { sourceSha: 'd'.repeat(40), treeSha256: 'd'.repeat(64) } })],
  ['unconsumed authority', r => r.deps.authenticateRecoveryIntent = async () => { throw Error('No consumed reservation'); }],
  ['invalid authorization', r => r.authorization.sourceSha = 'd'.repeat(40)],
  ['missing intent', r => r.receipts.length = 0],
  ['altered saved plan', r => r.p.savedPlanSha256 = 'e'.repeat(64)],
  ['altered artifact set', r => { const read=r.deps.readPlan; r.deps.readPlan=async()=>({...await read(),artifactSetSha256:'e'.repeat(64)}); }],
  ['receipt source substitution', r => { const record=r.deps.record; r.deps.record=async (id,status,value)=>record(id,status,{...value,sourceSha:'d'.repeat(40)}); }],
]) test(`read-only cross-source recovery rejects ${name}`, async () => {
  const r=await registrationRecoveryFixture(); change(r);
  if(name==='receipt source substitution'){await r.recover();await assert.rejects(r.recover);}else await assert.rejects(r.recover);
  assert.equal(r.writes(),1);
});
test('cross-source recovery cannot call registration, apply, service or task mutation hooks',async()=>{
  const r=await registrationRecoveryFixture();
  for(const method of ['applyTaskRegistration','registerTaskDefinition','updateService','runTask','stopTask'])r.deps[method]=()=>assert.fail('Mutation attempted in recovery');
  const result=await r.recover();assert.equal(result.sourceSha,r.p.sourceSha);assert.notEqual(result.sourceSha,result.recovery.tooling.sourceSha);assert.equal(r.writes(),1);
});

test('immutable recovered receipt retains its historical tooling provenance across later protected tooling',async()=>{
 const r=await registrationRecoveryFixture(),original=await r.recover(),identity=r.deps.authenticateRegistrationRecoveryIdentity;
 r.deps.authenticateRegistrationRecoveryIdentity=async prior=>prior||({...await identity(),tooling:{sourceSha:'e'.repeat(40),treeSha256:'e'.repeat(64)}});
 assert.deepEqual(await r.recover(),original);assert.equal(r.writes(),1);
});

test('explicit recovery dispatch authenticates dual identity without weakening mutation dispatch',async()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'registration-recovery-dispatch-'));fs.chmodSync(directory,0o700);
 try{
  const r=await registrationRecoveryFixture(),identity=await r.deps.authenticateRegistrationRecoveryIdentity();
  r.deps.authenticateRegistrationRecoveryIdentity=async prior=>prior||identity;
  r.deps.readCheckout=async()=>{throw Error('Requested source SHA does not match the freshly fetched protected main.');};
  const request={operation:'recover-registration',directory,preparation:r.p,authorization:r.authorization};
  const result=await runStagedBrokerRequest(request,{adapterFactory:()=>r.deps});assert.equal(result.sourceSha,r.p.sourceSha);assert.notEqual(result.sourceSha,result.recovery.tooling.sourceSha);
  await assert.rejects(()=>runStagedBrokerRequest({...request,operation:'register'},{adapterFactory:()=>r.deps}),/Requested source SHA/);
  await assert.rejects(()=>runStagedBrokerRequest({...request,operation:'register',allowSourceShaMismatch:true},{adapterFactory:()=>r.deps}),/Unknown staged request field/);
  assert.equal(r.writes(),1);
 }finally{fs.rmSync(directory,{recursive:true});}
});

async function handoffRig() {
  const r = rig('a', 42), p = { ...brokerPreparation(), schemaVersion: 2, purpose: TASK_REGISTRATION,
    sourceSha: r.p.sourceSha, treeSha256: r.p.treeSha256, savedPlanSha256: r.p.savedPlanSha256,
    logicalPlanSha256: r.p.logicalPlanSha256, canonicalAddresses: [...TASK_REGISTRATION_ADDRESSES, 'aws_lambda_function.broker', 'aws_lambda_alias.reviewed'],
    prerequisiteChain: null, target: null, publication: null };
  const auth = brokerAuthorization(p), id = brokerDigest(auth);
  r.p = p; r.deps.authenticatePrerequisiteAuthorization = async () => id;
  r.deps.readPlan = async () => ({ plan: r.plan, bytes: Buffer.from('saved-a'), artifactSetSha256: p.artifactSetSha256 });
  r.deps.now = () => new Date(Date.parse(auth.issuedAt) + 1000);
  const result = await executeTaskRegistration({ preparation: p, authorization: auth }, r.deps);
  const entry = { preparation: p, authorization: auth, result }, release = { sourceSha: 'b'.repeat(40), treeSha256: 'b'.repeat(64) };
  const plan = { errored: false, variables: { tooling_sha: { value: release.sourceSha } }, resource_changes: Object.entries(r.states).map(([address, after]) =>
    ({ address, mode: 'managed', change: { actions: ['no-op'], before: structuredClone(after), after: structuredClone(after), after_unknown: {} } })) };
  const impact = { imageReleaseSha: p.sourceSha, toolingSha: release.sourceSha, toolingInputTreeSha256: release.treeSha256,
    imageReuseCompatible: true, newImagesRequired: false, imageAffectingFiles: [] };
  const records = new Map(r.receipts.map(([, status, value]) => [status, value]));
  const reservation = { kind: 'STAGED_BROKER_RESERVATION', id, value: { purpose: TASK_REGISTRATION, nonce: auth.nonce, preparationSha256: brokerDigest(p) } };
  const deps = { verifyAuthorization: async () => true, authenticateTransactionSource: async original => assert.equal(original.sourceSha, 'a'.repeat(40)),
    readReceipt: async (_, status) => records.get(status), readReservation: async () => reservation };
  return { r, entry, release, plan, impact, deps, records, reservation };
}
test('current main explicitly adopts exact historical outputs without rewriting provenance or registering again', async () => {
  const x = await handoffRig(), before = structuredClone(x.entry);
  await authenticateRegistrationHandoffEvidence(x.entry, x.release, x.deps);
  const adopted = adoptRegisteredOutputs(x.entry, x.release, x.plan, x.impact);
  assertRegistrationHandoff(adopted, x.release);
  assert.deepEqual({ preparation: adopted.preparation, authorization: adopted.authorization, result: adopted.result }, before);
  assert.equal(adopted.result.sourceSha, 'a'.repeat(40)); assert.equal(adopted.adoption.release.sourceSha, 'b'.repeat(40));
  assert.deepEqual(adopted.result.taskMap, taskMapFromRegisteredDefinitions(before.result.definitions));
  assert.equal(x.r.writes(), 1);
  // A second tooling successor uses the same immutable transaction, not B's authority.
  const c = { sourceSha: 'c'.repeat(40), treeSha256: 'c'.repeat(64) };
  x.plan.variables.tooling_sha.value = c.sourceSha;
  const next = adoptRegisteredOutputs(x.entry, c, x.plan, { ...x.impact, toolingSha: c.sourceSha, toolingInputTreeSha256: c.treeSha256 });
  assert.equal(next.result.sourceSha, before.result.sourceSha); assert.equal(x.r.writes(), 1);
});
for (const [name, change] of [
  ['missing consumed reservation', x => x.deps.readReservation = async () => null],
  ['wrong reservation', x => x.reservation.value.nonce = 'wrong'],
  ['invalid original signature', x => x.deps.verifyAuthorization = async () => false],
  ['missing intent', x => x.records.delete('TASK_REGISTRATION_INTENT')],
  ['altered intent', x => x.records.get('TASK_REGISTRATION_INTENT').savedPlanSha256 = 'f'.repeat(64)],
  ['altered saved plan', x => x.entry.preparation.savedPlanSha256 = 'f'.repeat(64)],
  ['altered artifact set', x => x.entry.preparation.artifactSetSha256 = 'f'.repeat(64)],
  ['receipt from another transaction', x => x.entry.result.sourceSha = x.release.sourceSha],
  ['unauthenticated original source', x => x.deps.authenticateTransactionSource = async () => { throw new Error('wrong source'); }],
]) test(`historical adoption rejects ${name}`, async () => {
  const x = await handoffRig(); change(x);
  await assert.rejects(() => authenticateRegistrationHandoffEvidence(x.entry, x.release, x.deps)); assert.equal(x.r.writes(), 1);
});
for (const [name, change] of [
  ['changed image inputs', x => { x.impact.imageReuseCompatible = false; x.impact.imageAffectingFiles = ['backend/src/change.ts']; }],
  ['wrong compatibility source', x => x.impact.imageReleaseSha = x.release.sourceSha],
  ['wrong current-main tree', x => x.impact.toolingInputTreeSha256 = 'f'.repeat(64)],
  ['another successor ARN', x => x.plan.resource_changes[0].change.after.arn += '0'],
  ['changed image digest', x => { const c = x.plan.resource_changes[0].change; c.after.container_definitions = c.after.container_definitions.replace(/sha256:[a-f0-9]{64}/, `sha256:${'f'.repeat(64)}`); c.before = structuredClone(c.after); }],
  ['changed role', x => { const c = x.plan.resource_changes[0].change; c.after.task_role_arn += '-other'; c.before = structuredClone(c.after); }],
  ['changed command', x => { const c = x.plan.resource_changes[0].change; const containers = JSON.parse(c.after.container_definitions); containers[0].command = ['unexpected']; c.after.container_definitions = JSON.stringify(containers); c.before = structuredClone(c.after); }],
  ['registration required', x => x.plan.resource_changes[0].change.actions = ['create']],
  ['missing definition', x => x.plan.resource_changes.pop()],
  ['unknown definition', x => x.plan.resource_changes[0].change.after_unknown = { container_definitions: true }],
  ['partial registration', x => delete x.entry.result.definitions[TASK_REGISTRATION_ADDRESSES[0]]],
]) test(`current-main adoption rejects ${name}`, async () => {
  const x = await handoffRig(); change(x); assert.throws(() => adoptRegisteredOutputs(x.entry, x.release, x.plan, x.impact)); assert.equal(x.r.writes(), 1);
});
for (const [name, change] of [
  ['adoption omitted', entry => delete entry.adoption],
  ['new source substituted for old', entry => entry.result.sourceSha = entry.adoption.release.sourceSha],
  ['wrong original receipt hash', entry => entry.adoption.transaction.resultSha256 = 'f'.repeat(64)],
  ['wrong current release', entry => entry.adoption.release.sourceSha = 'f'.repeat(40)],
  ['wrong definitions hash', entry => entry.adoption.definitionsSha256 = 'f'.repeat(64)],
  ['unknown adoption field', entry => entry.adoption.allowMutation = true],
]) test(`handoff receipt substitution fails closed: ${name}`, async () => {
  const x = await handoffRig(), entry = adoptRegisteredOutputs(x.entry, x.release, x.plan, x.impact);
  change(entry); assert.throws(() => assertRegistrationHandoff(entry, x.release));
});

for (const field of ['preparation', 'authorization', 'planPath']) test(`adoption dispatch rejects mutation input ${field} before constructing an executor`, async () => {
  let called = false;
  await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration-adoption', [field]: {} },
    { adapterFactory: () => { called = true; throw new Error('must not execute'); } }));
  assert.equal(called, false);
});

test('pre-publication mismatch cannot be enabled with a caller boolean', async () => {
  let constructed = false;
  await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration', allowPrepublicationMismatch: true },
    { adapterFactory: () => { constructed = true; throw new Error('must reject before executor creation'); } }), /Unknown staged request field/);
  assert.equal(constructed, false);
});

test('fresh registration without receipt provenance retains the strict prerequisite reader', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-registration-strict-prerequisites-'));
  fs.chmodSync(directory, 0o700);
  try {
    const order = [], deps = { readCheckout: async () => ({ sourceSha: 'c'.repeat(40), treeSha256: 'c'.repeat(64) }),
      readPrerequisites: async () => { order.push('strict-live-reader'); throw new Error('policy/runtime task map mismatch'); },
      readRegistrationPreparationPredecessor: async () => { order.push('receipt-reader'); throw new Error('must not opt in implicitly'); } };
    await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration', directory },
      { adapterFactory: () => deps }), /policy\/runtime task map mismatch/);
    assert.deepEqual(order, ['strict-live-reader']);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('explicit receipt identities select only read-only pre-publication authentication before source guards', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-registration-predecessor-order-'));
  fs.chmodSync(directory, 0o700);
  try {
    const order = [], checkout = { sourceSha: '9fcb625c4174c4fd61c586601a84b243791a8bd5', treeSha256: 'c'.repeat(64) };
    const deps = { readCheckout: async () => checkout,
      readRegistrationPreparationPredecessor: async (ids, release) => {
        order.push('authenticate-receipt-predecessors');
        assert.deepEqual(ids, { registrationTransactionId: 'a'.repeat(64), policyTransactionId: 'b'.repeat(64) });
        assert.deepEqual(release, checkout); return { registrationPredecessor: {}, prerequisites: brokerPreparation().prerequisites };
      },
      readPrerequisites: async () => { order.push('ordinary-reader'); throw new Error('must use authenticated predecessor'); } };
    await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration', directory,
      files: { backendMetadata: path.join(directory, 'backend.json') }, terraformDataDir: directory,
      predecessorReceiptRecovery: { registrationTransactionId: 'a'.repeat(64), policyTransactionId: 'b'.repeat(64) } },
      { adapterFactory: () => deps }), /protected main|clean|checkout|commit/i);
    assert.deepEqual(order, ['authenticate-receipt-predecessors']);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('registration adoption authenticates its historical handoff before reading live prerequisites', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-registration-adoption-order-'));
  fs.chmodSync(directory, 0o700);
  try {
    const registration = (await handoffRig()).entry, order = [];
    const checkout = { sourceSha: 'c'.repeat(40), treeSha256: 'c'.repeat(64) };
    const deps = {
      readCheckout: async () => checkout,
      readRegistrationAdoptionPrerequisites: async (entry, current) => {
        order.push('authenticate-registration'); assert.deepEqual(entry, registration); assert.deepEqual(current, checkout);
        return brokerPreparation().prerequisites;
      },
      readPrerequisites: async () => { order.push('unauthenticated-prerequisites'); throw new Error('must not use alias task map'); },
    };
    await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration-adoption', directory,
      prerequisiteChain: { registration } }, { adapterFactory: () => deps }), /protected main|clean|checkout/i);
    assert.deepEqual(order, ['authenticate-registration']);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('registration adoption stops before live prerequisite read when historical authentication fails', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-registration-adoption-tamper-'));
  fs.chmodSync(directory, 0o700);
  try {
    const registration = (await handoffRig()).entry, order = [];
    const deps = {
      readCheckout: async () => ({ sourceSha: 'c'.repeat(40), treeSha256: 'c'.repeat(64) }),
      readRegistrationAdoptionPrerequisites: async () => { order.push('authenticate-registration'); throw new Error('historical registration evidence failed authentication'); },
      readPrerequisites: async () => { order.push('unauthenticated-prerequisites'); return brokerPreparation().prerequisites; },
    };
    await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-registration-adoption', directory,
      prerequisiteChain: { registration } }, { adapterFactory: () => deps }), /failed authentication/);
    assert.deepEqual(order, ['authenticate-registration']);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

test('normal policy preparation keeps using the strict ordinary prerequisite reader', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stage-b-policy-prerequisite-order-'));
  fs.chmodSync(directory, 0o700);
  try {
    const registration = (await handoffRig()).entry;
    let ordinaryRead = 0, adoptionRead = 0;
    const deps = {
      readCheckout: async () => ({ sourceSha: 'c'.repeat(40), treeSha256: 'c'.repeat(64) }),
      readPrerequisites: async () => { ordinaryRead++; return {}; },
      readRegistrationAdoptionPrerequisites: async () => { adoptionRead++; throw new Error('adoption reader must not be used'); },
    };
    await assert.rejects(() => runStagedBrokerRequest({ operation: 'prepare-policy', directory,
      prerequisiteChain: { registration } }, { adapterFactory: () => deps }), /Unknown\/missing staged broker fields/);
    assert.equal(ordinaryRead, 1); assert.equal(adoptionRead, 0);
  } finally { fs.rmSync(directory, { recursive: true }); }
});

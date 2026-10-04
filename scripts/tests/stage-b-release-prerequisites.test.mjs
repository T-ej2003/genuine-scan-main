import assert from 'node:assert/strict';
import test from 'node:test';
import { taskChange, rotationVariables } from './fixtures/stage-b-task-rotation.mjs';
import { canonicalBrokerPolicy } from './fixtures/staged-broker.mjs';
import { TASK_REGISTRATION, BROKER_POLICY_PRUNING, TASK_REGISTRATION_ADDRESSES, assertPrerequisitePlan, authenticateRegisteredDefinition, executeTaskRegistration, deriveBrokerPolicy, assertBrokerPolicyReconciliation, assertBrokerPolicyPruningPlan } from '../aws/stage-b-release-prerequisites.mjs';
import { brokerDigest, assertBrokerPublicationPlan } from '../aws/stage-b-staged-broker-contract.mjs';
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
for (const [name, mutate] of [
  ['remote mutation', r => r.refresh.resource_changes[0].change.actions = ['update']],
  ['unknown drift', r => r.refresh.resource_drift.push(structuredClone(r.refresh.resource_drift[0]))],
  ['wrong successor', r => r.refresh.resource_drift[0].change.after.policy = JSON.stringify(canonicalBrokerPolicy())],
  ['normal pending mutation', r => r.normal.resource_changes[0].change.actions = ['update']],
  ['unknown address', r => r.normal.resource_changes[0].address += '_other'],
  ['unknown value', r => r.normal.resource_changes[0].change.after_unknown = { policy: true }],
  ['wrong source', r => r.normal.variables.tooling_sha.value = 'b'.repeat(40)],
]) test(`IAM reconciliation rejects ${name}`, () => { const r = policyReconciliation(); mutate(r); assert.throws(() => assertBrokerPolicyReconciliation(r.refresh, r.normal, r.p)); });
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

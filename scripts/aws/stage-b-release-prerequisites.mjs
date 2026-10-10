import assert from 'node:assert/strict';
import { canonicalJson, STAGE_B, assertStageBBrokerTaskDefinitionMap } from './production-green-stage-b-contract.mjs';
import { STAGE_B_TASK_DEFINITION_FAMILIES, assertStageBTaskDefinitionRotation, canonicalizeEcsTaskDefinitionVolumes } from './stage-b-reference-audit-contract.mjs';
import { assertStageBBrokerPolicyDocument, STAGE_B_BROKER_POLICY } from './stage-b-deployment-contract.mjs';
import { brokerDigest, assertBrokerImageReuseCompatibility, assertRegistrationHandoff, assertBrokerAuthorization, assertBrokerPreparation } from './stage-b-staged-broker-contract.mjs';

export const TASK_REGISTRATION = 'STAGE_B_TASK_REGISTRATION';
export const BROKER_POLICY_CONVERGENCE = 'STAGE_B_BROKER_POLICY_CONVERGENCE';
export const BROKER_POLICY_PRUNING = 'STAGE_B_BROKER_POLICY_PRUNING';
const equal = (a, b, message) => assert.equal(canonicalJson(a), canonicalJson(b), message);
const known = value => value === false || value && typeof value === 'object' && Object.values(value).every(known);
const requireKnown = change => assert.ok(Object.values(change.after_unknown || {}).every(known), 'Unknown prerequisite value');
export const TASK_REGISTRATION_ADDRESSES = Object.freeze(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).sort());
export function assertBrokerPolicyPruningPlan(plan, preparation) {
  assert.equal(preparation.purpose, BROKER_POLICY_PRUNING);
  equal(plan, { purpose: BROKER_POLICY_PRUNING, sourceSha: preparation.sourceSha, policyArn: STAGE_B_BROKER_POLICY.arn,
    defaultVersionId: preparation.prerequisites.policyVersion, versionId: preparation.target.versionId,
    inventory: preparation.target.inventory, mutation: 'iam:DeletePolicyVersion' });
  assert.match(plan.versionId || '', /^v[1-9][0-9]*$/); assert.notEqual(plan.versionId, plan.defaultVersionId);
  assert.ok(Array.isArray(plan.inventory) && plan.inventory.length <= 5);
  for (const version of plan.inventory) {
    assert.match(version.VersionId || '', /^v[1-9][0-9]*$/);
    assert.equal(typeof version.IsDefaultVersion, 'boolean');
  }
  assert.equal(new Set(plan.inventory.map(v => v.VersionId)).size, plan.inventory.length);
  const selected = plan.inventory.find(v => v.VersionId === plan.versionId); assert.ok(selected); assert.equal(selected.IsDefaultVersion, false);
  const current = plan.inventory.filter(v => v.IsDefaultVersion); assert.equal(current.length, 1); assert.equal(current[0].VersionId, plan.defaultVersionId);
  return ['iam:DeletePolicyVersion'];
}
export function assertPrerequisitePlan(plan, preparation) {
  assert.equal(plan.variables.tooling_sha.value, preparation.sourceSha);
  assert.equal(plan.errored, false); assert.equal(plan.complete, false);
  assert.equal((plan.deferred_changes || []).length, 0); assert.equal((plan.resource_drift || []).length, 0);
  const changes = plan.resource_changes; assert.ok(Array.isArray(changes));
  assert.equal(new Set(changes.map(c => c.address)).size, changes.length);
  if (preparation.purpose === TASK_REGISTRATION) equal(changes.filter(c => TASK_REGISTRATION_ADDRESSES.includes(c.address)).map(c => c.address).sort(), TASK_REGISTRATION_ADDRESSES, 'Incomplete registration prerequisite census');
  for (const c of changes) {
    assert.ok(preparation.canonicalAddresses.includes(c.address)); assert.equal(c.mode, 'managed'); assert.equal(c.deposed, undefined);
    if (canonicalJson(c.change.actions) === '["no-op"]') { equal(c.change.before, c.change.after); requireKnown(c.change); continue; }
    if (preparation.purpose === TASK_REGISTRATION) {
      assert.ok(TASK_REGISTRATION_ADDRESSES.includes(c.address), 'Registration phase cannot mutate services, tasks, IAM or broker');
      assert.equal(c.change.after.skip_destroy, true, 'Registration must retain predecessors');
      assert.equal(c.change.before.skip_destroy, true, 'Registration cannot deregister its predecessor');
      assertStageBTaskDefinitionRotation(c, plan, { strict: true });
    } else {
      assert.equal(preparation.purpose, BROKER_POLICY_CONVERGENCE); assert.equal(c.address, 'aws_iam_policy.broker');
      equal(c.change.actions, ['update']); assert.equal(c.change.before.arn, STAGE_B_BROKER_POLICY.arn);
      assertStageBBrokerPolicyDocument(JSON.parse(c.change.before.policy));
      equal(JSON.parse(c.change.after.policy), preparation.target.policy);
      equal({ ...c.change.before, policy: c.change.after.policy }, c.change.after, 'Additional IAM attribute mutation');
      requireKnown(c.change);
    }
  }
  const mutations = changes.filter(c => canonicalJson(c.change.actions) !== '["no-op"]');
  if (preparation.purpose === BROKER_POLICY_CONVERGENCE) {
    assert.ok(mutations.length <= 1);
    const policy = changes.find(c => c.address === 'aws_iam_policy.broker'); assert.ok(policy);
    equal(JSON.parse(policy.change.after.policy), preparation.target.policy);
    if (!mutations.length) equal(preparation.prerequisites.policy, preparation.target.policy);
  } else assert.ok(mutations.length);
  return mutations.map(c => c.address).sort();
}

export function taskMapFromRegisteredDefinitions(definitions) {
  const map = Object.fromEntries(Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter(([address]) => address.includes('.executor[') || address.endsWith('candidate["canary"]'))
    .map(([address]) => [address.includes('.executor[') ? address.match(/\["([^"]+)"\]$/)[1] : 'full-rls-application-canary', definitions[address].arn]));
  assertStageBBrokerTaskDefinitionMap(map); return map;
}

export function deriveBrokerPolicy(predecessor, taskMap) {
  assertStageBBrokerPolicyDocument(predecessor); assertStageBBrokerTaskDefinitionMap(taskMap);
  const target = structuredClone(predecessor);
  target.Statement.find(s => s.Sid === 'RunOnlyApprovedExecutorAndCanaryRevisions').Resource = Object.keys(taskMap).sort().map(mode => taskMap[mode]);
  assertStageBBrokerPolicyDocument(target); return target;
}

export function assertBrokerPolicyClosurePlan(plan, preparation) {
    assert.equal(plan.errored, false); assert.equal(plan.complete, false);
    assert.equal(plan.variables.tooling_sha.value, preparation.sourceSha);
    assert.equal((plan.deferred_changes || []).length, 0);
    for (const output of Object.values(plan.output_changes || {})) {
      equal(output.actions, ['no-op']); equal(output.before, output.after);
      assert.ok(output.after_unknown === undefined || known(output.after_unknown), 'Unknown reconciliation output');
    }
    const changes = plan.resource_changes === undefined ? [] : plan.resource_changes;
    assert.ok(Array.isArray(changes), 'Terraform resource_changes must be an array when present');
    const drift = plan.resource_drift === undefined ? [] : plan.resource_drift;
    assert.ok(Array.isArray(drift), 'Terraform resource_drift must be an array when present');
    assert.equal(new Set(changes.map(c => c.address)).size, changes.length);
    for (const c of changes) {
      assert.ok(preparation.canonicalAddresses.includes(c.address)); assert.equal(c.mode, 'managed'); assert.equal(c.deposed, undefined);
      equal(c.change.actions, ['no-op']); equal(c.change.before, c.change.after); requireKnown(c.change);
    }
    const policy = changes.find(c => c.address === 'aws_iam_policy.broker')
      || drift.find(c => c.address === 'aws_iam_policy.broker'); assert.ok(policy);
    assert.equal(policy.change.after.arn, STAGE_B_BROKER_POLICY.arn);
    equal(JSON.parse(policy.change.after.policy), preparation.target.policy);
}
export function assertBrokerPolicyReconciliation(refresh, normal, preparation) {
  for (const plan of [refresh, normal]) assertBrokerPolicyClosurePlan(plan, preparation);
  const drift = refresh.resource_drift || []; assert.equal(drift.length, 1);
  const c = drift[0]; assert.equal(c.address, 'aws_iam_policy.broker'); assert.equal(c.type, 'aws_iam_policy');
  assert.equal(c.mode, 'managed'); assert.equal(c.deposed, undefined); equal(c.change.actions, ['update']); requireKnown(c.change);
  equal(JSON.parse(c.change.before.policy), preparation.prerequisites.policy);
  equal(JSON.parse(c.change.after.policy), preparation.target.policy);
  equal({ ...c.change.before, policy: c.change.after.policy }, c.change.after, 'Unapproved IAM state drift');
  assert.equal((normal.resource_drift || []).length, 0);
}

// Only these provider/API defaults are equivalent to an absent configuration.
const containerArrayDefaults = ['environment', 'mountPoints', 'portMappings', 'systemControls', 'volumesFrom'];
function canonicalContainers(value) {
  const containers = typeof value === 'string' ? JSON.parse(value) : structuredClone(value);
  assert.ok(Array.isArray(containers));
  assert.equal(new Set(containers.map(c => c.name)).size, containers.length, 'Duplicate container identity');
  return containers.map(c => {
    assert.equal(typeof c.name, 'string');
    for (const field of containerArrayDefaults) {
      if (c[field] == null) c[field] = [];
      assert.ok(Array.isArray(c[field]), `Invalid container ${field}`);
    }
    if (c.cpu == null) c.cpu = 0;
    for (const field of ['environment', 'secrets']) {
      if (c[field] === undefined) continue;
      assert.ok(Array.isArray(c[field]));
      assert.equal(new Set(c[field].map(e => e.name)).size, c[field].length, `Duplicate ${field} identity`);
      for (const entry of c[field]) assert.equal(typeof entry.name, 'string');
      c[field].sort((a, b) => a.name.localeCompare(b.name));
    }
    return c;
  });
}
function canonicalVolumes(value, aws = false) {
  const volumes = aws ? value.map(v => {
    assert.ok(v && typeof v === 'object' && !Array.isArray(v));
    assert.ok(Object.keys(v).every(k => ['name', 'host', 'configureAtLaunch'].includes(k)), 'Unapproved ECS volume field');
    if (v.host !== undefined) {
      assert.ok(v.host && typeof v.host === 'object' && !Array.isArray(v.host));
      assert.equal(Object.keys(v.host).length, 0, 'Only a structurally empty host is equivalent');
    }
    assert.ok(v.configureAtLaunch === undefined || v.configureAtLaunch === false, 'Unapproved launch configuration');
    return { name: v.name };
  }) : value;
  return canonicalizeEcsTaskDefinitionVolumes(volumes).sort((a, b) => a.name.localeCompare(b.name));
}
const absentMode = value => {
  assert.ok(value == null || typeof value === 'string', 'Invalid namespace mode');
  return value ?? '';
};
const faultInjection = value => {
  assert.ok(value == null || typeof value === 'boolean', 'Invalid fault-injection configuration');
  return value ?? false;
};
function canonicalDefinition(value) {
  const copy = structuredClone(value);
  copy.container_definitions = canonicalContainers(copy.container_definitions);
  copy.volume = canonicalVolumes(copy.volume ?? []);
  copy.enable_fault_injection = faultInjection(copy.enable_fault_injection);
  copy.ipc_mode = absentMode(copy.ipc_mode); copy.pid_mode = absentMode(copy.pid_mode);
  return copy;
}

// Identity outputs are checked structurally here and against exact live ECS in
// authenticateRegisteredDefinition. No other computed value supplies authority.
export function assertRegisteredTaskDefinitionState(desired, state, unknown) {
  const identities = ['arn', 'arn_without_revision', 'id', 'revision'];
  const identity = `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${desired.family}`;
  assert.ok(Number.isSafeInteger(state.revision) && state.revision > 0);
  assert.equal(state.arn, `${identity}:${state.revision}`);
  if (state.id !== undefined) assert.equal(state.id, desired.family);
  if (state.arn_without_revision !== undefined) assert.equal(state.arn_without_revision, identity);
  if (unknown !== undefined) {
    const check = (mask, path) => {
      if (mask === false) return;
      if (mask === true) {
        assert.ok(identities.includes(path) || path === 'enable_fault_injection' || /^volume\.\d+\.configure_at_launch$/.test(path), `Unapproved computed task field: ${path}`);
        return;
      }
      assert.ok(mask && typeof mask === 'object', 'Invalid computed-value mask');
      for (const [key, child] of Object.entries(mask)) {
        if (!path) assert.ok(Object.hasOwn(desired, key) || identities.includes(key) || key === 'enable_fault_injection', `Unknown provider field: ${key}`);
        check(child, path ? `${path}.${key}` : key);
      }
    };
    check(unknown, '');
  }
  const expected = structuredClone(desired);
  for (const key of identities) if (unknown?.[key] === true || unknown === undefined && expected[key] == null) {
    if (state[key] !== undefined) expected[key] = state[key];
  }
  equal(canonicalDefinition(state), canonicalDefinition(expected), 'Unexpected Terraform registration successor');
}

// Exact normalised input fields, shared with Terraform's canonical task templates.
// Concrete identity is taken from this execution's state/readback, never a family lookup.
export function authenticateRegisteredDefinition({ address, desired, observed, state }) {
  assert.equal(desired.family, STAGE_B_TASK_DEFINITION_FAMILIES[address]);
  const arn = observed.taskDefinitionArn;
  assert.match(arn || '', new RegExp(`^arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${desired.family}:[1-9][0-9]*$`));
  assert.equal(state.arn, arn); assert.equal(state.revision, observed.revision);
  assert.equal(arn.split(':').at(-1), String(observed.revision)); assert.equal(observed.status, 'ACTIVE');
  for (const [tf, aws] of [['family', 'family'], ['task_role_arn', 'taskRoleArn'], ['execution_role_arn', 'executionRoleArn'], ['network_mode', 'networkMode'], ['cpu', 'cpu'], ['memory', 'memory']]) {
    equal(desired[tf], observed[aws], `Registered definition mismatch: ${tf}`); equal(state[tf], desired[tf]);
  }
  equal([...desired.requires_compatibilities].sort(), [...observed.requiresCompatibilities].sort());
  const platform = Array.isArray(desired.runtime_platform) ? desired.runtime_platform[0] : desired.runtime_platform;
  equal(observed.runtimePlatform, { operatingSystemFamily: platform.operating_system_family, cpuArchitecture: platform.cpu_architecture });
  // Canonical Stage B volumes are empty named task-local volumes, not EFS/host mounts.
  equal(canonicalVolumes(observed.volumes, true), canonicalVolumes(desired.volume ?? []));
  equal(absentMode(observed.ipcMode), absentMode(desired.ipc_mode)); equal(absentMode(observed.pidMode), absentMode(desired.pid_mode));
  equal(faultInjection(observed.enableFaultInjection), faultInjection(desired.enable_fault_injection));
  assertRegisteredTaskDefinitionState(desired, state);
  assert.equal(observed.ephemeralStorage, undefined, 'Unreviewed ephemeral-storage configuration');
  equal(canonicalContainers(desired.container_definitions), canonicalContainers(observed.containerDefinitions), 'Registered executable container differs');
  equal(desired.tags, Object.fromEntries(observed.tags.map(t => [t.key, t.value])));
  return { arn, revision: observed.revision, definitionSha256: brokerDigest({ desired, observed }), desired: structuredClone(desired) };
}

// AWS CLI renders registeredAt in the runner's local timezone. Legacy signed
// receipts hashed that rendering, so authenticate the same instant in every
// valid UTC offset without changing any other observed field or receipt byte.
export function authenticateReceiptBoundRegisteredDefinition({ receipt, ...input }) {
  const authenticated = authenticateRegisteredDefinition(input);
  if (authenticated.definitionSha256 !== receipt.definitionSha256) {
    const timestamp = input.observed.registeredAt;
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(\.\d{6})([+-])(\d\d):(\d\d)$/.exec(timestamp || '');
    assert.ok(match, 'Receipt-bound ECS timestamp is not canonical');
    const instant = Date.parse(timestamp), offset = (match[3] === '-' ? -1 : 1) * (Number(match[4]) * 60 + Number(match[5]));
    assert.ok(Number.isFinite(instant) && offset >= -720 && offset <= 840 && offset % 15 === 0,
      'Receipt-bound ECS timestamp offset is invalid');
    const render = minutes => {
      const sign = minutes < 0 ? '-' : '+', absolute = Math.abs(minutes);
      return `${new Date(instant + minutes * 60_000).toISOString().slice(0, 19)}${match[2]}${sign}${String(Math.floor(absolute / 60)).padStart(2, '0')}:${String(absolute % 60).padStart(2, '0')}`;
    };
    assert.equal(render(offset), timestamp, 'Receipt-bound ECS timestamp instant is invalid');
    assert.ok(Array.from({ length: 105 }, (_, index) => -720 + index * 15).some(minutes =>
      brokerDigest({ desired: input.desired, observed: { ...input.observed, registeredAt: render(minutes) } }) === receipt.definitionSha256),
    'Registered definition differs from the signed receipt beyond timestamp timezone rendering');
    authenticated.definitionSha256 = receipt.definitionSha256;
  }
  return authenticated;
}

export async function executeTaskRegistration({ preparation: p, authorization }, deps) {
  const id = await deps.authenticatePrerequisiteAuthorization(p, authorization);
  assert.equal(p.purpose, TASK_REGISTRATION);
  const artifacts = await deps.readPlan();
  assert.equal(brokerDigest(artifacts.bytes), p.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), p.logicalPlanSha256);
  assert.equal(artifacts.artifactSetSha256, p.artifactSetSha256); const mutations = assertPrerequisitePlan(artifacts.plan, p);
  await deps.reserve(id, { purpose: p.purpose, nonce: authorization.nonce, preparationSha256: brokerDigest(p) });
  const authorizedAt = (deps.now?.() || new Date()).toISOString();
  await deps.record(id, 'TASK_REGISTRATION_INTENT', { savedPlanSha256: p.savedPlanSha256, authorizedAt });
  await deps.authenticatePrerequisiteAuthorization(p, authorization);
  // A thrown/uncertain apply remains reserved. Diagnosis cannot authorise a retry.
  await deps.applyTaskRegistration(artifacts.bytes);
  const definitions = {};
  for (const address of TASK_REGISTRATION_ADDRESSES) {
    const c = artifacts.plan.resource_changes.find(c => c.address === address); assert.ok(c, 'Incomplete task registration profile');
    const state = await deps.readRegisteredTaskDefinition(address);
    definitions[address] = authenticateRegisteredDefinition({ address, desired: c.change.after, state,
      observed: await deps.describeTaskDefinition(state.arn) });
  }
  const result = { schemaVersion: 1, status: 'REGISTERED_NONTERMINAL', sourceSha: p.sourceSha, treeSha256: p.treeSha256,
    authorizationSha256: id, preparationSha256: brokerDigest(p), savedPlanSha256: p.savedPlanSha256, authorizedAt, mutations, definitions,
    taskMap: taskMapFromRegisteredDefinitions(definitions),
    ...(p.schemaVersion === 3 ? { policyPredecessor: structuredClone(p.registrationPolicyPredecessor) } : {}) };
  await deps.record(id, 'TASK_REGISTERED', result); return result;
}

export function assertRegistrationRecoveryIdentity(identity, preparation) {
  assert.deepEqual(Object.keys(identity).sort(), ['mode', 'tooling', 'transaction']);
  assert.equal(identity.mode, 'READ_ONLY_EXACT_SUCCESSOR');
  for (const value of [identity.transaction, identity.tooling]) {
    assert.deepEqual(Object.keys(value).sort(), ['sourceSha', 'treeSha256']);
    assert.match(value.sourceSha || '', /^[a-f0-9]{40}$/);
    assert.match(value.treeSha256 || '', /^[a-f0-9]{64}$/);
  }
  equal(identity.transaction, { sourceSha: preparation.sourceSha, treeSha256: preparation.treeSha256 });
  return identity;
}

// Diagnosis consumes no new authority and never invokes Terraform apply/ECS writes.
export async function recoverTaskRegistration({ preparation: p, authorization }, deps) {
  assert.equal(p.purpose, TASK_REGISTRATION);
  const { id, authorizedAt } = await deps.authenticateRecoveryIntent('TASK_REGISTRATION_INTENT', { savedPlanSha256: p.savedPlanSha256 });
  assert.equal(id, brokerDigest(authorization));
  const artifacts = await deps.readPlan();
  assert.equal(brokerDigest(artifacts.bytes), p.savedPlanSha256); assert.equal(brokerDigest(artifacts.plan), p.logicalPlanSha256);
  assert.equal(artifacts.artifactSetSha256, p.artifactSetSha256);
  const mutations = assertPrerequisitePlan(artifacts.plan, p);
  const recovery = assertRegistrationRecoveryIdentity(await deps.authenticateRegistrationRecoveryIdentity(), p);
  equal(await deps.getAlias(), p.alias); equal(await deps.readPrerequisites(), p.prerequisites);
  const stateBefore = await deps.readStateIdentity();
  assert.equal(stateBefore.lineage, p.state.lineage); assert.ok(stateBefore.serial > p.state.serial, 'Registration predecessor has not observably completed');
  await deps.authenticateRegistrationState(artifacts.plan);
  const definitions = {};
  for (const address of TASK_REGISTRATION_ADDRESSES) {
    const c = artifacts.plan.resource_changes.find(c => c.address === address); assert.ok(c);
    const state = await deps.readRegisteredTaskDefinition(address);
    if (mutations.includes(address)) assert.notEqual(state.arn, c.change.before.arn, 'Partial/predecessor registration cannot authenticate success');
    else assert.equal(state.arn, c.change.after.arn);
    definitions[address] = authenticateRegisteredDefinition({ address, desired: c.change.after, state, observed: await deps.describeTaskDefinition(state.arn) });
  }
  equal(await deps.readStateIdentity(), stateBefore);
  equal(await deps.getAlias(), p.alias); equal(await deps.readPrerequisites(), p.prerequisites);
  const result = { schemaVersion: 1, status: 'REGISTERED_NONTERMINAL', sourceSha: p.sourceSha, treeSha256: p.treeSha256,
    authorizationSha256: id, preparationSha256: brokerDigest(p), savedPlanSha256: p.savedPlanSha256, authorizedAt, mutations, definitions,
    taskMap: taskMapFromRegisteredDefinitions(definitions),
    ...(p.schemaVersion === 3 ? { policyPredecessor: structuredClone(p.registrationPolicyPredecessor) } : {}) };
  equal(await deps.authenticateRegistrationRecoveryIdentity(), recovery);
  const persisted = await deps.readRecoveryReceipt(id, 'TASK_REGISTERED');
  if (persisted) {
    const { recovery: provenance, ...transaction } = persisted; equal(transaction, result);
    if (provenance !== undefined) { assertRegistrationRecoveryIdentity(provenance, p); equal(await deps.authenticateRegistrationRecoveryIdentity(provenance), provenance); }
    return persisted;
  }
  const recovered = { ...result, recovery };
  await deps.record(id, 'TASK_REGISTERED', recovered); return recovered;
}

// Pure semantic check; production supplies independently derived image-impact
// evidence and a fresh current-main diagnostic plan, never client assertions.
export function adoptRegisteredOutputs(entry, release, plan, imageImpact) {
  const { preparation: p, result } = entry;
  assert.notEqual(p.sourceSha, release.sourceSha, 'Same-main outputs need no adoption');
  assertBrokerImageReuseCompatibility(imageImpact, p.sourceSha, release);
  assert.equal(plan.variables.tooling_sha.value, release.sourceSha); assert.equal(plan.errored, false);
  equal(plan.deferred_changes || [], []);
  assert.ok(!(plan.resource_drift || []).some(c => TASK_REGISTRATION_ADDRESSES.includes(c.address)), 'Registration state drift');
  equal(Object.keys(result.definitions).sort(), TASK_REGISTRATION_ADDRESSES);
  equal(result.taskMap, taskMapFromRegisteredDefinitions(result.definitions));
  const changes = plan.resource_changes; assert.ok(Array.isArray(changes));
  assert.equal(new Set(changes.map(c => c.address)).size, changes.length);
  for (const address of TASK_REGISTRATION_ADDRESSES) {
    const c = changes.find(c => c.address === address); assert.ok(c, 'Incomplete current-main registration census');
    assert.equal(c.mode, 'managed'); assert.equal(c.deposed, undefined);
    equal(c.change.actions, ['no-op'], 'Current main requires different task definitions');
    equal(c.change.before, c.change.after); requireKnown(c.change);
    const definition = result.definitions[address]; assert.equal(c.change.after.arn, definition.arn);
    assertRegisteredTaskDefinitionState(definition.desired, c.change.after);
  }
  const adopted = { preparation: p, authorization: entry.authorization, result,
    adoption: { kind: 'REGISTERED_OUTPUT_ADOPTION', schemaVersion: 1,
      transaction: { sourceSha: p.sourceSha, treeSha256: p.treeSha256, preparationSha256: brokerDigest(p),
        authorizationSha256: brokerDigest(entry.authorization), resultSha256: brokerDigest(result) },
      release: structuredClone(release), imageImpactSha256: brokerDigest(imageImpact), definitionsSha256: brokerDigest(result.definitions) } };
  assertRegistrationHandoff(adopted, release); return adopted;
}

export async function authenticateRegistrationHandoffEvidence(entry, release, deps) {
  const { preparation: p, authorization: auth, result } = entry;
  assertBrokerPreparation(p); assert.equal(p.purpose, TASK_REGISTRATION);
  await deps.authenticateTransactionSource(p, result.recovery, release);
  const id = await assertBrokerAuthorization(auth, p, { verify: deps.verifyAuthorization, now: new Date(result.authorizedAt) });
  assert.equal(result.authorizationSha256, id); assert.equal(result.preparationSha256, brokerDigest(p));
  assert.equal(result.savedPlanSha256, p.savedPlanSha256); assert.equal(result.status, 'REGISTERED_NONTERMINAL');
  assert.equal(result.sourceSha, p.sourceSha); assert.equal(result.treeSha256, p.treeSha256);
  equal(await deps.readReceipt(id, 'TASK_REGISTERED'), result);
  equal(await deps.readReceipt(id, 'TASK_REGISTRATION_INTENT'), { savedPlanSha256: p.savedPlanSha256, authorizedAt: result.authorizedAt });
  equal(await deps.readReservation(id), { kind: 'STAGED_BROKER_RESERVATION', id,
    value: { purpose: TASK_REGISTRATION, nonce: auth.nonce, preparationSha256: brokerDigest(p) } });
  return id; // Historical consumed authority, never a new reservation or mutation.
}

import assert from "node:assert/strict";
import test from "node:test";
import { APP_ONLY, buildAppOnlyRegistrationRequest } from "../aws/production-app-only-contract.mjs";
import { assertUnavailableGreenBackend, certifyGreenBackendRecoveryPreDispatch, runGreenBackendHealthRecovery } from "../aws/production-green-backend-health-recovery.mjs";
import { assertCompletedBackendRecoveryEvidence, commitBackendRecoveryComponentState } from "../aws/commit-production-component-recovery-state.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";
import { createProductionComponentDeploymentState } from "../aws/production-component-deployment-state.mjs";

const oldDigest = `sha256:${"1".repeat(64)}`;
const newDigest = `sha256:${"2".repeat(64)}`;
const arn = `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task-definition/${APP_ONLY.family}:24`;
const deploymentId = "ecs-svc/100";
const at = "2026-10-23T10:00:00.000Z";
function fixture() {
  const definition = { taskDefinitionArn: arn, family: APP_ONLY.family, revision: 24, status: "ACTIVE",
    taskRoleArn: APP_ONLY.taskRoleArn, executionRoleArn: APP_ONLY.executionRoleArn, networkMode: "awsvpc",
    runtimePlatform: { cpuArchitecture: "X86_64", operatingSystemFamily: "LINUX" }, cpu: "2048", memory: "4096",
    containerDefinitions: [{ name: "backend", image: `${APP_ONLY.backendRepository}@${oldDigest}`, environment: [], secrets: [] }], tags: [] };
  const service = { serviceArn: APP_ONLY.serviceArn, clusterArn: APP_ONLY.clusterArn, serviceName: APP_ONLY.service,
    status: "ACTIVE", taskDefinition: arn, desiredCount: 2, runningCount: 0, pendingCount: 0,
    deployments: [{ id: deploymentId, status: "PRIMARY", rolloutState: "COMPLETED", taskDefinition: arn,
      failedTasks: 2, createdAt: at }], networkConfiguration: {}, loadBalancers: [] };
  const stoppedTaskFailures = [{ taskArn: `arn:aws:ecs:${APP_ONLY.region}:${APP_ONLY.account}:task/${APP_ONLY.cluster}/${"a".repeat(32)}`,
    taskDefinitionArn: arn, startedBy: deploymentId, desiredStatus: "STOPPED", lastStatus: "STOPPED",
    stopCode: "TaskFailedToStart", stoppedReason: `CannotPullContainerError: image ${oldDigest} not found`,
    containerReasons: [], createdAt: at, startedAt: at, stoppedAt: at }];
  return { service, currentTaskDefinition: definition, currentImageExists: false, stoppedTaskFailures,
    replacementImage: { exists: true, immutable: true, signatureValid: true, attestationValid: true,
      provenanceValid: true, criticalFindings: 0, repository: "mscqr-backend", digest: newDigest }, recoveryImageDigest: newDigest };
}

test("unavailable green predecessor permits only the exact image delta", () => {
  const input = fixture();
  const checked = assertUnavailableGreenBackend(input);
  assert.equal(checked.proof.deploymentId, deploymentId);
  assert.equal(checked.candidate.containerDefinitions[0].image, `${APP_ONLY.backendRepository}@${newDigest}`);
  assert.deepEqual(input.currentTaskDefinition.containerDefinitions[0].image, `${APP_ONLY.backendRepository}@${oldDigest}`);
});

test("green recovery binds all service settings, including new AWS fields", () => {
  const original = assertUnavailableGreenBackend(fixture()).serviceConfigurationSha256;
  const changed = fixture(); changed.service.enableExecuteCommand = true;
  assert.notEqual(assertUnavailableGreenBackend(changed).serviceConfigurationSha256, original);
});

for (const [name, change] of [
  ["partially serving", (value) => { value.service.runningCount = 1; }],
  ["pending", (value) => { value.service.pendingCount = 1; }],
  ["another deployment", (value) => { value.service.deployments.push({ id: "ecs-svc/200" }); }],
  ["changed deployment", (value) => { value.service.deployments[0].id = "ecs-svc/200"; }],
  ["image still exists", (value) => { value.currentImageExists = true; }],
  ["missing target", (value) => { value.replacementImage.exists = false; }],
  ["stopped task from another revision", (value) => { value.stoppedTaskFailures[0].taskDefinitionArn = arn.replace(":24", ":23"); }],
  ["unrelated stopped-task error", (value) => { value.stoppedTaskFailures[0].stoppedReason = "ResourceInitializationError"; }],
  ["unexpected family", (value) => { value.currentTaskDefinition.family = "mscqr-backend"; }],
]) test(`green recovery rejects ${name}`, () => {
  const input = fixture(); change(input);
  assert.throws(() => assertUnavailableGreenBackend(input));
});

function scenario({ loseRegisterResponse = false, loseUpdateResponse = false } = {}) {
  const failure = fixture();
  const checked = assertUnavailableGreenBackend(failure);
  const targetArn = arn.replace(":24", ":25");
  const targetDefinition = { ...checked.candidate, taskDefinitionArn: targetArn, family: APP_ONLY.family,
    revision: 25, status: "ACTIVE", tags: [] };
  const entries = new Map();
  const key = (operationId, phase) => `${operationId}:${phase}`;
  const store = {
    readOperation: async (operationId, phase) => entries.get(key(operationId, phase)) || null,
    writeOperation: async (operationId, phase, value) => { if (entries.has(key(operationId, phase))) throw new Error("Duplicate journal write"); entries.set(key(operationId, phase), structuredClone(value)); return true; },
    claimOperation: async (operationId, phase, value) => { if (entries.has(key(operationId, phase))) throw new Error("Concurrent claim"); entries.set(key(operationId, phase), structuredClone(value)); return true; },
  };
  let registered = false, registrations = 0, updates = 0;
  let service = structuredClone(failure.service);
  const input = { sourceSha: "a".repeat(40), taskDefinitionArn: arn, recoveryImageDigest: newDigest,
    candidateFingerprint: checked.fingerprint, serviceConfigurationSha256: checked.serviceConfigurationSha256,
    deploymentId, runtimeConsumabilitySha256: "8".repeat(64), approval: { authorizationSha256: "f".repeat(64) } };
  const adapters = {
    store,
    readFailure: async () => ({ ...failure, service: structuredClone(service) }),
    census: async () => registered ? [targetArn] : [],
    register: async () => { registrations++; registered = true; if (loseRegisterResponse) throw new Error("Lost RegisterTaskDefinition response"); return { taskDefinitionArn: targetArn }; },
    describe: async (value) => value === arn ? failure.currentTaskDefinition : targetDefinition,
    readService: async () => structuredClone(service),
    updateService: async () => { updates++; service = { ...service, taskDefinition: targetArn, runningCount: 2,
      deployments: [{ ...service.deployments[0], taskDefinition: targetArn, id: "ecs-svc/101", rolloutState: "COMPLETED" }] };
      if (loseUpdateResponse) throw new Error("Lost UpdateService response"); },
    verifyStable: async (value) => assert.equal(value, targetArn),
    verifyRegisteredRevision: async () => {},
    verifyHealth: async () => ({ healthy: true, dependencies: { database: "ready" } }),
    authorizePhase: async () => {},
    verifyDispatchedAuthorization: async () => {},
    validateRegistrationRequest: async (request) => { assert.deepEqual(request, buildAppOnlyRegistrationRequest(checked.candidate)); },
  };
  return { input, adapters, counts: () => ({ registrations, updates }), entries,
    live: () => ({ service: structuredClone(service), definition: structuredClone(targetDefinition),
      tasks: ["a", "b"].map((id) => ({ taskArn: `task-${id}`, clusterArn: APP_ONLY.clusterArn,
        group: `service:${APP_ONLY.service}`, taskDefinitionArn: targetArn, lastStatus: "RUNNING",
        healthStatus: "HEALTHY", startedBy: service.deployments[0].id,
        containers: [{ name: "backend", imageDigest: newDigest }] })) }) };
}

test("read-only certification authenticates fresh predecessor and never claims or mutates", async () => {
  const run = scenario();
  let checks = 0;
  const result = await certifyGreenBackendRecoveryPreDispatch(run.input, {
    readFailure: run.adapters.readFailure, readDefinition: run.adapters.describe,
    readOperation: run.adapters.store.readOperation,
    verifyAuthorization: async () => { checks++; },
    verifyRuntime: async () => ({ evidenceSha256: run.input.runtimeConsumabilitySha256 }),
    validateRegistrationRequest: run.adapters.validateRegistrationRequest,
  });
  assert.equal(result.status, "READ_ONLY_PRE_DISPATCH_VERIFIED");
  assert.equal(checks, 3);
  assert.equal(run.entries.size, 0);
  assert.deepEqual(run.counts(), { registrations: 0, updates: 0 });
});
test("invalid production ECS request fails before a durable registration dispatch claim", async () => {
  const run = scenario();
  run.adapters.validateRegistrationRequest = async () => { throw new Error("ECS input model rejected registration request"); };
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /ECS input model rejected/);
  assert.equal([...run.entries.keys()].some((key) => key.endsWith("BACKEND:REGISTER:DISPATCH")), false);
  assert.deepEqual(run.counts(), { registrations: 0, updates: 0 });
});

for (const [name, change, expected] of [
  ["expired approval", (value) => { value.verifyAuthorization = async () => { throw new Error("approval expired"); }; }, /approval expired/],
  ["lost image", (value) => { value.readFailure = async () => ({ ...await value.originalRead(), replacementImage: { exists: false } }); }, /replacement|image/i],
  ["service drift", (value) => { let count = 0; value.readFailure = async () => { const failure = await value.originalRead(); if (++count === 2) failure.service.networkConfiguration = { changed: true }; return failure; }; }, /changed during certification/],
  ["existing dispatch", (value) => { value.readOperation = async (_id, phase) => phase === "BACKEND:REGISTER:DISPATCH" ? { owner: "other" } : null; }, /requires governed native reconciliation/],
  ["runtime evidence substitution", (value) => { value.verifyRuntime = async () => ({ evidenceSha256: "9".repeat(64) }); }, /Runtime consumability evidence differs/],
  ["task-definition substitution", (value) => { value.readDefinition = async () => ({ ...await value.originalDefinition(arn), taskDefinitionArn: arn.replace(":24", ":23") }); }, /Expected values to be strictly equal/],
]) test(`read-only certification fails closed on ${name}`, async () => {
  const run = scenario();
  const value = { originalRead: run.adapters.readFailure, readFailure: run.adapters.readFailure,
    originalDefinition: run.adapters.describe, readDefinition: run.adapters.describe,
    readOperation: run.adapters.store.readOperation, verifyAuthorization: async () => {},
    verifyRuntime: async () => ({ evidenceSha256: run.input.runtimeConsumabilitySha256 }),
    validateRegistrationRequest: run.adapters.validateRegistrationRequest };
  change(value);
  await assert.rejects(certifyGreenBackendRecoveryPreDispatch(run.input, {
    readFailure: value.readFailure, readDefinition: value.readDefinition, readOperation: value.readOperation,
    verifyAuthorization: value.verifyAuthorization, verifyRuntime: value.verifyRuntime,
    validateRegistrationRequest: value.validateRegistrationRequest,
  }), expected);
  assert.equal(run.entries.size, 0);
  assert.deepEqual(run.counts(), { registrations: 0, updates: 0 });
});

async function componentCommitScenario() {
  const run = scenario();
  const result = await runGreenBackendHealthRecovery(run.input, run.adapters);
  const body = { schemaVersion: 1, kind: "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE",
    sourceSha: run.input.sourceSha, imageDigest: newDigest, originalTaskDefinitionArn: arn,
    targetTaskDefinitionArn: result.targetArn, operationId: result.operationId,
    candidateFingerprint: run.input.candidateFingerprint,
    completionSha256: canonicalSha256(result.completion), completion: result.completion };
  const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
  for (const phase of ["BACKEND:REGISTER", "BACKEND:UPDATE"]) {
    const dispatch = run.entries.get(`${result.operationId}:${phase}:DISPATCH`);
    run.entries.set(`${result.operationId}:BACKEND:AUTHORIZATION:${phase}:${dispatch.authorizationSha256}`, {
      phase, input: { sourceSha: run.input.sourceSha, recoveryImageDigest: newDigest,
        serviceConfigurationSha256: run.input.serviceConfigurationSha256,
        approval: { authorizationSha256: dispatch.authorizationSha256,
          serviceConfigurationSha256: run.input.serviceConfigurationSha256 } },
    });
  }
  const store = { readOperation: (operationId, phase) => run.entries.get(`${operationId}:${phase}`) || null };
  let state = createProductionComponentDeploymentState({ components: {
    backend: { sourceSha: "b".repeat(40), establishedThroughSha: "b".repeat(40), imageDigest: oldDigest,
      taskDefinitionArn: arn, desiredCount: 2 },
    frontend: { sourceSha: "b".repeat(40), establishedThroughSha: "b".repeat(40), imageDigest: oldDigest,
      taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-frontend:1", desiredCount: 2 },
    database: null, security: null } });
  let writes = 0;
  const client = { read: () => state, advance: (_before, next) => { writes++; state = next; } };
  let snapshot = run.live();
  const readers = { readLive: () => structuredClone(snapshot), readBackendImageSource: () => run.input.sourceSha };
  const commit = () => commitBackendRecoveryComponentState({ evidence, store, readers, client,
    isProtectedMainAncestor: () => true });
  return { run, evidence, store, readers, client, commit,
    change: (mutate) => mutate(snapshot), writes: () => writes };
}

test("component commit accepts only the exact authorized green service and is repeatable", async () => {
  const run = await componentCommitScenario();
  assert.equal(run.commit().state.components.backend.desiredCount, 2);
  assert.equal(run.writes(), 1);
  assert.equal(run.commit().alreadyCurrent, true);
  assert.equal(run.writes(), 1);
});

for (const [name, change] of [
  ["desired count", (value) => { value.service.desiredCount = 3; value.service.runningCount = 3;
    value.tasks.push({ ...value.tasks[0], taskArn: "task-c" }); }],
  ["deployment configuration", (value) => { value.service.deploymentConfiguration = { maximumPercent: 300 }; }],
  ["network configuration", (value) => { value.service.networkConfiguration = { awsvpcConfiguration: { subnets: ["subnet-unapproved"] } }; }],
  ["load balancers", (value) => { value.service.loadBalancers = [{ targetGroupArn: "unapproved" }]; }],
  ["new service field", (value) => { value.service.enableExecuteCommand = true; }],
  ["task definition", (value) => { value.service.taskDefinition = arn; }],
  ["image digest", (value) => { value.tasks[0].containers[0].imageDigest = oldDigest; }],
  ["unhealthy task", (value) => { value.tasks[0].healthStatus = "UNHEALTHY"; }],
]) test(`component commit rejects healthy-looking ${name} drift before state write`, async () => {
  const run = await componentCommitScenario();
  run.change(change);
  assert.throws(run.commit);
  assert.equal(run.writes(), 0);
});

test("component commit rejects malformed durable fingerprints and missing native receipt", async () => {
  for (const change of [
    (run) => { run.store.readOperation = (read => (id, phase) => phase === "BACKEND:PREDECESSOR"
      ? { ...read(id, phase), serviceConfigurationSha256: null } : read(id, phase))(run.store.readOperation); },
    (run) => { run.store.readOperation = (read => (id, phase) => phase === "BACKEND:UPDATE:COMPLETED"
      ? null : read(id, phase))(run.store.readOperation); },
  ]) {
    const run = await componentCommitScenario(); change(run);
    assert.throws(run.commit); assert.equal(run.writes(), 0);
  }
});

test("component commit rechecks ECS on concurrent mutation before CAS and after lost response", async () => {
  const concurrent = await componentCommitScenario();
  const original = concurrent.readers.readLive;
  let reads = 0;
  concurrent.readers.readLive = () => {
    const value = original();
    if (++reads > 1) value.service.networkConfiguration = { awsvpcConfiguration: { subnets: ["subnet-raced"] } };
    return value;
  };
  assert.throws(concurrent.commit, /service configuration changed/);
  assert.equal(concurrent.writes(), 0);

  const lost = await componentCommitScenario();
  const advance = lost.client.advance;
  lost.client.advance = (...args) => { advance(...args); throw new Error("component-state response lost"); };
  assert.throws(lost.commit, /response lost/);
  assert.equal(lost.writes(), 1);
  assert.equal(lost.commit().alreadyCurrent, true);
  assert.equal(lost.writes(), 1);
});

for (const loss of [{}, { loseRegisterResponse: true }, { loseUpdateResponse: true }])
  test(`green recovery reconciles native response loss ${JSON.stringify(loss)}`, async () => {
    const run = scenario(loss);
    if (loss.loseRegisterResponse || loss.loseUpdateResponse)
      await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /Lost/);
    const first = await runGreenBackendHealthRecovery(run.input, run.adapters);
    assert.equal(first.targetArn, arn.replace(":24", ":25"));
    assert.deepEqual(run.counts(), { registrations: 1, updates: 1 });
    const second = await runGreenBackendHealthRecovery(run.input, run.adapters);
    assert.equal(second.registrationReused, true);
    assert.equal(second.updateReused, true);
    assert.deepEqual(run.counts(), { registrations: 1, updates: 1 });
  });

test("crash after registration dispatch with no native revision fails closed", async () => {
  const run = scenario();
  run.adapters.register = async () => { throw new Error("Unknown RegisterTaskDefinition outcome"); };
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters));
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /OUTCOME_UNKNOWN/);
  assert.deepEqual(run.counts(), { registrations: 0, updates: 0 });
});

test("preparation registers once and normal-deployer resumes without list or registration rights", async () => {
  const run = scenario();
  const prepared = await runGreenBackendHealthRecovery(run.input, { ...run.adapters, stopAfterRegistration: true });
  assert.equal(prepared.targetArn, arn.replace(":24", ":25"));
  assert.deepEqual(run.counts(), { registrations: 1, updates: 0 });
  const execute = { ...run.adapters,
    census: async () => { throw new Error("normal-deployer may not list revisions"); },
    register: async () => { throw new Error("normal-deployer may not register"); } };
  const result = await runGreenBackendHealthRecovery(run.input, execute);
  assert.equal(result.registrationReused, true);
  assert.deepEqual(run.counts(), { registrations: 1, updates: 1 });
  const repeated = await runGreenBackendHealthRecovery(run.input, execute);
  assert.equal(repeated.updateReused, true);
  assert.deepEqual(run.counts(), { registrations: 1, updates: 1 });
});

test("a fresh phase authorization resumes a completed registration without replay", async () => {
  const run = scenario();
  let stop = true;
  const original = run.adapters.authorizePhase;
  run.adapters.authorizePhase = async (input, phase) => {
    if (phase === "BACKEND:UPDATE" && stop) throw new Error("approval expired before update");
    return original(input, phase);
  };
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /approval expired/);
  assert.deepEqual(run.counts(), { registrations: 1, updates: 0 });
  stop = false;
  run.input.approval.authorizationSha256 = "e".repeat(64);
  const resumed = await runGreenBackendHealthRecovery(run.input, run.adapters);
  assert.equal(resumed.registrationReused, true);
  assert.deepEqual(run.counts(), { registrations: 1, updates: 1 });
});

test("authorization expiry immediately before registration dispatch leaves no native claim", async () => {
  const run = scenario(); let checks = 0;
  run.adapters.authorizePhase = async (_input, phase) => {
    if (phase === "BACKEND:REGISTER" && ++checks === 2) throw new Error("approval expired before dispatch");
  };
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /approval expired/);
  assert.equal([...run.entries.keys()].some((key) => key.endsWith("BACKEND:REGISTER:DISPATCH")), false);
  assert.deepEqual(run.counts(), { registrations: 0, updates: 0 });
});

test("authorization expiry immediately before service update leaves registered revision reusable", async () => {
  const run = scenario(); let checks = 0;
  run.adapters.authorizePhase = async (_input, phase) => {
    if (phase === "BACKEND:UPDATE" && ++checks === 2) throw new Error("approval expired before update dispatch");
  };
  await assert.rejects(runGreenBackendHealthRecovery(run.input, run.adapters), /approval expired/);
  assert.equal([...run.entries.keys()].some((key) => key.endsWith("BACKEND:UPDATE:DISPATCH")), false);
  assert.deepEqual(run.counts(), { registrations: 1, updates: 0 });
});

test("forged green completion cannot advance component state without native journal", async () => {
  const run = scenario();
  const result = await runGreenBackendHealthRecovery(run.input, run.adapters);
  const body = { schemaVersion: 1, kind: "GREEN_BACKEND_HEALTH_RECOVERY_EVIDENCE",
    sourceSha: run.input.sourceSha, imageDigest: newDigest, originalTaskDefinitionArn: arn,
    targetTaskDefinitionArn: result.targetArn, operationId: result.operationId,
    candidateFingerprint: run.input.candidateFingerprint,
    completionSha256: canonicalSha256(result.completion), completion: result.completion };
  const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
  assert.doesNotThrow(() => assertCompletedBackendRecoveryEvidence(evidence));
  const broken = { ...evidence, completion: { ...evidence.completion, candidateFingerprint: "0".repeat(64) } };
  broken.completionSha256 = canonicalSha256(broken.completion);
  broken.evidenceSha256 = canonicalSha256(Object.fromEntries(Object.entries(broken).filter(([key]) => key !== "evidenceSha256")));
  assert.throws(() => assertCompletedBackendRecoveryEvidence(broken));
  assert.throws(() => commitBackendRecoveryComponentState({ evidence, store: { readOperation: () => null },
    client: { read: () => assert.fail("component state read reached") } }), /durable completion/);
});

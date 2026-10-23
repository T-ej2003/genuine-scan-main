import assert from "node:assert/strict";
import test from "node:test";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { assertUnavailableGreenBackend, runGreenBackendHealthRecovery } from "../aws/production-green-backend-health-recovery.mjs";
import { assertCompletedBackendRecoveryEvidence, commitBackendRecoveryComponentState } from "../aws/commit-production-component-recovery-state.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

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
    deploymentId, approval: { authorizationSha256: "f".repeat(64) } };
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
  };
  return { input, adapters, counts: () => ({ registrations, updates }), entries };
}

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

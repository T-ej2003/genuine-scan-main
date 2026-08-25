import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  BACKEND_HEALTH_RECOVERY,
  assertLegacyBackendRecoveryCandidate,
  assertLegacyBackendRecoveryEvidence,
  assertLegacyBackendRecoveryEligibility,
  buildLegacyBackendRecoveryCandidate,
  createLegacyBackendRecoveryAuthorization,
  runLegacyBackendHealthRecovery as runRecoveryContract,
} from "../aws/production-backend-health-recovery-contract.mjs";
import { canonicalSha256, taskDefinitionFingerprint } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";
import { classifyRollbackViability } from "../aws/production-ecs-rollback-viability.mjs";

const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const digest = "sha256:3dbd02136a99d1741fdfa655397a661fa2275812e1cad0675c93fc5c7c4b4477";
const now = new Date("2026-08-20T18:00:00.000Z");
const githubContext = { repository: "T-ej2003/genuine-scan-main", workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", eventName: "workflow_dispatch", workflowRunId: "123", workflowRunAttempt: "1", githubActions: "true", now };
const environmentApproval = createProductionEnvironmentApprovalEvidence({
  repository: githubContext.repository, environment: "production", sourceSha, workflowRunId: githubContext.workflowRunId,
  workflowRef: githubContext.workflowRef, eventName: githubContext.eventName, workflowRunAttempt: githubContext.workflowRunAttempt, executionActor: "release-operator", observedAt: now.toISOString(),
  environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "security-reviewer" } }] }] },
});
const current = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const artifactSigningBindings = Object.freeze({
  ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-key-current-AbCd12",
  ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/active-key-version-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEYS_JSON: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-keys-json-AbCd12",
});
const artifactSigningBindingSha256 = "7".repeat(64);
const runtimeConsumabilitySha256 = "8".repeat(64);
const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha, imageDigests: {
  backend: digest,
  worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
  "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
  "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
} });
const approval = {
  ticket: "INC-BACKEND-IMAGE-0001", approvedBy: "security-reviewer", approverRole: "Security Lead",
  reason: "Restore backend health so canonical dual-slot rotation can run", verificationRef: "https://example.invalid/recovery/1",
  sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
  runtimeConsumabilitySha256,
};
const authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, approval });
const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha: imageFixture.imageReleaseSha, artifactSigningBindings });
const failedDeploymentId = "ecs-svc/3599551810517927503";
const stoppedTaskFailure = ({ taskDefinitionArn = current.taskDefinition.taskDefinitionArn, startedBy = failedDeploymentId,
  reason = `TaskFailedToStart: CannotPullContainerError: image ${current.taskDefinition.containerDefinitions[0].image} not found`, suffix = "1" } = {}) => ({
  taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${suffix.padStart(32, "0")}`,
  taskDefinitionArn, startedBy, desiredStatus: "STOPPED", lastStatus: "STOPPED", stopCode: "TaskFailedToStart",
  stoppedReason: reason, containerReasons: [reason], createdAt: "2026-08-24T18:00:00.000Z",
  startedAt: "2026-08-24T18:00:01.000Z", stoppedAt: "2026-08-24T18:00:02.000Z",
});
const base = () => ({
  sourceSha,
  service: { serviceArn: `arn:aws:ecs:eu-west-2:368992683803:service/${BACKEND_HEALTH_RECOVERY.cluster}/${BACKEND_HEALTH_RECOVERY.service}`, clusterArn: `arn:aws:ecs:eu-west-2:368992683803:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`, serviceName: BACKEND_HEALTH_RECOVERY.service, taskDefinition: current.taskDefinition.taskDefinitionArn, desiredCount: 2, runningCount: 0, pendingCount: 0, deployments: [{ id: failedDeploymentId, status: "PRIMARY", taskDefinition: current.taskDefinition.taskDefinitionArn, rolloutState: "FAILED", failedTasks: 2, createdAt: "2026-08-24T17:59:00.000Z" }], networkConfiguration: { awsvpcConfiguration: { subnets: ["subnet-fixture"], securityGroups: ["sg-fixture"], assignPublicIp: "DISABLED" } }, loadBalancers: [{ targetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/fixture/123", containerName: "backend", containerPort: 4000 }] },
  currentTaskDefinition: structuredClone(current),
  currentImageExists: false,
  stoppedTaskFailures: [stoppedTaskFailure()],
  replacementImage: { exists: true, immutable: true, signatureValid: true, attestationValid: true, provenanceValid: true, criticalFindings: 0, repository: "mscqr-backend", digest },
  authorization,
  imageAuthorization: imageFixture.authorization,
  imageValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence },
  environmentApproval,
  artifactSigningBindings,
  artifactSigningBindingSha256,
  runtimeConsumabilitySha256,
  githubContext: { ...githubContext },
  executionActor: "release-operator",
  candidate: structuredClone(candidate),
});
const healthy = Object.freeze({ healthy: true, success: true, status: "ready" });
const runtimeClosure = Object.freeze({ status: "PASS", evidenceSha256: runtimeConsumabilitySha256, liveVerifiedAt: new Date().toISOString() });
const runLegacyBackendHealthRecovery = (input, adapters) => runRecoveryContract(input, {
  record: async () => {}, verifyRuntimeClosure: async () => runtimeClosure,
  readLegacyFailureState: async () => ({ service: input.service, stoppedTaskFailures: input.stoppedTaskFailures, census: await adapters.census() }),
  ...adapters,
});
const readMissingImageFailureState = (input, census) => async () => ({ service: input.service, stoppedTaskFailures: input.stoppedTaskFailures, census: await census() });
const rollbackProof = ({ rollbackDeploymentArn, rollbackServiceRevisionArn, rollbackTaskDefinitionArn, rollbackDigest, forwardTaskDefinitionArn, forwardTaskDefinitionFingerprint = "f".repeat(64), forwardDigest = digest } = {}) => {
  const forwardServiceRevisionArn = rollbackServiceRevisionArn.replace("minus-1", "failed-forward");
  const rollbackEcsServiceDeploymentId = "ecs-svc/3599551810517927503";
  const rollbackEcsServiceDeployment = { id: rollbackEcsServiceDeploymentId, status: "PRIMARY", taskDefinition: rollbackTaskDefinitionArn };
  const rollbackStartedAt = "2026-08-24T09:59:00.000Z";
  const resolved = (serviceRevisionArn, taskDefinitionArn, imageDigest, imageExists, fingerprint = "e".repeat(64)) => ({ serviceRevisionArn, taskDefinitionArn, taskDefinitionFingerprint: fingerprint, digest: imageDigest, repository: "mscqr-backend", imageExists, imageFailure: null });
  const rollbackTarget = resolved(rollbackServiceRevisionArn, rollbackTaskDefinitionArn, rollbackDigest, false);
  return classifyRollbackViability({
    service: { serviceArn: `arn:aws:ecs:eu-west-2:368992683803:service/${BACKEND_HEALTH_RECOVERY.cluster}/${BACKEND_HEALTH_RECOVERY.service}`, taskDefinition: rollbackTaskDefinitionArn, desiredCount: 2, runningCount: 0, pendingCount: 0, deployments: [rollbackEcsServiceDeployment] },
    deployment: { serviceDeploymentArn: rollbackDeploymentArn, status: "ROLLBACK_IN_PROGRESS", targetServiceRevision: { arn: forwardServiceRevisionArn }, sourceServiceRevisions: [{ arn: rollbackServiceRevisionArn }], rollback: { serviceRevisionArn: rollbackServiceRevisionArn, startedAt: rollbackStartedAt } },
    forwardTarget: resolved(forwardServiceRevisionArn, forwardTaskDefinitionArn, forwardDigest, true, forwardTaskDefinitionFingerprint),
    sourceRevisions: [rollbackTarget], rollbackTarget,
    taskAttempts: [1, 2].map((n) => ({ taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${`${n}`.padStart(32, "0")}`, startedBy: rollbackEcsServiceDeploymentId,
      taskDefinitionArn: rollbackTaskDefinitionArn, classification: "CANNOT_PULL_IMAGE", errorCode: "CannotPullContainerError", digest: rollbackDigest, failureReasonSha256: `${n}`.repeat(64),
      createdAt: `2026-08-24T10:0${n}:00.000Z`, stoppedAt: `2026-08-24T10:0${n}:30.000Z` })),
    observationStart: "2026-08-24T10:00:00.000Z", observationEnd: "2026-08-24T10:01:00.000Z",
  });
};

const mutate = (path, value) => {
  const input = base();
  const keys = path.split(".");
  let target = input;
  for (const key of keys.slice(0, -1)) target = target[key];
  target[keys.at(-1)] = value;
  return input;
};

test("real legacy :47 fixture permits only image and source identity replacement", () => {
  const result = assertLegacyBackendRecoveryEligibility(base());
  assert.equal(result.currentTaskDefinitionArn, current.taskDefinition.taskDefinitionArn);
  assert.equal(result.recoveryImageDigest, digest);
  const backend = candidate.containerDefinitions.find(({ name }) => name === "backend");
  assert.equal(backend.image.endsWith(`@${digest}`), true);
  assert.deepEqual(backend.secrets.slice(0, -4), current.taskDefinition.containerDefinitions[0].secrets);
  assert.equal(backend.environment.length, 44);
  assert.equal(backend.secrets.length, 18);
  assert.deepEqual(Object.fromEntries(backend.secrets.slice(-4).map(({ name, valueFrom }) => [name, valueFrom])), artifactSigningBindings);
  assert.equal(candidate.taskRoleArn, current.taskDefinition.taskRoleArn);
  assert.equal(candidate.executionRoleArn, current.taskDefinition.executionRoleArn);
});

test("legacy source receives exactly four authenticated secret bindings and rejects every binding expansion", () => {
  const sourceBackend = current.taskDefinition.containerDefinitions[0];
  assert.equal(sourceBackend.secrets.some(({ name }) => name.startsWith("ARTIFACT_SIGN_")), false);
  assert.equal(candidate.containerDefinitions[0].environment.some(({ name }) => name.startsWith("ARTIFACT_SIGN_")), false);
  for (const mutateBindings of [
    (value) => { delete value.ARTIFACT_SIGN_PUBLIC_KEYS_JSON; },
    (value) => { value.UNRELATED_FIFTH_BINDING = value.ARTIFACT_SIGN_PUBLIC_KEYS_JSON; },
    (value) => { value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = "plaintext-private-key"; },
    (value) => { value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT.replace("private-key-current", "unapproved-key"); },
    (value) => { value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = value.ARTIFACT_SIGN_PUBLIC_KEY_CURRENT; },
    (value) => { value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT.replace("368992683803", "111111111111"); },
    (value) => { value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT = value.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT.replace("eu-west-2", "us-east-1"); },
  ]) {
    const bindings = structuredClone(artifactSigningBindings);
    mutateBindings(bindings);
    assert.throws(() => buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha: sourceSha, artifactSigningBindings: bindings }), /artifact-signing bindings/);
  }
  for (const [location, entry] of [
    ["environment", { name: "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", value: "plaintext" }],
    ["secrets", { name: "ARTIFACT_SIGN_PRIVATE_KEY_CURRENT", valueFrom: artifactSigningBindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT }],
  ]) {
    const source = structuredClone(current);
    source.taskDefinition.containerDefinitions[0][location].push(entry);
    assert.throws(() => buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: source, recoveryImageDigest: digest, imageReleaseSha: sourceSha, artifactSigningBindings }), /plaintext|partial|duplicate/);
  }
  const override = structuredClone(candidate);
  override.containerDefinitions[0].secrets.find(({ name }) => name === "ARTIFACT_SIGN_PUBLIC_KEY_CURRENT").valueFrom += "-caller";
  assert.throws(() => assertLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, candidate: override, recoveryImageDigest: digest, imageReleaseSha: sourceSha, artifactSigningBindings }), /outside the exact/);
});

test("optional legacy secrets normalize without changing existing entries", () => {
  for (const secrets of [undefined, []]) {
    const source = structuredClone(current);
    source.taskDefinition.containerDefinitions[0].secrets = secrets;
    if (secrets === undefined) delete source.taskDefinition.containerDefinitions[0].secrets;
    const rendered = buildLegacyBackendRecoveryCandidate({
      currentTaskDefinition: source,
      recoveryImageDigest: digest,
      imageReleaseSha: sourceSha,
      artifactSigningBindings,
    });
    assert.deepEqual(rendered.containerDefinitions[0].secrets, Object.entries(artifactSigningBindings).map(([name, valueFrom]) => ({ name, valueFrom })));
  }
  assert.deepEqual(candidate.containerDefinitions[0].secrets.slice(0, -4), current.taskDefinition.containerDefinitions[0].secrets);
});

test("production failure fixture lacks startup prerequisites while corrected candidate supplies every required binding", () => {
  const runtimeSource = fs.readFileSync(new URL("../../backend/src/index.ts", import.meta.url), "utf8");
  const legacy = new Set(current.taskDefinition.containerDefinitions[0].secrets.map(({ name }) => name));
  const corrected = new Set(candidate.containerDefinitions[0].secrets.map(({ name }) => name));
  for (const name of Object.keys(artifactSigningBindings)) {
    assert.match(runtimeSource, new RegExp(`process\\.env\\.${name}`));
    assert.equal(legacy.has(name), false);
    assert.equal(corrected.has(name), true);
  }
});

test("authenticated terminal :49-style runtime failure is reconciled but never reused", async () => {
  const failed = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", revision: 49, status: "ACTIVE" }, tags: [] };
  const predecessor = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", revision: 48, status: "ACTIVE", cpu: "1024" }, tags: [] };
  const failedRecoveryEvidenceSha256 = "c".repeat(64);
  const failedRecoveryEvidenceReferenceSha256 = "d".repeat(64);
  const failedFingerprint = taskDefinitionFingerprint(failed, []);
  const predecessorRevision = { repository: "T-ej2003/genuine-scan-main", workflowRunId: "32759665989", sourceSha: "b".repeat(40), service: BACKEND_HEALTH_RECOVERY.service, releaseMode: BACKEND_HEALTH_RECOVERY.kind,
    taskDefinitionArn: predecessor.taskDefinition.taskDefinitionArn, taskDefinitionFingerprint: taskDefinitionFingerprint(predecessor, []), classification: "AUTHENTICATED_LEGACY_PREDECESSOR",
    evidenceContract: "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE", evidenceFileSha256: "a".repeat(64), terminalTaskDefinitionArn: failed.taskDefinition.taskDefinitionArn };
  const terminalRevision = { repository: "T-ej2003/genuine-scan-main", taskDefinitionArn: failed.taskDefinition.taskDefinitionArn, candidateFingerprint: failedFingerprint, taskDefinitionFingerprint: failedFingerprint, evidenceFileSha256: "a".repeat(64), workflowRunId: "32759665989", workflowCreatedAt: "2026-08-24T17:53:00.000Z", status: "SERVICE_STABILIZATION_FAILED", classification: "TERMINAL_FAILURE", failureClassification: "SERVICE_STABILIZATION_FAILED", sourceSha: "b".repeat(40), service: BACKEND_HEALTH_RECOVERY.service, releaseMode: BACKEND_HEALTH_RECOVERY.kind, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageReleaseSha: "b".repeat(40), artifactSigningBindingSha256, runtimeConsumabilitySha256: null, predecessorHistoryReferenceSha256: null, predecessorHistoryLineageSha256: null, initialRevisionCensusSha256: null, expectedRevisionCensusSha256: null, registrations: 1, updates: 1, evidenceContract: "PRE_RUNTIME_CLOSURE_LEGACY_EVIDENCE", requiresLiveFailureReconciliation: true, authenticatedLegacyPredecessors: [predecessorRevision] };
  const knownFailedRevisions = [predecessorRevision, terminalRevision];
  const boundApproval = { ...approval, failedRecoveryEvidenceSha256, failedRecoveryEvidenceReferenceSha256 };
  const boundAuthorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256, failedRecoveryEvidenceReferenceSha256, approval: boundApproval });
  const input = base(); input.authorization = boundAuthorization; input.authenticatedFailedRecoveryEvidence = { envelopeSha256: failedRecoveryEvidenceSha256, referenceSha256: failedRecoveryEvidenceReferenceSha256, recoveryHistory: [terminalRevision], knownFailedRevisions, interruptedRecoveries: [] }; input.service.taskDefinition = failed.taskDefinition.taskDefinitionArn; input.service.deployments = [{ id: failedDeploymentId, status: "PRIMARY", taskDefinition: failed.taskDefinition.taskDefinitionArn, rolloutState: "FAILED", failedTasks: 6, createdAt: "2026-08-24T17:59:00.000Z" }]; input.currentImageExists = true; input.stoppedTaskFailures = [stoppedTaskFailure({ taskDefinitionArn: failed.taskDefinition.taskDefinitionArn, reason: "ResourceInitializationError: execution role denied exact runtime secret" })];
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50";
  const target = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 50, status: "ACTIVE" }, tags: [] };
  let registered = 0; let updated = 0; let serviceTarget = failed.taskDefinition.taskDefinitionArn;
  const result = await runLegacyBackendHealthRecovery(input, {
    census: async () => [current, predecessor, failed, ...(registered ? [target] : [])],
    register: async () => { registered += 1; return target; }, describe: async () => target,
    readService: async () => ({ ...input.service, taskDefinition: serviceTarget, runningCount: serviceTarget === targetArn ? 2 : 0, pendingCount: 0 }),
    readLegacyFailureState: async () => ({ service: input.service, stoppedTaskFailures: input.stoppedTaskFailures, census: [current, predecessor, failed, ...(registered ? [target] : [])] }),
    updateService: async (arn) => { updated += 1; serviceTarget = arn; }, waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
  });
  assert.equal(result.targetArn, targetArn); assert.equal(registered, 1); assert.equal(updated, 1); assert.notEqual(result.targetArn, failed.taskDefinition.taskDefinitionArn);

  for (const boundary of ["registration", "update"]) {
    let attempts = 0; let registrations = 0; let updates = 0;
    const changedDeployment = { ...input.service, deployments: [{ ...input.service.deployments[0], id: "ecs-svc/4599551810517927504", createdAt: "2026-08-24T18:01:00.000Z" }] };
    await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
      census: async () => [current, predecessor, failed, ...(registrations ? [target] : [])],
      register: async () => { registrations += 1; return target; }, describe: async () => target,
      readService: async () => input.service,
      readLegacyFailureState: async () => {
        attempts += 1;
        const changed = boundary === "registration" || attempts > 1;
        return { service: changed ? changedDeployment : input.service, stoppedTaskFailures: input.stoppedTaskFailures, census: [current, predecessor, failed, ...(registrations ? [target] : [])] };
      },
      updateService: async () => { updates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /deployment proof changed|degradation is not authenticated/);
    assert.deepEqual({ registrations, updates }, boundary === "registration" ? { registrations: 0, updates: 0 } : { registrations: 1, updates: 0 });
  }
  let forceDeploymentRegistrations = 0;
  const forceDeployment = { ...input.service, deployments: [...input.service.deployments, { ...input.service.deployments[0], id: "ecs-svc/5599551810517927505", status: "PRIMARY", rolloutState: "IN_PROGRESS", failedTasks: 0, createdAt: "2026-08-24T18:02:00.000Z" }] };
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [current, predecessor, failed], register: async () => { forceDeploymentRegistrations += 1; return target; }, describe: async () => target,
    readService: async () => input.service,
    readLegacyFailureState: async () => ({ service: forceDeployment, stoppedTaskFailures: input.stoppedTaskFailures, census: [current, predecessor, failed] }),
    updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /deployment proof changed/);
  assert.equal(forceDeploymentRegistrations, 0);
  let disappearedRegistrations = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [current, predecessor, failed], register: async () => { disappearedRegistrations += 1; return target; }, describe: async () => target,
    readService: async () => input.service,
    readLegacyFailureState: async () => ({ service: input.service, stoppedTaskFailures: [], census: [current, predecessor, failed] }),
    updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /degradation is not authenticated|deployment proof changed/);
  assert.equal(disappearedRegistrations, 0);

  for (const changed of [
    { stoppedTaskFailures: [stoppedTaskFailure({ taskDefinitionArn: current.taskDefinition.taskDefinitionArn, reason: "ResourceInitializationError: old :47 failure" })] },
    { stoppedTaskFailures: [stoppedTaskFailure({ taskDefinitionArn: failed.taskDefinition.taskDefinitionArn, startedBy: "ecs-svc/999", reason: "ResourceInitializationError: wrong deployment" })] },
    { stoppedTaskFailures: [], serviceEvents: [{ message: "ResourceInitializationError: historical event" }] },
  ]) assert.throws(() => assertLegacyBackendRecoveryEligibility({ ...input, ...changed }), /degradation is not authenticated/);

  assert.throws(() => assertLegacyBackendRecoveryEligibility({ ...input, service: { ...input.service, runningCount: 2 }, stoppedTaskFailures: [stoppedTaskFailure({ taskDefinitionArn: current.taskDefinition.taskDefinitionArn, reason: "ResourceInitializationError: historical" })] }), /degradation is not authenticated/);

  await assert.rejects(() => runLegacyBackendHealthRecovery({ ...input, service: { ...input.service, deployments: [] } }, {
    census: async () => [current, predecessor, failed], register: async () => {}, describe: async () => target, readService: async () => input.service,
    updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /unavailable approved terminal recovery failure/);

  for (const state of [{ runningCount: 1, pendingCount: 0 }, { runningCount: 0, pendingCount: 1 }]) {
    const unsafe = { ...input, service: { ...input.service, ...state } };
    await assert.rejects(() => runLegacyBackendHealthRecovery(unsafe, {
      census: async () => [current, predecessor, failed], verifyRuntimeClosure: async () => runtimeClosure,
      register: async () => {}, describe: async () => target, readService: async () => unsafe.service,
      updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy, record: async () => {},
    }), /unavailable approved terminal recovery failure/);
  }
});

test("authenticated mutation interruptions are reconciled from live ECS state before eligibility", async (t) => {
  const interruptedArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49";
  const recoveredArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:50";
  const interrupted = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: interruptedArn, revision: 49, status: "ACTIVE" }, tags: [] };
  const recovered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: recoveredArn, revision: 50, status: "ACTIVE" }, tags: [] };
  const identities = (items) => items.map((item) => ({ taskDefinitionArn: item.taskDefinition.taskDefinitionArn, taskDefinitionFingerprint: taskDefinitionFingerprint(item, item.tags || []) })).sort((a, b) => a.taskDefinitionArn.localeCompare(b.taskDefinitionArn));
  const initialRevisionCensusSha256 = canonicalSha256(identities([current]));
  const expectedRevisionCensusSha256 = canonicalSha256(identities([current, interrupted]));
  const failedRecoveryEvidenceSha256 = "c".repeat(64);
  const failedRecoveryEvidenceReferenceSha256 = "d".repeat(64);
  const makeInterruption = (status = "SERVICE_UPDATE_CONFIRMED") => ({
    repository: "T-ej2003/genuine-scan-main", workflowRunId: "32759665989", sourceSha, service: BACKEND_HEALTH_RECOVERY.service,
    releaseMode: BACKEND_HEALTH_RECOVERY.kind, taskDefinitionArn: interruptedArn, candidateFingerprint: taskDefinitionFingerprint(interrupted, []), taskDefinitionFingerprint: taskDefinitionFingerprint(interrupted, []),
    recoveryImageDigest: digest, artifactSigningBindingSha256, runtimeConsumabilitySha256, predecessorHistoryReferenceSha256: null, status, classification: "INTERRUPTED_MUTATION", failureClassification: null,
    currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, initialRevisionCensusSha256, expectedRevisionCensusSha256,
    registrations: 1, updates: status === "SERVICE_UPDATE_CONFIRMED" ? 1 : 0, evidenceFileSha256: "a".repeat(64),
  });
  const makeInput = (service, interruption = makeInterruption()) => {
    const boundApproval = { ...approval, failedRecoveryEvidenceSha256, failedRecoveryEvidenceReferenceSha256 };
    const boundAuthorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, failedRecoveryEvidenceSha256, failedRecoveryEvidenceReferenceSha256, approval: boundApproval });
    return { ...base(), service, currentImageExists: true, authorization: boundAuthorization,
      authenticatedFailedRecoveryEvidence: { envelopeSha256: failedRecoveryEvidenceSha256, referenceSha256: failedRecoveryEvidenceReferenceSha256, recoveryHistory: [interruption], knownFailedRevisions: [], interruptedRecoveries: [interruption] } };
  };
  const deployment = (rolloutState) => ({ id: "ecs-svc/3599551810517927503", taskDefinition: interruptedArn, rolloutState, createdAt: "2026-08-24T18:00:00.000Z" });
  const failedTasks = [1, 2].map((n) => ({ taskArn: `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${String(n).padStart(32, "0")}`, startedBy: "ecs-svc/3599551810517927503", taskDefinitionArn: interruptedArn,
    createdAt: `2026-08-24T18:0${n}:00.000Z`, stoppedAt: `2026-08-24T18:0${n}:30.000Z`, stoppedReason: "ResourceInitializationError: execution role denied secretsmanager:GetSecretValue",
    containers: [{ name: "backend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`, imageDigest: digest }] }));
  const snapshot = (service, overrides = {}) => ({ service, census: [current, interrupted], runningTasks: [], stoppedTasks: [], health: null, ...overrides });

  await t.test("healthy candidate is recognized as success and never superseded", async () => {
    const service = { ...base().service, taskDefinition: interruptedArn, runningCount: 2, pendingCount: 0, deployments: [deployment("COMPLETED")] };
    let registrations = 0; let updates = 0;
    const result = await runLegacyBackendHealthRecovery(makeInput(service), {
      readInterruptedRecoveryState: async () => snapshot(service, { runningTasks: [1, 2].map(() => ({ taskDefinitionArn: interruptedArn, imageDigest: digest, healthStatus: "HEALTHY" })), health: healthy }),
      census: async () => [current, interrupted], register: async () => { registrations += 1; }, describe: async () => interrupted,
      readService: async () => service, updateService: async () => { updates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    });
    assert.equal(result.reconciledInterruption, true); assert.deepEqual({ registrations, updates }, { registrations: 0, updates: 0 });
  });

  await t.test("progressing candidate blocks another recovery", async () => {
    const service = { ...base().service, taskDefinition: interruptedArn, runningCount: 1, pendingCount: 1, deployments: [deployment("IN_PROGRESS")] };
    let mutations = 0;
    await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(service), {
      readInterruptedRecoveryState: async () => snapshot(service), census: async () => [current, interrupted], register: async () => { mutations += 1; }, describe: async () => interrupted,
      readService: async () => service, updateService: async () => { mutations += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /still progressing|remains in progress/);
    assert.equal(mutations, 0);
  });

  await t.test("two current exact startup failures authorize a fresh revision without reusing the interrupted candidate", async () => {
    let service = { ...base().service, taskDefinition: interruptedArn, deployments: [deployment("FAILED")] };
    let registered = 0; let updated = 0;
    const readSnapshot = async () => snapshot(service, { census: [current, interrupted, ...(registered ? [recovered] : [])], stoppedTasks: failedTasks });
    const result = await runLegacyBackendHealthRecovery(makeInput(service), {
      readInterruptedRecoveryState: readSnapshot, census: async () => [current, interrupted, ...(registered ? [recovered] : [])],
      register: async () => { registered += 1; return recovered; }, describe: async () => recovered,
      readService: async () => service, updateService: async (arn) => { updated += 1; service = { ...service, taskDefinition: arn, runningCount: 2, deployments: [] }; },
      waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: recoveredArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
    });
    assert.equal(result.targetArn, recoveredArn); assert.deepEqual({ registered, updated }, { registered: 1, updated: 1 });
  });

  await t.test("attempted update on the old service resumes, while confirmed or concurrent service state fails closed", async () => {
    const oldService = { ...base().service, deployments: [] };
    const attempted = makeInterruption("SERVICE_UPDATE_ATTEMPTED");
    let service = oldService; let updates = 0;
    const resumable = makeInput(service, attempted); resumable.currentImageExists = false;
    const result = await runLegacyBackendHealthRecovery(resumable, {
      readInterruptedRecoveryState: async () => snapshot(service), census: async () => [current, interrupted], register: async () => assert.fail("registered candidate must be reused"), describe: async () => interrupted,
      readService: async () => service, updateService: async (arn) => { updates += 1; service = { ...service, taskDefinition: arn, runningCount: 2 }; }, waitStable: async () => {},
      readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: interruptedArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
    });
    assert.equal(result.targetArn, interruptedArn); assert.equal(updates, 1);
    const healthyOldService = { ...oldService, runningCount: 2, pendingCount: 0 };
    const healthyOld = makeInput(healthyOldService, attempted); healthyOld.currentImageExists = false;
    await assert.rejects(() => runLegacyBackendHealthRecovery(healthyOld, {
      readInterruptedRecoveryState: async () => snapshot(healthyOldService), census: async () => [current, interrupted], register: async () => assert.fail("register called"), describe: async () => interrupted,
      readService: async () => healthyOldService, updateService: async () => assert.fail("update called"), waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /degradation is not authenticated/);
    await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(oldService), {
      readInterruptedRecoveryState: async () => snapshot(oldService), census: async () => [current, interrupted], register: async () => {}, describe: async () => interrupted,
      readService: async () => oldService, updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /Confirmed interrupted service update disagrees/);
    const foreign = { ...oldService, taskDefinition: recoveredArn };
    await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(foreign), {
      readInterruptedRecoveryState: async () => snapshot(foreign), census: async () => [current, interrupted], register: async () => {}, describe: async () => interrupted,
      readService: async () => foreign, updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /unauthenticated revision/);
  });

  await t.test("historical, mixed, duplicated, or changing task-attempt proof cannot authorize supersession", async () => {
    const failedService = { ...base().service, taskDefinition: interruptedArn, deployments: [deployment("FAILED")] };
    const historical = { ...failedTasks[0], taskArn: failedTasks[0].taskArn.replace(/1$/, "a"), createdAt: "2026-08-24T17:59:00.000Z", stoppedAt: "2026-08-24T17:59:30.000Z" };
    for (const stoppedTasks of [[historical, failedTasks[0]], [failedTasks[0], failedTasks[0]], [{ ...failedTasks[0], startedBy: "ecs-svc/999" }, failedTasks[1]]]) {
      let mutations = 0;
      await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(failedService), {
        readInterruptedRecoveryState: async () => snapshot(failedService, { stoppedTasks }), census: async () => [current, interrupted],
        register: async () => { mutations += 1; }, describe: async () => interrupted, readService: async () => failedService,
        updateService: async () => { mutations += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
      }), /outcome is ambiguous/);
      assert.equal(mutations, 0);
    }
    let reads = 0; let registrations = 0;
    await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(failedService), {
      readInterruptedRecoveryState: async () => snapshot(failedService, { stoppedTasks: ++reads === 1 ? failedTasks : [failedTasks[0]] }),
      census: async () => [current, interrupted], register: async () => { registrations += 1; }, describe: async () => interrupted,
      readService: async () => failedService, updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /outcome is ambiguous|live state changed|did not converge/);
    assert.equal(registrations, 0);

    reads = 0;
    const replacementFailures = failedTasks.map((task, index) => ({ ...task, taskArn: task.taskArn.replace(/[12]$/, String(index + 3)) }));
    await assert.rejects(() => runLegacyBackendHealthRecovery(makeInput(failedService), {
      readInterruptedRecoveryState: async () => snapshot(failedService, { stoppedTasks: ++reads === 1 ? failedTasks : replacementFailures }),
      census: async () => [current, interrupted], register: async () => { registrations += 1; }, describe: async () => interrupted,
      readService: async () => failedService, updateService: async () => {}, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    }), /live state changed|did not converge/);
    assert.equal(registrations, 0);
  });

  await t.test("registration intent reconciles both no-effect and response-loss outcomes", async () => {
    const intent = { ...makeInterruption("TASK_DEFINITION_REGISTRATION_ATTEMPTED"), taskDefinitionArn: null, registrations: 0, updates: 0, expectedRevisionCensusSha256: null };
    for (const responseLost of [false, true]) {
      let service = { ...base().service, deployments: [] }; let registered = 0; let updated = 0;
      const input = makeInput(service, intent); input.currentImageExists = false;
      const liveCandidate = responseLost ? interrupted : recovered;
      const existing = responseLost ? [interrupted] : [];
      const result = await runLegacyBackendHealthRecovery(input, {
        readInterruptedRecoveryState: async () => snapshot(service, { census: [current, ...existing, ...(registered ? [recovered] : [])] }),
        census: async () => [current, ...existing, ...(registered ? [recovered] : [])],
        register: async () => { registered += 1; return recovered; }, describe: async () => liveCandidate,
        readService: async () => service, updateService: async (arn) => { updated += 1; service = { ...service, taskDefinition: arn, runningCount: 2 }; },
        waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: liveCandidate.taskDefinition.taskDefinitionArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
      });
      assert.deepEqual({ target: result.targetArn, registered, updated }, { target: liveCandidate.taskDefinition.taskDefinitionArn, registered: responseLost ? 0 : 1, updated: 1 });
    }
  });
});

test("a forged failed-revision summary cannot bless a healthy newer revision", async () => {
  const healthyNewer = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", revision: 49, status: "ACTIVE" }, tags: [] };
  const forged = structuredClone(authorization);
  delete forged.failedRecoveryEvidenceSha256;
  forged.knownFailedRevisions = [{ taskDefinitionArn: healthyNewer.taskDefinition.taskDefinitionArn, taskDefinitionFingerprint: taskDefinitionFingerprint(healthyNewer, []), evidenceSha256: "f".repeat(64), workflowRunId: "32759665989", status: "SERVICE_STABILIZATION_FAILED", sourceSha, service: BACKEND_HEALTH_RECOVERY.service, recoveryImageDigest: digest }];
  forged.authorizationSha256 = canonicalSha256(Object.fromEntries(Object.entries(forged).filter(([key]) => key !== "authorizationSha256")));
  const input = base(); input.authorization = forged; input.service.taskDefinition = healthyNewer.taskDefinition.taskDefinitionArn; input.stoppedTaskFailures = [stoppedTaskFailure({ taskDefinitionArn: healthyNewer.taskDefinition.taskDefinitionArn, reason: "ResourceInitializationError" })];
  let registrations = 0; let updates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [current, healthyNewer], register: async () => { registrations += 1; }, describe: async () => healthyNewer,
    readService: async () => input.service, updateService: async () => { updates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /authorization schema|degradation is not authenticated/);
  assert.equal(registrations, 0); assert.equal(updates, 0);
});

test("authenticated cross-source failed revision is audited but never reused", async () => {
  const oldDigest = `sha256:${"a".repeat(64)}`;
  const oldSha = "b".repeat(40);
  const oldCandidate = structuredClone(candidate);
  const oldBackend = oldCandidate.containerDefinitions[0];
  oldBackend.image = oldBackend.image.replace(digest, oldDigest);
  oldBackend.environment = oldBackend.environment.map((entry) => ["GIT_SHA", "RELEASE_GIT_SHA"].includes(entry.name) ? { ...entry, value: oldSha } : entry);
  oldBackend.secrets = oldBackend.secrets.filter(({ name }) => !name.startsWith("ARTIFACT_SIGN_"));
  const failed48 = { taskDefinition: { ...oldCandidate, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", revision: 48, status: "ACTIVE" }, tags: [] };
  const corrected49 = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", revision: 49, status: "ACTIVE" }, tags: [] };
  const rollbackDeploymentArn = "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/failed-cross-source";
  const rollbackServiceRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/failed-cross-source-minus-1";
  const rollbackDigest = current.taskDefinition.containerDefinitions[0].image.split("@")[1];
  const proof = rollbackProof({ rollbackDeploymentArn, rollbackServiceRevisionArn, rollbackTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, rollbackDigest,
    forwardTaskDefinitionArn: failed48.taskDefinition.taskDefinitionArn, forwardTaskDefinitionFingerprint: taskDefinitionFingerprint(failed48, failed48.tags), forwardDigest: oldDigest });
  const rollbackService = { ...base().service, runningCount: 0, pendingCount: 0, deployments: [{ status: "PRIMARY", taskDefinition: current.taskDefinition.taskDefinitionArn, rolloutState: "IN_PROGRESS", desiredCount: 2, runningCount: 0, pendingCount: 0 }] };
  const stalledApproval = { ...approval, rollbackDeploymentArn, rollbackTargetTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, rollbackTargetDigest: rollbackDigest };
  const stalledAuthorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, rollbackProof: proof, approval: stalledApproval });
  const input = { ...base(), service: rollbackService, authorization: stalledAuthorization };
  let registrations = 0;
  let service = rollbackService;
  const records = [];
  const census = async () => registrations ? [failed48, corrected49] : [failed48];
  const recovered = await runLegacyBackendHealthRecovery(input, {
    census,
    register: async () => { registrations += 1; return corrected49; },
    describe: async () => corrected49,
    readService: async () => service,
    readRollbackViability: async () => proof,
    updateService: async (arn) => { service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; },
    waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: corrected49.taskDefinition.taskDefinitionArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy,
    record: async (entry) => { records.push(structuredClone(entry)); },
  });
  assert.equal(registrations, 1);
  assert.equal(recovered.targetArn, corrected49.taskDefinition.taskDefinitionArn);
  assert.notEqual(recovered.targetArn, failed48.taskDefinition.taskDefinitionArn);
  assert.deepEqual(records[0].knownFailedRevisions, [{ taskDefinitionArn: failed48.taskDefinition.taskDefinitionArn, taskDefinitionFingerprint: taskDefinitionFingerprint(failed48, failed48.tags) }]);

  const unauthenticated = structuredClone(failed48);
  unauthenticated.taskDefinition.cpu = "999";
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, { census: async () => [unauthenticated], register: async () => assert.fail("register called"), describe: async () => unauthenticated,
    readService: async () => rollbackService, readRollbackViability: async () => proof, updateService: async () => assert.fail("update called"), waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy }), /failed forward task definition/);

  const unknown50 = structuredClone(corrected49);
  unknown50.taskDefinition.taskDefinitionArn = unknown50.taskDefinition.taskDefinitionArn.replace(":49", ":50");
  unknown50.taskDefinition.revision = 50;
  unknown50.taskDefinition.containerDefinitions[0].cpu = 999;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, { census: async () => [failed48, unknown50], register: async () => assert.fail("register called"), describe: async () => unknown50,
    readService: async () => rollbackService, readRollbackViability: async () => proof, updateService: async () => assert.fail("update called"), waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy }), /newer unknown/);

  let censusCalls = 0;
  let preRaceRegistrations = 0;
  let preRaceUpdates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, { census: async () => ++censusCalls === 1 ? [failed48] : [failed48, unknown50], register: async () => { preRaceRegistrations += 1; }, describe: async () => unknown50,
    readService: async () => rollbackService, readRollbackViability: async () => proof, updateService: async () => { preRaceUpdates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy }), /newer unknown|census changed/);
  assert.deepEqual({ registrations: preRaceRegistrations, updates: preRaceUpdates }, { registrations: 0, updates: 0 });

  let lateCensusCalls = 0;
  let lateRaceRegistrations = 0;
  let lateRaceUpdates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, { census: async () => ++lateCensusCalls < 4 ? (lateCensusCalls < 3 ? [failed48] : [failed48, corrected49]) : [failed48, corrected49, unknown50], register: async () => { lateRaceRegistrations += 1; return corrected49; }, describe: async () => corrected49,
    readService: async () => rollbackService, readRollbackViability: async () => proof, updateService: async () => { lateRaceUpdates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy }), /newer unknown/);
  assert.deepEqual({ registrations: lateRaceRegistrations, updates: lateRaceUpdates }, { registrations: 1, updates: 0 });
});

test("authenticated stalled rollback with an unrecoverable exact target may be superseded once", async () => {
  const rollbackDeploymentArn = "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-N";
  const rollbackServiceRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-N-minus-1";
  const rollbackTargetDigest = current.taskDefinition.containerDefinitions[0].image.split("@")[1];
  const rollbackService = { ...base().service, runningCount: 0, pendingCount: 0, deployments: [{ status: "PRIMARY", taskDefinition: current.taskDefinition.taskDefinitionArn, rolloutState: "IN_PROGRESS", desiredCount: 2, runningCount: 0, pendingCount: 0 }] };
  const forward = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", revision: 48, status: "ACTIVE" }, tags: [] };
  const proof = rollbackProof({ rollbackDeploymentArn, rollbackServiceRevisionArn, rollbackTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, rollbackDigest: rollbackTargetDigest, forwardTaskDefinitionArn: forward.taskDefinition.taskDefinitionArn, forwardTaskDefinitionFingerprint: taskDefinitionFingerprint(forward, []) });
  const stalledApproval = { ...approval, rollbackDeploymentArn, rollbackTargetTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, rollbackTargetDigest };
  const stalledAuthorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, rollbackProof: proof, approval: stalledApproval });
  const input = { ...base(), service: rollbackService, authorization: stalledAuthorization };
  assert.equal(assertLegacyBackendRecoveryEligibility(input).rollbackProof.classification, "ROLLBACK_STALLED_UNRECOVERABLE_TARGET");
  let mutations = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [current, forward], register: async () => { mutations += 1; }, describe: async () => ({}), readService: async () => rollbackService,
    readRollbackViability: async () => ({ ...proof, rollbackDeploymentArn: rollbackDeploymentArn.replace("future-N", "changed") }),
    updateService: async () => { mutations += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /stalled-unrecoverable|changed/);
  assert.equal(mutations, 0);
});

test("future failed revision N registers a distinct corrected N+1 after exact N-1 rollback proof", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:998";
  const currentN = structuredClone(current);
  Object.assign(currentN.taskDefinition, { taskDefinitionArn: targetArn, revision: 998 });
  const candidateN = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: currentN, recoveryImageDigest: digest, imageReleaseSha: sourceSha, artifactSigningBindings });
  const failedN = { taskDefinition: { ...structuredClone(candidateN), taskDefinitionArn: targetArn.replace(":998", ":999"), revision: 999 }, tags: [] };
  failedN.taskDefinition.containerDefinitions[0].secrets = failedN.taskDefinition.containerDefinitions[0].secrets.filter(({ name }) => !name.startsWith("ARTIFACT_SIGN_"));
  const correctedN = { taskDefinition: { ...structuredClone(candidateN), taskDefinitionArn: targetArn.replace(":998", ":1000"), revision: 1000 }, tags: [] };
  const rollbackDeploymentArn = "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-N";
  const rollbackServiceRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-N-minus-1";
  const rollbackTargetDigest = currentN.taskDefinition.containerDefinitions[0].image.split("@")[1];
  const rollbackService = { ...base().service, taskDefinition: targetArn, runningCount: 0, pendingCount: 0, deployments: [{ id: failedDeploymentId, status: "PRIMARY", taskDefinition: targetArn, rolloutState: "FAILED", failedTasks: 2, createdAt: "2026-08-24T17:59:00.000Z", desiredCount: 2, runningCount: 0, pendingCount: 0 }] };
  const proof = rollbackProof({ rollbackDeploymentArn, rollbackServiceRevisionArn, rollbackTaskDefinitionArn: targetArn, rollbackDigest: rollbackTargetDigest,
    forwardTaskDefinitionArn: failedN.taskDefinition.taskDefinitionArn, forwardTaskDefinitionFingerprint: taskDefinitionFingerprint(failedN, failedN.tags) });
  const approvalN = { ...approval, currentTaskDefinitionArn: targetArn, rollbackDeploymentArn, rollbackTargetTaskDefinitionArn: targetArn, rollbackTargetDigest };
  const authorizationN = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: targetArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, rollbackProof: proof, approval: approvalN });
  const input = { ...base(), service: rollbackService, currentTaskDefinition: currentN, candidate: candidateN, authorization: authorizationN, stoppedTaskFailures: [stoppedTaskFailure({ taskDefinitionArn: targetArn, reason: `CannotPullContainerError: image ${currentN.taskDefinition.containerDefinitions[0].image} not found` })] };
  const matchingFailedForward = { taskDefinition: { ...structuredClone(candidateN), taskDefinitionArn: failedN.taskDefinition.taskDefinitionArn, revision: 999 }, tags: [] };
  let prohibitedReuseMutations = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [matchingFailedForward], register: async () => { prohibitedReuseMutations += 1; }, describe: async () => matchingFailedForward,
    readService: async () => rollbackService, readRollbackViability: async () => proof, updateService: async () => { prohibitedReuseMutations += 1; },
    waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /failed forward/);
  assert.equal(prohibitedReuseMutations, 0);
  let service = rollbackService;
  let registrations = 0;
  const result = await runLegacyBackendHealthRecovery(input, {
    census: async () => registrations ? [failedN, correctedN] : [failedN],
    register: async () => { registrations += 1; return correctedN; },
    describe: async () => correctedN,
    readService: async () => service,
    readRollbackViability: async () => proof,
    updateService: async (arn) => { service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; },
    waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: correctedN.taskDefinition.taskDefinitionArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy,
  });
  assert.equal(registrations, 1);
  assert.equal(result.targetArn, correctedN.taskDefinition.taskDefinitionArn);
  assert.notEqual(result.targetArn, failedN.taskDefinition.taskDefinitionArn);
});

test("eligibility rejects absent approval, wrong bindings, present current image, and invalid image evidence", () => {
  for (const [input, pattern] of [
    [mutate("authorization", undefined), /authorization/],
    [mutate("currentImageExists", true), /degradation is not authenticated/],
    [mutate("service.serviceName", "mscqr-frontend-servi-euw2"), /boundary/],
    [mutate("currentTaskDefinition.taskDefinition.family", "mscqr-production-rls-green-backend-candidate"), /legacy backend|identity/],
    [mutate("replacementImage.repository", "mscqr-web"), /image/],
    [mutate("replacementImage.signatureValid", false), /image/],
    [mutate("replacementImage.attestationValid", false), /image/],
    [mutate("replacementImage.provenanceValid", false), /image/],
    [mutate("replacementImage.criticalFindings", 1), /image/],
    [mutate("stoppedTaskFailures", [stoppedTaskFailure({ reason: "ResourceInitializationError: secrets unavailable" })]), /missing-image/],
    [mutate("stoppedTaskFailures", [stoppedTaskFailure({ reason: "CannotPullContainerError: image sha256:" + "f".repeat(64) + " not found" })]), /missing-image/],
  ]) assert.throws(() => assertLegacyBackendRecoveryEligibility(input), pattern);
  const wrongApproval = base();
  wrongApproval.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: "sha256:" + "a".repeat(64), imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, approval: { ...approval, recoveryImageDigest: "sha256:" + "a".repeat(64) } });
  assert.throws(() => assertLegacyBackendRecoveryEligibility(wrongApproval), /different incident|digest/);
});

test("missing-image recovery requires the canonical unavailable service state and exact current failure", () => {
  assert.doesNotThrow(() => assertLegacyBackendRecoveryEligibility(base()));
  for (const [input, label] of [
    [mutate("service.runningCount", 2), "healthy"],
    [mutate("service.runningCount", 1), "partially serving"],
    [mutate("service.pendingCount", 1), "progressing"],
    [mutate("stoppedTaskFailures.0.taskDefinitionArn", "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:46"), "old revision"],
    [mutate("stoppedTaskFailures", []), "missing authoritative task failure"],
  ]) assert.throws(() => assertLegacyBackendRecoveryEligibility(input), /degradation is not authenticated/, label);
});

test("missing-image availability and exact deployment failure are refreshed at both mutation boundaries", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  for (const [changeAt, expected] of [[1, { registrations: 0, updates: 0 }], [2, { registrations: 1, updates: 0 }]]) {
    const input = base(); let checks = 0; let registrations = 0; let updates = 0;
    const census = async () => registrations ? [registered] : [];
    await assert.rejects(() => runRecoveryContract(input, {
      verifyRuntimeClosure: async () => runtimeClosure, census,
      readLegacyFailureState: async () => ({ service: ++checks === changeAt ? { ...input.service, runningCount: 2 } : input.service, stoppedTaskFailures: input.stoppedTaskFailures, census: await census() }),
      register: async () => { registrations += 1; return registered; }, describe: async () => registered,
      readService: async () => input.service, updateService: async () => { updates += 1; }, waitStable: async () => {},
      readRunningTasks: async () => [], verifyHealth: async () => healthy, record: async () => {},
    }), /deployment proof changed/);
    assert.deepEqual({ registrations, updates }, expected);
  }
});

test("hybrid green semantics and every protected legacy field fail closed", () => {
  const mutations = [
    (x) => { x.taskRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task"; },
    (x) => { x.executionRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution"; },
    (x) => { x.networkMode = "bridge"; },
    (x) => { x.containerDefinitions[0].secrets.find(({ name }) => name === "DATABASE_URL").valueFrom = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-ABC123"; },
    (x) => { x.containerDefinitions[0].healthCheck.command = ["CMD-SHELL", "true"]; },
    (x) => { x.containerDefinitions[0].portMappings[0].containerPort = 5432; },
    (x) => { x.containerDefinitions[0].command = ["migrate"]; },
    (x) => { x.containerDefinitions[0].environment.push({ name: "DATABASE_MODE", value: "green" }); },
  ];
  for (const change of mutations) {
    const changed = structuredClone(candidate);
    change(changed);
    assert.throws(() => assertLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, candidate: changed, recoveryImageDigest: digest, imageReleaseSha: imageFixture.imageReleaseSha }), /outside/);
  }
});

test("runtime source identity is bound to the authenticated image release, not executor tooling", () => {
  const imageReleaseSha = "a".repeat(40);
  const rendered = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha, artifactSigningBindings });
  const environment = new Map(rendered.containerDefinitions[0].environment.map(({ name, value }) => [name, value]));
  assert.equal(environment.get("GIT_SHA"), imageReleaseSha);
  assert.equal(environment.get("RELEASE_GIT_SHA"), imageReleaseSha);
  assert.notEqual(imageReleaseSha, sourceSha);
});

test("runner reconciles registration and update partial success without duplicate mutation", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  let service = base().service;
  let registrationCalls = 0;
  let updateCalls = 0;
  const result = await runLegacyBackendHealthRecovery(base(), {
    census: async () => registrationCalls ? [registered] : [],
    register: async () => { registrationCalls += 1; throw new Error("response lost"); },
    describe: async () => registered,
    readService: async () => service,
    updateService: async (arn) => { updateCalls += 1; service = { taskDefinition: arn, desiredCount: 2, runningCount: 2, pendingCount: 0 }; throw new Error("response lost"); },
    waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy,
  });
  assert.equal(result.registrations, 1);
  assert.equal(result.updates, 1);
  assert.equal(registrationCalls, 1);
  assert.equal(updateCalls, 1);
});

test("already recovered replay performs no registration or service update", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const service = { taskDefinition: targetArn, desiredCount: 2, runningCount: 2, pendingCount: 0 };
  const input = base();
  input.service.taskDefinition = targetArn;
  const result = await runLegacyBackendHealthRecovery(input, {
    census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered, readService: async () => service,
    updateService: async () => assert.fail("update called"), waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
  });
  assert.equal(result.registrations, 0);
  assert.equal(result.updates, 0);
});

test("stale source revisions fail before registration while authenticated recovery replay remains valid", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  for (const staleArn of [
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:46",
    "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49",
  ]) {
    const input = base();
    input.service.taskDefinition = staleArn;
    let registrations = 0;
    let updates = 0;
    await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
      census: async () => [], register: async () => { registrations += 1; }, describe: async () => registered,
      readService: async () => input.service, updateService: async () => { updates += 1; }, waitStable: async () => {},
      readRunningTasks: async () => [], verifyHealth: async () => false,
    }), /current task definition is stale/);
    assert.equal(registrations, 0);
    assert.equal(updates, 0);
  }

  const replay = base();
  replay.service.taskDefinition = targetArn;
  const result = await runLegacyBackendHealthRecovery(replay, {
    census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered,
    readService: async () => ({ ...replay.service, runningCount: 2, pendingCount: 0 }), updateService: async () => assert.fail("update called"),
    waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })), verifyHealth: async () => healthy,
  });
  assert.equal(result.registrations, 0);
  assert.equal(result.updates, 0);
});

test("registration follows initial live revision validation and pre-update concurrency remains fail closed", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const input = base();
  const order = [];
  let registeredLive = false;
  let updates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => { order.push("census"); return registeredLive ? [registered] : []; },
    register: async () => { order.push("register"); registeredLive = true; return registered; },
    describe: async () => registered,
    readService: async () => ({ ...input.service, taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49" }),
    updateService: async () => { updates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => false,
  }), /changed concurrently/);
  assert.deepEqual(order, ["census", "census", "register", "census"]);
  assert.equal(updates, 0);
});

test("runtime resource availability changes fail at both ECS mutation boundaries", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  for (const [failureCheck, expected] of [[2, { registrations: 0, updates: 0 }], [3, { registrations: 1, updates: 0 }]]) {
    let checks = 0; let registrations = 0; let updates = 0;
    const input = base(); const census = async () => registrations ? [registered] : [];
    await assert.rejects(() => runRecoveryContract(input, {
      verifyRuntimeClosure: async () => { if (++checks === failureCheck) throw new Error("runtime resource became unavailable"); return runtimeClosure; },
      census, readLegacyFailureState: readMissingImageFailureState(input, census),
      register: async () => { registrations += 1; return registered; },
      describe: async () => registered,
      readService: async () => base().service,
      updateService: async () => { updates += 1; },
      waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy, record: async () => {},
    }), /runtime resource became unavailable/);
    assert.deepEqual({ registrations, updates }, expected);
  }
});

test("stale live runtime verification fails at the final mutation handoff", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  for (const [staleCheck, expected] of [[2, { registrations: 0, updates: 0 }], [3, { registrations: 1, updates: 0 }]]) {
    let checks = 0; let registrations = 0; let updates = 0; let clock = Date.now();
    const input = base(); const census = async () => registrations ? [registered] : [];
    await assert.rejects(() => runRecoveryContract(input, {
      now: () => clock,
      verifyRuntimeClosure: async () => ({ ...runtimeClosure, liveVerifiedAt: new Date(++checks === staleCheck ? clock - 60_001 : clock).toISOString() }),
      census, readLegacyFailureState: readMissingImageFailureState(input, census),
      register: async () => { registrations += 1; return registered; },
      describe: async () => registered,
      readService: async () => base().service,
      updateService: async () => { updates += 1; },
      waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy, record: async () => {},
    }), /live runtime dependency verification is stale/);
    assert.deepEqual({ registrations, updates }, expected);
  }
});

test("non-rollback recovery rejects concurrent revision registration before its own registration", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const unknownArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const unknown = structuredClone(registered);
  Object.assign(unknown.taskDefinition, { taskDefinitionArn: unknownArn, revision: 49, cpu: "999" });
  let censusCalls = 0;
  let registrations = 0;
  let updates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(base(), {
    census: async () => ++censusCalls === 1 ? [] : [unknown],
    register: async () => { registrations += 1; return registered; },
    describe: async () => registered,
    readService: async () => base().service,
    updateService: async () => { updates += 1; },
    waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /census changed|newer unknown/);
  assert.equal(registrations, 0);
  assert.equal(updates, 0);
});

test("global revision census admits only this transaction's exact registration", async (t) => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const unknown = structuredClone(registered);
  Object.assign(unknown.taskDefinition, { taskDefinitionArn: targetArn.replace(":48", ":49"), revision: 49, cpu: "999" });
  const historical = (revision) => {
    const item = structuredClone(registered);
    Object.assign(item.taskDefinition, { taskDefinitionArn: targetArn.replace(":48", `:${revision}`), revision, cpu: `${revision}` });
    return item;
  };
  const run = async (census, { described = registered, serviceChanged = false } = {}) => {
    let registrations = 0;
    let updates = 0;
    let service = base().service;
    const execute = runLegacyBackendHealthRecovery(base(), {
      census,
      register: async () => { registrations += 1; return registered; },
      describe: async () => described,
      readService: async () => serviceChanged ? { ...service, taskDefinition: unknown.taskDefinition.taskDefinitionArn } : service,
      updateService: async (arn) => { updates += 1; service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; },
      waitStable: async () => {},
      readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })),
      verifyHealth: async () => healthy,
    });
    return { execute, counts: () => ({ registrations, updates }) };
  };

  await t.test("unchanged census and exact own registration proceed", async () => {
    let call = 0;
    const execution = await run(async () => ++call < 3 ? [] : [registered]);
    await execution.execute;
    assert.deepEqual(execution.counts(), { registrations: 1, updates: 1 });
  });

  await t.test("unknown initial revision fails before mutation", async () => {
    const execution = await run(async () => [unknown]);
    await assert.rejects(execution.execute, /newer unknown/);
    assert.deepEqual(execution.counts(), { registrations: 0, updates: 0 });
  });

  await t.test("unknown revision after own registration fails before update", async () => {
    let call = 0;
    const execution = await run(async () => ++call < 3 ? [] : [registered, unknown]);
    await assert.rejects(execution.execute, /newer unknown|census changed/);
    assert.deepEqual(execution.counts(), { registrations: 1, updates: 0 });
  });

  await t.test("wrong registered payload fails before update", async () => {
    const changed = structuredClone(registered);
    changed.taskDefinition.cpu = "999";
    const execution = await run(async () => [], { described: changed });
    await assert.rejects(execution.execute, /target readback/);
    assert.deepEqual(execution.counts(), { registrations: 1, updates: 0 });
  });

  await t.test("duplicate and malformed census fail before mutation", async () => {
    for (const census of [[historical(46), historical(46)], [{}]]) {
      const execution = await run(async () => census);
      await assert.rejects(execution.execute, /duplicate|invalid/);
      assert.deepEqual(execution.counts(), { registrations: 0, updates: 0 });
    }
  });

  await t.test("semantic reorder is stable", async () => {
    const old = [historical(45), historical(46)];
    let call = 0;
    const execution = await run(async () => {
      call += 1;
      if (call === 1) return old;
      if (call === 2) return [...old].reverse();
      return call === 3 ? [registered, ...old].reverse() : [old[1], registered, old[0]];
    });
    await execution.execute;
    assert.deepEqual(execution.counts(), { registrations: 1, updates: 1 });
  });

  await t.test("service movement remains an independent guard", async () => {
    let call = 0;
    const execution = await run(async () => ++call < 3 ? [] : [registered], { serviceChanged: true });
    await assert.rejects(execution.execute, /changed concurrently/);
    assert.deepEqual(execution.counts(), { registrations: 1, updates: 0 });
  });
});

test("authorization hash and human bindings fail closed", () => {
  for (const change of [
    (x) => { delete x.approval; },
    (x) => { x.approval.recoveryImageDigest = "sha256:" + "b".repeat(64); },
    (x) => { x.approval.currentTaskDefinitionArn = x.approval.currentTaskDefinitionArn.replace(":47", ":46"); },
    (x) => { x.sourceSha = "a".repeat(40); },
    (x) => { x.kind = "UNRELATED_RECOVERY_MODE"; },
  ]) {
    const input = base();
    input.authorization = structuredClone(authorization);
    change(input.authorization);
    const { authorizationSha256, ...body } = input.authorization;
    input.authorization.authorizationSha256 = canonicalSha256(body);
    assert.throws(() => assertLegacyBackendRecoveryEligibility(input));
  }
  const selfEnvironmentApproval = createProductionEnvironmentApprovalEvidence({
    repository: githubContext.repository, environment: "production", sourceSha, workflowRunId: githubContext.workflowRunId,
    workflowRef: githubContext.workflowRef, eventName: githubContext.eventName, workflowRunAttempt: githubContext.workflowRunAttempt, executionActor: "release-operator", observedAt: now.toISOString(),
    environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "release-operator" } }] }] },
  });
  const selfApproved = base();
  selfApproved.environmentApproval = selfEnvironmentApproval;
  selfApproved.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval: selfEnvironmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, approval: { ...approval, approvedBy: "Release-Operator" } });
  assert.throws(() => assertLegacyBackendRecoveryEligibility(selfApproved), /prevents self-review/);
});

test("configured solo operator may dispatch and approve when GitHub allows self-review", () => {
  const soloEnvironmentApproval = createProductionEnvironmentApprovalEvidence({
    repository: githubContext.repository, environment: "production", sourceSha, workflowRunId: githubContext.workflowRunId,
    workflowRef: githubContext.workflowRef, eventName: githubContext.eventName, workflowRunAttempt: githubContext.workflowRunAttempt, executionActor: "T-ej2003", observedAt: now.toISOString(),
    environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: false, reviewers: [{ type: "User", reviewer: { id: 183396573, login: "T-ej2003" } }] }] },
  });
  const input = base();
  input.executionActor = "T-ej2003";
  input.environmentApproval = soloEnvironmentApproval;
  input.authorization = createLegacyBackendRecoveryAuthorization({
    sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
    imageAuthorization: imageFixture.authorization, environmentApproval: soloEnvironmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, approval: { ...approval, approvedBy: "T-ej2003" },
  });
  assert.equal(assertLegacyBackendRecoveryEligibility(input).recoveryImageDigest, digest);
});

test("fabricated human metadata cannot replace authenticated GitHub environment approval", async () => {
  for (const change of [
    (input) => { input.environmentApproval = undefined; },
    (input) => { input.githubContext.repository = "attacker/repository"; },
    (input) => { input.githubContext.githubActions = "false"; },
    (input) => { input.githubContext.workflowRunId = "999"; },
    (input) => { input.githubContext.now = new Date(now.getTime() + 31 * 60 * 1000); },
  ]) {
    const input = base();
    input.authorization = createLegacyBackendRecoveryAuthorization({
      sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
      imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, runtimeConsumabilitySha256, approval: { ...approval, approvedBy: "fabricated-reviewer", approverRole: "fabricated-role" },
    });
    change(input);
    let calls = 0;
    const forbidden = async () => { calls += 1; };
    await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
      census: forbidden, register: forbidden, describe: forbidden, readService: forbidden, updateService: forbidden,
      waitStable: forbidden, readRunningTasks: forbidden, verifyHealth: forbidden,
    }), /authorization|protected recovery run|stale/);
    assert.equal(calls, 0);
  }
});

test("invalid evidence makes zero mutation adapter calls", async () => {
  const input = base();
  input.currentImageExists = true;
  let calls = 0;
  const forbidden = async () => { calls += 1; };
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [current], register: forbidden, describe: forbidden, readService: forbidden, updateService: forbidden,
    waitStable: forbidden, readRunningTasks: forbidden, verifyHealth: forbidden,
  }), /degradation is not authenticated/);
  assert.equal(calls, 0);
});

test("service desired count is preserved and unhealthy or mismatched readback fails", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const service = { taskDefinition: targetArn, desiredCount: 3, runningCount: 2, pendingCount: 1 };
  const input = base();
  input.service.desiredCount = 3;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => [registered], register: async () => {}, describe: async () => registered,
    readService: async () => service, updateService: async () => {}, waitStable: async () => {},
    readRunningTasks: async () => [], verifyHealth: async () => false,
  }), /converge/);
});

test("concurrent desired-count or network changes fail before service update", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  for (const live of [
    { ...base().service, desiredCount: 3 },
    { ...base().service, networkConfiguration: { awsvpcConfiguration: { subnets: ["subnet-foreign"], securityGroups: ["sg-fixture"], assignPublicIp: "DISABLED" } } },
  ]) {
    let updates = 0;
    await assert.rejects(() => runLegacyBackendHealthRecovery(base(), {
      census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered,
      readService: async () => live, updateService: async () => { updates += 1; }, waitStable: async () => {},
      readRunningTasks: async () => [], verifyHealth: async () => false,
    }), /changed concurrently/);
    assert.equal(updates, 0);
  }
});

test("registered revision is reused after a rejected update and health/digest failures remain terminal", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  let service = { ...base().service, runningCount: 0, pendingCount: 2 };
  let registrations = 0;
  let updates = 0;
  const adapters = {
    census: async () => registrations ? [registered] : [],
    register: async () => { registrations += 1; return registered; },
    describe: async () => registered,
    readService: async () => service,
    updateService: async (arn) => { updates += 1; if (updates === 1) throw new Error("rejected"); service = { taskDefinition: arn, desiredCount: 2, runningCount: 2, pendingCount: 0 }; },
    waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy,
  };
  await assert.rejects(() => runLegacyBackendHealthRecovery(base(), adapters), /rejected/);
  const recovered = await runLegacyBackendHealthRecovery(base(), adapters);
  assert.equal(recovered.registrations, 0);
  assert.equal(registrations, 1);
  assert.equal(updates, 2);

  const stable = { ...adapters, census: async () => [registered], readService: async () => ({ taskDefinition: targetArn, desiredCount: 2, runningCount: 2, pendingCount: 0 }) };
  const already = base();
  already.service.taskDefinition = targetArn;
  await assert.rejects(() => runLegacyBackendHealthRecovery(already, { ...stable, readRunningTasks: async () => [{ taskDefinitionArn: targetArn, imageDigest: "sha256:" + "f".repeat(64), healthStatus: "HEALTHY" }, { taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" }] }), /Running backend/);
  await assert.rejects(() => runLegacyBackendHealthRecovery(already, { ...stable, verifyHealth: async () => false }), /health did not recover/);
});

test("durable recovery states preserve every confirmed partial mutation and terminal verification failure", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const run = async ({ register = async () => registered, updateService, waitStable = async () => {}, readRunningTasks, verifyHealth }) => {
    const records = [];
    let registeredLive = false;
    const input = base(); let service = input.service;
    const adapters = {
      census: async () => registeredLive ? [registered] : [],
      register: async (...args) => { const result = await register(...args); registeredLive = true; return result; },
      describe: async () => registered, readService: async () => service,
      updateService: updateService || (async (arn) => { service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; }),
      waitStable,
      readRunningTasks: readRunningTasks || (async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" }))),
      verifyHealth: verifyHealth || (async () => healthy),
      record: async (entry) => { records.push(structuredClone(entry)); },
    };
    adapters.readLegacyFailureState = readMissingImageFailureState(input, adapters.census);
    return { records, execute: () => runRecoveryContract(input, { verifyRuntimeClosure: async () => runtimeClosure, ...adapters }), setService: (value) => { service = value; } };
  };

  const updateFailure = await run({ updateService: async () => { throw new Error("update rejected"); } });
  await assert.rejects(updateFailure.execute(), /update rejected/);
  assert.deepEqual(updateFailure.records.map(({ status }) => status), [
    "TASK_DEFINITION_REGISTRATION_ATTEMPTED", "TASK_DEFINITION_REGISTERED_ONLY", "SERVICE_UPDATE_ATTEMPTED", "TASK_DEFINITION_REGISTERED_ONLY",
  ]);

  const waiterFailure = await run({ waitStable: async () => { throw new Error("waiter timeout"); } });
  await assert.rejects(waiterFailure.execute(), /waiter timeout/);
  assert.equal(waiterFailure.records.at(-1).status, "SERVICE_STABILIZATION_FAILED");
  assert.equal(waiterFailure.records.at(-1).updates, 1);

  const digestFailure = await run({ readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: "sha256:" + "f".repeat(64), healthStatus: "HEALTHY" })) });
  await assert.rejects(digestFailure.execute(), /Running backend/);
  assert.equal(digestFailure.records.at(-1).status, "RUNNING_DIGEST_VERIFICATION_FAILED");

  const oneTaskUnhealthy = await run({ readRunningTasks: async () => ["HEALTHY", "UNHEALTHY"].map((healthStatus) => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus })) });
  await assert.rejects(oneTaskUnhealthy.execute(), /Every running backend task/);
  assert.equal(oneTaskUnhealthy.records.at(-1).status, "SERVICE_STABILIZATION_FAILED");

  const healthFailure = await run({ verifyHealth: async () => { throw new Error("HTTP 503"); } });
  await assert.rejects(healthFailure.execute(), /HTTP 503/);
  assert.equal(healthFailure.records.at(-1).status, "HEALTH_VERIFICATION_FAILED");

  const success = await run({});
  const result = await success.execute();
  assert.equal(result.health.status, "ready");
  assert.equal(success.records.at(-1).status, "RECOVERY_COMPLETE");
  assert.equal(success.records.at(-1).health.healthy, true);
});

test("already-recovered replay records completion without fake mutations", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const input = base();
  input.service.taskDefinition = targetArn;
  const records = [];
  await runRecoveryContract(input, {
    verifyRuntimeClosure: async () => runtimeClosure,
    census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered,
    readService: async () => ({ ...input.service, runningCount: 2, pendingCount: 0 }), updateService: async () => assert.fail("update called"),
    waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy, record: async (entry) => { records.push(structuredClone(entry)); },
  });
  assert.deepEqual(records.map(({ status }) => status), ["RECOVERY_COMPLETE"]);
  assert.equal(records[0].registrations, 0);
  assert.equal(records[0].updates, 0);
});

test("fresh registration followed by an already-pointing service preserves terminal 1/0 evidence", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const records = []; let registeredLive = false;
  const input = base(); const census = async () => registeredLive ? [registered] : [];
  await assert.rejects(() => runRecoveryContract(input, {
    verifyRuntimeClosure: async () => runtimeClosure,
    census, readLegacyFailureState: readMissingImageFailureState(input, census),
    register: async () => { registeredLive = true; return registered; }, describe: async () => registered,
    readService: async () => ({ ...base().service, taskDefinition: targetArn, runningCount: 0, pendingCount: 2 }),
    updateService: async () => assert.fail("update called"), waitStable: async () => { throw new Error("stabilization failed"); },
    readRunningTasks: async () => [], verifyHealth: async () => healthy, record: async (entry) => { records.push(structuredClone(entry)); },
  }), /stabilization failed/);
  assert.deepEqual({ registrations: records.at(-1).registrations, updates: records.at(-1).updates }, { registrations: 1, updates: 0 });
  assert.equal(records.at(-1).status, "SERVICE_STABILIZATION_FAILED");
});

test("reused orphan revision preserves zero-mutation update-failure evidence", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const records = [];
  const input = base(); const census = async () => [registered];
  await assert.rejects(() => runRecoveryContract(input, {
    verifyRuntimeClosure: async () => runtimeClosure,
    census, readLegacyFailureState: readMissingImageFailureState(input, census), register: async () => assert.fail("register called"), describe: async () => registered,
    readService: async () => base().service, updateService: async () => { throw new Error("update rejected"); },
    waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => healthy,
    record: async (entry) => { records.push(structuredClone(entry)); },
  }), /update rejected/);
  assert.deepEqual(records.map(({ status }) => status), ["SERVICE_UPDATE_ATTEMPTED", "SERVICE_UPDATE_ATTEMPTED"]);
  assert.equal(records.at(-1).registrations, 0);
  assert.equal(records.at(-1).updates, 0);
});

test("partial and complete recovery evidence is self-authenticating", () => {
  const bindings = {
    authorizationFileSha256: "1".repeat(64), authorizationSha256: "2".repeat(64),
    environmentApprovalFileSha256: "3".repeat(64), environmentApprovalSha256: "4".repeat(64),
    imageAuthorizationFileSha256: "5".repeat(64), imageAuthorizationSha256: "6".repeat(64),
    artifactSigningBindingSha256, runtimeConsumabilitySha256,
    rollbackProofSha256: null,
    imageReleaseSha: sourceSha,
    account: "368992683803", region: "eu-west-2",
  };
  const body = {
    schemaVersion: 5, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha,
    currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
    ...bindings, status: "NO_MUTATION_FAILURE", targetArn: null, registrations: 0, updates: 0,
    artifactSigningVerification: "PENDING", artifactSigningFailure: null, knownFailedRevisions: [], generatedAt: now.toISOString(),
  };
  const evidence = { ...body, evidenceSha256: canonicalSha256(body) };
  const expected = { sourceSha, currentTaskDefinitionArn: body.currentTaskDefinitionArn, recoveryImageDigest: digest, ...bindings };
  assert.equal(assertLegacyBackendRecoveryEvidence(evidence, expected).status, "NO_MUTATION_FAILURE");
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...evidence, status: "RECOVERY_COMPLETE" }, expected), /tampered/);
  const contradictoryBody = { ...body, registrations: 1 };
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...contradictoryBody, evidenceSha256: canonicalSha256(contradictoryBody) }, expected), /No-mutation/);
  const incompleteBody = { ...body };
  delete incompleteBody.environmentApprovalSha256;
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...incompleteBody, evidenceSha256: canonicalSha256(incompleteBody) }, expected), /malformed/);
  const overcountedBody = { ...body, registrations: 2 };
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...overcountedBody, evidenceSha256: canonicalSha256(overcountedBody) }, expected), /malformed/);
  const malformedHistory = { ...body, knownFailedRevisions: [{ taskDefinitionArn: body.currentTaskDefinitionArn, taskDefinitionFingerprint: "bad" }] };
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...malformedHistory, evidenceSha256: canonicalSha256(malformedHistory) }, expected), /malformed/);
  const rollbackProofSha256 = "a".repeat(64);
  const multipleHistory = { ...body, rollbackProofSha256, knownFailedRevisions: [47, 48].map((revision) => ({
    taskDefinitionArn: `arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:${revision}`,
    taskDefinitionFingerprint: `${revision}`.repeat(32),
  })) };
  assert.equal(assertLegacyBackendRecoveryEvidence({ ...multipleHistory, evidenceSha256: canonicalSha256(multipleHistory) }, { ...expected, rollbackProofSha256 }).knownFailedRevisions.length, 2);
  const incompleteHealthBody = { ...body, status: "RECOVERY_COMPLETE", targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", artifactSigningVerification: "VERIFIED", backendHealthy: true, rotationRequired: true, health: { healthy: true, success: true, status: "ready" } };
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...incompleteHealthBody, evidenceSha256: canonicalSha256(incompleteHealthBody) }, expected), /readiness proof/);
});

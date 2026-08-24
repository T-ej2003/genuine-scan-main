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
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

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
};
const authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, approval });
const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha: imageFixture.imageReleaseSha, artifactSigningBindings });
const base = () => ({
  sourceSha,
  service: { clusterArn: `arn:aws:ecs:eu-west-2:368992683803:cluster/${BACKEND_HEALTH_RECOVERY.cluster}`, serviceName: BACKEND_HEALTH_RECOVERY.service, taskDefinition: current.taskDefinition.taskDefinitionArn, desiredCount: 2, networkConfiguration: { awsvpcConfiguration: { subnets: ["subnet-fixture"], securityGroups: ["sg-fixture"], assignPublicIp: "DISABLED" } }, loadBalancers: [{ targetGroupArn: "arn:aws:elasticloadbalancing:eu-west-2:368992683803:targetgroup/fixture/123", containerName: "backend", containerPort: 4000 }] },
  currentTaskDefinition: structuredClone(current),
  currentImageExists: false,
  stoppedReasons: [`TaskFailedToStart: CannotPullContainerError: image ${current.taskDefinition.containerDefinitions[0].image} not found`],
  replacementImage: { exists: true, immutable: true, signatureValid: true, attestationValid: true, provenanceValid: true, criticalFindings: 0, repository: "mscqr-backend", digest },
  authorization,
  imageAuthorization: imageFixture.authorization,
  imageValidation: { now: imageFixture.now, verifyImageEvidence: imageFixture.verifyImageEvidence },
  environmentApproval,
  artifactSigningBindings,
  artifactSigningBindingSha256,
  githubContext: { ...githubContext },
  executionActor: "release-operator",
  candidate: structuredClone(candidate),
});
const healthy = Object.freeze({ healthy: true, success: true, status: "ready" });
const runLegacyBackendHealthRecovery = (input, adapters) => runRecoveryContract(input, { record: async () => {}, ...adapters });

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

test("failed :48 is never reused as the corrected recovery revision", async () => {
  const oldCandidate = structuredClone(candidate);
  oldCandidate.containerDefinitions[0].secrets = oldCandidate.containerDefinitions[0].secrets.filter(({ name }) => !name.startsWith("ARTIFACT_SIGN_"));
  const failed48 = { taskDefinition: { ...oldCandidate, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", revision: 48, status: "ACTIVE" }, tags: [] };
  const corrected49 = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49", revision: 49, status: "ACTIVE" }, tags: [] };
  let registrations = 0;
  let service = { ...base().service, runningCount: 0, pendingCount: 0 };
  const recovered = await runLegacyBackendHealthRecovery(base(), {
    census: async () => [failed48],
    register: async () => { registrations += 1; return corrected49; },
    describe: async (arn) => arn.endsWith(":49") ? corrected49 : failed48,
    readService: async () => service,
    updateService: async (arn) => { service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; },
    waitStable: async () => {},
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: corrected49.taskDefinition.taskDefinitionArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy,
  });
  assert.equal(registrations, 1);
  assert.equal(recovered.targetArn.endsWith(":49"), true);

  const rollbackInProgress = base();
  rollbackInProgress.service.taskDefinition = failed48.taskDefinition.taskDefinitionArn;
  let mutations = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(rollbackInProgress, {
    census: async () => [failed48], register: async () => { mutations += 1; }, describe: async () => failed48,
    readService: async () => rollbackInProgress.service, updateService: async () => { mutations += 1; }, waitStable: async () => {},
    readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /stale/);
  assert.equal(mutations, 0);

  const rollingBack = base();
  rollingBack.service.deployments = [{ status: "PRIMARY", taskDefinition: current.taskDefinition.taskDefinitionArn, rolloutState: "IN_PROGRESS", desiredCount: 2, runningCount: 0, pendingCount: 0 }];
  assert.throws(() => assertLegacyBackendRecoveryEligibility(rollingBack), /rollback or deployment remains in progress/);

  const unknown49 = structuredClone(corrected49);
  unknown49.taskDefinition.containerDefinitions[0].cpu = 999;
  let unknownMutations = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(base(), {
    census: async () => [failed48, unknown49], register: async () => { unknownMutations += 1; }, describe: async () => unknown49,
    readService: async () => base().service, updateService: async () => { unknownMutations += 1; }, waitStable: async () => {},
    readRunningTasks: async () => [], verifyHealth: async () => healthy,
  }), /newer unknown/);
  assert.equal(unknownMutations, 0);
});

test("eligibility rejects absent approval, wrong bindings, present current image, and invalid image evidence", () => {
  for (const [input, pattern] of [
    [mutate("authorization", undefined), /authorization/],
    [mutate("currentImageExists", true), /absent/],
    [mutate("service.serviceName", "mscqr-frontend-servi-euw2"), /boundary/],
    [mutate("currentTaskDefinition.taskDefinition.family", "mscqr-production-rls-green-backend-candidate"), /legacy backend|identity/],
    [mutate("replacementImage.repository", "mscqr-web"), /image/],
    [mutate("replacementImage.signatureValid", false), /image/],
    [mutate("replacementImage.attestationValid", false), /image/],
    [mutate("replacementImage.provenanceValid", false), /image/],
    [mutate("replacementImage.criticalFindings", 1), /image/],
    [mutate("stoppedReasons", ["ResourceInitializationError: secrets unavailable"]), /missing-image/],
    [mutate("stoppedReasons", ["CannotPullContainerError: image sha256:" + "f".repeat(64) + " not found"]), /missing-image/],
  ]) assert.throws(() => assertLegacyBackendRecoveryEligibility(input), pattern);
  const wrongApproval = base();
  wrongApproval.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: "sha256:" + "a".repeat(64), imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, approval: { ...approval, recoveryImageDigest: "sha256:" + "a".repeat(64) } });
  assert.throws(() => assertLegacyBackendRecoveryEligibility(wrongApproval), /different incident|digest/);
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
  let service = { ...base().service, runningCount: 0, pendingCount: 2 };
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
  let updates = 0;
  await assert.rejects(() => runLegacyBackendHealthRecovery(input, {
    census: async () => { order.push("census"); return []; },
    register: async () => { order.push("register"); return registered; },
    describe: async () => registered,
    readService: async () => ({ ...input.service, taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49" }),
    updateService: async () => { updates += 1; }, waitStable: async () => {}, readRunningTasks: async () => [], verifyHealth: async () => false,
  }), /changed concurrently/);
  assert.deepEqual(order, ["census", "register"]);
  assert.equal(updates, 0);
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
  selfApproved.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval: selfEnvironmentApproval, artifactSigningBindingSha256, approval: { ...approval, approvedBy: "Release-Operator" } });
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
    imageAuthorization: imageFixture.authorization, environmentApproval: soloEnvironmentApproval, artifactSigningBindingSha256, approval: { ...approval, approvedBy: "T-ej2003" },
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
      imageAuthorization: imageFixture.authorization, environmentApproval, artifactSigningBindingSha256, approval: { ...approval, approvedBy: "fabricated-reviewer", approverRole: "fabricated-role" },
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
    census: forbidden, register: forbidden, describe: forbidden, readService: forbidden, updateService: forbidden,
    waitStable: forbidden, readRunningTasks: forbidden, verifyHealth: forbidden,
  }), /absent/);
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
    let service = { ...base().service, runningCount: 0, pendingCount: 2 };
    const adapters = {
      census: async () => [], register, describe: async () => registered, readService: async () => service,
      updateService: updateService || (async (arn) => { service = { ...service, taskDefinition: arn, runningCount: 2, pendingCount: 0 }; }),
      waitStable,
      readRunningTasks: readRunningTasks || (async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" }))),
      verifyHealth: verifyHealth || (async () => healthy),
      record: async (entry) => { records.push(structuredClone(entry)); },
    };
    return { records, execute: () => runRecoveryContract(base(), adapters), setService: (value) => { service = value; } };
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
    census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered,
    readService: async () => ({ ...input.service, runningCount: 2, pendingCount: 0 }), updateService: async () => assert.fail("update called"),
    waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest, healthStatus: "HEALTHY" })),
    verifyHealth: async () => healthy, record: async (entry) => { records.push(structuredClone(entry)); },
  });
  assert.deepEqual(records.map(({ status }) => status), ["RECOVERY_COMPLETE"]);
  assert.equal(records[0].registrations, 0);
  assert.equal(records[0].updates, 0);
});

test("reused orphan revision preserves zero-mutation update-failure evidence", async () => {
  const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
  const registered = { taskDefinition: { ...structuredClone(candidate), taskDefinitionArn: targetArn, revision: 48, status: "ACTIVE" }, tags: [] };
  const records = [];
  await assert.rejects(() => runRecoveryContract(base(), {
    census: async () => [registered], register: async () => assert.fail("register called"), describe: async () => registered,
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
    artifactSigningBindingSha256,
    imageReleaseSha: sourceSha,
    account: "368992683803", region: "eu-west-2",
  };
  const body = {
    schemaVersion: 2, kind: "BACKEND_HEALTH_RECOVERY_EVIDENCE", sourceSha,
    currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
    ...bindings, status: "NO_MUTATION_FAILURE", targetArn: null, registrations: 0, updates: 0, generatedAt: now.toISOString(),
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
  const incompleteHealthBody = { ...body, status: "RECOVERY_COMPLETE", targetArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", backendHealthy: true, rotationRequired: true, health: { healthy: true, success: true, status: "ready" } };
  assert.throws(() => assertLegacyBackendRecoveryEvidence({ ...incompleteHealthBody, evidenceSha256: canonicalSha256(incompleteHealthBody) }, expected), /readiness proof/);
});

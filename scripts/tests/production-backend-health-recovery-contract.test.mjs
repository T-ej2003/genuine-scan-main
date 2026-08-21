import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  BACKEND_HEALTH_RECOVERY,
  assertLegacyBackendRecoveryCandidate,
  assertLegacyBackendRecoveryEligibility,
  buildLegacyBackendRecoveryCandidate,
  createLegacyBackendRecoveryAuthorization,
  runLegacyBackendHealthRecovery,
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
  environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1 } }] }] },
});
const current = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url)));
const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha, imageDigests: {
  backend: digest,
  worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
  "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
  "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
} });
const approval = {
  ticket: "INC-BACKEND-IMAGE-0001", approvedBy: "security@example.invalid", approverRole: "Security Lead",
  reason: "Restore backend health so canonical dual-slot rotation can run", verificationRef: "https://example.invalid/recovery/1",
  sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest,
};
const authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, approval });
const candidate = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha: imageFixture.imageReleaseSha });
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
  githubContext: { ...githubContext },
  executionActor: "release-operator",
  candidate: structuredClone(candidate),
});

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
  assert.deepEqual(backend.secrets, current.taskDefinition.containerDefinitions[0].secrets);
  assert.equal(backend.environment.length, 44);
  assert.equal(backend.secrets.length, 14);
  assert.equal(candidate.taskRoleArn, current.taskDefinition.taskRoleArn);
  assert.equal(candidate.executionRoleArn, current.taskDefinition.executionRoleArn);
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
  wrongApproval.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: "sha256:" + "a".repeat(64), imageAuthorization: imageFixture.authorization, environmentApproval, approval: { ...approval, recoveryImageDigest: "sha256:" + "a".repeat(64) } });
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
  const rendered = buildLegacyBackendRecoveryCandidate({ currentTaskDefinition: current, recoveryImageDigest: digest, imageReleaseSha });
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
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest })),
    verifyHealth: async () => true,
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
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest })), verifyHealth: async () => true,
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
    waitStable: async () => {}, readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest })), verifyHealth: async () => true,
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
  ]) {
    const input = base();
    input.authorization = structuredClone(authorization);
    change(input.authorization);
    const { authorizationSha256, ...body } = input.authorization;
    input.authorization.authorizationSha256 = canonicalSha256(body);
    assert.throws(() => assertLegacyBackendRecoveryEligibility(input));
  }
  const selfApproved = base();
  selfApproved.authorization = createLegacyBackendRecoveryAuthorization({ sourceSha, currentTaskDefinitionArn: current.taskDefinition.taskDefinitionArn, recoveryImageDigest: digest, imageAuthorization: imageFixture.authorization, environmentApproval, approval: { ...approval, approvedBy: "Release-Operator" } });
  assert.throws(() => assertLegacyBackendRecoveryEligibility(selfApproved), /self-approved/);
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
      imageAuthorization: imageFixture.authorization, environmentApproval, approval: { ...approval, approvedBy: "fabricated-reviewer", approverRole: "fabricated-role" },
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
    readRunningTasks: async () => [1, 2].map(() => ({ taskDefinitionArn: targetArn, imageDigest: digest })),
    verifyHealth: async () => true,
  };
  await assert.rejects(() => runLegacyBackendHealthRecovery(base(), adapters), /rejected/);
  const recovered = await runLegacyBackendHealthRecovery(base(), adapters);
  assert.equal(recovered.registrations, 0);
  assert.equal(registrations, 1);
  assert.equal(updates, 2);

  const stable = { ...adapters, census: async () => [registered], readService: async () => ({ taskDefinition: targetArn, desiredCount: 2, runningCount: 2, pendingCount: 0 }) };
  const already = base();
  already.service.taskDefinition = targetArn;
  await assert.rejects(() => runLegacyBackendHealthRecovery(already, { ...stable, readRunningTasks: async () => [{ taskDefinitionArn: targetArn, imageDigest: "sha256:" + "f".repeat(64) }, { taskDefinitionArn: targetArn, imageDigest: digest }] }), /Running backend/);
  await assert.rejects(() => runLegacyBackendHealthRecovery(already, { ...stable, verifyHealth: async () => false }), /health did not recover/);
});

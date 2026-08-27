import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runBackendHealthRecoveryCli, verifyInterruptedProductionBackendHealth, verifyProductionBackendHealth } from "../aws/recover-production-backend-health.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const digest = "sha256:3dbd02136a99d1741fdfa655397a661fa2275812e1cad0675c93fc5c7c4b4477";
const currentArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const now = new Date("2026-08-20T18:00:00.000Z");
const githubEnv = { GITHUB_ACTIONS: "true", GITHUB_ACTOR: "release-operator", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_WORKFLOW_REF: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1" };
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const artifactSigningBindings = Object.freeze({
  ARTIFACT_SIGN_PRIVATE_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/private-key-current-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEY_CURRENT: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-key-current-AbCd12",
  ARTIFACT_SIGN_ACTIVE_KEY_VERSION: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/active-key-version-AbCd12",
  ARTIFACT_SIGN_PUBLIC_KEYS_JSON: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/artifact-signing/public-keys-json-AbCd12",
});
const artifactSigningBindingSha256 = "7".repeat(64);
const runtimeConsumabilitySha256 = "8".repeat(64);
const currentTaskDefinition = JSON.parse(fs.readFileSync(new URL("./fixtures/mscqr-backend-47.task-definition.json", import.meta.url), "utf8"));

function privateFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "backend-health-recovery-"));
  fs.chmodSync(dir, 0o700);
  const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha, imageDigests: {
    backend: digest,
    worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
    "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
    "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
  } });
  const approval = { ticket: "INC-1", approvedBy: "security", approverRole: "Security Lead", reason: "backend recovery", verificationRef: "https://example.invalid/1", sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest, runtimeConsumabilitySha256 };
  const imageBytes = Buffer.from(JSON.stringify(imageFixture.authorization));
  const approvalBytes = Buffer.from(JSON.stringify(approval));
  const environmentApproval = createProductionEnvironmentApprovalEvidence({
    repository: githubEnv.GITHUB_REPOSITORY, environment: "production", sourceSha, workflowRunId: githubEnv.GITHUB_RUN_ID,
    workflowRef: githubEnv.GITHUB_WORKFLOW_REF, eventName: githubEnv.GITHUB_EVENT_NAME, workflowRunAttempt: githubEnv.GITHUB_RUN_ATTEMPT, executionActor: githubEnv.GITHUB_ACTOR, observedAt: now.toISOString(),
    environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1, login: "security" } }] }] },
  });
  const environmentBytes = Buffer.from(JSON.stringify(environmentApproval));
  const runtimeBytes = Buffer.from(JSON.stringify({ evidence: { evidenceSha256: runtimeConsumabilitySha256, candidateFingerprint: "9".repeat(64) } }));
  const failedReferenceBytes = Buffer.from("null");
  const failedBytes = Buffer.from("null");
  const image = path.join(dir, "image.json");
  const approvalPath = path.join(dir, "approval.json");
  const environmentPath = path.join(dir, "environment-approval.json");
  const runtimePath = path.join(dir, "runtime-consumability.json");
  const failedReferencePath = path.join(dir, "failed-recovery-evidence-reference.json");
  const failedPath = path.join(dir, "failed-recovery-evidence.json");
  fs.writeFileSync(image, imageBytes, { mode: 0o600 });
  fs.writeFileSync(approvalPath, approvalBytes, { mode: 0o600 });
  fs.writeFileSync(environmentPath, environmentBytes, { mode: 0o600 });
  fs.writeFileSync(runtimePath, runtimeBytes, { mode: 0o600 });
  fs.writeFileSync(failedReferencePath, failedReferenceBytes, { mode: 0o600 });
  fs.writeFileSync(failedPath, failedBytes, { mode: 0o600 });
  return { dir, image, imageBytes, approvalPath, approvalBytes, environmentApproval, environmentPath, environmentBytes, runtimePath, runtimeBytes, failedReferencePath, failedReferenceBytes, failedPath, failedBytes, imageFixture };
}

const environmentArgs = (fixture) => ["--aws-profile", "mscqr-production-release-deployer", "--environment-approval", fixture.environmentPath, "--environment-approval-sha256", sha(fixture.environmentBytes), "--runtime-consumability", fixture.runtimePath, "--runtime-consumability-sha256", sha(fixture.runtimeBytes), "--failed-recovery-evidence-reference", fixture.failedReferencePath, "--failed-recovery-evidence-reference-sha256", sha(fixture.failedReferenceBytes), "--failed-recovery-evidence", fixture.failedPath, "--failed-recovery-evidence-sha256", sha(fixture.failedBytes)];
const deps = (fixture, overrides = {}) => ({
  baseEnv: githubEnv, now, readProtectedMain: () => ({ headSha: sourceSha, freshRemoteMainSha: sourceSha }),
  verifyImageEvidence: fixture.imageFixture.verifyImageEvidence,
  resolveArtifactSigning: async () => ({ bindings: artifactSigningBindings, evidenceSha256: artifactSigningBindingSha256, created: [], uninitializedSecretRefs: [], verification: { valid: true } }),
  verifyRuntimeClosure: async () => ({ status: "PASS", evidenceSha256: runtimeConsumabilitySha256, liveVerifiedAt: now.toISOString() }),
  readCurrentTaskDefinition: async () => currentTaskDefinition,
  ...overrides,
});
const readiness = (overrides = {}) => JSON.stringify({ success: true, status: "ready", timestamp: now.toISOString(), release: { gitSha: sourceSha }, dependencies: { database: { configured: true, ready: true }, redis: { configured: true, ready: true }, objectStorage: { configured: true, ready: true } }, ...overrides });

test("health verifier rejects HTTP failure, timeout, malformed JSON, and HTTP-200 degraded payloads", () => {
  const response = (body, status = 200) => `${body}\n${status}`;
  const run = (body, status) => (_command, args) => {
    assert.equal(args.includes("--location") || args.includes("-L") || args.includes("--insecure") || args.includes("-k"), false);
    assert.equal(args[0], "--disable");
    return response(body, status);
  };
  assert.equal(verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run(readiness()), sourceSha).healthy, true);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run(readiness({ success: false, status: "degraded" }))), /readiness/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run("not-json")), /JSON/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run("<html>frontend</html>")), /JSON/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run(readiness()), "a".repeat(40)), /release identity/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run(readiness(), 302)), /HTTP 302/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", run(readiness(), 503)), /HTTP 503/);
  assert.throws(() => verifyProductionBackendHealth("https://www.mscqr.com/api/health/ready", () => { throw new Error("curl: operation timed out"); }), /operation timed out/);
});

test("interrupted health verification is bound to its authenticated historical release identity", () => {
  const historicalSha = "a".repeat(40); const retrySha = "b".repeat(40);
  const run = () => `${readiness({ release: { gitSha: historicalSha } })}\n200`;
  assert.equal(verifyInterruptedProductionBackendHealth("https://www.mscqr.com/api/health/ready", run, { imageReleaseSha: historicalSha }).healthy, true);
  assert.throws(() => verifyInterruptedProductionBackendHealth("https://www.mscqr.com/api/health/ready", run, { imageReleaseSha: retrySha }), /release identity/);
  assert.throws(() => verifyInterruptedProductionBackendHealth("https://www.mscqr.com/api/health/ready", run, {}), /release identity/);
});

test("prepare authenticates private input bytes and writes a bound private authorization", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const output = path.join(fixture.dir, "authorization.json");
  const result = await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture),
    "--recovery-image-digest", digest, "--image-authorization", fixture.image,
    "--image-authorization-sha256", sha(fixture.imageBytes), "--approval", fixture.approvalPath,
    "--approval-sha256", sha(fixture.approvalBytes), "--output", output,
  ], deps(fixture));
  assert.equal(result.currentTaskDefinitionArn, currentArn);
  assert.equal(result.recoveryImageDigest, digest);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
});

test("prepare rejects tampered bytes and self approval before any AWS call", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  fs.appendFileSync(fixture.approvalPath, " ");
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture),
    "--recovery-image-digest", digest, "--image-authorization", fixture.image,
    "--image-authorization-sha256", sha(fixture.imageBytes), "--approval", fixture.approvalPath,
    "--approval-sha256", sha(fixture.approvalBytes), "--output", path.join(fixture.dir, "authorization.json"),
  ], deps(fixture)), /SHA-256/);

  const selfApproved = privateFixture();
  t.after(() => fs.rmSync(selfApproved.dir, { recursive: true, force: true }));
  const approval = JSON.parse(selfApproved.approvalBytes);
  approval.approvedBy = "release-operator";
  const approvalBytes = Buffer.from(JSON.stringify(approval));
  fs.writeFileSync(selfApproved.approvalPath, approvalBytes, { mode: 0o600 });
  let signingReads = 0;
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(selfApproved),
    "--recovery-image-digest", digest, "--image-authorization", selfApproved.image,
    "--image-authorization-sha256", sha(selfApproved.imageBytes), "--approval", selfApproved.approvalPath,
    "--approval-sha256", sha(approvalBytes), "--output", path.join(selfApproved.dir, "authorization.json"),
  ], deps(selfApproved, { resolveArtifactSigning: async () => { signingReads += 1; } })), /configured production environment reviewer/);
  assert.equal(signingReads, 0);
});

test("execute authenticates semantic authorization before any AWS call", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorization = {
    schemaVersion: 4, kind: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", environment: "production",
    account: "368992683803", region: "eu-west-2", cluster: "mscqr-prod-euw2-main", service: "wrong-service", family: "mscqr-backend",
    sourceSha, imageReleaseSha: fixture.imageFixture.imageReleaseSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest,
    imageAuthorizationSha256: fixture.imageFixture.authorization.evidenceSha256, reasonCode: "CURRENT_IMAGE_DIGEST_MISSING",
    environmentApprovalSha256: fixture.environmentApproval.evidenceSha256,
    artifactSigningBindingSha256,
    runtimeConsumabilitySha256,
    failedRecoveryEvidenceSha256: null,
    failedRecoveryEvidenceReferenceSha256: null,
    rollbackProof: null,
    allowedDeltaProfile: "IMAGE_SOURCE_IDENTITY_AND_EXACT_ARTIFACT_SIGNING_BINDINGS",
    approval: { ticket: "INC-1", approvedBy: "security", approverRole: "Security Lead", reason: "backend recovery", verificationRef: "https://example.invalid/1", sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest, runtimeConsumabilitySha256 },
  };
  authorization.authorizationSha256 = canonicalSha256(authorization);
  const authorizationBytes = Buffer.from(JSON.stringify(authorization));
  const authorizationPath = path.join(fixture.dir, "authorization.json");
  fs.writeFileSync(authorizationPath, authorizationBytes, { mode: 0o600 });
  let externalCalls = 0;
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--execute", "--source-sha", sourceSha, "--image-authorization", fixture.image,
    ...environmentArgs(fixture),
    "--image-authorization-sha256", sha(fixture.imageBytes), "--authorization", authorizationPath,
    "--authorization-sha256", sha(authorizationBytes), "--health-url", "https://example.invalid/api/health",
    "--evidence-out", path.join(fixture.dir, "evidence.json"),
  ], deps(fixture, { exec: () => { externalCalls += 1; throw new Error("external call"); } })), /different incident/);
  assert.equal(externalCalls, 0);
});

test("execute requires authenticated environment bytes before any external call", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  let externalCalls = 0;
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--execute", "--source-sha", sourceSha, "--image-authorization", fixture.image,
    "--image-authorization-sha256", sha(fixture.imageBytes), "--authorization", fixture.approvalPath,
    "--authorization-sha256", sha(fixture.approvalBytes), "--health-url", "https://example.invalid/api/health",
    "--evidence-out", path.join(fixture.dir, "evidence.json"),
  ], deps(fixture, { exec: () => { externalCalls += 1; } })), /--environment-approval/);
  assert.equal(externalCalls, 0);
});

test("execute rejects a foreign health origin before any AWS call", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorizationPath = path.join(fixture.dir, "authorization.json");
  await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture), "--recovery-image-digest", digest,
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--approval", fixture.approvalPath, "--approval-sha256", sha(fixture.approvalBytes), "--output", authorizationPath,
  ], deps(fixture));
  const authorizationBytes = fs.readFileSync(authorizationPath);
  const evidencePath = path.join(fixture.dir, "evidence.json");
  let externalCalls = 0;
  let registrations = 0;
  let updates = 0;
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--execute", "--source-sha", sourceSha, ...environmentArgs(fixture),
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--authorization", authorizationPath, "--authorization-sha256", sha(authorizationBytes),
    "--health-url", "https://example.invalid/api/health/ready", "--evidence-out", evidencePath,
  ], deps(fixture, { exec: (_command, args = []) => {
    externalCalls += 1;
    if (args.includes("register-task-definition")) registrations += 1;
    if (args.includes("update-service")) updates += 1;
    throw new Error("external call");
  } })), /canonical public HTTPS/);
  assert.equal(externalCalls, 0);
  assert.equal(registrations, 0);
  assert.equal(updates, 0);
  assert.equal(fs.existsSync(evidencePath), false);
});

test("execute publishes authenticated zero-mutation evidence before the first AWS read", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorizationPath = path.join(fixture.dir, "authorization.json");
  const authorization = await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture), "--recovery-image-digest", digest,
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--approval", fixture.approvalPath, "--approval-sha256", sha(fixture.approvalBytes), "--output", authorizationPath,
  ], deps(fixture));
  const authorizationBytes = fs.readFileSync(authorizationPath);
  const evidencePath = path.join(fixture.dir, "evidence.json");
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--execute", "--source-sha", sourceSha, ...environmentArgs(fixture),
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--authorization", authorizationPath, "--authorization-sha256", sha(authorizationBytes),
    "--health-url", "https://www.mscqr.com/api/health/ready", "--evidence-out", evidencePath,
  ], deps(fixture, { exec: () => { throw new Error("STS unavailable"); } })), /STS unavailable/);
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
  assert.equal(evidence.status, "NO_MUTATION_FAILURE");
  assert.equal(evidence.registrations, 0);
  assert.equal(evidence.updates, 0);
  assert.equal(evidence.currentTaskDefinitionArn, currentArn);
  assert.equal(evidence.recoveryImageDigest, digest);
  assert.equal(evidence.authorizationSha256, authorization.authorizationSha256);
  assert.equal(evidence.artifactSigningVerification, "VERIFIED");
  assert.equal(evidence.artifactSigningFailure, null);
  assert.equal(evidence.evidenceSha256, canonicalSha256(Object.fromEntries(Object.entries(evidence).filter(([key]) => key !== "evidenceSha256"))));
  assert.equal(fs.statSync(evidencePath).mode & 0o777, 0o600);
});

test("stale or inconsistent live artifact-signing evidence fails before ECS mutation", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorizationPath = path.join(fixture.dir, "authorization.json");
  await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture), "--recovery-image-digest", digest,
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--approval", fixture.approvalPath, "--approval-sha256", sha(fixture.approvalBytes), "--output", authorizationPath,
  ], deps(fixture));
  const authorizationBytes = fs.readFileSync(authorizationPath);
  for (const resolveArtifactSigning of [
    async () => ({ bindings: artifactSigningBindings, evidenceSha256: "8".repeat(64), created: [], uninitializedSecretRefs: [], verification: { valid: true } }),
    async () => ({ bindings: artifactSigningBindings, evidenceSha256: artifactSigningBindingSha256, created: [], uninitializedSecretRefs: [], verification: { valid: false } }),
    async () => ({ bindings: artifactSigningBindings, evidenceSha256: artifactSigningBindingSha256, created: [], uninitializedSecretRefs: [artifactSigningBindings.ARTIFACT_SIGN_PRIVATE_KEY_CURRENT], verification: { valid: true } }),
  ]) {
    let ecsMutations = 0;
    await assert.rejects(() => runBackendHealthRecoveryCli([
      "--execute", "--source-sha", sourceSha, ...environmentArgs(fixture),
      "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
      "--authorization", authorizationPath, "--authorization-sha256", sha(authorizationBytes),
      "--health-url", "https://www.mscqr.com/api/health/ready", "--evidence-out", path.join(fixture.dir, `evidence-${ecsMutations}.json`),
    ], deps(fixture, {
      resolveArtifactSigning,
      exec: (_command, args = []) => { if (args.includes("register-task-definition") || args.includes("update-service")) ecsMutations += 1; throw new Error("unexpected external call"); },
    })), /Artifact-signing discovery failed/);
    assert.equal(ecsMutations, 0);
  }
});

test("every live artifact-signing discovery failure preserves sanitized durable evidence", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorizationPath = path.join(fixture.dir, "authorization-discovery.json");
  await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture), "--recovery-image-digest", digest,
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--approval", fixture.approvalPath, "--approval-sha256", sha(fixture.approvalBytes), "--output", authorizationPath,
  ], deps(fixture));
  const authorizationBytes = fs.readFileSync(authorizationPath);
  const secretSentinel = "PRIVATE_KEY_MUST_NOT_APPEAR";
  const caller = JSON.stringify({ Account: "368992683803", Arn: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/GitHubActions" });
  const cases = [
    ["CALLER_IDENTITY_DISCOVERY_FAILED", { exec: () => { throw new Error(`STS failed ${secretSentinel}`); } }],
    ["SECRET_REFERENCE_DISCOVERY_FAILED", {
      exec: () => caller,
      resolveExistingArtifactSigningBindings: async () => { throw new Error(`DescribeSecret failed ${secretSentinel}`); },
    }],
    ["SECRET_VALUE_VERIFICATION_FAILED", {
      exec: () => caller,
      resolveExistingArtifactSigningBindings: async () => ({ bindingFile: "/private/fake", evidenceSha256: artifactSigningBindingSha256, bindings: artifactSigningBindings, created: [], uninitializedSecretRefs: [] }),
      createArtifactSigningAdapter: () => ({ verify: async () => { throw new Error(`GetSecretValue failed ${secretSentinel}`); } }),
    }],
  ];
  for (const [expectedFailure, overrides] of cases) {
    const evidencePath = path.join(fixture.dir, `evidence-${expectedFailure}.json`);
    let pendingObserved = false;
    const wrappedOverrides = { ...overrides, resolveArtifactSigning: undefined };
    if (overrides.resolveExistingArtifactSigningBindings) {
      const original = overrides.resolveExistingArtifactSigningBindings;
      wrappedOverrides.resolveExistingArtifactSigningBindings = async (...args) => {
        const pending = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
        pendingObserved = pending.artifactSigningVerification === "PENDING" && pending.artifactSigningFailure === null;
        return original(...args);
      };
    } else {
      const original = overrides.exec;
      wrappedOverrides.exec = (...args) => {
        const pending = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
        pendingObserved = pending.artifactSigningVerification === "PENDING" && pending.artifactSigningFailure === null;
        return original(...args);
      };
    }
    await assert.rejects(() => runBackendHealthRecoveryCli([
      "--execute", "--source-sha", sourceSha, ...environmentArgs(fixture),
      "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
      "--authorization", authorizationPath, "--authorization-sha256", sha(authorizationBytes),
      "--health-url", "https://www.mscqr.com/api/health/ready", "--evidence-out", evidencePath,
    ], deps(fixture, wrappedOverrides)), (error) => {
      assert.match(error.message, /Artifact-signing discovery failed/);
      assert.equal(error.message.includes(secretSentinel), false);
      assert.equal(error.cause, undefined);
      return true;
    });
    const bytes = fs.readFileSync(evidencePath, "utf8");
    const evidence = JSON.parse(bytes);
    assert.equal(pendingObserved, true);
    assert.equal(evidence.status, "NO_MUTATION_FAILURE");
    assert.equal(evidence.artifactSigningVerification, "FAILED");
    assert.equal(evidence.artifactSigningFailure, expectedFailure);
    assert.equal(bytes.includes(secretSentinel), false);
  }
});

test("malformed live signing state is recorded as failed, never verified", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorizationPath = path.join(fixture.dir, "authorization-malformed.json");
  await runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(fixture), "--recovery-image-digest", digest,
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--approval", fixture.approvalPath, "--approval-sha256", sha(fixture.approvalBytes), "--output", authorizationPath,
  ], deps(fixture));
  const authorizationBytes = fs.readFileSync(authorizationPath);
  const evidencePath = path.join(fixture.dir, "evidence-malformed.json");
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--execute", "--source-sha", sourceSha, ...environmentArgs(fixture),
    "--image-authorization", fixture.image, "--image-authorization-sha256", sha(fixture.imageBytes),
    "--authorization", authorizationPath, "--authorization-sha256", sha(authorizationBytes),
    "--health-url", "https://www.mscqr.com/api/health/ready", "--evidence-out", evidencePath,
  ], deps(fixture, {
    resolveArtifactSigning: async () => ({ bindings: artifactSigningBindings, evidenceSha256: artifactSigningBindingSha256, created: [], uninitializedSecretRefs: [], verification: { valid: false } }),
  })), /Artifact-signing discovery failed/);
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
  assert.equal(evidence.artifactSigningVerification, "FAILED");
  assert.equal(evidence.artifactSigningFailure, "LIVE_BINDING_VALIDATION_FAILED");
});

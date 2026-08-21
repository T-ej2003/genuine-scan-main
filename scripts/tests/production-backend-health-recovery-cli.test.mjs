import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { runBackendHealthRecoveryCli } from "../aws/recover-production-backend-health.mjs";
import { canonicalSha256 } from "../aws/stage-b-task-definition-recovery-contract.mjs";
import { createProductionEnvironmentApprovalEvidence } from "../aws/production-github-environment-approval.mjs";
import { makeCanonicalImageAuthorization } from "./fixtures/canonical-image-authorization.mjs";

const sourceSha = "565f78be803558feb40a543ead464c5410738960";
const digest = "sha256:3dbd02136a99d1741fdfa655397a661fa2275812e1cad0675c93fc5c7c4b4477";
const currentArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const now = new Date("2026-08-20T18:00:00.000Z");
const githubEnv = { GITHUB_ACTIONS: "true", GITHUB_ACTOR: "release-operator", GITHUB_REPOSITORY: "T-ej2003/genuine-scan-main", GITHUB_WORKFLOW_REF: "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main", GITHUB_EVENT_NAME: "workflow_dispatch", GITHUB_RUN_ID: "123", GITHUB_RUN_ATTEMPT: "1" };
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

function privateFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "backend-health-recovery-"));
  fs.chmodSync(dir, 0o700);
  const imageFixture = makeCanonicalImageAuthorization({ sourceSha, imageReleaseSha: sourceSha, imageDigests: {
    backend: digest,
    worker: "sha256:949a4f25d9cc5d67358722c7af75e91bd9a944e75496c76fa36b4677fd152cfe",
    "rls-executor": "sha256:6a06c2435f7330c0b5efacce91e526aa0cca9f3f1df02efaec2c8f993b6fde37",
    "rls-canary": "sha256:f26b3c87ef6b7d1545936e50a41a049e5d02b3f11ef81bd41946ca1c967b05ab",
  } });
  const approval = { ticket: "INC-1", approvedBy: "security", approverRole: "Security Lead", reason: "backend recovery", verificationRef: "https://example.invalid/1", sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest };
  const imageBytes = Buffer.from(JSON.stringify(imageFixture.authorization));
  const approvalBytes = Buffer.from(JSON.stringify(approval));
  const environmentApproval = createProductionEnvironmentApprovalEvidence({
    repository: githubEnv.GITHUB_REPOSITORY, environment: "production", sourceSha, workflowRunId: githubEnv.GITHUB_RUN_ID,
    workflowRef: githubEnv.GITHUB_WORKFLOW_REF, eventName: githubEnv.GITHUB_EVENT_NAME, workflowRunAttempt: githubEnv.GITHUB_RUN_ATTEMPT, executionActor: githubEnv.GITHUB_ACTOR, observedAt: now.toISOString(),
    environmentConfig: { id: 14514600120, name: "production", can_admins_bypass: false, protection_rules: [{ type: "required_reviewers", prevent_self_review: true, reviewers: [{ type: "User", reviewer: { id: 1 } }] }] },
  });
  const environmentBytes = Buffer.from(JSON.stringify(environmentApproval));
  const image = path.join(dir, "image.json");
  const approvalPath = path.join(dir, "approval.json");
  const environmentPath = path.join(dir, "environment-approval.json");
  fs.writeFileSync(image, imageBytes, { mode: 0o600 });
  fs.writeFileSync(approvalPath, approvalBytes, { mode: 0o600 });
  fs.writeFileSync(environmentPath, environmentBytes, { mode: 0o600 });
  return { dir, image, imageBytes, approvalPath, approvalBytes, environmentApproval, environmentPath, environmentBytes, imageFixture };
}

const environmentArgs = (fixture) => ["--environment-approval", fixture.environmentPath, "--environment-approval-sha256", sha(fixture.environmentBytes)];
const deps = (fixture, overrides = {}) => ({ baseEnv: githubEnv, now, readProtectedMain: () => ({ headSha: sourceSha, freshRemoteMainSha: sourceSha }), verifyImageEvidence: fixture.imageFixture.verifyImageEvidence, ...overrides });

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
  await assert.rejects(() => runBackendHealthRecoveryCli([
    "--prepare", "--source-sha", sourceSha, "--current-task-definition", currentArn,
    ...environmentArgs(selfApproved),
    "--recovery-image-digest", digest, "--image-authorization", selfApproved.image,
    "--image-authorization-sha256", sha(selfApproved.imageBytes), "--approval", selfApproved.approvalPath,
    "--approval-sha256", sha(approvalBytes), "--output", path.join(selfApproved.dir, "authorization.json"),
  ], deps(selfApproved)), /self-approved/);
});

test("execute authenticates semantic authorization before any AWS call", async (t) => {
  const fixture = privateFixture();
  t.after(() => fs.rmSync(fixture.dir, { recursive: true, force: true }));
  const authorization = {
    schemaVersion: 1, kind: "BACKEND_HEALTH_RECOVERY_LEGACY_RUNTIME", environment: "production",
    account: "368992683803", region: "eu-west-2", cluster: "mscqr-prod-euw2-main", service: "wrong-service", family: "mscqr-backend",
    sourceSha, imageReleaseSha: fixture.imageFixture.imageReleaseSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest,
    imageAuthorizationSha256: fixture.imageFixture.authorization.evidenceSha256, reasonCode: "CURRENT_IMAGE_DIGEST_MISSING",
    environmentApprovalSha256: fixture.environmentApproval.evidenceSha256,
    allowedDeltaProfile: "IMAGE_AND_SOURCE_IDENTITY_ONLY",
    approval: { ticket: "INC-1", approvedBy: "security", approverRole: "Security Lead", reason: "backend recovery", verificationRef: "https://example.invalid/1", sourceSha, currentTaskDefinitionArn: currentArn, recoveryImageDigest: digest },
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

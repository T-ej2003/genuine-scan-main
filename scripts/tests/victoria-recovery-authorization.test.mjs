import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { consumeVictoriaRecoveryNonce, createVictoriaRecoveryAuthorization, verifyVictoriaRecoveryAuthorization } from "../aws/victoria-recovery-authorization.mjs";

const sourceSha = "1e621ae122156bb6346c78fee1889136a79ff174";
const signingKeyArn = "arn:aws:kms:eu-west-2:368992683803:key/123e4567-e89b-42d3-a456-426614174000";
const executorImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-victoria-recovery@sha256:${"b".repeat(64)}`;
const executorTaskDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-victoria-recovery:1";
const nonce = "550e8400-e29b-41d4-a716-446655440000";
const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const approvalEvidence = {
  schemaVersion: 3, sourceSha, environment: "production-victoria-recovery", executionActor: "operator",
  workflowRef: "T-ej2003/genuine-scan-main/.github/workflows/execute-victoria-onboarding-recovery.yml@refs/heads/main",
  workflowRunId: "123456", workflowRunAttempt: "1", evidenceSha256: "a".repeat(64),
  actualApproval: { userLogin: "reviewer" }, configuredReviewers: [{ name: "reviewer" }], preventSelfReview: true,
};
const sign = async ({ message }) => crypto.sign("sha256", message, { key: pair.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 });
const verify = async ({ message, signature }) => crypto.verify("sha256", message, { key: pair.publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature);
const validateApproval = (value) => {
  if (value.actualApproval.userLogin !== "reviewer" || value.workflowRef !== "T-ej2003/genuine-scan-main/.github/workflows/execute-victoria-onboarding-recovery.yml@refs/heads/main") throw new Error("test approval invalid");
};

test("KMS-signable contract binds fixed source, target, database, image, task, operator and authenticated approval", async () => {
  process.env.GITHUB_ACTOR = "operator";
  const authorization = await createVictoriaRecoveryAuthorization({
    sourceSha, executorImage, executorTaskDefinition, signingKeyArn,
    nonce, issuedAt: "2026-10-01T12:00:00.000Z", approvalEvidence, sign, validateApproval,
  });
  const expected = { sourceSha, implementationSha256: authorization.implementationSha256, executorImage, executorTaskDefinition, signingKeyArn, operator: "operator", approvedBy: "reviewer", approvalWorkflowRunId: "123456", approvalWorkflowRunAttempt: "1", nonce };
  assert.equal((await verifyVictoriaRecoveryAuthorization(authorization, expected, { verify, now: new Date("2026-10-01T12:01:00.000Z") })).targetEmail, "victoria@mscqr.com");
  assert.equal(authorization.targetDatabase, "mscqr_production");
  assert.equal("mfa" in authorization, false);
});

test("modified binding, expired authorization, or forged signature is rejected", async () => {
  process.env.GITHUB_ACTOR = "operator";
  const authorization = await createVictoriaRecoveryAuthorization({
    sourceSha, executorImage, executorTaskDefinition, signingKeyArn,
    nonce, issuedAt: "2026-10-01T12:00:00.000Z", approvalEvidence, sign, validateApproval,
  });
  const expected = { sourceSha, implementationSha256: authorization.implementationSha256, executorImage, executorTaskDefinition, signingKeyArn, operator: "operator", approvedBy: "reviewer", approvalWorkflowRunId: "123456", approvalWorkflowRunAttempt: "1", nonce };
  await assert.rejects(verifyVictoriaRecoveryAuthorization(authorization, { ...expected, sourceSha: "0".repeat(40) }, { verify }));
  await assert.rejects(verifyVictoriaRecoveryAuthorization(authorization, expected, { verify, now: new Date("2026-10-01T12:10:00.000Z") }));
  await assert.rejects(verifyVictoriaRecoveryAuthorization({ ...authorization, targetEmail: "other@example.com" }, expected, { verify }));
});

test("all immutable authorization bindings reject substitution", async () => {
  process.env.GITHUB_ACTOR = "operator";
  const authorization = await createVictoriaRecoveryAuthorization({ sourceSha, executorImage, executorTaskDefinition, signingKeyArn,
    nonce, issuedAt: "2026-10-01T12:00:00.000Z", approvalEvidence, sign, validateApproval });
  const expected = { sourceSha, implementationSha256: authorization.implementationSha256, executorImage, executorTaskDefinition,
    signingKeyArn, operator: "operator", approvedBy: "reviewer", approvalWorkflowRunId: "123456", approvalWorkflowRunAttempt: "1", nonce };
  for (const [field, value] of Object.entries({ executorImage: `${executorImage.slice(0, -1)}c`,
    executorTaskDefinition: executorTaskDefinition.replace(":1", ":2"), signingKeyArn: signingKeyArn.replace("123e", "223e"),
    operator: "attacker", approvedBy: "attacker", approvalWorkflowRunId: "123457", approvalWorkflowRunAttempt: "2",
    implementationSha256: "c".repeat(64), nonce: "550e8400-e29b-41d4-a716-446655440001" })) {
    await assert.rejects(verifyVictoriaRecoveryAuthorization(authorization, { ...expected, [field]: value }, { verify }), field);
  }
  await assert.rejects(verifyVictoriaRecoveryAuthorization({ ...authorization, environment: "production" }, expected, { verify }));
  await assert.rejects(verifyVictoriaRecoveryAuthorization({ ...authorization, operation: "OTHER" }, expected, { verify }));
});

test("nonce consumption is durable and concurrent/replayed use is rejected", async () => {
  process.env.GITHUB_ACTOR = "operator";
  const authorization = await createVictoriaRecoveryAuthorization({
    sourceSha, executorImage, executorTaskDefinition, signingKeyArn,
    nonce, issuedAt: "2026-10-01T12:00:00.000Z", approvalEvidence, sign, validateApproval,
  });
  const keys = new Set();
  const putIfAbsent = async ({ key }) => keys.has(key) ? false : (keys.add(key), true);
  const attempts = await Promise.allSettled([
    consumeVictoriaRecoveryNonce(authorization, { putIfAbsent }),
    consumeVictoriaRecoveryNonce(authorization, { putIfAbsent }),
  ]);
  assert.equal(attempts.filter(({ status }) => status === "fulfilled").length, 1);
  assert.equal(attempts.filter(({ status }) => status === "rejected").length, 1);
  assert.match([...keys][0], /^nonces\//);
});

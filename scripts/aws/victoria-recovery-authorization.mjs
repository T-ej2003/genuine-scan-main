import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const VICTORIA_RECOVERY_IDENTITY = Object.freeze({
  operation: "VICTORIA_FAILED_ONBOARDING_RECOVERY_V1",
  email: "victoria@mscqr.com",
  database: "mscqr_production",
  environment: "production-victoria-recovery",
});
export const VICTORIA_RECOVERY_IMPLEMENTATION_FILES = Object.freeze([
  "scripts/aws/victoria-recovery-authorization.mjs",
  "scripts/aws/victoria-recovery-result.mjs",
  "scripts/aws/publish-victoria-recovery-authorization.mjs",
  "scripts/aws/register-victoria-recovery-task-definition.mjs",
  "scripts/aws/production-github-environment-approval.mjs",
  "scripts/security/victoria-recovery-sql.mjs",
  "scripts/security/victoria-recovery-installation.mjs",
  "backend/scripts/victoria-rds-iam-token.mjs",
  "scripts/security/victoria-recovery-dependencies.json",
  "backend/src/rls-waves/session-c/c05/victoriaRecovery.template.sql",
  "backend/src/rls-waves/session-c/c05/victoriaRecovery.sql",
  "backend/scripts/victoria-failed-onboarding-recovery.mjs",
  ".github/workflows/execute-victoria-onboarding-recovery.yml",
  "infra/aws/terraform/production-victoria-recovery/task-definition.json",
  "infra/aws/terraform/production-victoria-recovery/Dockerfile",
  "infra/aws/terraform/lambda/victoria-recovery-broker/index.mjs",
  "infra/aws/terraform/lambda/victoria-recovery-broker/task-cleanup.mjs",
  "infra/aws/terraform/production-victoria-recovery/main.tf",
  "infra/aws/terraform/production-victoria-recovery/variables.tf",
  "infra/aws/terraform/production-victoria-recovery/outputs.tf",
  "infra/aws/terraform/production-victoria-recovery/versions.tf",
]);
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KMS_ARN = /^arn:aws:kms:eu-west-2:368992683803:key\/[0-9a-f-]{36}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-victoria-recovery@sha256:[a-f0-9]{64}$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-victoria-recovery:[1-9][0-9]*$/;
const FIELDS = ["schemaVersion", "operation", "sourceSha", "implementationSha256", "targetEmail", "targetDatabase", "environment", "executorImage", "executorTaskDefinition", "signingKeyArn", "operator", "approvedBy", "approvalEvidenceSha256", "approvalWorkflowRunId", "approvalWorkflowRunAttempt", "nonce", "issuedAt", "expiresAt"];
const stable = (value) => Array.isArray(value) ? `[${value.map(stable).join(",")}]`
  : value && typeof value === "object" ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`
    : JSON.stringify(value);
const digest = (value) => crypto.createHash("sha256").update(stable(value)).digest();

export function victoriaRecoveryImplementationSha256() {
  const hash = crypto.createHash("sha256");
  for (const file of VICTORIA_RECOVERY_IMPLEMENTATION_FILES) {
    hash.update(file).update("\0").update(fs.readFileSync(path.join(root, file))).update("\0");
  }
  return hash.digest("hex");
}

function validateFields(value) {
  if (!value || (Object.keys(value).sort().join(",") !== [...FIELDS, "signatureBase64"].sort().join(",")
      && Object.keys(value).sort().join(",") !== [...FIELDS].sort().join(","))
      || value.schemaVersion !== 1 || value.operation !== VICTORIA_RECOVERY_IDENTITY.operation
      || value.targetEmail !== VICTORIA_RECOVERY_IDENTITY.email || value.targetDatabase !== VICTORIA_RECOVERY_IDENTITY.database
      || value.environment !== VICTORIA_RECOVERY_IDENTITY.environment || !SHA40.test(value.sourceSha || "")
      || !SHA256.test(value.implementationSha256 || "") || !IMAGE.test(value.executorImage || "")
      || !TASK.test(value.executorTaskDefinition || "") || !KMS_ARN.test(value.signingKeyArn || "")
      || !UUID.test(value.nonce || "") || !/^[A-Za-z0-9-]{1,39}$/.test(value.operator || "")
      || !/^[A-Za-z0-9-]{1,39}$/.test(value.approvedBy || "")
      || !SHA256.test(value.approvalEvidenceSha256 || "")
      || !/^[1-9][0-9]*$/.test(value.approvalWorkflowRunId || "")
      || !/^[1-9][0-9]*$/.test(value.approvalWorkflowRunAttempt || "")) throw new Error("Victoria recovery authorization fields are invalid.");
  const issued = Date.parse(value.issuedAt), expires = Date.parse(value.expiresAt);
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || new Date(issued).toISOString() !== value.issuedAt
      || new Date(expires).toISOString() !== value.expiresAt || expires - issued !== 10 * 60_000) throw new Error("Victoria recovery authorization time bounds are invalid.");
}

export async function createVictoriaRecoveryAuthorization({ sourceSha, executorImage, executorTaskDefinition, signingKeyArn, nonce = crypto.randomUUID(), issuedAt = new Date().toISOString(), approvalEvidence, sign, validateApproval }) {
  if (typeof sign !== "function" || typeof validateApproval !== "function") throw new Error("Authenticated approval validation and a KMS signer are required.");
  if (!KMS_ARN.test(signingKeyArn || "") || approvalEvidence?.schemaVersion !== 3
      || approvalEvidence?.sourceSha !== sourceSha || approvalEvidence?.environment !== VICTORIA_RECOVERY_IDENTITY.environment
      || approvalEvidence?.executionActor !== process.env.GITHUB_ACTOR
      || approvalEvidence?.workflowRef !== "T-ej2003/genuine-scan-main/.github/workflows/execute-victoria-onboarding-recovery.yml@refs/heads/main"
      || !SHA256.test(approvalEvidence?.evidenceSha256 || "")) throw new Error("Authenticated production approval evidence is required.");
  validateApproval(approvalEvidence);
  const approvedBy = approvalEvidence.actualApproval.userLogin;
  if (!approvalEvidence.configuredReviewers?.some(({ name }) => name.toLowerCase() === approvedBy.toLowerCase())
      || approvalEvidence.preventSelfReview && approvedBy.toLowerCase() === approvalEvidence.executionActor.toLowerCase()) throw new Error("Approval identity is not an eligible production reviewer.");
  const body = {
    schemaVersion: 1,
    operation: VICTORIA_RECOVERY_IDENTITY.operation,
    sourceSha,
    implementationSha256: victoriaRecoveryImplementationSha256(),
    targetEmail: VICTORIA_RECOVERY_IDENTITY.email,
    targetDatabase: VICTORIA_RECOVERY_IDENTITY.database,
    environment: VICTORIA_RECOVERY_IDENTITY.environment,
    executorImage,
    executorTaskDefinition,
    signingKeyArn,
    operator: approvalEvidence.executionActor,
    approvedBy,
    approvalEvidenceSha256: approvalEvidence.evidenceSha256,
    approvalWorkflowRunId: approvalEvidence.workflowRunId,
    approvalWorkflowRunAttempt: approvalEvidence.workflowRunAttempt,
    nonce,
    issuedAt,
    expiresAt: new Date(Date.parse(issuedAt) + 10 * 60_000).toISOString(),
  };
  validateFields(body);
  const signature = await sign({ keyId: signingKeyArn, message: digest(body) });
  if (!Buffer.isBuffer(signature) || signature.length < 64) throw new Error("KMS returned an invalid authorization signature.");
  return Object.freeze({ ...body, signatureBase64: signature.toString("base64") });
}

export async function verifyVictoriaRecoveryAuthorization(value, expected, { verify, now = new Date() } = {}) {
  if (typeof verify !== "function") throw new Error("A KMS-backed authorization verifier is required.");
  validateFields(value);
  if (value.sourceSha !== expected.sourceSha || value.implementationSha256 !== expected.implementationSha256
      || value.executorImage !== expected.executorImage || value.executorTaskDefinition !== expected.executorTaskDefinition
      || value.signingKeyArn !== expected.signingKeyArn || value.operator !== expected.operator
      || value.approvedBy !== expected.approvedBy || value.approvalWorkflowRunId !== expected.approvalWorkflowRunId
      || value.approvalWorkflowRunAttempt !== expected.approvalWorkflowRunAttempt
      || value.nonce !== expected.nonce) throw new Error("Authorization binding does not match the running executor.");
  const issued = Date.parse(value.issuedAt), expires = Date.parse(value.expiresAt);
  if (now.getTime() < issued || now.getTime() >= expires) throw new Error("Authorization is not currently valid.");
  let signature;
  try { signature = Buffer.from(value.signatureBase64, "base64"); } catch { throw new Error("Authorization signature encoding is invalid."); }
  const { signatureBase64, ...body } = value;
  if (!signatureBase64 || signature.toString("base64") !== signatureBase64
      || await verify({ keyId: value.signingKeyArn, message: digest(body), signature }) !== true) throw new Error("Authorization signature verification failed.");
  return Object.freeze({ ...value });
}

export async function consumeVictoriaRecoveryNonce(authorization, { putIfAbsent }) {
  if (typeof putIfAbsent !== "function" || !UUID.test(authorization?.nonce || "")
      || authorization?.operation !== VICTORIA_RECOVERY_IDENTITY.operation) throw new Error("Recovery nonce store or authorization is invalid.");
  const key = `nonces/${authorization.nonce}`;
  const evidence = Buffer.from(stable({
    operation: authorization.operation,
    sourceSha: authorization.sourceSha,
    authorizationSha256: crypto.createHash("sha256").update(stable(authorization)).digest("hex"),
    consumedAt: new Date().toISOString(),
  }));
  if (await putIfAbsent({ key, body: evidence }) !== true) throw new Error("Recovery authorization nonce was already consumed.");
  return Object.freeze({ key, evidenceSha256: crypto.createHash("sha256").update(evidence).digest("hex") });
}

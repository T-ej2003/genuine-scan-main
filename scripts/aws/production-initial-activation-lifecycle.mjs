import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJson, PRODUCTION_ACTIVATION_LIFECYCLE } from "./production-green-stage-b-contract.mjs";

export const CLAIM_KIND = "PRODUCTION_INITIAL_ACTIVATION_CLAIM";
export const COMPLETION_KIND = "PRODUCTION_INITIAL_ACTIVATION_COMPLETION";
const REPOSITORY = "T-ej2003/genuine-scan-main";
const SHA40 = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;
const TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-backend-candidate:[1-9][0-9]*$/;
const ISO = (value) => typeof value === "string" && Number.isFinite(Date.parse(value)) && new Date(Date.parse(value)).toISOString() === value;
const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const awsError = (code, operation, message) => new RegExp(`^(?:aws: \\[ERROR\\]: )?An error occurred \\(${code}\\) when calling the ${operation} operation: ${message}\\s*$`);
const exactKeys = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const CLAIM_FIELDS = Object.freeze(["schemaVersion", "kind", "environment", "repository", "sourceSha", "rotationId", "overlapDeploymentSha", "taskDefinitionArn", "activationTaskDefinitionArn", "imageDigest", "overlapRuntimeProofSha256", "activationTransactionId", "createdAt"]);
const COMPLETION_FIELDS = Object.freeze(["schemaVersion", "kind", "environment", "repository", "sourceSha", "rotationId", "overlapDeploymentSha", "taskDefinitionArn", "activationTaskDefinitionArn", "imageDigest", "activationTransactionId", "claimSha256", "claimVersionId", "rlsReceiptSha256", "onboardingEvidenceSha256", "completedAt"]);

const canonicalBytes = (value) => Buffer.from(`${canonicalJson(value)}\n`);
const identity = (value) => ({ sourceSha: value.sourceSha, rotationId: value.rotationId, overlapDeploymentSha: value.overlapDeploymentSha, taskDefinitionArn: value.taskDefinitionArn, activationTaskDefinitionArn: value.activationTaskDefinitionArn, imageDigest: value.imageDigest, activationTransactionId: value.activationTransactionId });
const assertIdentity = (value) => {
  if (!SHA40.test(value.sourceSha || "") || !ROTATION_ID.test(value.rotationId || "") || !SHA40.test(value.overlapDeploymentSha || "") || !TASK_DEFINITION.test(value.taskDefinitionArn || "") || !TASK_DEFINITION.test(value.activationTaskDefinitionArn || "") || !DIGEST.test(value.imageDigest || "") || !SHA256.test(value.activationTransactionId || "")) throw new Error("Production activation lifecycle identity is invalid.");
};
const transactionId = (value) => sha256(canonicalJson({ environment: "production", repository: REPOSITORY, sourceSha: value.sourceSha, rotationId: value.rotationId, overlapDeploymentSha: value.overlapDeploymentSha, taskDefinitionArn: value.taskDefinitionArn, activationTaskDefinitionArn: value.activationTaskDefinitionArn, imageDigest: value.imageDigest, overlapRuntimeProofSha256: value.overlapRuntimeProofSha256 }));

export function buildInitialActivationClaim({ sourceSha, rotationId, overlapDeploymentSha, taskDefinitionArn, activationTaskDefinitionArn, imageDigest, overlapRuntimeProofSha256, createdAt } = {}) {
  const claim = { schemaVersion: 1, kind: CLAIM_KIND, environment: "production", repository: REPOSITORY, sourceSha, rotationId, overlapDeploymentSha, taskDefinitionArn, activationTaskDefinitionArn, imageDigest, overlapRuntimeProofSha256, activationTransactionId: "", createdAt };
  claim.activationTransactionId = transactionId(claim);
  validateInitialActivationClaim(claim);
  return Object.freeze(claim);
}

export function validateInitialActivationClaim(value, expected) {
  if (!exactKeys(value, CLAIM_FIELDS) || value.schemaVersion !== 1 || value.kind !== CLAIM_KIND || value.environment !== "production" || value.repository !== REPOSITORY || !SHA256.test(value.overlapRuntimeProofSha256 || "") || !ISO(value.createdAt)) throw new Error("Production initial activation claim schema is invalid.");
  assertIdentity(value);
  if (value.activationTransactionId !== transactionId(value)) throw new Error("Production initial activation claim transaction identity is invalid.");
  if (expected && Object.entries(identity(expected)).some(([key, expectedValue]) => expectedValue !== undefined && value[key] !== expectedValue)) throw new Error("Production initial activation claim conflicts with the authenticated transaction.");
  return value;
}

export function parseInitialActivationClaim(raw, expected) {
  if (!Buffer.isBuffer(raw)) throw new Error("Production initial activation claim bytes are required.");
  let value;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); } catch { throw new Error("Production initial activation claim is not valid UTF-8 JSON."); }
  validateInitialActivationClaim(value, expected);
  if (!raw.equals(canonicalBytes(value))) throw new Error("Production initial activation claim bytes are not canonical.");
  return Object.freeze({ value: Object.freeze(value), sha256: sha256(raw) });
}

export function buildInitialActivationCompletion({ claim, claimSha256, claimVersionId, rlsReceiptSha256, onboardingEvidenceSha256, completedAt } = {}) {
  validateInitialActivationClaim(claim);
  const completion = { schemaVersion: 1, kind: COMPLETION_KIND, environment: "production", repository: REPOSITORY, ...identity(claim), claimSha256, claimVersionId: claimVersionId || "UNVERSIONED", rlsReceiptSha256, onboardingEvidenceSha256, completedAt };
  validateInitialActivationCompletion(completion, { claim, claimSha256, claimVersionId });
  return Object.freeze(completion);
}

export function validateInitialActivationCompletion(value, { claim, claimSha256, claimVersionId, expected } = {}) {
  if (!exactKeys(value, COMPLETION_FIELDS) || value.schemaVersion !== 1 || value.kind !== COMPLETION_KIND || value.environment !== "production" || value.repository !== REPOSITORY || !SHA256.test(value.claimSha256 || "") || !SHA256.test(value.rlsReceiptSha256 || "") || !SHA256.test(value.onboardingEvidenceSha256 || "") || !ISO(value.completedAt) || !(value.claimVersionId === "UNVERSIONED" || /^[A-Za-z0-9._-]{1,1024}$/.test(value.claimVersionId || ""))) throw new Error("Production initial activation completion schema is invalid.");
  assertIdentity(value);
  if (claim) validateInitialActivationClaim(claim, value);
  if (claimSha256 && value.claimSha256 !== claimSha256) throw new Error("Production activation completion claim digest is invalid.");
  if (value.claimVersionId !== (claimVersionId || "UNVERSIONED")) throw new Error("Production activation completion claim version is invalid.");
  if (expected) {
    const withoutTimestamp = ({ completedAt: _completedAt, ...rest }) => rest;
    if (canonicalJson(withoutTimestamp(value)) !== canonicalJson(withoutTimestamp(expected))) throw new Error("Production activation completion conflicts with the authenticated transaction.");
  }
  return value;
}

const awsCli = (args) => {
  const result = spawnSync("aws", [...args, "--region", "eu-west-2", "--output", "json", "--no-cli-pager"], { encoding: "utf8" });
  if (result.status === 0) return { ok: true, value: result.stdout.trim() ? JSON.parse(result.stdout) : {} };
  const stderr = String(result.stderr || "");
  if (awsError("PreconditionFailed", "PutObject", "At least one of the pre-conditions you specified did not hold\\.?").test(stderr)) return { ok: false, conflict: "PRECONDITION_FAILED" };
  if (awsError("ConditionalRequestConflict", "PutObject", "A conflicting conditional operation is currently in progress against this resource\\. Please try again\\.?").test(stderr)) return { ok: false, conflict: "CONDITIONAL_REQUEST_CONFLICT" };
  if (awsError("NoSuchKey", "GetObject", "The specified key does not exist\\.?").test(stderr)) return { ok: false, missing: true };
  throw new Error("Production activation lifecycle S3 request failed.");
};

const readObject = ({ key, aws = awsCli }) => {
  const directory = mkdtempSync(path.join(tmpdir(), "mscqr-activation-lifecycle-"));
  const output = path.join(directory, "object.json");
  try {
    const result = aws(["s3api", "get-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, output]);
    if (result?.missing) return null;
    if (!result?.ok || !result.value || typeof result.value !== "object" || Array.isArray(result.value)
      || (result.value.VersionId !== undefined && !/^[A-Za-z0-9._-]{1,1024}$/.test(result.value.VersionId))) throw new Error("Production activation lifecycle object read failed.");
    return { raw: readFileSync(output), versionId: result.value.VersionId || "UNVERSIONED" };
  } finally { rmSync(directory, { recursive: true, force: true }); }
};

const createObject = ({ key, value, parse, expected, aws = awsCli }) => {
  const raw = canonicalBytes(value);
  const directory = mkdtempSync(path.join(tmpdir(), "mscqr-activation-lifecycle-"));
  const body = path.join(directory, "object.json");
  try {
    writeFileSync(body, raw, { mode: 0o600, flag: "wx" });
    const created = aws(["s3api", "put-object", "--bucket", PRODUCTION_ACTIVATION_LIFECYCLE.bucket, "--key", key, "--body", body, "--content-type", "application/json", "--server-side-encryption", "AES256", "--if-none-match", "*"]);
    if (created?.ok) {
      const persisted = readObject({ key, aws });
      if (!persisted) throw new Error("Production activation lifecycle create succeeded without durable readback.");
      const parsed = parse(persisted.raw, expected);
      return Object.freeze({ status: "CREATED", value: parsed.value, sha256: parsed.sha256, versionId: persisted.versionId });
    }
    if (!created?.conflict) throw new Error("Production activation lifecycle conditional create failed.");
    const existing = readObject({ key, aws });
    if (!existing) throw new Error("Production activation lifecycle conflict could not be authenticated; retry the conditional create without changing its bindings.");
    const parsed = parse(existing.raw, expected);
    return Object.freeze({ status: "ALREADY_EXISTS_MATCHING", value: parsed.value, sha256: parsed.sha256, versionId: existing.versionId });
  } finally { rmSync(directory, { recursive: true, force: true }); }
};

export const createInitialActivationClaim = ({ claim, aws } = {}) => createObject({ key: PRODUCTION_ACTIVATION_LIFECYCLE.claimKey, value: validateInitialActivationClaim(claim), parse: parseInitialActivationClaim, expected: claim, aws });
export const readInitialActivationClaim = ({ expected, aws } = {}) => {
  const result = readObject({ key: PRODUCTION_ACTIVATION_LIFECYCLE.claimKey, aws });
  if (!result) throw new Error("Production initial activation claim is missing.");
  const parsed = parseInitialActivationClaim(result.raw, expected);
  return Object.freeze({ ...parsed, versionId: result.versionId });
};

export const createInitialActivationCompletion = ({ completion, claim, claimSha256, claimVersionId, aws } = {}) => createObject({
  key: PRODUCTION_ACTIVATION_LIFECYCLE.completionKey,
  value: validateInitialActivationCompletion(completion, { claim, claimSha256, claimVersionId }),
  parse: (raw) => {
    let value; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); } catch { throw new Error("Production activation completion is not valid UTF-8 JSON."); }
    validateInitialActivationCompletion(value, { claim, claimSha256, claimVersionId, expected: completion });
    if (!raw.equals(canonicalBytes(value))) throw new Error("Production activation completion bytes are not canonical.");
    return { value, sha256: sha256(raw) };
  },
  expected: completion,
  aws,
});

export const readInitialActivationCompletion = ({ claim, claimSha256, claimVersionId, aws } = {}) => {
  const result = readObject({ key: PRODUCTION_ACTIVATION_LIFECYCLE.completionKey, aws });
  if (!result) throw new Error("Production initial activation completion is missing.");
  let value; try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(result.raw)); } catch { throw new Error("Production activation completion is not valid UTF-8 JSON."); }
  validateInitialActivationCompletion(value, { claim, claimSha256, claimVersionId });
  if (!result.raw.equals(canonicalBytes(value))) throw new Error("Production activation completion bytes are not canonical.");
  return Object.freeze({ value: Object.freeze(value), sha256: sha256(result.raw), versionId: result.versionId });
};

export const assertInitialActivationCompletionAbsent = ({ aws } = {}) => {
  if (readObject({ key: PRODUCTION_ACTIVATION_LIFECYCLE.completionKey, aws })) throw new Error("Production initial activation is already completed.");
  return true;
};

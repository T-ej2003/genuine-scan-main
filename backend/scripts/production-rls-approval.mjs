import crypto from "node:crypto";

export const PRODUCTION_RLS_APPROVAL_SCHEMA_VERSION = 1;
export const PRODUCTION_RLS_APPROVAL_ALGORITHM = "RSASSA_PSS_SHA_256";
export const PRODUCTION_RLS_APPROVAL_MAX_LIFETIME_MS = 2 * 60 * 60 * 1000;

const exactKeys = [
  "administratorIdentity",
  "approvalId",
  "deploymentId",
  "environment",
  "expiresAt",
  "greenDatabase",
  "independentCheckerIdentity",
  "issuedAt",
  "kmsKeyArn",
  "migrationSetDigest",
  "releaseSha",
  "schemaVersion",
  "signatureAlgorithm",
  "sourceContractSha256",
  "ticketId",
];

const stable = (value) => {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stable(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};

export const canonicalProductionApprovalPayload = (approval) =>
  Buffer.from(stable(Object.fromEntries(exactKeys.map((key) => [key, approval[key]]))));

export const productionApprovalSha256 = (approval) =>
  crypto.createHash("sha256").update(canonicalProductionApprovalPayload(approval)).digest("hex");

const parseArtifact = (raw) => {
  let artifact;
  try {
    artifact = typeof raw === "string" ? JSON.parse(raw) : raw;
  } catch {
    throw new Error("Production RLS approval artifact is not valid JSON.");
  }
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)
      || Object.keys(artifact).sort().join(",") !== [...exactKeys, "signatureBase64"].sort().join(",")) {
    throw new Error("Production RLS approval artifact fields do not match schema version 1.");
  }
  return artifact;
};

const defaultVerify = async ({ keyId, message, signature }) => {
  const { KMSClient, VerifyCommand } = await import("@aws-sdk/client-kms");
  const response = await new KMSClient({ region: "eu-west-2" }).send(new VerifyCommand({
    KeyId: keyId,
    Message: message,
    MessageType: "RAW",
    Signature: signature,
    SigningAlgorithm: PRODUCTION_RLS_APPROVAL_ALGORITHM,
  }));
  return response.SignatureValid === true;
};

export async function validateProductionRlsApproval(raw, expected, {
  now = new Date(),
  verifySignature = defaultVerify,
  allowExpiredRollback = false,
} = {}) {
  const artifact = parseArtifact(raw);
  const issuedAt = new Date(artifact.issuedAt);
  const expiresAt = new Date(artifact.expiresAt);
  if (artifact.schemaVersion !== PRODUCTION_RLS_APPROVAL_SCHEMA_VERSION
      || artifact.environment !== "production"
      || artifact.signatureAlgorithm !== PRODUCTION_RLS_APPROVAL_ALGORITHM
      || !/^[a-f0-9]{40}$/.test(artifact.releaseSha)
      || !/^[a-f0-9]{64}$/.test(artifact.sourceContractSha256)
      || !/^[a-f0-9]{64}$/.test(artifact.migrationSetDigest)
      || !/^[a-z][a-z0-9_]{0,15}$/.test(artifact.deploymentId)
      || !/^mscqr_production_rls_green_[a-z][a-z0-9_]{0,15}$/.test(artifact.greenDatabase)
      || !/^mscqr_prod_admin$/.test(artifact.administratorIdentity)
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(artifact.approvalId)
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(artifact.ticketId)
      || !/^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{2,64}$/.test(artifact.independentCheckerIdentity)
      || !/^arn:aws:kms:eu-west-2:368992683803:key\/[0-9a-f-]{36}$/.test(artifact.kmsKeyArn)
      || !Number.isFinite(issuedAt.getTime())
      || !Number.isFinite(expiresAt.getTime())
      || issuedAt.getTime() > now.getTime() + 5 * 60_000
      || expiresAt.getTime() <= issuedAt.getTime()
      || (expiresAt.getTime() <= now.getTime()
        && (!allowExpiredRollback || now.getTime() > expiresAt.getTime() + 24 * 60 * 60 * 1000))
      || expiresAt.getTime() - issuedAt.getTime() > PRODUCTION_RLS_APPROVAL_MAX_LIFETIME_MS
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(artifact.signatureBase64)) {
    throw new Error("Production RLS approval artifact is invalid or expired.");
  }
  for (const key of [
    "releaseSha",
    "sourceContractSha256",
    "migrationSetDigest",
    "deploymentId",
    "greenDatabase",
    "administratorIdentity",
    "kmsKeyArn",
  ]) {
    if (artifact[key] !== expected[key]) {
      throw new Error(`Production RLS approval ${key} does not match the execution contract.`);
    }
  }
  const signature = Buffer.from(artifact.signatureBase64, "base64");
  if (!signature.length || !await verifySignature({
    keyId: artifact.kmsKeyArn,
    message: canonicalProductionApprovalPayload(artifact),
    signature,
  })) {
    throw new Error("Production RLS approval signature verification failed.");
  }
  const approval = Object.fromEntries(exactKeys.map((key) => [key, artifact[key]]));
  return {
    approval,
    signatureBase64: artifact.signatureBase64,
    approvalContractSha256: productionApprovalSha256(approval),
  };
}

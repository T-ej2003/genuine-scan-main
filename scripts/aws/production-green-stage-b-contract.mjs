import crypto from "node:crypto";

export const STAGE_B = Object.freeze({
  account: "368992683803",
  region: "eu-west-2",
  clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  greenDatabaseIdentifier: "mscqr-production-rls-green-phase2",
  databaseSecurityGroupId: "sg-0703d3f227f35b81c",
  executorSecurityGroupId: "sg-051a24aedff773761",
  privateSubnetIds: Object.freeze(["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"]),
  receiptBucket: "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  approvalSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho",
  approvalKmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478",
  brokerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
  checkerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
  executorRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
  executorExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
  brokerAliasArn: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed",
  frontendTaskDefinition: "mscqr-frontend:20",
});

export const STAGE_B_MODES = Object.freeze([
  "full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision",
  "full-rls-role-verify", "full-rls-admin-ownership", "full-rls-runtime-policy",
  "full-rls-verification", "full-rls-application-canary", "full-rls-rollback",
]);
export const STAGE_B_APPROVAL_ALGORITHM = "RSASSA_PSS_SHA_256";
export const STAGE_B_APPROVAL_SCHEMA_VERSION = 2;
const imagePattern = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-(?:backend|worker|web)@sha256:[a-f0-9]{64}$/;
const imagePatterns = Object.freeze({
  backendImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  workerImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-worker@sha256:[a-f0-9]{64}$/,
  executorImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  canaryImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
});
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
export const canonicalSha256 = (value) => sha256(canonicalJson(value));
export const assertImmutableImage = (value, field = "image") => {
  if (!imagePattern.test(String(value || ""))) throw new Error(`${field} must be an immutable reviewed ECR digest.`);
  return value;
};

export const STAGE_B_APPROVAL_FIELDS = Object.freeze([
  "account", "approvalId", "backendImageDigest", "brokerAliasArn", "brokerVersion", "canaryImageDigest",
  "administratorIdentity", "checkerIdentity", "databaseSecurityGroupId", "deployerIdentity", "deploymentId", "environment",
  "executorIdentity", "executorImageDigest", "executorSecurityGroupId", "expiresAt", "greenDatabaseIdentifier", "greenDatabaseName",
  "issuedAt", "migrationSetDigest", "nonce", "packageChecksumSha256", "region", "releaseSha",
  "schemaVersion", "signatureAlgorithm", "sourceContractSha256", "taskDefinitionArns", "taskDefinitionTemplateHashes", "ticketId", "workerImageDigest",
]);

export const canonicalStageBApproval = (approval) => canonicalJson(Object.fromEntries(
  STAGE_B_APPROVAL_FIELDS.map((key) => [key, approval[key]])
));
export const stageBApprovalSha256 = (approval) => sha256(canonicalStageBApproval(approval));

const assumedRole = (role) => new RegExp(`^arn:aws:sts::${STAGE_B.account}:assumed-role/${role}/[A-Za-z0-9+=,.@_-]{2,64}$`);
const isDigest = (value) => /^[a-f0-9]{64}$/.test(value || "");
const strictKeys = (value, expected) => Object.keys(value || {}).sort().join(",") === [...expected].sort().join(",");

export async function validateStageBApproval(raw, expected, { now = new Date(), verifySignature, allowExpiredRollback = false, requestedMode = "" } = {}) {
  let artifact;
  try { artifact = typeof raw === "string" ? JSON.parse(raw) : raw; } catch { throw new Error("Stage B approval is not valid JSON."); }
  if (!artifact || typeof artifact !== "object" || Array.isArray(artifact)
      || !strictKeys(artifact, [...STAGE_B_APPROVAL_FIELDS, "signatureBase64"])) {
    throw new Error("Stage B approval fields do not match schema version 2.");
  }
  const issuedAt = Date.parse(artifact.issuedAt);
  const expiresAt = Date.parse(artifact.expiresAt);
  const withinRollbackGrace = allowExpiredRollback && requestedMode === "full-rls-rollback"
    && Number.isFinite(expiresAt) && now.getTime() <= expiresAt + 24 * 60 * 60 * 1000;
  const templateHashes = artifact.taskDefinitionTemplateHashes;
  const taskDefinitionArns = artifact.taskDefinitionArns;
  if (artifact.schemaVersion !== STAGE_B_APPROVAL_SCHEMA_VERSION
      || artifact.environment !== "production" || artifact.account !== STAGE_B.account || artifact.region !== STAGE_B.region
      || artifact.signatureAlgorithm !== STAGE_B_APPROVAL_ALGORITHM || !/^[a-f0-9]{40}$/.test(artifact.releaseSha)
      || !isDigest(artifact.sourceContractSha256) || !isDigest(artifact.migrationSetDigest) || !isDigest(artifact.packageChecksumSha256)
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(artifact.approvalId || "")
      || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(artifact.ticketId || "") || !/^[a-f0-9-]{16,64}$/.test(artifact.nonce || "")
      || artifact.greenDatabaseIdentifier !== STAGE_B.greenDatabaseIdentifier
      || artifact.greenDatabaseName !== "mscqr_production_rls_green_phase2" || artifact.administratorIdentity !== "mscqr_prod_admin"
      || artifact.databaseSecurityGroupId !== STAGE_B.databaseSecurityGroupId || artifact.executorSecurityGroupId !== STAGE_B.executorSecurityGroupId
      || artifact.brokerAliasArn !== STAGE_B.brokerAliasArn || !/^[1-9][0-9]*$/.test(String(artifact.brokerVersion || ""))
      || !assumedRole("mscqr-production-rls-independent-checker").test(artifact.checkerIdentity || "")
      || !assumedRole("mscqr-production-release-deployer").test(artifact.deployerIdentity || "")
      || artifact.checkerIdentity === artifact.deployerIdentity
      || artifact.executorIdentity !== STAGE_B.executorRoleArn || !Number.isFinite(issuedAt) || !Number.isFinite(expiresAt)
      || issuedAt > now.getTime() + 300_000 || (expiresAt <= now.getTime() && !withinRollbackGrace) || expiresAt <= issuedAt || expiresAt - issuedAt > 7_200_000
      || !templateHashes || typeof templateHashes !== "object" || Array.isArray(templateHashes)
      || Object.values(templateHashes).some((value) => !isDigest(value))
      || !taskDefinitionArns || typeof taskDefinitionArns !== "object" || Array.isArray(taskDefinitionArns)
      || Object.values(taskDefinitionArns).some((value) => !/^arn:aws:ecs:eu-west-2:368992683803:task-definition\//.test(value || ""))
      || Object.entries(imagePatterns).some(([field, pattern]) => !pattern.test(artifact[field] || ""))
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(artifact.signatureBase64 || "")) {
    throw new Error("Stage B approval is invalid or expired.");
  }
  for (const field of ["releaseSha", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256", "deploymentId", "approvalId", "ticketId", "greenDatabaseName", "administratorIdentity"]) {
    if (expected?.[field] && artifact[field] !== expected[field]) throw new Error(`Stage B approval ${field} does not match the release contract.`);
  }
  for (const [field, value] of Object.entries(expected?.images || {})) {
    if (artifact[field] !== value) throw new Error(`Stage B approval ${field} does not match the immutable image contract.`);
  }
  if (expected?.taskDefinitionArns && canonicalJson(artifact.taskDefinitionArns) !== canonicalJson(expected.taskDefinitionArns)) {
    throw new Error("Stage B approval taskDefinitionArns do not match the fixed broker contract.");
  }
  if (!verifySignature || !await verifySignature({
    keyId: STAGE_B.approvalKmsKeyArn,
    message: Buffer.from(canonicalStageBApproval(artifact)),
    signature: Buffer.from(artifact.signatureBase64, "base64"),
  })) throw new Error("Stage B approval signature verification failed.");
  return { approval: Object.fromEntries(STAGE_B_APPROVAL_FIELDS.map((field) => [field, artifact[field]])), approvalContractSha256: stageBApprovalSha256(artifact) };
}

export async function validateStageBApprovalPayload(payload, expected, options = {}) {
  return validateStageBApproval(
    { ...payload, signatureBase64: "AA==" },
    expected,
    { ...options, verifySignature: async () => true },
  );
}

export const assertBrokerRequest = (event) => {
  if (!event || typeof event !== "object" || Array.isArray(event) || !strictKeys(event, ["approvalId", "mode"])
      || !STAGE_B_MODES.includes(event.mode) || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(event.approvalId || "")) {
    throw new Error("Stage B broker request is outside the reviewed contract.");
  }
  return event;
};

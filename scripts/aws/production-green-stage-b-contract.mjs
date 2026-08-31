import crypto from "node:crypto";

export const STAGE_B = Object.freeze({
  account: "368992683803",
  region: "eu-west-2",
  clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
  greenDatabaseIdentifier: "mscqr-production-rls-green-phase2",
  databaseSecurityGroupId: "sg-0703d3f227f35b81c",
  executorSecurityGroupId: "sg-051a24aedff773761",
  privateSubnetIds: Object.freeze(["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"]),
  inventoryLogGroupName: "/ecs/mscqr-production/rls-green-backend",
  inventoryTaskDefinitionFamily: "mscqr-production-rls-green-predeployment-inventory",
  inventoryDatabaseSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh",
  inventoryRlsRole: "mscqr_prod_rls_read",
  receiptBucket: "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  approvalSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/approval-e0shho",
  approvalKmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:key/437cdebd-95e7-4aba-8f0f-2ca08edb0478",
  rootDropKmsKeyArn: "arn:aws:kms:eu-west-2:368992683803:alias/mscqr-production-root-drop",
  brokerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
  checkerRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-independent-checker",
  executorRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-task",
  executorExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
  brokerFunctionArn: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker",
  brokerFunctionArnWildcard: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:*",
  brokerAliasArn: "arn:aws:lambda:eu-west-2:368992683803:function:mscqr-production-rls-approval-broker:reviewed",
  brokerAliasQualifier: "reviewed",
  frontendTaskDefinition: "mscqr-frontend:20",
});

export const PRODUCTION_ACTIVATION_LIFECYCLE = Object.freeze({
  bucket: STAGE_B.receiptBucket,
  claimKey: "production-activation-lifecycle/claim.json",
  completionKey: "production-activation-lifecycle/completion.json",
  claimArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-activation-lifecycle/claim.json`,
  completionArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-activation-lifecycle/completion.json`,
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
});

export const PRODUCTION_ECS_CLUSTER_NAME = STAGE_B.clusterArn.slice(STAGE_B.clusterArn.lastIndexOf("/") + 1);

export function canonicalProductionEcsClusterArn(value) {
  if (value === PRODUCTION_ECS_CLUSTER_NAME || value === STAGE_B.clusterArn) return STAGE_B.clusterArn;
  throw new Error("ECS cluster identity is not the exact production cluster name or ARN.");
}

const brokerAliasParts = (value) => {
  const match = /^arn:aws:lambda:([^:]+):([^:]+):function:([^:]+)(?::([^:]+))?$/.exec(String(value || ""));
  return match ? { region: match[1], account: match[2], functionName: match[3], qualifier: match[4] || "" } : null;
};

export function assertStageBBrokerAliasArn(value) {
  const expected = STAGE_B.brokerAliasArn;
  if (value === expected) return expected;
  const expectedParts = brokerAliasParts(expected);
  const receivedParts = brokerAliasParts(value);
  const differences = [
    expectedParts?.functionName !== receivedParts?.functionName ? "function" : null,
    expectedParts?.qualifier !== receivedParts?.qualifier ? "alias" : null,
    expectedParts?.account !== receivedParts?.account ? "account" : null,
    expectedParts?.region !== receivedParts?.region ? "region" : null,
    expectedParts?.qualifier !== receivedParts?.qualifier ? "qualifier" : null,
  ].filter(Boolean);
  throw new Error([
    "Stage B broker alias ARN mismatch.",
    `Expected: ${expected}`,
    `Received: ${String(value)}`,
    `Difference: ${differences.length ? differences.join(", ") : "ARN shape"}`,
  ].join("\n"));
}

export function assertStageBBrokerConfigurationIdentity({ configuration, alias }) {
  const configurationFunctionArn = String(configuration?.FunctionArn || "");
  const configurationVersion = String(configuration?.Version || "");
  if (!/^[1-9][0-9]*$/.test(configurationVersion)) {
    throw new Error(`Broker Lambda configuration Version is missing or malformed: ${configurationVersion || "<empty>"}`);
  }

  const isBaseArn = configurationFunctionArn === STAGE_B.brokerFunctionArn;
  const isNumericVersionArn = configurationFunctionArn === `${STAGE_B.brokerFunctionArn}:${configurationVersion}`;
  const isReviewedAliasArn = configurationFunctionArn === STAGE_B.brokerAliasArn;
  if (!isBaseArn && !isNumericVersionArn && !isReviewedAliasArn) {
    throw new Error(`Broker Lambda configuration FunctionArn is outside the exact Stage B identity contract. Expected: ${STAGE_B.brokerFunctionArn}, ${STAGE_B.brokerFunctionArn}:<matching-version>, or ${STAGE_B.brokerAliasArn}; Received: ${configurationFunctionArn}; Version: ${configurationVersion}`);
  }

  if (!alias || typeof alias !== "object" || Array.isArray(alias)) {
    throw new Error("Broker Lambda reviewed alias evidence is missing or malformed.");
  }
  try {
    assertStageBBrokerAliasArn(alias.AliasArn);
  } catch (error) {
    throw new Error(`Broker Lambda reviewed alias identity does not match the exact Stage B contract. ${error.message}`);
  }
  if (alias.Name !== STAGE_B.brokerAliasQualifier) {
    throw new Error(`Broker Lambda reviewed alias name does not match the exact Stage B contract. Expected: ${STAGE_B.brokerAliasQualifier}; Received: ${String(alias.Name)}`);
  }
  const aliasFunctionVersion = String(alias.FunctionVersion || "");
  if (!/^[1-9][0-9]*$/.test(aliasFunctionVersion) || aliasFunctionVersion !== configurationVersion) {
    throw new Error(`Broker Lambda reviewed alias version does not match configuration Version. Alias version: ${aliasFunctionVersion || "<empty>"}; Configuration Version: ${configurationVersion}`);
  }

  return {
    functionArn: STAGE_B.brokerFunctionArn,
    aliasArn: STAGE_B.brokerAliasArn,
    aliasName: STAGE_B.brokerAliasQualifier,
    aliasFunctionVersion,
    configurationFunctionArn,
    configurationVersion,
    resolvedVersionArn: `${STAGE_B.brokerFunctionArn}:${configurationVersion}`,
  };
}

export const STAGE_B_MODES = Object.freeze([
  "full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision",
  "full-rls-role-verify", "full-rls-admin-ownership", "full-rls-runtime-policy",
  "full-rls-verification", "full-rls-application-canary", "full-rls-rollback",
]);
export const STAGE_B_BROKER_TASK_DEFINITION_FAMILIES = Object.freeze(Object.fromEntries(
  STAGE_B_MODES.map((mode) => [mode, mode === "full-rls-application-canary"
    ? "mscqr-production-full-rls-green-application-canary"
    : `mscqr-production-full-rls-green-${mode}`]),
));
export const STAGE_B_TASK_TEMPLATE_KEYS = Object.freeze(["executor", "canary", "backend", "worker"]);
export const STAGE_B_APPROVAL_ALGORITHM = "RSASSA_PSS_SHA_256";
export const STAGE_B_APPROVAL_SCHEMA_VERSION = 2;
export const STAGE_B_APPROVAL_ID_PREFIX = "APR-STAGE-B-";
export const STAGE_B_APPROVAL_PUBLICATION_VALIDATION_OPERATION = "validate-approval";
export const STAGE_B_BROKER_APPROVAL_EXPECTED_FIELDS = Object.freeze([
  "releaseSha", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256",
  "deploymentId", "greenDatabaseName", "administratorIdentity", "databaseSecurityGroupId", "executorSecurityGroupId",
]);
export const STAGE_B_BROKER_IMAGE_FIELDS = Object.freeze(["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"]);
const imagePattern = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-(?:backend|worker|web)@sha256:[a-f0-9]{64}$/;
const imagePatterns = Object.freeze({
  backendImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  workerImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-worker@sha256:[a-f0-9]{64}$/,
  executorImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
  canaryImageDigest: /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/,
});
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export const stageBApprovalIdForReleaseSha = (releaseSha) => {
  if (!/^[a-f0-9]{40}$/.test(releaseSha || "")) throw new Error("Stage B approval release SHA is not exact.");
  return `${STAGE_B_APPROVAL_ID_PREFIX}${releaseSha}`;
};

export const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
};
export const canonicalSha256 = (value) => sha256(canonicalJson(value));
export const STAGE_B_LAMBDA_ENVIRONMENT_HARD_LIMIT_BYTES = 4096;
export const STAGE_B_LAMBDA_ENVIRONMENT_TARGET_BYTES = 3500;
export const stageBLambdaEnvironmentUtf8Bytes = (variables) => Buffer.byteLength(JSON.stringify(variables), "utf8");
export function assertStageBLambdaEnvironmentSize(variables, maxBytes = STAGE_B_LAMBDA_ENVIRONMENT_TARGET_BYTES) {
  if (!variables || typeof variables !== "object" || Array.isArray(variables) || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new Error("Stage B Lambda environment payload is malformed.");
  const bytes = stageBLambdaEnvironmentUtf8Bytes(variables);
  if (bytes > STAGE_B_LAMBDA_ENVIRONMENT_HARD_LIMIT_BYTES || bytes > maxBytes) throw new Error(`Stage B broker Lambda environment payload is ${bytes} UTF-8 bytes; maximum allowed safety bound is ${maxBytes} bytes (AWS hard limit: ${STAGE_B_LAMBDA_ENVIRONMENT_HARD_LIMIT_BYTES}).`);
  return bytes;
}
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
const taskDefinitionArn = (value) => /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(value || "");
const taskDefinitionArnForFamily = (value, family) => new RegExp(`^arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:[1-9][0-9]*$`).test(value || "");

export function assertStageBBrokerTaskDefinitionMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !strictKeys(value, STAGE_B_MODES)
      || Object.entries(value).some(([mode, arn]) => !taskDefinitionArnForFamily(arn, STAGE_B_BROKER_TASK_DEFINITION_FAMILIES[mode]))) {
    throw new Error("Stage B broker task-definition map is incomplete or outside the reviewed mode/family contract.");
  }
  return value;
}

export function assertStageBBrokerRuntimeBindings({ clusterArn, approvalSecretArn, executorSecurityGroupId, privateSubnetIds, replayTable, receiptBucket } = {}) {
  if (clusterArn !== STAGE_B.clusterArn || approvalSecretArn !== STAGE_B.approvalSecretArn || executorSecurityGroupId !== STAGE_B.executorSecurityGroupId
      || !Array.isArray(privateSubnetIds) || [...privateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")
      || !/^[A-Za-z0-9._-]{3,255}$/.test(replayTable || "") || receiptBucket !== STAGE_B.receiptBucket) {
    throw new Error("Stage B broker runtime bindings are outside the reviewed contract.");
  }
  return { clusterArn, approvalSecretArn, executorSecurityGroupId, privateSubnetIds, replayTable, receiptBucket };
}

export function assertStageBBrokerApprovalExpected(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !strictKeys(value, STAGE_B_BROKER_APPROVAL_EXPECTED_FIELDS)
      || !/^[a-f0-9]{40}$/.test(value.releaseSha || "")
      || [value.sourceContractSha256, value.migrationSetDigest, value.packageChecksumSha256].some((item) => !isDigest(item))
      || value.deploymentId !== "phase2" || value.greenDatabaseName !== "mscqr_production_rls_green_phase2"
      || value.administratorIdentity !== "mscqr_prod_admin" || value.databaseSecurityGroupId !== STAGE_B.databaseSecurityGroupId
      || value.executorSecurityGroupId !== STAGE_B.executorSecurityGroupId) {
    throw new Error("Stage B broker approval expectation is incomplete or outside the reviewed contract.");
  }
  return value;
}

export function assertStageBBrokerImageBindings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !strictKeys(value, STAGE_B_BROKER_IMAGE_FIELDS)
      || Object.entries(value).some(([field, item]) => !imagePatterns[field]?.test(item || ""))) {
    throw new Error("Stage B broker image bindings are incomplete or outside the reviewed contract.");
  }
  return value;
}

export function assertStageBBrokerTemplateHashBindings(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !strictKeys(value, STAGE_B_TASK_TEMPLATE_KEYS)
      || Object.values(value).some((item) => !isDigest(item))) {
    throw new Error("Stage B broker task-definition template hashes are incomplete or malformed.");
  }
  return value;
}

export function assertStageBBrokerConfigurationBindings({ approvalExpected, images, templateHashes } = {}) {
  assertStageBBrokerApprovalExpected(approvalExpected);
  assertStageBBrokerImageBindings(images);
  assertStageBBrokerTemplateHashBindings(templateHashes);
  return { approvalExpected, images, templateHashes };
}

export const canonicalStageBBrokerApprovalExpected = ({ releaseSha, sourceContractSha256, migrationSetDigest, packageChecksumSha256 } = {}) => ({
  releaseSha, sourceContractSha256, migrationSetDigest, packageChecksumSha256,
  deploymentId: "phase2", greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
});

export const hasCompleteStageBTaskMaps = (taskDefinitionArns, taskDefinitionTemplateHashes) =>
  Boolean(taskDefinitionArns && typeof taskDefinitionArns === "object" && !Array.isArray(taskDefinitionArns)
    && taskDefinitionTemplateHashes && typeof taskDefinitionTemplateHashes === "object" && !Array.isArray(taskDefinitionTemplateHashes)
    && strictKeys(taskDefinitionArns, STAGE_B_MODES) && strictKeys(taskDefinitionTemplateHashes, STAGE_B_TASK_TEMPLATE_KEYS)
    && Object.values(taskDefinitionArns).every(taskDefinitionArn)
    && Object.values(taskDefinitionTemplateHashes).every(isDigest));

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
      || !hasCompleteStageBTaskMaps(taskDefinitionArns, templateHashes)
      || Object.entries(imagePatterns).some(([field, pattern]) => !pattern.test(artifact[field] || ""))
      || !/^[A-Za-z0-9+/]+={0,2}$/.test(artifact.signatureBase64 || "")) {
    throw new Error("Stage B approval is invalid or expired.");
  }
  if (artifact.approvalId !== stageBApprovalIdForReleaseSha(artifact.releaseSha)) {
    throw new Error("Stage B approval approvalId does not match releaseSha.");
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

export const assertBrokerApprovalValidationRequest = (event) => {
  if (!event || typeof event !== "object" || Array.isArray(event)
      || !strictKeys(event, ["approvalId", "approvalSha256", "operation", "sourceSha"])
      || event.operation !== STAGE_B_APPROVAL_PUBLICATION_VALIDATION_OPERATION
      || !/^[a-f0-9]{40}$/.test(event.sourceSha || "")
      || event.approvalId !== stageBApprovalIdForReleaseSha(event.sourceSha)
      || !/^[a-f0-9]{64}$/.test(event.approvalSha256 || "")) {
    throw new Error("Stage B approval validation request is outside the reviewed contract.");
  }
  return event;
};

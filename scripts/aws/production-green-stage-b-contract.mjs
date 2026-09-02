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
  executorLogGroupName: "/ecs/mscqr-production/full-rls-green",
  canaryLogGroupName: "/ecs/mscqr-production/rls-green-canary",
  inventoryTaskDefinitionFamily: "mscqr-production-rls-green-predeployment-inventory",
  inventoryDatabaseSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh",
  inventoryRlsRole: "mscqr_prod_rls_read",
  receiptBucket: "mscqr-prod-euw2-artifacts-368992683803-eu-west-2-an",
  replayTable: "mscqr-production-rls-stage-b-replay",
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
  taskRuntimePlatform: Object.freeze({ operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" }),
  brokerLambdaConfiguration: Object.freeze({
    functionName: "mscqr-production-rls-approval-broker",
    role: "arn:aws:iam::368992683803:role/mscqr-production-rls-approval-broker",
    handler: "index.handler",
    runtime: "nodejs24.x",
    architectures: Object.freeze(["x86_64"]),
    timeout: 180,
    memorySize: 128,
    packageType: "Zip",
    ephemeralStorage: Object.freeze({ Size: 512 }),
    loggingConfig: Object.freeze({
      logFormat: "Text",
      logGroup: "/aws/lambda/mscqr-production-rls-approval-broker",
      systemLogLevel: "INFO",
    }),
    kmsKeyArn: null,
    codeSigningConfigArn: null,
  }),
  frontendTaskDefinition: "mscqr-frontend:20",
});

export const PRODUCTION_ACTIVATION_LIFECYCLE = Object.freeze({
  bucket: STAGE_B.receiptBucket,
  claimKey: "production-activation-lifecycle/claim.json",
  completionKey: "production-activation-lifecycle/completion.json",
  claimArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-activation-lifecycle/claim.json`,
  completionArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-activation-lifecycle/completion.json`,
  rebaselineEvidencePrefix: "production-dual-slot-rebaseline-evidence/",
  rebaselineEvidenceArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-dual-slot-rebaseline-evidence/*`,
  stageAProductionArtifactsReconciliationPrefix: "production-stage-a-production-artifacts-reconciliation/",
  stageAProductionArtifactsReconciliationArn: `arn:aws:s3:::${STAGE_B.receiptBucket}/production-stage-a-production-artifacts-reconciliation/*`,
  releaseRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer",
});

export function assertStageBRuntimePlatform(value, { format = "either", label = "Stage B runtime platform" } = {}) {
  const isPlainObject = (candidate) => candidate !== null && typeof candidate === "object" && !Array.isArray(candidate);
  const isTerraform = format === "terraform";
  const isAws = format === "aws";
  if (!(["either", "terraform", "aws"].includes(format))) throw new Error(`${label} format is unsupported.`);
  const platform = isTerraform
    ? (Array.isArray(value) ? (value.length === 1 ? value[0] : undefined) : value)
    : value;
  if (!isPlainObject(platform)) throw new Error(`${label} is malformed.`);
  const keys = Object.keys(platform).sort();
  const terraformKeys = ["cpu_architecture", "operating_system_family"];
  const awsKeys = ["cpuArchitecture", "operatingSystemFamily"];
  const expectedKeys = isTerraform ? terraformKeys : isAws ? awsKeys : keys.includes("cpu_architecture") || keys.includes("operating_system_family") ? terraformKeys : awsKeys;
  if (JSON.stringify(keys) !== JSON.stringify([...expectedKeys].sort())) throw new Error(`${label} has an unsupported shape.`);
  const normalized = isTerraform || expectedKeys === terraformKeys
    ? { cpuArchitecture: platform.cpu_architecture, operatingSystemFamily: platform.operating_system_family }
    : { cpuArchitecture: platform.cpuArchitecture, operatingSystemFamily: platform.operatingSystemFamily };
  if (normalized.operatingSystemFamily !== STAGE_B.taskRuntimePlatform.operatingSystemFamily
    || normalized.cpuArchitecture !== STAGE_B.taskRuntimePlatform.cpuArchitecture) throw new Error(`${label} is outside the exact Stage B domain.`);
  return normalized;
}

export function assertStageBTerraformRuntimePlatformSource(terraformConfiguration) {
  if (typeof terraformConfiguration !== "string" || terraformConfiguration.length === 0) throw new Error("Stage B Terraform runtime-platform source is missing.");
  const lines = terraformConfiguration.split("\n");
  const starts = lines.flatMap((line, index) => line.trim() === "task_runtime_platform = {" ? [index] : []);
  if (starts.length !== 1) throw new Error("Stage B Terraform runtime-platform local must be declared exactly once.");
  const assignments = [];
  let end = -1;
  for (let index = starts[0] + 1; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (line === "}") { end = index; break; }
    const match = /^(cpu_architecture|operating_system_family)\s*=\s*"([^"\\]+)"$/.exec(line);
    if (!match) throw new Error("Stage B Terraform runtime-platform local contains an unsupported expression.");
    assignments.push(match);
  }
  if (end < 0 || assignments.length !== 2 || new Set(assignments.map(([key]) => key)).size !== 2) throw new Error("Stage B Terraform runtime-platform local is incomplete.");
  assertStageBRuntimePlatform([Object.fromEntries(assignments.map(([, key, value]) => [key, value]))], { format: "terraform", label: "Stage B Terraform runtime platform" });
  return true;
}

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
  if (alias.RoutingConfig !== undefined) {
    const routing = alias.RoutingConfig;
    if (!routing || typeof routing !== "object" || Array.isArray(routing)
        || Object.keys(routing).some((key) => key !== "AdditionalVersionWeights")) {
      throw new Error("Broker Lambda reviewed alias routing configuration is malformed or outside the reviewed contract.");
    }
    const weights = routing.AdditionalVersionWeights;
    if (weights !== undefined && (!weights || typeof weights !== "object" || Array.isArray(weights) || Object.keys(weights).length !== 0)) {
      throw new Error("Broker Lambda reviewed alias routes traffic to an unreviewed version.");
    }
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
export const STAGE_B_BROKER_ENVIRONMENT_VARIABLES = Object.freeze([
  "BROKER_APPROVAL_EXPECTED_JSON", "BROKER_APPROVAL_SECRET_ARN", "BROKER_CLUSTER_ARN",
  "BROKER_EXECUTOR_SECURITY_GROUP_ID", "BROKER_IMAGES_JSON", "BROKER_PRIVATE_SUBNETS_JSON",
  "BROKER_RECEIPT_BUCKET", "BROKER_REPLAY_TABLE", "BROKER_TASK_DEFINITIONS_JSON", "BROKER_TASK_TEMPLATE_HASHES_JSON",
]);
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

export const STAGE_B_RUNTIME_APPROVAL_AUTHORITY = "EXISTING_LIVE_RESOURCE_AUTHORITY";

export function assertStageBBrokerRuntimeVersion(value) {
  const version = String(value || "");
  if (!/^[1-9][0-9]*$/.test(version)) throw new Error("Stage B broker must execute from an immutable published Lambda version.");
  return version;
}

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
      || replayTable !== STAGE_B.replayTable || receiptBucket !== STAGE_B.receiptBucket) {
    throw new Error("Stage B broker runtime bindings are outside the reviewed contract.");
  }
  return { clusterArn, approvalSecretArn, executorSecurityGroupId, privateSubnetIds, replayTable, receiptBucket };
}

const exactKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).sort().join(",") === [...expected].sort().join(",");
const emptyArray = (value) => value === undefined || Array.isArray(value) && value.length === 0;
const emptyObject = (value) => value === undefined || value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0;
const emptyString = (value) => value === undefined || value === null || value === "";
const noVpcConfiguration = (value) => value === undefined || value === null || value && typeof value === "object" && !Array.isArray(value)
  && !value.VpcId && emptyArray(value.SubnetIds) && emptyArray(value.SecurityGroupIds) && !value.Ipv6AllowedForDualStack;
const RUNTIME_VERSION_CONFIG_FIELDS = Object.freeze(["Error", "RuntimeVersionArn"]);
const RUNTIME_VERSION_ERROR_FIELDS = Object.freeze(["ErrorCode", "Message"]);
const isPlainObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

export function normalizeStageBBrokerRuntimeVersionConfig(value) {
  if (value === undefined) return null;
  if (!isPlainObject(value) || Object.keys(value).some((key) => !RUNTIME_VERSION_CONFIG_FIELDS.includes(key))) {
    throw new Error("Resolved broker Lambda RuntimeVersionConfig is malformed or contains an unknown field.");
  }
  const runtimeVersionArn = value.RuntimeVersionArn;
  if (runtimeVersionArn !== undefined
      && (typeof runtimeVersionArn !== "string" || runtimeVersionArn.length < 26 || runtimeVersionArn.length > 2048
        || !new RegExp(`^arn:aws:lambda:${STAGE_B.region}::runtime:.+$`).test(runtimeVersionArn))) {
    throw new Error("Resolved broker Lambda RuntimeVersionArn is malformed or outside the AWS-managed runtime contract.");
  }
  if (value.Error !== undefined) {
    const error = value.Error;
    if (!isPlainObject(error) || Object.keys(error).some((key) => !RUNTIME_VERSION_ERROR_FIELDS.includes(key))
        || error.ErrorCode !== undefined && typeof error.ErrorCode !== "string"
        || error.Message !== undefined && typeof error.Message !== "string") {
      throw new Error("Resolved broker Lambda RuntimeVersionConfig error is malformed or contains an unknown field.");
    }
    throw new Error("Resolved broker Lambda runtime version retrieval returned an error.");
  }
  return Object.freeze(runtimeVersionArn === undefined ? {} : { RuntimeVersionArn: runtimeVersionArn });
}

const LAMBDA_CONFIGURATION_RESPONSE_FIELDS = Object.freeze([
  "Architectures", "CapacityProviderConfig", "CodeSha256", "CodeSize", "ConfigSha256", "DeadLetterConfig", "Description",
  "DurableConfig", "Environment", "EphemeralStorage", "FileSystemConfigs", "FunctionArn", "FunctionName", "Handler",
  "ImageConfigResponse", "KMSKeyArn", "LastModified", "LastUpdateStatus", "LastUpdateStatusReason", "LastUpdateStatusReasonCode",
  "Layers", "LoggingConfig", "MasterArn", "MemorySize", "PackageType", "RevisionId", "Role", "Runtime", "RuntimeVersionConfig",
  "SigningJobArn", "SigningProfileVersionArn", "SnapStart", "State", "StateReason", "StateReasonCode", "TenancyConfig", "Timeout",
  "TracingConfig", "Version", "VpcConfig",
]);

function assertStageBBrokerLambdaResponseShape(configuration) {
  if (!configuration || typeof configuration !== "object" || Array.isArray(configuration)
      || Object.keys(configuration).some((key) => !LAMBDA_CONFIGURATION_RESPONSE_FIELDS.includes(key))) {
    throw new Error("Resolved broker Lambda configuration contains an unknown or malformed GetFunctionConfiguration field.");
  }
}

function assertStageBBrokerLoggingConfig(value, expected) {
  if (value === undefined || value === null) return;
  if (typeof value !== "object" || Array.isArray(value)
      || Object.keys(value).some((key) => !["ApplicationLogLevel", "LogFormat", "LogGroup", "SystemLogLevel"].includes(key))
      || value.ApplicationLogLevel !== undefined
      || value.LogFormat !== undefined && value.LogFormat !== expected.logFormat
      || value.LogGroup !== undefined && value.LogGroup !== expected.logGroup
      || value.SystemLogLevel !== undefined && value.SystemLogLevel !== expected.systemLogLevel) {
    throw new Error("Resolved broker Lambda LoggingConfig is outside the reviewed default logging contract.");
  }
}

function assertStageBBrokerLambdaDefaults(configuration, expected) {
  if (!emptyString(configuration.KMSKeyArn) || !emptyString(configuration.CodeSigningConfigArn)
      || !emptyObject(configuration.CapacityProviderConfig) || !emptyObject(configuration.DurableConfig)
      || !emptyString(configuration.Description) || !emptyString(configuration.MasterArn)
      || !emptyString(configuration.SigningJobArn) || !emptyString(configuration.SigningProfileVersionArn)
      || configuration.State !== undefined && configuration.State !== "Active"
      || configuration.LastUpdateStatus !== undefined && configuration.LastUpdateStatus !== "Successful"
      || !emptyString(configuration.StateReason) || !emptyString(configuration.StateReasonCode)
      || !emptyObject(configuration.TenancyConfig)) {
    throw new Error("Resolved broker Lambda configuration contains an unexpected AWS default or runtime state.");
  }
  assertStageBBrokerLoggingConfig(configuration.LoggingConfig, expected.loggingConfig);
  return normalizeStageBBrokerRuntimeVersionConfig(configuration.RuntimeVersionConfig);
}

export function assertStageBBrokerLambdaConfiguration({ configuration, alias, brokerPackageRawSha256 } = {}) {
  assertStageBBrokerLambdaResponseShape(configuration);
  const broker = assertStageBBrokerConfigurationIdentity({ configuration, alias });
  const expected = STAGE_B.brokerLambdaConfiguration;
  const codeSha256 = configuration?.CodeSha256;
  if (!/^[a-f0-9]{64}$/.test(brokerPackageRawSha256 || "") || typeof codeSha256 !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(codeSha256)
      || Buffer.from(codeSha256, "base64").length !== 32 || Buffer.from(codeSha256, "base64").toString("base64") !== codeSha256
      || codeSha256 !== Buffer.from(brokerPackageRawSha256, "hex").toString("base64")
      || configuration.FunctionName !== expected.functionName || configuration.Role !== expected.role || configuration.Handler !== expected.handler
      || configuration.Runtime !== expected.runtime || canonicalJson(configuration.Architectures) !== canonicalJson(expected.architectures)
      || configuration.Timeout !== expected.timeout || configuration.MemorySize !== expected.memorySize || configuration.PackageType !== expected.packageType
      || canonicalJson(configuration.EphemeralStorage) !== canonicalJson(expected.ephemeralStorage)
      || !exactKeys(configuration.Environment?.Variables, STAGE_B_BROKER_ENVIRONMENT_VARIABLES)
      || !emptyArray(configuration.Layers) || !emptyArray(configuration.FileSystemConfigs) || !emptyObject(configuration.DeadLetterConfig)
      || !noVpcConfiguration(configuration.VpcConfig) || !emptyObject(configuration.ImageConfigResponse)
      || configuration.SnapStart !== undefined && configuration.SnapStart?.ApplyOn !== "None"
      || configuration.TracingConfig !== undefined && configuration.TracingConfig?.Mode !== "PassThrough") {
    throw new Error("Resolved broker Lambda configuration is outside the reviewed executable contract.");
  }
  const runtimeVersionConfig = assertStageBBrokerLambdaDefaults(configuration, expected);
  return Object.freeze({
    broker,
    codeSha256,
    configuration: Object.freeze({
      FunctionName: configuration.FunctionName, FunctionArn: configuration.FunctionArn, Version: configuration.Version,
      CodeSha256: codeSha256, Role: configuration.Role, Handler: configuration.Handler, Runtime: configuration.Runtime,
      Architectures: [...configuration.Architectures], Timeout: configuration.Timeout, MemorySize: configuration.MemorySize,
      PackageType: configuration.PackageType, EphemeralStorage: { ...configuration.EphemeralStorage },
      Environment: { Variables: { ...configuration.Environment.Variables } },
      Layers: [...(configuration.Layers || [])], FileSystemConfigs: [...(configuration.FileSystemConfigs || [])],
      DeadLetterConfig: { ...(configuration.DeadLetterConfig || {}) }, VpcConfig: configuration.VpcConfig || null,
      ImageConfigResponse: configuration.ImageConfigResponse || {}, SnapStart: configuration.SnapStart || null,
      TracingConfig: configuration.TracingConfig || null,
      LoggingConfig: configuration.LoggingConfig || null, KMSKeyArn: configuration.KMSKeyArn || null,
      CodeSigningConfigArn: configuration.CodeSigningConfigArn || null,
      RuntimeVersionConfig: runtimeVersionConfig,
    }),
  });
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
  for (const field of ["releaseSha", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256", "deploymentId", "approvalId", "ticketId", "greenDatabaseName", "administratorIdentity", "brokerVersion"]) {
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

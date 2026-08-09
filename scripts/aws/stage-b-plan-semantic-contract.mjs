import {
  canonicalizeEcsTaskDefinitionVolumes,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS,
  STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS,
} from "./stage-b-reference-audit-contract.mjs";
import {
  assertStageBProviderSemanticSnapshot,
  STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT,
} from "./stage-b-provider-semantic-snapshot.mjs";
import { assertStageBBrokerPolicyDocument } from "./stage-b-deployment-contract.mjs";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";

export const STAGE_B_PLAN_SEMANTIC_CLASSES = Object.freeze([
  "STABLE_REQUIRED",
  "REVIEWED_CONCRETE_CHANGE",
  "REVIEWED_COMPUTED_CHANGE",
  "REVIEWED_PROVIDER_NORMALIZATION",
  "REVIEWED_REPLACEMENT_TRIGGER",
  "CONFIGURATION_BOUND_PACKAGE_DIGEST",
  "DIAGNOSTIC_ONLY",
]);

export const STAGE_B_PLAN_SEMANTIC_PROFILES = Object.freeze({
  ECS_INITIAL_CREATE: "ECS_INITIAL_CREATE",
  ECS_REVIEWED_ROLLOVER: "ECS_REVIEWED_ROLLOVER",
  BROKER_POLICY_INITIAL_CREATE: "BROKER_POLICY_INITIAL_CREATE",
  BROKER_FUNCTION_INITIAL_CREATE: "BROKER_FUNCTION_INITIAL_CREATE",
  BROKER_ALIAS_INITIAL_CREATE: "BROKER_ALIAS_INITIAL_CREATE",
  BROKER_POLICY_UPDATE: "BROKER_POLICY_UPDATE",
  BROKER_FUNCTION_PUBLISH_UPDATE: "BROKER_FUNCTION_PUBLISH_UPDATE",
  REVIEWED_RECOVERY_ALIAS_UPDATE: "REVIEWED_RECOVERY_ALIAS_UPDATE",
});

export const STAGE_B_SUPPORTED_PLAN_PROFILES = Object.freeze([
  Object.freeze({ profile: "BASELINE_INITIAL_CREATE", ecsActions: [["create"]], brokerPolicyActions: [["create"]], brokerFunctionActions: [["create"]], brokerAliasActions: [["create"]], recoveryRequired: false, fixture: "production-green-stage-b-production-shaped.plan.json" }),
  Object.freeze({ profile: "ROLLOVER_RECOVERY", ecsActions: [["create", "delete"], ["delete", "create"]], brokerPolicyActions: [["update"]], brokerFunctionActions: [["update"]], brokerAliasActions: [["update"]], recoveryRequired: true, fixture: "production-green-stage-b-plan-semantic.test.mjs" }),
  Object.freeze({ profile: "NO_CHANGE_OR_APPEND_ONLY_RETRY", ecsActions: [["create"], ["no-op"]], brokerPolicyActions: [["create"], ["no-op"]], brokerFunctionActions: [["create"], ["no-op"]], brokerAliasActions: [["create"], ["no-op"]], recoveryRequired: false, fixture: "production-green-stage-b-plan-semantic.test.mjs" }),
]);

const ECS_ADDRESSES = new Set(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES));
const ECS_INITIAL_CREATE_ACTIONS = ["create"];
const ECS_INITIAL_CREATE_PATHS = new Set([
  "container_definitions", "cpu", "enable_fault_injection", "ephemeral_storage",
  "execution_role_arn", "family", "ipc_mode", "memory", "network_mode", "pid_mode",
  "placement_constraints", "proxy_configuration", "region", "requires_compatibilities",
  "requires_compatibilities[0]", "runtime_platform[0].operating_system_family",
  "runtime_platform[0].cpu_architecture", "skip_destroy", "task_role_arn", "track_latest",
  "tags.Component", "tags.Environment", "tags.ManagedBy", "tags_all.Component",
  "tags_all.Environment", "tags_all.ManagedBy",
]);
const ECS_INITIAL_CREATE_PROVIDER_PATHS = new Set([
  "ipc_mode", "pid_mode", "volume", "volume[0].configure_at_launch",
  "volume[0].docker_volume_configuration", "volume[0].efs_volume_configuration",
  "volume[0].fsx_windows_file_server_volume_configuration", "volume[0].host_path",
  "volume[0].s3files_volume_configuration",
]);
const DIFF_ATOMIC_PATHS = new Set(["environment[0].variables"]);
const BROKER_PROFILES = new Map([
  ["aws_iam_policy.broker", { type: "aws_iam_policy", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_UPDATE }] }],
  ["aws_lambda_function.broker", { type: "aws_lambda_function", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_PUBLISH_UPDATE }] }],
  ["aws_lambda_alias.reviewed", { type: "aws_lambda_alias", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_ALIAS_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.REVIEWED_RECOVERY_ALIAS_UPDATE }] }],
]);
const BROKER_ADDRESSES = new Set(BROKER_PROFILES.keys());
const BROKER_INITIAL_TAG_PATHS = new Set(["tags.Component", "tags.Environment", "tags.ManagedBy", "tags_all.Component", "tags_all.Environment", "tags_all.ManagedBy"]);
const BROKER_POLICY_INITIAL_CHANGED_PATHS = new Set(["name", "path", "arn", "id", "policy", ...BROKER_INITIAL_TAG_PATHS]);
const BROKER_FUNCTION_INITIAL_CHANGED_PATHS = new Set([
  "function_name", "role", "handler", "runtime", "filename", "source_code_hash", "timeout", "publish",
  "memory_size", "package_type", "region", "environment[0].variables", ...BROKER_INITIAL_TAG_PATHS,
]);
export const STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION = Object.freeze({
  memory_size: Object.freeze({ category: "PROVIDER_DEFAULTED_CONCRETE", expected: 128 }),
  package_type: Object.freeze({ category: "PROVIDER_DEFAULTED_CONCRETE", expected: "Zip" }),
  region: Object.freeze({ category: "PROVIDER_OPTIONAL_COMPUTED_CONCRETE", expected: STAGE_B.region }),
  tags_all: Object.freeze({ category: "PROVIDER_OPTIONAL_COMPUTED_CONCRETE", expected: "tags" }),
  architectures: Object.freeze({ category: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", expectedUnknown: [true] }),
  code_sha256: Object.freeze({ category: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", expectedUnknown: true }),
  id: Object.freeze({ category: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", expectedUnknown: true }),
  source_code_hash: Object.freeze({ category: "CONFIGURATION_BOUND_INPUT", expected: "concrete" }),
  environment: Object.freeze({ category: "CONFIGURATION_DEPENDENCY_COMPUTED", expected: "unresolved-or-resolved" }),
});
const BROKER_ENVIRONMENT_PLACEHOLDER_PATH = "environment[0]";
const BROKER_ALIAS_INITIAL_CHANGED_PATHS = new Set(["name", "function_name", "function_version"]);
const ECS_METADATA_PATHS = new Set(["arn", "arn_without_revision", "enable_fault_injection", "id", "revision"]);
const ECS_UNKNOWN_PATHS = new Set([...ECS_METADATA_PATHS, "volume[0].configure_at_launch"]);
const ECS_SENSITIVE_PATHS = new Set(["requires_compatibilities[0]"]);
const BROKER_POLICY_CHANGED_PATHS = new Set(["policy"]);
const BROKER_POLICY_UNKNOWN_PATHS = new Set(["policy"]);
const BROKER_FUNCTION_CHANGED_PATHS = new Set([
  "environment[0].variables",
  "filename",
  "source_code_hash",
  "last_modified",
  "qualified_arn",
  "qualified_invoke_arn",
  "version",
]);
const BROKER_FUNCTION_UNKNOWN_PATHS = new Set([
  "architectures[0]",
  "environment[0].variables",
  "last_modified",
  "qualified_arn",
  "qualified_invoke_arn",
  "version",
]);
const BROKER_FUNCTION_SENSITIVE_PATHS = new Set(["architectures[0]"]);
const ALIAS_CHANGED_PATHS = new Set(["function_version"]);
const ALIAS_UNKNOWN_PATHS = new Set(["function_version"]);
const ALIAS_SENSITIVE_PATHS = new Set();

const providerAttributes = (resourceType) => new Map(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT.resources[resourceType].attributes.map((entry) => [entry.attributePath, entry]));
const providerComputedOnlyPaths = (resourceType) => [...providerAttributes(resourceType).values()].filter((entry) => entry.computed && !entry.optional && !entry.required).map((entry) => entry.attributePath);
const BROKER_POLICY_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_iam_policy"), "id"]);
const BROKER_FUNCTION_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_lambda_function"), "architectures[0]", "code_sha256", "id"]);
const BROKER_ALIAS_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_lambda_alias"), "function_version", "id"]);
const BROKER_POLICY_INITIAL_DEPENDENCY_COMPUTED_PATHS = new Set(["policy"]);
const BROKER_FUNCTION_INITIAL_DEPENDENCY_COMPUTED_PATHS = new Set(["environment[0].variables"]);
const ECS_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_ecs_task_definition"), "enable_fault_injection", "id"]);

const CONFIGURATION_REFERENCE_RULES = Object.freeze({
  "aws_ecs_task_definition.candidate": {
    container_definitions: ["each.value.containerDefinitions", "each.value"],
    cpu: ["each.value.cpu", "each.value"],
    execution_role_arn: ["aws_iam_role.execution", "each.key"],
    family: ["each.value.family", "each.value"],
    memory: ["each.value.memory", "each.value"],
    network_mode: ["each.value.networkMode", "each.value"],
    requires_compatibilities: ["each.value.requiresCompatibilities", "each.value"],
    tags: ["local.tags"],
    task_role_arn: ["aws_iam_role.task", "each.key"],
  },
  "aws_ecs_task_definition.executor": {
    container_definitions: ["each.value.containerDefinitions", "each.value"],
    cpu: ["each.value.cpu", "each.value"],
    execution_role_arn: ["aws_iam_role.execution[\"executor\"].arn", "aws_iam_role.execution[\"executor\"]", "aws_iam_role.execution"],
    family: ["each.value.family", "each.value"],
    memory: ["each.value.memory", "each.value"],
    network_mode: ["each.value.networkMode", "each.value"],
    requires_compatibilities: ["each.value.requiresCompatibilities", "each.value"],
    tags: ["local.tags"],
    task_role_arn: ["var.stage_a_executor_task_role_arn"],
  },
  "aws_iam_policy.broker": {
    policy: ["local.broker_runtime_policy"],
    tags: ["local.tags"],
  },
  "aws_lambda_function.broker": {
    "environment[0].variables": [
      "aws_dynamodb_table.replay.name", "aws_dynamodb_table.replay", "var.receipt_bucket_arn",
      "var.ecs_cluster_arn", "var.approval_secret_arn", "var.stage_a_executor_security_group_id",
      "var.private_subnet_ids", "local.broker_task_definition_arns", "local.broker_template_hashes",
      "local.broker_approval_expected", "local.broker_images",
    ],
    filename: ["var.broker_package_path"],
    role: ["var.stage_a_broker_role_arn"],
    source_code_hash: ["var.broker_package_path"],
    tags: ["local.tags"],
  },
  "aws_lambda_alias.reviewed": {
    function_name: ["aws_lambda_function.broker.function_name", "aws_lambda_function.broker"],
    function_version: ["aws_lambda_function.broker.version", "aws_lambda_function.broker"],
  },
});

const exactJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const isObject = (value) => value !== null && typeof value === "object";
const pathFor = (base, key) => typeof key === "number" ? `${base}[${key}]` : (base ? `${base}.${key}` : key);

function diffPaths(before, after, base = "") {
  if (exactJson(before, after)) return [];
  if (DIFF_ATOMIC_PATHS.has(base)) return [base];
  if (before === null || before === undefined) return leafPaths(after, base);
  if (after === null || after === undefined) return leafPaths(before, base);
  if (!isObject(before) || !isObject(after) || Array.isArray(before) !== Array.isArray(after)) return [base];
  const keys = Array.isArray(before) || Array.isArray(after)
    ? [...new Set([...Array(Math.max(before.length, after.length)).keys()])]
    : [...new Set([...Object.keys(before), ...Object.keys(after)])].sort();
  return keys.flatMap((key) => diffPaths(before[key], after[key], pathFor(base, key)));
}

function leafPaths(value, base = "") {
  if (DIFF_ATOMIC_PATHS.has(base)) return [base];
  if (!isObject(value)) return [base];
  if (Array.isArray(value)) return value.length === 0
    ? [base]
    : value.flatMap((item, index) => leafPaths(item, pathFor(base, index)));
  const keys = Object.keys(value);
  return keys.length === 0 ? [base] : keys.sort().flatMap((key) => leafPaths(value[key], pathFor(base, key)));
}

function truePaths(value, base = "") {
  if (value === true) return [base];
  if (!isObject(value)) return [];
  return Object.entries(value).flatMap(([key, nested]) => truePaths(nested, pathFor(base, Array.isArray(value) ? Number(key) : key)));
}

function referenceExpressions(value, base = "") {
  if (!isObject(value)) return [];
  const results = [];
  if (Array.isArray(value.references)) results.push({ field: base, references: [...value.references] });
  for (const [key, nested] of Object.entries(value)) {
    if (key !== "references") results.push(...referenceExpressions(nested, pathFor(base, Array.isArray(value) ? Number(key) : key)));
  }
  return results;
}

function rootConfigurationResources(plan) {
  return plan?.configuration?.root_module?.resources || [];
}

function configurationBase(address) {
  if (ECS_ADDRESSES.has(address)) return address.replace(/\["[^\"]+"\]$/, "");
  return address;
}

function collectConfigurationReferences(plan, address) {
  const base = configurationBase(address);
  const resource = rootConfigurationResources(plan).find((item) => item?.address === base);
  const expected = CONFIGURATION_REFERENCE_RULES[base];
  if (!resource || !expected) throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${address}`);
  const actual = referenceExpressions(resource.expressions || {});
  const expectedKeys = Object.keys(expected).sort();
  const actualKeys = actual.map(({ field }) => field).sort();
  if (!exactJson(expectedKeys, actualKeys)) throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${address}`);
  return actual.sort((left, right) => left.field.localeCompare(right.field)).map((item) => {
    const allowed = [...expected[item.field]].sort();
    const references = [...item.references].sort();
    if (!exactJson(references, allowed)) throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${address}.${item.field}`);
    return {
      ...item,
      references,
      classification: address === "aws_lambda_alias.reviewed" && item.field === "function_version"
        ? "REVIEWED_COMPUTED_CHANGE" : "STABLE_REQUIRED",
    };
  });
}

function assertClass(value, label) {
  if (!STAGE_B_PLAN_SEMANTIC_CLASSES.includes(value)) throw new Error(`UNCLASSIFIED_${label}`);
  return value;
}

function isEcsInitialCreate(change) {
  return ECS_ADDRESSES.has(change.address) && exactJson(change.change?.actions, ECS_INITIAL_CREATE_ACTIONS);
}

function isBrokerInitialCreate(change) {
  return BROKER_ADDRESSES.has(change.address) && exactJson(change.change?.actions, ["create"]);
}

function assertInitialBrokerEnvironment(change) {
  if (change.address !== "aws_lambda_function.broker" || !isBrokerInitialCreate(change)) return;
  if (change.change?.before !== null && change.change?.before !== undefined) {
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.environment`);
  }
  const environment = change.change?.after?.environment;
  const unknownEnvironment = change.change?.after_unknown?.environment;
  if (!Array.isArray(environment) || environment.length !== 1 || !environment[0] || typeof environment[0] !== "object" || Array.isArray(environment[0])) {
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.environment`);
  }
  const environmentKeys = Object.keys(environment[0]);
  const unknownKeys = Array.isArray(unknownEnvironment) && unknownEnvironment.length === 1 && unknownEnvironment[0] && typeof unknownEnvironment[0] === "object" && !Array.isArray(unknownEnvironment[0])
    ? Object.keys(unknownEnvironment[0]) : null;
  const structuralPlaceholder = environmentKeys.length === 0
    && unknownKeys?.length === 1
    && unknownKeys[0] === "variables"
    && unknownEnvironment[0].variables === true;
  const concreteVariables = environmentKeys.length === 1
    && environmentKeys[0] === "variables"
    && environment[0].variables
    && typeof environment[0].variables === "object"
    && !Array.isArray(environment[0].variables)
    && unknownEnvironment === undefined;
  if (!structuralPlaceholder && !concreteVariables) throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.environment`);
  if (concreteVariables) assertConcreteBrokerEnvironment(environment[0].variables);
  return concreteVariables ? "resolved" : "unresolved";
}

function assertInitialLambdaCreateRepresentation(change) {
  if (change.address !== "aws_lambda_function.broker" || !isBrokerInitialCreate(change)) return;
  const { after = {}, after_unknown: unknown = {} } = change.change || {};
  if (after.memory_size !== STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.memory_size.expected
    || after.package_type !== STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.package_type.expected
    || after.region !== STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.region.expected) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.defaulted_fields`);
  }
  if (typeof after.source_code_hash !== "string" || after.source_code_hash.length === 0) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.source_code_hash`);
  }
  if (after.code_sha256 !== undefined || unknown.code_sha256 !== STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.code_sha256.expectedUnknown) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.code_sha256`);
  }
  if (after.architectures !== undefined || JSON.stringify(unknown.architectures) !== JSON.stringify(STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.architectures.expectedUnknown)) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.architectures`);
  }
  if (after.id !== undefined || unknown.id !== STAGE_B_LAMBDA_INITIAL_CREATE_REPRESENTATION.id.expectedUnknown) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.id`);
  }
  if (!after.tags || JSON.stringify(after.tags_all) !== JSON.stringify(after.tags)) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.tags_all`);
  }
}

const BROKER_ENVIRONMENT_VARIABLES = Object.freeze([
  "BROKER_APPROVAL_EXPECTED_JSON", "BROKER_APPROVAL_SECRET_ARN", "BROKER_CLUSTER_ARN",
  "BROKER_EXECUTOR_SECURITY_GROUP_ID", "BROKER_IMAGES_JSON", "BROKER_PRIVATE_SUBNETS_JSON",
  "BROKER_RECEIPT_BUCKET", "BROKER_REPLAY_TABLE", "BROKER_TASK_DEFINITIONS_JSON", "BROKER_TASK_TEMPLATE_HASHES_JSON",
]);
const brokerTaskDefinitionModes = Object.freeze(Object.fromEntries([
  ["full-rls-application-canary", STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']],
  ...Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter(([address]) => address.startsWith("aws_ecs_task_definition.executor["))
    .map(([address, family]) => [address.match(/\["([^"]+)"\]$/)[1], family]),
]));
const exactObjectKeys = (value, expected) => JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort());
const parseEnvironmentJson = (value, label) => {
  if (typeof value !== "string") throw new Error(`UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.${label}`);
  try { return JSON.parse(value); } catch { throw new Error(`UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.${label}`); }
};

function assertConcreteBrokerEnvironment(variables) {
  if (!variables || typeof variables !== "object" || Array.isArray(variables) || !exactObjectKeys(variables, BROKER_ENVIRONMENT_VARIABLES)) {
    throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables");
  }
  if (variables.BROKER_REPLAY_TABLE !== "mscqr-production-rls-stage-b-replay"
    || variables.BROKER_RECEIPT_BUCKET !== STAGE_B.receiptBucket
    || variables.BROKER_CLUSTER_ARN !== STAGE_B.clusterArn
    || variables.BROKER_APPROVAL_SECRET_ARN !== STAGE_B.approvalSecretArn
    || variables.BROKER_EXECUTOR_SECURITY_GROUP_ID !== STAGE_B.executorSecurityGroupId) {
    throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables");
  }
  const taskDefinitions = parseEnvironmentJson(variables.BROKER_TASK_DEFINITIONS_JSON, "BROKER_TASK_DEFINITIONS_JSON");
  if (!exactObjectKeys(taskDefinitions, Object.keys(brokerTaskDefinitionModes))) throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_TASK_DEFINITIONS_JSON");
  for (const [mode, family] of Object.entries(brokerTaskDefinitionModes)) {
    if (typeof taskDefinitions[mode] !== "string" || !new RegExp(`^arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${family}:[1-9][0-9]*$`).test(taskDefinitions[mode])) {
      throw new Error(`UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_TASK_DEFINITIONS_JSON.${mode}`);
    }
  }
  const templates = parseEnvironmentJson(variables.BROKER_TASK_TEMPLATE_HASHES_JSON, "BROKER_TASK_TEMPLATE_HASHES_JSON");
  if (!exactObjectKeys(templates, ["backend", "worker", "executor", "canary"]) || Object.values(templates).some((value) => !/^[a-f0-9]{64}$/.test(value))) throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_TASK_TEMPLATE_HASHES_JSON");
  const approval = parseEnvironmentJson(variables.BROKER_APPROVAL_EXPECTED_JSON, "BROKER_APPROVAL_EXPECTED_JSON");
  if (!exactObjectKeys(approval, ["releaseSha", "sourceContractSha256", "migrationSetDigest", "packageChecksumSha256", "deploymentId", "greenDatabaseName", "administratorIdentity", "databaseSecurityGroupId", "executorSecurityGroupId"])
    || !/^[a-f0-9]{40}$/.test(approval.releaseSha) || [approval.sourceContractSha256, approval.migrationSetDigest, approval.packageChecksumSha256].some((value) => !/^[a-f0-9]{64}$/.test(value))
    || approval.deploymentId !== "phase2" || approval.greenDatabaseName !== "mscqr_production_rls_green_phase2" || approval.administratorIdentity !== "mscqr_prod_admin"
    || approval.databaseSecurityGroupId !== STAGE_B.databaseSecurityGroupId || approval.executorSecurityGroupId !== STAGE_B.executorSecurityGroupId) {
    throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_APPROVAL_EXPECTED_JSON");
  }
  const images = parseEnvironmentJson(variables.BROKER_IMAGES_JSON, "BROKER_IMAGES_JSON");
  if (!exactObjectKeys(images, ["backendImageDigest", "workerImageDigest", "executorImageDigest", "canaryImageDigest"])
    || Object.values(images).some((value) => !/^\d{12}\.dkr\.ecr\.[^@]+@sha256:[a-f0-9]{64}$/.test(value))) {
    throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_IMAGES_JSON");
  }
  const subnets = parseEnvironmentJson(variables.BROKER_PRIVATE_SUBNETS_JSON, "BROKER_PRIVATE_SUBNETS_JSON");
  if (JSON.stringify(subnets) !== JSON.stringify(STAGE_B.privateSubnetIds)) throw new Error("UNCLASSIFIED_CHANGED_PATH: aws_lambda_function.broker.environment[0].variables.BROKER_PRIVATE_SUBNETS_JSON");
}

function assertInitialProviderComputedShape(change) {
  let expected = change.address === "aws_iam_policy.broker" ? BROKER_POLICY_INITIAL_PROVIDER_UNKNOWN_PATHS
    : change.address === "aws_lambda_function.broker" ? BROKER_FUNCTION_INITIAL_PROVIDER_UNKNOWN_PATHS
      : change.address === "aws_lambda_alias.reviewed" ? BROKER_ALIAS_INITIAL_PROVIDER_UNKNOWN_PATHS
        : ECS_ADDRESSES.has(change.address) ? ECS_INITIAL_PROVIDER_UNKNOWN_PATHS : null;
  if (!expected) return;
  assertInitialLambdaCreateRepresentation(change);
  const actual = new Set(truePaths(change.change?.after_unknown).filter(Boolean));
  if (actual.has("volume[0].configure_at_launch")) {
    if (!change.change?.after?.volume) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.volume`);
    expected = new Set([...expected, "volume[0].configure_at_launch"]);
  }
  const dependencyPaths = change.address === "aws_iam_policy.broker" ? BROKER_POLICY_INITIAL_DEPENDENCY_COMPUTED_PATHS
    : change.address === "aws_lambda_function.broker" ? BROKER_FUNCTION_INITIAL_DEPENDENCY_COMPUTED_PATHS : new Set();
  const dependencyPath = [...dependencyPaths][0] || null;
  const dependencyUnknown = dependencyPath !== null && actual.has(dependencyPath);
  const concretePaths = new Set(leafPaths(change.change?.after).filter(Boolean));
  const dependencyConcrete = dependencyPath !== null && concretePaths.has(dependencyPath);
  if (dependencyPath !== null && dependencyUnknown === dependencyConcrete) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${dependencyPath}`);
  }
  if (dependencyPath === "policy" && dependencyConcrete) {
    if (Object.hasOwn(change.change?.after_unknown || {}, "policy")) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.policy`);
    try { assertStageBBrokerPolicyDocument(JSON.parse(change.change.after.policy)); } catch { throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.policy`); }
  }
  if (dependencyPath === "environment[0].variables" && dependencyConcrete) assertInitialBrokerEnvironment(change);
  expected = dependencyUnknown ? new Set([...expected, dependencyPath]) : expected;
  if (actual.size !== expected.size || [...expected].some((path) => !actual.has(path)) || [...actual].some((path) => !expected.has(path))) {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}`);
  }
  for (const path of expected) if (concretePaths.has(path)) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${path}`);
}

function assertInitialEcsSemanticDomain(change) {
  const after = change.change?.after || {};
  const runtimePlatform = after.runtime_platform;
  const runtimePlatformBlock = STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT.resources.aws_ecs_task_definition.blocks
    .find((entry) => entry.blockPath === "runtime_platform");
  if (runtimePlatformBlock?.nestingMode !== "list" || runtimePlatformBlock.maxItems !== 1
    || !Array.isArray(runtimePlatform) || runtimePlatform.length !== 1
    || !runtimePlatform[0] || Array.isArray(runtimePlatform[0])
    || !exactJson(Object.keys(runtimePlatform[0]).sort(), ["cpu_architecture", "operating_system_family"])
    || runtimePlatform[0].operating_system_family !== "LINUX"
    || runtimePlatform[0].cpu_architecture !== "X86_64") {
    throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES: ${change.address}.runtime_platform`);
  }
  try {
    if (after.volume !== undefined) canonicalizeEcsTaskDefinitionVolumes(after.volume);
  } catch {
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.volume`);
  }
  for (const field of ["ipc_mode", "pid_mode"]) {
    if (after[field] !== undefined && ![null, ""].includes(after[field])) {
      throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${field}`);
    }
  }
}

function classifyEcsInitialChangedPath(change, path) {
  if (ECS_INITIAL_CREATE_PROVIDER_PATHS.has(path) || /^volume\[\d+\]\.(?:configure_at_launch|docker_volume_configuration|efs_volume_configuration|fsx_windows_file_server_volume_configuration|host_path|s3files_volume_configuration)$/.test(path)) {
    assertInitialEcsSemanticDomain(change);
    return "REVIEWED_PROVIDER_NORMALIZATION";
  }
  if (ECS_INITIAL_CREATE_PATHS.has(path) || /^volume\[\d+\]\.name$/.test(path)) return "REVIEWED_CONCRETE_CHANGE";
  throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
}

function classifyEcsChangedPath(change, path) {
  if (isEcsInitialCreate(change)) return classifyEcsInitialChangedPath(change, path);
  if (path === "container_definitions") return "REVIEWED_CONCRETE_CHANGE";
  if (ECS_METADATA_PATHS.has(path)) return "DIAGNOSTIC_ONLY";
  if (path === "ipc_mode" || path === "pid_mode") {
    const before = change.change.before[path]; const after = change.change.after[path];
    if (![null, ""].includes(before) || ![null, ""].includes(after)) throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
    return "REVIEWED_PROVIDER_NORMALIZATION";
  }
  const volumeMatch = /^volume\[(\d+)\]\.configure_at_launch$/.exec(path);
  if (volumeMatch) {
    try {
      const before = canonicalizeEcsTaskDefinitionVolumes(change.change.before.volume);
      const after = canonicalizeEcsTaskDefinitionVolumes(change.change.after.volume);
      if (!exactJson(before, after)) throw new Error();
    } catch {
      throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
    }
    return "REVIEWED_PROVIDER_NORMALIZATION";
  }
  throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
}

function assertEcsSemanticDomain(change) {
  if (isEcsInitialCreate(change)) {
    assertInitialEcsSemanticDomain(change);
    return;
  }
  try {
    canonicalizeEcsTaskDefinitionVolumes(change.change.before.volume);
    canonicalizeEcsTaskDefinitionVolumes(change.change.after.volume);
  } catch {
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.volume`);
  }
  for (const field of ["ipc_mode", "pid_mode"]) {
    if (![null, ""].includes(change.change.before[field]) || ![null, ""].includes(change.change.after[field])) {
      throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${field}`);
    }
  }
}

function classifyChangedPath(change, path) {
  if (ECS_ADDRESSES.has(change.address)) return classifyEcsChangedPath(change, path);
  if (change.address === "aws_iam_policy.broker" && isBrokerInitialCreate(change)) {
    if (BROKER_POLICY_INITIAL_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
  }
  if (change.address === "aws_iam_policy.broker" && BROKER_POLICY_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
  if (change.address === "aws_lambda_function.broker" && isBrokerInitialCreate(change)) {
    if (path === BROKER_ENVIRONMENT_PLACEHOLDER_PATH) {
      assertInitialBrokerEnvironment(change);
      return "REVIEWED_COMPUTED_CHANGE";
    }
    if (BROKER_FUNCTION_INITIAL_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
  }
  if (change.address === "aws_lambda_function.broker" && BROKER_FUNCTION_CHANGED_PATHS.has(path)) {
    if (path === "source_code_hash") return "CONFIGURATION_BOUND_PACKAGE_DIGEST";
    return ["last_modified", "qualified_arn", "qualified_invoke_arn", "version"].includes(path)
      ? "DIAGNOSTIC_ONLY" : "REVIEWED_CONCRETE_CHANGE";
  }
  if (change.address === "aws_lambda_alias.reviewed" && isBrokerInitialCreate(change)) {
    if (BROKER_ALIAS_INITIAL_CHANGED_PATHS.has(path)) {
      if (path === "function_version" && change.change.after?.function_version === undefined && change.change.after_unknown?.function_version !== true) throw new Error(`UNCLASSIFIED_COMPUTED_CHANGE: ${change.address}.${path}`);
      return path === "function_version" ? "REVIEWED_COMPUTED_CHANGE" : "REVIEWED_CONCRETE_CHANGE";
    }
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
  }
  if (change.address === "aws_lambda_alias.reviewed" && ALIAS_CHANGED_PATHS.has(path)) {
    const after = change.change.after?.function_version;
    const unknown = change.change.after_unknown?.function_version === true;
    if ((after === undefined || after === null) && !unknown) throw new Error(`UNCLASSIFIED_COMPUTED_CHANGE: ${change.address}.${path}`);
    if (after !== undefined && after !== null && unknown) throw new Error(`UNCLASSIFIED_COMPUTED_CHANGE: ${change.address}.${path}`);
    return unknown ? "REVIEWED_COMPUTED_CHANGE" : "REVIEWED_CONCRETE_CHANGE";
  }
  throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
}

function classifyUnknownPath(change, path) {
  if (ECS_ADDRESSES.has(change.address) && ECS_UNKNOWN_PATHS.has(path)) {
    return path === "volume[0].configure_at_launch" ? "REVIEWED_PROVIDER_NORMALIZATION" : "DIAGNOSTIC_ONLY";
  }
  if (change.address === "aws_iam_policy.broker" && isBrokerInitialCreate(change)
    && (BROKER_POLICY_INITIAL_PROVIDER_UNKNOWN_PATHS.has(path) || BROKER_POLICY_INITIAL_DEPENDENCY_COMPUTED_PATHS.has(path))) {
    return path === "policy" ? "REVIEWED_COMPUTED_CHANGE" : "DIAGNOSTIC_ONLY";
  }
  if (change.address === "aws_iam_policy.broker" && BROKER_POLICY_UNKNOWN_PATHS.has(path)) return "REVIEWED_COMPUTED_CHANGE";
  if (change.address === "aws_lambda_function.broker" && isBrokerInitialCreate(change)
    && (BROKER_FUNCTION_INITIAL_PROVIDER_UNKNOWN_PATHS.has(path) || BROKER_FUNCTION_INITIAL_DEPENDENCY_COMPUTED_PATHS.has(path))) {
    return ["architectures[0]", "environment[0].variables", "version"].includes(path) ? "REVIEWED_COMPUTED_CHANGE" : "DIAGNOSTIC_ONLY";
  }
  if (change.address === "aws_lambda_function.broker" && BROKER_FUNCTION_UNKNOWN_PATHS.has(path)) {
    return ["environment[0].variables", "version"].includes(path) ? "REVIEWED_COMPUTED_CHANGE" : "DIAGNOSTIC_ONLY";
  }
  if (change.address === "aws_lambda_alias.reviewed" && isBrokerInitialCreate(change) && BROKER_ALIAS_INITIAL_PROVIDER_UNKNOWN_PATHS.has(path)) {
    return path === "function_version" ? "REVIEWED_COMPUTED_CHANGE" : "DIAGNOSTIC_ONLY";
  }
  if (change.address === "aws_lambda_alias.reviewed" && ALIAS_UNKNOWN_PATHS.has(path)) return "REVIEWED_COMPUTED_CHANGE";
  throw new Error(`UNCLASSIFIED_AFTER_UNKNOWN: ${change.address}.${path}`);
}

function assertSensitivePaths(change, kind, paths) {
  const allowed = ECS_ADDRESSES.has(change.address) ? ECS_SENSITIVE_PATHS
    : change.address === "aws_iam_policy.broker" ? new Set()
      : change.address === "aws_lambda_function.broker" ? BROKER_FUNCTION_SENSITIVE_PATHS : ALIAS_SENSITIVE_PATHS;
  for (const path of paths) if (!allowed.has(path)) throw new Error(`UNCLASSIFIED_${kind}_SENSITIVE_PATH: ${change.address}.${path}`);
  return paths;
}

function classifyResource(change) {
  const actions = change?.change?.actions;
  if (ECS_ADDRESSES.has(change?.address) && change.type === "aws_ecs_task_definition" && change.mode === "managed"
    && (change.module === undefined || change.module === null)) {
    if (exactJson(actions, ECS_INITIAL_CREATE_ACTIONS)) return STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_INITIAL_CREATE;
    if (STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS.some((expected) => exactJson(actions, expected))) return STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_REVIEWED_ROLLOVER;
  }
  const profile = BROKER_PROFILES.get(change?.address);
  const brokerProfile = profile?.profiles.find((candidate) => exactJson(actions, candidate.actions));
  if (profile && change.type === profile.type && change.mode === "managed"
    && (change.module === undefined || change.module === null) && brokerProfile) return brokerProfile.classification;
  throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change?.address}`);
}

function assertBrokerActionProfile(plan) {
  const active = plan.resource_changes.filter((change) => BROKER_ADDRESSES.has(change?.address)
    && !exactJson(change.change?.actions, ["no-op"]));
  if (active.length === 0) return;
  if (active.length !== BROKER_ADDRESSES.size || !active.every((change) => exactJson(change.change?.actions, active[0].change.actions))) {
    throw new Error("UNCLASSIFIED_RESOURCE_ACTION: broker initial/update profile is not atomic.");
  }
}

function classifyReplacePaths(change) {
  const paths = change.change?.replace_paths || [];
  if (isEcsInitialCreate(change) && paths.length === 0) return [];
  if (ECS_ADDRESSES.has(change.address) && exactJson(paths, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)) {
    return paths.map((path) => ({ path: path.join("."), classification: "REVIEWED_REPLACEMENT_TRIGGER" }));
  }
  if (paths.length === 0 && BROKER_PROFILES.has(change.address)) return [];
  throw new Error(`UNCLASSIFIED_REPLACE_PATH: ${change.address}.${JSON.stringify(paths)}`);
}

function assertComputedAliasBinding(plan) {
  const alias = plan.resource_changes.find((change) => change?.address === "aws_lambda_alias.reviewed");
  if (!alias || exactJson(alias.change?.actions, ["no-op"]) || alias.change?.after_unknown?.function_version !== true) return;
  if (alias.change.after?.function_version !== undefined && alias.change.after?.function_version !== null) {
    throw new Error("UNCLASSIFIED_COMPUTED_CHANGE: aws_lambda_alias.reviewed.function_version");
  }
  const expectedBrokerAction = exactJson(alias.change?.actions, ["create"]) ? ["create"] : ["update"];
  const brokerChanges = plan.resource_changes.filter((change) => change?.address === "aws_lambda_function.broker");
  if (brokerChanges.length !== 1 || !exactJson(brokerChanges[0].change?.actions, expectedBrokerAction)) {
    throw new Error("UNCLASSIFIED_COMPUTED_CHANGE: aws_lambda_alias.reviewed.function_version");
  }
  if (brokerChanges[0].change?.after_unknown?.version !== true) {
    throw new Error("UNCLASSIFIED_COMPUTED_CHANGE: aws_lambda_function.broker.version");
  }
  const brokerConfiguration = rootConfigurationResources(plan).find((item) => item?.address === "aws_lambda_function.broker");
  if (brokerConfiguration?.expressions?.publish?.constant_value !== true) {
    throw new Error("UNCLASSIFIED_CONFIGURATION_REFERENCES: aws_lambda_function.broker.publish");
  }
}

export function censusStageBPlanSemantics(plan) {
  if (!plan || !Array.isArray(plan.resource_changes)) throw new Error("Stage B semantic census requires Terraform plan resource_changes.");
  assertStageBProviderSemanticSnapshot();
  assertBrokerActionProfile(plan);
  const resources = [];
  const seenAddresses = new Set();
  for (const change of plan.resource_changes) {
    const actions = change?.change?.actions || [];
    if (exactJson(actions, ["no-op"]) || actions.length === 0) continue;
    if (seenAddresses.has(change.address)) throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change.address}`);
    seenAddresses.add(change.address);
    const classification = classifyResource(change);
    if (ECS_ADDRESSES.has(change.address)) assertEcsSemanticDomain(change);
    assertInitialBrokerEnvironment(change);
    if (isBrokerInitialCreate(change) || isEcsInitialCreate(change)) assertInitialProviderComputedShape(change);
    const changedPaths = diffPaths(change.change?.before, change.change?.after).filter(Boolean).map((path) => ({ path, classification: assertClass(classifyChangedPath(change, path), "CHANGED_PATH") }));
    const afterUnknownPaths = truePaths(change.change?.after_unknown).filter(Boolean).map((path) => ({ path, classification: assertClass(classifyUnknownPath(change, path), "AFTER_UNKNOWN") }));
    const beforeSensitivePaths = assertSensitivePaths(change, "BEFORE", truePaths(change.change?.before_sensitive));
    const afterSensitivePaths = assertSensitivePaths(change, "AFTER", truePaths(change.change?.after_sensitive));
    const replacePaths = classifyReplacePaths(change);
    const configurationReferences = collectConfigurationReferences(plan, change.address);
    resources.push({
      address: change.address,
      mode: change.mode ?? null,
      type: change.type ?? null,
      module: change.module ?? null,
      actions: [...actions],
      beforeKeys: Object.keys(change.change?.before || {}).sort(),
      afterKeys: Object.keys(change.change?.after || {}).sort(),
      changedPaths,
      afterUnknownPaths,
      beforeSensitivePaths,
      afterSensitivePaths,
      replacePaths,
      configurationReferences,
      classification,
    });
  }
  assertComputedAliasBinding(plan);
  const counts = {
    nonNoopResources: resources.length,
    resourceActions: resources.length,
    changedPaths: resources.reduce((sum, item) => sum + item.changedPaths.length, 0),
    afterUnknownPaths: resources.reduce((sum, item) => sum + item.afterUnknownPaths.length, 0),
    replacePaths: resources.reduce((sum, item) => sum + item.replacePaths.length, 0),
    configurationReferences: resources.reduce((sum, item) => sum + item.configurationReferences.length, 0),
    unclassifiedResourceActions: 0,
    unclassifiedChangedPaths: 0,
    unclassifiedAfterUnknownPaths: 0,
    unclassifiedReplacePaths: 0,
    unclassifiedConfigurationReferences: 0,
    unfaithfulProviderComputedFields: 0,
  };
  return { schemaVersion: 1, resources, counts };
}

export function assertStageBPlanSemanticCompleteness(plan) {
  const census = censusStageBPlanSemantics(plan);
  if (Object.entries(census.counts).some(([key, value]) => key.startsWith("unclassified") && value !== 0)) {
    throw new Error("Stage B plan semantic completeness contains unclassified semantics.");
  }
  return census;
}

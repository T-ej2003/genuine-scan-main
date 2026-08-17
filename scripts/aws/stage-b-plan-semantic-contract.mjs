import {
  canonicalizeEcsTaskDefinitionVolumes,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  assertStageBImportedBackendRolloverActions,
  STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS,
  STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS,
  exactReviewedTaskDefinitionTags,
} from "./stage-b-reference-audit-contract.mjs";
import {
  assertStageBProviderResourceShapeUniverse,
  assertStageBProviderSemanticSnapshot,
  STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE,
  STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT,
} from "./stage-b-provider-semantic-snapshot.mjs";
import {
  assertStageBBrokerPolicyDocument,
  assertStageBBackendEcsExecPolicyChange,
  assertStageBBrokerPublishProviderMetadataRepresentation,
  assertStageBImportedBackendMetadataNormalization,
  assertStageBPartialApplyRecoveryPlan,
  assertStageBFreshImagePartialApplyRecoveryPlan,
  STAGE_B_FRESH_IMAGE_PARTIAL_APPLY_RECOVERY,
  isStageBPartialApplyDeposedTaskDefinitionCleanup,
  assertReviewedBrokerTimeoutTransition,
  STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS,
  STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION,
  assertStageBTerraformBrokerPolicySource,
  STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS,
  STAGE_B_BROKER_PUBLISH_PROVIDER_UNKNOWN_METADATA_FIELDS,
  stageBMutationInstanceIdentity,
  resolveStageBRecoveryMode,
} from "./stage-b-deployment-contract.mjs";
import { assertStageBLambdaEnvironmentSize, STAGE_B } from "./production-green-stage-b-contract.mjs";

export const STAGE_B_PLAN_SEMANTIC_CLASSES = Object.freeze([
  "STABLE_REQUIRED",
  "REVIEWED_CONCRETE_CHANGE",
  "REVIEWED_COMPUTED_CHANGE",
  "REVIEWED_PROVIDER_NORMALIZATION",
  "REVIEWED_REPLACEMENT_TRIGGER",
  "CONFIGURATION_BOUND_PACKAGE_DIGEST",
  "PROVIDER_COMPUTED_CODE_METADATA",
  "DIAGNOSTIC_ONLY",
]);

export const STAGE_B_PLAN_SEMANTIC_PROFILES = Object.freeze({
  ECS_INITIAL_CREATE: "ECS_INITIAL_CREATE",
  ECS_REVIEWED_ROLLOVER: "ECS_REVIEWED_ROLLOVER",
  IMPORTED_BACKEND_METADATA_NORMALIZATION: STAGE_B_IMPORTED_BACKEND_METADATA_NORMALIZATION,
  BROKER_POLICY_INITIAL_CREATE: "BROKER_POLICY_INITIAL_CREATE",
  BROKER_FUNCTION_INITIAL_CREATE: "BROKER_FUNCTION_INITIAL_CREATE",
  BROKER_ALIAS_INITIAL_CREATE: "BROKER_ALIAS_INITIAL_CREATE",
  BROKER_POLICY_UPDATE: "BROKER_POLICY_UPDATE",
  BROKER_FUNCTION_PUBLISH_UPDATE: "BROKER_FUNCTION_PUBLISH_UPDATE",
  REVIEWED_RECOVERY_ALIAS_UPDATE: "REVIEWED_RECOVERY_ALIAS_UPDATE",
  PARTIAL_APPLY_RECOVERY: "PARTIAL_APPLY_RECOVERY",
  FRESH_IMAGE_PARTIAL_APPLY_RECOVERY: STAGE_B_FRESH_IMAGE_PARTIAL_APPLY_RECOVERY,
  BACKEND_ECS_EXEC_POLICY_CREATE: "BACKEND_ECS_EXEC_POLICY_CREATE",
});

export const STAGE_B_SUPPORTED_PLAN_PROFILES = Object.freeze([
  Object.freeze({ profile: "BASELINE_INITIAL_CREATE", ecsActions: [["create"]], brokerPolicyActions: [["create"]], brokerFunctionActions: [["create"]], brokerAliasActions: [["create"]], recoveryRequired: false, fixture: "production-green-stage-b-production-shaped.plan.json" }),
  Object.freeze({ profile: "ROLLOVER_RECOVERY", ecsActions: [["create", "delete"], ["delete", "create"]], brokerPolicyActions: [["update"]], brokerFunctionActions: [["update"]], brokerAliasActions: [["update"]], recoveryRequired: true, fixture: "production-green-stage-b-plan-semantic.test.mjs" }),
  Object.freeze({ profile: "RECOVERY_ALIAS_ONLY", ecsActions: [], brokerPolicyActions: [["no-op"]], brokerFunctionActions: [["no-op"]], brokerAliasActions: [["update"]], recoveryRequired: true, fixture: "stage-b-partial-apply-recovery-contract.test.mjs" }),
  Object.freeze({ profile: "NO_CHANGE_OR_APPEND_ONLY_RETRY", ecsActions: [["create"], ["no-op"]], brokerPolicyActions: [["create"], ["no-op"]], brokerFunctionActions: [["create"], ["no-op"]], brokerAliasActions: [["create"], ["no-op"]], recoveryRequired: false, fixture: "production-green-stage-b-plan-semantic.test.mjs" }),
  Object.freeze({ profile: "PARTIAL_APPLY_RECOVERY", ecsActions: [["delete"]], brokerPolicyActions: [["no-op"]], brokerFunctionActions: [["update"]], brokerAliasActions: [["update"]], recoveryRequired: true, fixture: "production-green-stage-b-plan-semantic.test.mjs" }),
  Object.freeze({ profile: "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY", ecsActions: [["create", "delete"]], brokerPolicyActions: [["update"]], brokerFunctionActions: [["update"]], brokerAliasActions: [["update"]], recoveryRequired: true, fixture: "production-green-stage-b-fresh-image-partial-recovery.test.mjs" }),
]);

const ECS_ADDRESSES = new Set(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES));
const ECS_INITIAL_CREATE_ACTIONS = ["create"];
const ECS_INITIAL_CREATE_PATHS = new Set([
  "container_definitions", "cpu", "enable_fault_injection", "ephemeral_storage",
  "execution_role_arn", "family", "ipc_mode", "memory", "network_mode", "pid_mode",
  "placement_constraints", "proxy_configuration", "region", "requires_compatibilities",
  "requires_compatibilities[0]", "runtime_platform[0].operating_system_family",
  "runtime_platform[0].cpu_architecture", "skip_destroy", "task_role_arn", "track_latest",
  "tags.Component", "tags.Environment", "tags.ManagedBy", "tags.MSCQRExecTarget", "tags_all.Component",
  "tags_all.Environment", "tags_all.ManagedBy",
]);
const ECS_INITIAL_CREATE_PROVIDER_PATHS = new Set([
  "ipc_mode", "pid_mode", "ephemeral_storage", "placement_constraints", "proxy_configuration",
  "volume", "volume[0].configure_at_launch",
  "volume[0].docker_volume_configuration", "volume[0].efs_volume_configuration",
  "volume[0].fsx_windows_file_server_volume_configuration", "volume[0].host_path",
  "volume[0].s3files_volume_configuration",
]);
export const STAGE_B_TYPED_REPRESENTATION_CATEGORIES = Object.freeze([
  "CONFIGURED_CONCRETE", "CONFIGURATION_DEPENDENCY_UNKNOWN", "CONFIGURATION_DEPENDENCY_CONCRETE",
  "CONFIGURATION_DEPENDENCY_COMPUTED",
  "PROVIDER_COMPUTED_UNKNOWN", "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", "PROVIDER_DEFAULTED_CONCRETE",
  "PROVIDER_NORMALIZED_CONCRETE", "KNOWN_UNSET_NULL", "KNOWN_FALSE_MARKER", "KNOWN_EMPTY_LIST", "KNOWN_EMPTY_OBJECT",
  "NOT_EMITTED_IN_SUPPORTED_PROFILE",
]);
const DIFF_ATOMIC_PATHS = new Set(["environment[0].variables"]);
const BROKER_PROFILES = new Map([
  ["aws_iam_policy.broker", { type: "aws_iam_policy", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_POLICY_UPDATE }] }],
  ["aws_lambda_function.broker", { type: "aws_lambda_function", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_FUNCTION_PUBLISH_UPDATE }] }],
  ["aws_lambda_alias.reviewed", { type: "aws_lambda_alias", profiles: [{ actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BROKER_ALIAS_INITIAL_CREATE }, { actions: ["update"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.REVIEWED_RECOVERY_ALIAS_UPDATE }] }],
]);
const STATIC_PROFILES = new Map([
  ["aws_iam_role_policy.backend_ecs_exec", { type: "aws_iam_role_policy", actions: ["create"], classification: STAGE_B_PLAN_SEMANTIC_PROFILES.BACKEND_ECS_EXEC_POLICY_CREATE }],
]);
const BROKER_ADDRESSES = new Set(BROKER_PROFILES.keys());
const BROKER_INITIAL_TAG_PATHS = new Set(["tags.Component", "tags.Environment", "tags.ManagedBy"]);
const BROKER_POLICY_INITIAL_CHANGED_PATHS = new Set(["name", "path", "arn", "id", "policy", ...BROKER_INITIAL_TAG_PATHS]);
const BROKER_FUNCTION_INITIAL_CHANGED_PATHS = new Set([
  "function_name", "role", "handler", "runtime", "filename", "source_code_hash", "timeout", "publish",
  "environment[0].variables", ...BROKER_INITIAL_TAG_PATHS,
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
  ...STAGE_B_BROKER_PUBLISH_PROVIDER_METADATA_FIELDS,
]);
const BROKER_FUNCTION_UNKNOWN_PATHS = new Set([
  "architectures[0]",
  "environment[0].variables",
  ...STAGE_B_BROKER_PUBLISH_PROVIDER_UNKNOWN_METADATA_FIELDS,
]);
const BROKER_FUNCTION_SENSITIVE_PATHS = new Set(["architectures[0]"]);
const ALIAS_CHANGED_PATHS = new Set(["function_version"]);
const ALIAS_UNKNOWN_PATHS = new Set(["function_version"]);
const ALIAS_SENSITIVE_PATHS = new Set();

const providerAttributes = (resourceType) => new Map(STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT.resources[resourceType].attributes.map((entry) => [entry.attributePath, entry]));
const providerTopLevelPaths = (resourceType) => new Set([
  ...STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[resourceType].attributes.map((entry) => entry.attributePath),
  ...STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[resourceType].blocks.map((entry) => entry.blockPath.split(".")[0].replace(/\[\]$/, "")),
]);
const providerShapeTopLevelNames = (resourceType) => [
  ...STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[resourceType].attributes.map((entry) => entry.attributePath),
  ...STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources[resourceType].blocks.map((entry) => entry.blockPath.split(".")[0].replace(/\[\]$/, "")),
].sort();
const TYPED_NULL_PATHS = Object.freeze({
  aws_iam_policy: new Set(["description", "name_prefix", "delay_after_policy_creation_in_ms"]),
  aws_lambda_function: new Set(["description", "publish_to", "replace_security_groups_on_destroy", "replacement_security_group_ids", "s3_bucket", "s3_key", "s3_object_version", "timeouts", "use_resource_timeout_for_propagation"]),
  aws_lambda_alias: new Set(["description", "timeouts"]),
  aws_ecs_task_definition: new Set(["ipc_mode", "pid_mode"]),
});
const TYPED_EMPTY_PATHS = Object.freeze({
  aws_iam_policy: new Set(["tags", "tags_all"]),
  aws_lambda_function: new Set(["capacity_provider_config", "dead_letter_config", "durable_config", "file_system_config", "image_config", "layers", "snap_start", "tags", "tags_all", "tenancy_config", "vpc_config"]),
  aws_lambda_alias: new Set(["routing_config"]),
  aws_ecs_task_definition: new Set(["ephemeral_storage", "placement_constraints", "proxy_configuration", "tags", "tags_all"]),
});
const TYPED_MARKER_PATHS = Object.freeze({
  aws_iam_policy: new Set(["arn", "attachment_count", "id", "policy", "policy_id", "tags", "tags_all"]),
  aws_lambda_function: new Set([
    "architectures[0]", "arn", "capacity_provider_config", "code_sha256", "dead_letter_config", "durable_config", "environment[0].variables", "ephemeral_storage", "file_system_config", "id", "image_config", "invoke_arn", "last_modified", "layers",
    "logging_config", "qualified_arn", "qualified_invoke_arn", "response_streaming_invoke_arn", "signing_job_arn",
    "signing_profile_version_arn", "snap_start", "source_code_size", "tags", "tags_all", "tenancy_config", "tracing_config", "version", "vpc_config",
  ]),
  aws_lambda_alias: new Set(["arn", "function_version", "id", "invoke_arn", "routing_config"]),
  aws_ecs_task_definition: new Set([
    "arn", "arn_without_revision", "enable_fault_injection", "id", "revision", "ephemeral_storage",
    "placement_constraints", "proxy_configuration", "requires_compatibilities[0]", "runtime_platform",
    "tags", "tags_all", "volume", "volume[0].configure_at_launch", "volume[0].docker_volume_configuration",
    "volume[0].efs_volume_configuration", "volume[0].fsx_windows_file_server_volume_configuration",
    "volume[0].s3files_volume_configuration",
  ]),
});
const providerComputedOnlyPaths = (resourceType) => [...providerAttributes(resourceType).values()].filter((entry) => entry.computed && !entry.optional && !entry.required).map((entry) => entry.attributePath);
const BROKER_POLICY_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_iam_policy"), "id"]);
const BROKER_FUNCTION_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_lambda_function"), "architectures[0]", "code_sha256", "id"]);
const BROKER_ALIAS_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_lambda_alias"), "function_version", "id"]);
const BROKER_POLICY_INITIAL_DEPENDENCY_COMPUTED_PATHS = new Set(["policy"]);
const BROKER_FUNCTION_INITIAL_DEPENDENCY_COMPUTED_PATHS = new Set(["environment[0].variables"]);
const ECS_INITIAL_PROVIDER_UNKNOWN_PATHS = new Set([...providerComputedOnlyPaths("aws_ecs_task_definition"), "enable_fault_injection", "id"]);

const CONFIGURATION_REFERENCE_RULES = Object.freeze({
  "aws_cloudwatch_log_group.stage_b": {
    name: ["each.value"],
    retention_in_days: ["var.log_retention_days"],
    tags: ["local.tags"],
  },
  "aws_dynamodb_table.replay": {
    tags: ["local.tags"],
  },
  "aws_ecs_task_definition.candidate": {
    container_definitions: ["each.value.containerDefinitions", "each.value"],
    cpu: ["each.value.cpu", "each.value"],
    execution_role_arn: ["aws_iam_role.execution", "each.key"],
    family: ["each.value.family", "each.value"],
    memory: ["each.value.memory", "each.value"],
    network_mode: ["each.value.networkMode", "each.value"],
    requires_compatibilities: ["each.value.requiresCompatibilities", "each.value"],
    tags: ["each.key", "local.backend_exec_tags", "local.tags"],
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
  "aws_ecs_task_definition.candidate_retained": {
    container_definitions: ["each.value", "each.value.definition", "each.value.definition.containerDefinitions"],
    cpu: ["each.value", "each.value.definition", "each.value.definition.cpu"],
    execution_role_arn: ["aws_iam_role.execution", "each.value", "each.value.kind"],
    family: ["each.value", "each.value.definition", "each.value.definition.family"],
    memory: ["each.value", "each.value.definition", "each.value.definition.memory"],
    network_mode: ["each.value", "each.value.definition", "each.value.definition.networkMode"],
    requires_compatibilities: ["each.value", "each.value.definition", "each.value.definition.requiresCompatibilities"],
    tags: ["local.tags"],
    task_role_arn: ["aws_iam_role.task", "each.value", "each.value.kind"],
  },
  "aws_ecs_task_definition.executor_retained": {
    container_definitions: ["each.value", "each.value.definition", "each.value.definition.containerDefinitions"],
    cpu: ["each.value", "each.value.definition", "each.value.definition.cpu"],
    execution_role_arn: ["aws_iam_role.execution", "aws_iam_role.execution[\"executor\"]", "aws_iam_role.execution[\"executor\"].arn"],
    family: ["each.value", "each.value.definition", "each.value.definition.family"],
    memory: ["each.value", "each.value.definition", "each.value.definition.memory"],
    network_mode: ["each.value", "each.value.definition", "each.value.definition.networkMode"],
    requires_compatibilities: ["each.value", "each.value.definition", "each.value.definition.requiresCompatibilities"],
    tags: ["local.tags"],
    task_role_arn: ["var.stage_a_executor_task_role_arn"],
  },
  "aws_iam_policy.broker": {
    policy: ["local.broker_runtime_policy"],
    tags: ["local.tags"],
  },
  "aws_iam_role_policy.backend_ecs_exec": {
    role: ["aws_iam_role.task", "aws_iam_role.task[\"backend\"]", "aws_iam_role.task[\"backend\"].id"],
  },
  "aws_iam_role.execution": {
    name: ["each.value"],
    tags: ["local.tags"],
  },
  "aws_iam_role.task": {
    name: ["each.value"],
    tags: ["local.tags"],
  },
  "aws_iam_role_policy.candidate_object_storage": {
    policy: ["var.receipt_bucket_arn"],
    role: ["each.value", "each.value.id"],
  },
  "aws_iam_role_policy.execution": {
    policy: ["each.key", "local.active_execution_secret_arns", "local.backend_execution_secret_arns", "local.ecr_repository_arns", "local.execution_log_group_arns", "var.stage_b_recovery_only"],
    role: ["each.value", "each.value.id"],
  },
  "aws_iam_role_policy.executor_runtime": {
    policy: ["var.approval_kms_key_arn", "var.receipt_bucket_arn", "var.stage_a_runtime_secret_arns"],
    role: ["var.stage_a_executor_task_role_arn"],
  },
  "aws_iam_role_policy_attachment.broker": {
    policy_arn: ["aws_iam_policy.broker", "aws_iam_policy.broker.arn"],
    role: ["var.stage_a_broker_role_arn"],
  },
  "aws_lambda_function.broker": {
    "environment[0].variables": [
      "local.broker_environment",
    ],
    filename: ["var.broker_package_path"],
    role: ["var.stage_a_broker_role_arn"],
    source_code_hash: ["var.broker_package_path"],
    tags: ["local.tags"],
  },
  "aws_lambda_alias.reviewed": {
    function_name: ["aws_lambda_function.broker.function_name", "aws_lambda_function.broker"],
    function_version: [
      "aws_lambda_function.broker",
      "aws_lambda_function.broker.version",
      "var.stage_b_recovery_alias_target_version",
      "var.stage_b_recovery_only",
    ],
  },
  "aws_lambda_permission.release_deployer": {
    function_name: ["aws_lambda_function.broker", "aws_lambda_function.broker.function_name"],
    qualifier: ["aws_lambda_alias.reviewed", "aws_lambda_alias.reviewed.name"],
  },
});

export const STAGE_B_STATIC_CONFIGURATION_CLASSES = Object.freeze([
  "EXACT_IMMUTABLE", "EXACT_SOURCE_BOUND", "REVIEWED_TRANSITION", "PROVIDER_NORMALIZATION",
  "COMPUTED_ONLY", "SENSITIVE_HASH_BOUND", "REJECTED",
]);

const STATIC_CONFIGURATION_PROFILES = Object.freeze({
  "aws_cloudwatch_log_group.stage_b": { fields: ["name", "retention_in_days", "tags"], forEach: ["local.stage_b_logs"] },
  "aws_dynamodb_table.replay": { fields: ["attribute", "billing_mode", "hash_key", "name", "tags", "ttl"] },
  "aws_ecs_task_definition.candidate": { fields: ["container_definitions", "cpu", "execution_role_arn", "family", "memory", "network_mode", "requires_compatibilities", "runtime_platform", "skip_destroy", "tags", "task_role_arn"], forEach: ["local.candidate_definitions_for_resources"] },
  "aws_ecs_task_definition.candidate_retained": { fields: ["container_definitions", "cpu", "execution_role_arn", "family", "memory", "network_mode", "requires_compatibilities", "runtime_platform", "skip_destroy", "tags", "task_role_arn"], forEach: ["local.retained_candidate_definitions"] },
  "aws_ecs_task_definition.executor": { fields: ["container_definitions", "cpu", "execution_role_arn", "family", "memory", "network_mode", "requires_compatibilities", "runtime_platform", "skip_destroy", "tags", "task_role_arn"], forEach: ["local.executor_definitions_for_resources"] },
  "aws_ecs_task_definition.executor_retained": { fields: ["container_definitions", "cpu", "execution_role_arn", "family", "memory", "network_mode", "requires_compatibilities", "runtime_platform", "skip_destroy", "tags", "task_role_arn"], forEach: ["local.retained_executor_definitions"] },
  "aws_iam_policy.broker": { fields: ["name", "path", "policy", "tags"] },
  "aws_iam_role.execution": { fields: ["assume_role_policy", "name", "tags"], forEach: ["local.execution_role_names"] },
  "aws_iam_role.task": { fields: ["assume_role_policy", "name", "tags"], forEach: ["local.task_role_names"] },
  "aws_iam_role_policy.backend_ecs_exec": { fields: ["name", "policy", "role"] },
  "aws_iam_role_policy.candidate_object_storage": { fields: ["name", "policy", "role"], forEach: ["aws_iam_role.task"] },
  "aws_iam_role_policy.execution": { fields: ["name", "policy", "role"], forEach: ["aws_iam_role.execution"] },
  "aws_iam_role_policy.executor_runtime": { fields: ["name", "policy", "role"] },
  "aws_iam_role_policy_attachment.broker": { fields: ["policy_arn", "role"] },
  "aws_lambda_alias.reviewed": { fields: ["function_name", "function_version", "name"] },
  "aws_lambda_function.broker": { fields: ["environment", "filename", "function_name", "handler", "publish", "role", "runtime", "source_code_hash", "tags", "timeout"] },
  "aws_lambda_permission.release_deployer": { fields: ["action", "function_name", "principal", "qualifier", "statement_id"] },
});

const STATIC_CONFIGURATION_CONSTANTS = Object.freeze({
  "aws_dynamodb_table.replay": {
    attribute: [{ name: { constant_value: "approvalMode" }, type: { constant_value: "S" } }],
    billing_mode: "PAY_PER_REQUEST",
    hash_key: "approvalMode",
    name: "mscqr-production-rls-stage-b-replay",
    ttl: [{ attribute_name: { constant_value: "expiresAt" }, enabled: { constant_value: true } }],
  },
  "aws_ecs_task_definition.candidate": { runtime_platform: [{ cpu_architecture: { constant_value: "X86_64" }, operating_system_family: { constant_value: "LINUX" } }], skip_destroy: true },
  "aws_ecs_task_definition.executor": { runtime_platform: [{ cpu_architecture: { constant_value: "X86_64" }, operating_system_family: { constant_value: "LINUX" } }], skip_destroy: true },
  "aws_ecs_task_definition.candidate_retained": { runtime_platform: [{ cpu_architecture: { constant_value: "X86_64" }, operating_system_family: { constant_value: "LINUX" } }], skip_destroy: true },
  "aws_ecs_task_definition.executor_retained": { runtime_platform: [{ cpu_architecture: { constant_value: "X86_64" }, operating_system_family: { constant_value: "LINUX" } }], skip_destroy: true },
  "aws_iam_policy.broker": { name: "mscqr-production-rls-approval-broker-runtime", path: "/" },
  "aws_iam_role.execution": { assume_role_policy: {} },
  "aws_iam_role.task": { assume_role_policy: {} },
  "aws_iam_role_policy.backend_ecs_exec": { name: "stage-b-backend-ecs-exec-ssm-channels", policy: {} },
  "aws_iam_role_policy.candidate_object_storage": { name: "stage-b-object-storage" },
  "aws_iam_role_policy.execution": { name: "stage-b-exact-image-logs-and-secrets" },
  "aws_iam_role_policy.executor_runtime": { name: "stage-b-executor-runtime" },
  "aws_lambda_alias.reviewed": { name: "reviewed" },
  "aws_lambda_function.broker": { function_name: "mscqr-production-rls-approval-broker", handler: "index.handler", publish: true, runtime: "nodejs24.x", timeout: 180 },
  "aws_lambda_permission.release_deployer": { action: "lambda:InvokeFunction", principal: "arn:aws:iam::368992683803:role/mscqr-production-release-deployer", statement_id: "OnlyProtectedReleaseRoleMayInvokeReviewedAlias" },
});

export function getStageBConfigurationReferenceRules() {
  return Object.fromEntries(Object.entries(CONFIGURATION_REFERENCE_RULES).map(([address, fields]) => [
    address,
    Object.fromEntries(Object.entries(fields).map(([field, references]) => [field, [...references]])),
  ]));
}

const exactJson = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const isObject = (value) => value !== null && typeof value === "object";
const pathFor = (base, key) => typeof key === "number" ? `${base}[${key}]` : (base ? `${base}.${key}` : key);

function canonicalExpression(value) {
  if (Array.isArray(value)) return value.map((item) => canonicalExpression(item));
  if (!isObject(value)) return { type: value === null ? "null" : typeof value, value };
  const keys = Object.keys(value).sort();
  if (keys.length === 1 && keys[0] === "references" && Array.isArray(value.references)) {
    return { references: canonicalReferenceSet(value.references) };
  }
  return Object.fromEntries(keys.map((key) => [key, canonicalExpression(value[key])]));
}

function expressionHasNonReferenceContent(value) {
  if (Array.isArray(value)) return value.some(expressionHasNonReferenceContent);
  if (!isObject(value)) return value !== undefined;
  return Object.entries(value).some(([key, nested]) => key !== "references" && expressionHasNonReferenceContent(nested));
}

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

export const STAGE_B_TYPED_REPRESENTATION_MANIFEST = Object.freeze({
  aws_iam_policy: Object.freeze({
    arn: "PROVIDER_COMPUTED_UNKNOWN", attachment_count: "PROVIDER_COMPUTED_UNKNOWN", delay_after_policy_creation_in_ms: "KNOWN_UNSET_NULL", description: "KNOWN_UNSET_NULL", id: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", name: "CONFIGURED_CONCRETE", name_prefix: "KNOWN_UNSET_NULL", path: "CONFIGURED_CONCRETE", policy: "CONFIGURATION_DEPENDENCY_COMPUTED",
    policy_id: "PROVIDER_COMPUTED_UNKNOWN", tags: "CONFIGURED_CONCRETE", tags_all: "PROVIDER_NORMALIZED_CONCRETE",
  }),
  aws_lambda_function: Object.freeze({
    architectures: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", arn: "PROVIDER_COMPUTED_UNKNOWN", capacity_provider_config: "KNOWN_EMPTY_LIST", code_sha256: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", code_signing_config_arn: "PROVIDER_NORMALIZED_CONCRETE", dead_letter_config: "KNOWN_EMPTY_LIST", description: "KNOWN_UNSET_NULL", durable_config: "KNOWN_EMPTY_LIST", environment: "CONFIGURATION_DEPENDENCY_COMPUTED", ephemeral_storage: "PROVIDER_NORMALIZED_CONCRETE", file_system_config: "KNOWN_EMPTY_LIST", filename: "CONFIGURED_CONCRETE", function_name: "CONFIGURED_CONCRETE", handler: "CONFIGURED_CONCRETE", id: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", image_config: "KNOWN_EMPTY_LIST", image_uri: "PROVIDER_NORMALIZED_CONCRETE", invoke_arn: "PROVIDER_COMPUTED_UNKNOWN", kms_key_arn: "PROVIDER_NORMALIZED_CONCRETE", last_modified: "PROVIDER_COMPUTED_UNKNOWN", layers: "KNOWN_EMPTY_LIST", logging_config: "PROVIDER_NORMALIZED_CONCRETE", memory_size: "PROVIDER_DEFAULTED_CONCRETE", package_type: "PROVIDER_DEFAULTED_CONCRETE", publish: "CONFIGURED_CONCRETE", publish_to: "KNOWN_UNSET_NULL", qualified_arn: "PROVIDER_COMPUTED_UNKNOWN", qualified_invoke_arn: "PROVIDER_COMPUTED_UNKNOWN", region: "PROVIDER_NORMALIZED_CONCRETE", replace_security_groups_on_destroy: "KNOWN_UNSET_NULL", replacement_security_group_ids: "KNOWN_UNSET_NULL", reserved_concurrent_executions: "PROVIDER_DEFAULTED_CONCRETE", response_streaming_invoke_arn: "PROVIDER_COMPUTED_UNKNOWN", role: "CONFIGURED_CONCRETE", runtime: "CONFIGURED_CONCRETE", s3_bucket: "KNOWN_UNSET_NULL", s3_key: "KNOWN_UNSET_NULL", s3_object_version: "KNOWN_UNSET_NULL", signing_job_arn: "PROVIDER_COMPUTED_UNKNOWN", signing_profile_version_arn: "PROVIDER_COMPUTED_UNKNOWN", skip_destroy: "PROVIDER_DEFAULTED_CONCRETE", snap_start: "KNOWN_EMPTY_LIST", source_code_hash: "CONFIGURED_CONCRETE", source_code_size: "PROVIDER_COMPUTED_UNKNOWN", source_kms_key_arn: "PROVIDER_NORMALIZED_CONCRETE", tags: "CONFIGURED_CONCRETE", tags_all: "PROVIDER_NORMALIZED_CONCRETE", tenancy_config: "KNOWN_EMPTY_LIST", timeout: "CONFIGURED_CONCRETE", timeouts: "KNOWN_UNSET_NULL", tracing_config: "PROVIDER_NORMALIZED_CONCRETE", use_resource_timeout_for_propagation: "KNOWN_UNSET_NULL", vpc_config: "KNOWN_EMPTY_LIST", version: "PROVIDER_COMPUTED_UNKNOWN",
    "environment[0].variables": "CONFIGURATION_DEPENDENCY_COMPUTED",
  }),
  aws_lambda_alias: Object.freeze({
    arn: "PROVIDER_COMPUTED_UNKNOWN", description: "KNOWN_UNSET_NULL", function_name: "CONFIGURED_CONCRETE", function_version: "CONFIGURATION_DEPENDENCY_COMPUTED", id: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", invoke_arn: "PROVIDER_COMPUTED_UNKNOWN", name: "CONFIGURED_CONCRETE", region: "PROVIDER_NORMALIZED_CONCRETE", routing_config: "KNOWN_EMPTY_LIST", timeouts: "KNOWN_UNSET_NULL",
  }),
  aws_ecs_task_definition: Object.freeze({
    family: "CONFIGURED_CONCRETE", container_definitions: "CONFIGURED_CONCRETE", cpu: "CONFIGURED_CONCRETE", memory: "CONFIGURED_CONCRETE", network_mode: "CONFIGURED_CONCRETE", requires_compatibilities: "CONFIGURED_CONCRETE", execution_role_arn: "CONFIGURED_CONCRETE", task_role_arn: "CONFIGURED_CONCRETE", region: "PROVIDER_NORMALIZED_CONCRETE", skip_destroy: "CONFIGURED_CONCRETE", track_latest: "PROVIDER_DEFAULTED_CONCRETE", tags: "CONFIGURED_CONCRETE",
    ipc_mode: "KNOWN_UNSET_NULL", pid_mode: "KNOWN_UNSET_NULL", ephemeral_storage: "KNOWN_EMPTY_LIST",
    placement_constraints: "KNOWN_EMPTY_LIST", proxy_configuration: "KNOWN_EMPTY_LIST", tags_all: "PROVIDER_NORMALIZED_CONCRETE",
    arn: "PROVIDER_COMPUTED_UNKNOWN", arn_without_revision: "PROVIDER_COMPUTED_UNKNOWN", enable_fault_injection: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN",
    id: "PROVIDER_OPTIONAL_COMPUTED_UNKNOWN", revision: "PROVIDER_COMPUTED_UNKNOWN", runtime_platform: "CONFIGURED_CONCRETE",
    volume: "PROVIDER_NORMALIZED_CONCRETE",
  }),
});

const INITIAL_REPRESENTATION_ONLY_CATEGORIES = new Set([
  "PROVIDER_DEFAULTED_CONCRETE", "PROVIDER_NORMALIZED_CONCRETE", "KNOWN_UNSET_NULL", "KNOWN_EMPTY_LIST", "KNOWN_EMPTY_OBJECT", "KNOWN_FALSE_MARKER",
]);

export function initialRepresentationOnlyPaths(resourceType) {
  return new Set(Object.entries(STAGE_B_TYPED_REPRESENTATION_MANIFEST[resourceType] || {})
    .filter(([, category]) => INITIAL_REPRESENTATION_ONLY_CATEGORIES.has(category))
    .map(([path]) => path));
}

export function assertStageBTypedRepresentationManifestComplete() {
  const missing = [];
  for (const resourceType of Object.keys(STAGE_B_PROVIDER_RESOURCE_SHAPE_UNIVERSE.resources)) {
    const expected = providerShapeTopLevelNames(resourceType);
    const manifest = STAGE_B_TYPED_REPRESENTATION_MANIFEST[resourceType] || {};
    for (const field of expected) {
      if (!STAGE_B_TYPED_REPRESENTATION_CATEGORIES.includes(manifest[field])) missing.push(`${resourceType}.${field}`);
    }
  }
  if (missing.length) throw new Error(`MISSING_TYPED_REPRESENTATION_CLASSIFICATIONS: ${missing.join(",")}`);
  return { missingTypedRepresentationClassifications: 0 };
}

function typedMarkerPaths(value, base = "") {
  if (value === true || value === false) return [{ path: base, value }];
  if (!isObject(value)) return [{ path: base, value }];
  if (Array.isArray(value)) {
    if (value.length === 0) return [{ path: base, value }];
    return value.flatMap((item, index) => typedMarkerPaths(item, pathFor(base, index)));
  }
  const keys = Object.keys(value);
  if (keys.length === 0) return [{ path: base, value }];
  return keys.flatMap((key) => typedMarkerPaths(value[key], pathFor(base, key)));
}

function assertTypedNestedShape(change, field, value, unknown) {
  if (field === "environment" || field === "routing_config" || field === "runtime_platform") {
    if (!Array.isArray(value)) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    if (field === "routing_config" && value.length === 0) return;
    if (value.length !== 1 || !value[0] || typeof value[0] !== "object" || Array.isArray(value[0])) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    const allowed = field === "environment" ? ["variables"] : field === "routing_config" ? ["additional_version_weights"] : ["cpu_architecture", "operating_system_family"];
    if (Object.keys(value[0]).some((key) => !allowed.includes(key))) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    if (field === "runtime_platform" && !exactJson(Object.keys(value[0]).sort(), allowed.sort())) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    if (field === "environment" && value[0].variables !== undefined && (!value[0].variables || typeof value[0].variables !== "object" || Array.isArray(value[0].variables))) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}.variables`);
    return;
  }
  if (["ephemeral_storage", "placement_constraints", "proxy_configuration", "volume"].includes(field) && !Array.isArray(value)) {
    throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
  }
  if (field === "volume" && Array.isArray(value)) {
    for (const item of value) {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.volume`);
      const allowed = ["configure_at_launch", "name", "host_path", "docker_volume_configuration", "efs_volume_configuration", "fsx_windows_file_server_volume_configuration", "s3files_volume_configuration"];
      if (Object.keys(item).some((key) => !allowed.includes(key))) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.volume`);
      for (const nested of ["docker_volume_configuration", "efs_volume_configuration", "fsx_windows_file_server_volume_configuration", "s3files_volume_configuration"]) {
        if (item[nested] !== undefined && !Array.isArray(item[nested])) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.volume.${nested}`);
      }
    }
  }
  if (unknown !== undefined && field === "routing_config" && !Array.isArray(unknown)) throw new Error(`UNCLASSIFIED_AFTER_UNKNOWN (UNMODELED_AFTER_UNKNOWN_MARKERS): ${change.address}.${field}`);
}

function assertTypedRepresentationEnvelope(change) {
  const type = change.type;
  const after = change.change?.after;
  const unknown = change.change?.after_unknown;
  if (STATIC_PROFILES.has(change.address)) return;
  if (!BROKER_ADDRESSES.has(change.address) && !ECS_ADDRESSES.has(change.address)) return;
  if (after !== null && after !== undefined && (typeof after !== "object" || Array.isArray(after))) throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}`);
  const allowed = providerTopLevelPaths(type);
  for (const field of Object.keys(after || {})) {
    if (!allowed.has(field)) throw new Error(`UNCLASSIFIED_CHANGED_PATH (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    const category = STAGE_B_TYPED_REPRESENTATION_MANIFEST[type]?.[field];
    if (!STAGE_B_TYPED_REPRESENTATION_CATEGORIES.includes(category)) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    if (category === "NOT_EMITTED_IN_SUPPORTED_PROFILE") throw new Error(`UNFAITHFUL_SUPPORTED_PROFILE_FIXTURES (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
    assertTypedNestedShape(change, field, after[field], unknown?.[field]);
  }
  for (const marker of typedMarkerPaths(unknown)) {
    if (!marker.path) continue;
    if (![...TYPED_MARKER_PATHS[type]].some((allowedPath) => marker.path === allowedPath || marker.path.startsWith(`${allowedPath}.`) || marker.path.startsWith(`${allowedPath}[`))) {
      throw new Error(`UNCLASSIFIED_AFTER_UNKNOWN (UNMODELED_AFTER_UNKNOWN_MARKERS): ${change.address}.${marker.path}`);
    }
  }
  if (isBrokerInitialCreate(change) || isEcsInitialCreate(change)) {
    for (const field of TYPED_NULL_PATHS[type] || []) if (Object.hasOwn(after || {}, field) && after[field] !== null) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS (UNMODELED_TYPED_AFTER_FIELDS): ${change.address}.${field}`);
  }
  for (const field of TYPED_EMPTY_PATHS[type] || []) if (Object.hasOwn(after || {}, field) && !((Array.isArray(after[field]) && after[field].length === 0) || (isObject(after[field]) && !Array.isArray(after[field]) && Object.keys(after[field]).length === 0))) {
    if (field === "tags" || field === "tags_all") continue;
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS (UNMODELED_EMPTY_STRUCTURES): ${change.address}.${field}`);
  }
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

function canonicalReferenceSet(references) {
  const unique = new Set(references || []);
  if (unique.has("local.logs.backend")) unique.delete("local.logs");
  return [...unique].sort();
}

function staticConfigurationClass(address, field) {
  if (["policy", "container_definitions", "environment", "source_code_hash"].includes(field)) return "SENSITIVE_HASH_BOUND";
  if (["runtime_platform", "skip_destroy", "billing_mode", "hash_key", "ttl"].includes(field)) return "EXACT_IMMUTABLE";
  return "EXACT_SOURCE_BOUND";
}

function rootConfigurationResources(plan) {
  return plan?.configuration?.root_module?.resources || [];
}

function expectedStaticExpression(plan, address, field) {
  const constants = STATIC_CONFIGURATION_CONSTANTS[address]?.[field];
  if (constants !== undefined) return isObject(constants) || Array.isArray(constants) ? constants : { constant_value: constants };
  const references = allowedConfigurationReferences(plan, address, field === "environment" ? "environment[0].variables" : field);
  if (references === undefined) return {};
  if (field === "environment") return [{ variables: { references: canonicalReferenceSet(references) } }];
  return { references: canonicalReferenceSet(references) };
}

export function assertStageBStaticConfigurationCoverage(plan, { terraformConfiguration } = {}) {
  const resources = rootConfigurationResources(plan);
  const profiles = Object.entries(STATIC_CONFIGURATION_PROFILES);
  const expectedAddresses = new Set(profiles.map(([address]) => address));
  const configured = new Set();
  const configuredTypes = new Map();
  for (const resource of resources) {
    const profile = STATIC_CONFIGURATION_PROFILES[resource?.address];
    if (!profile || !expectedAddresses.has(resource.address)) throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_RESOURCE: ${resource?.address || "<missing>"}`);
    if (configured.has(resource.address)) throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_RESOURCE: ${resource.address}`);
    if (resource.type !== resource.address.split(".")[0]) throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_RESOURCE: ${resource.address}`);
    configured.add(resource.address);
    configuredTypes.set(resource.address, resource.type);
    const fields = Object.keys(resource.expressions || {}).sort();
    if (!exactJson(fields, [...profile.fields].sort())) throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_FIELDS: ${resource.address}`);
    for (const field of profile.fields) {
      const actual = resource.expressions?.[field];
      const expected = expectedStaticExpression(plan, resource.address, field);
      if ((expressionHasNonReferenceContent(actual) || expressionHasNonReferenceContent(expected))
        && !exactJson(canonicalExpression(actual), canonicalExpression(expected))) {
        throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_EXPRESSION: ${resource.address}.${field}`);
      }
    }
    const actualForEach = canonicalReferenceSet(referenceExpressions(resource.for_each_expression || {}).flatMap((item) => item.references));
    const expectedForEach = canonicalReferenceSet(profile.forEach || []);
    if (!exactJson(actualForEach, expectedForEach)) throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_FOR_EACH: ${resource.address}`);
    const references = referenceExpressions(resource.expressions || {});
    const expectedReferences = CONFIGURATION_REFERENCE_RULES[resource.address] || {};
    const actualReferenceFields = references.map(({ field }) => field).sort();
    if (!exactJson(actualReferenceFields, Object.keys(expectedReferences).sort())) throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${resource.address}`);
    for (const { field, references: values } of references) {
      if (!exactJson(canonicalReferenceSet(values), canonicalReferenceSet(allowedConfigurationReferences(plan, resource.address, field)))) {
        throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${resource.address}.${field}`);
      }
    }
  }
  const missing = [...expectedAddresses].filter((address) => !configured.has(address)).sort();
  const unexpected = [...configured].filter((address) => !expectedAddresses.has(address)).sort();
  if (missing.length || unexpected.length || configured.size !== expectedAddresses.size || configuredTypes.size !== expectedAddresses.size) {
    throw new Error(`UNCLASSIFIED_STATIC_CONFIGURATION_RESOURCE_SET: missing=${missing.join(",") || "<none>"};unexpected=${unexpected.join(",") || "<none>"}`);
  }
  if (typeof terraformConfiguration === "string") assertStageBTerraformBrokerPolicySource(terraformConfiguration, true);
  const brokerChange = plan?.resource_changes?.find((change) => change.address === "aws_iam_policy.broker");
  const brokerPolicy = brokerChange?.change?.after?.policy;
  if (typeof brokerPolicy === "string") {
    try { assertStageBBrokerPolicyDocument(JSON.parse(brokerPolicy)); } catch { throw new Error("UNCLASSIFIED_STATIC_CONFIGURATION_EXPRESSION: aws_iam_policy.broker.policy"); }
  }
  const attributes = profiles.flatMap(([address, profile]) => profile.fields.map((field) => ({ address, field, classification: staticConfigurationClass(address, field) })));
  return {
    resourceProfiles: profiles.length,
    configuredResourceProfiles: configured.size,
    configurationAttributes: attributes.length,
    unclassifiedConfigurationAttributes: 0,
    missingExpectedStaticProfiles: missing.length,
    unexpectedStaticResources: unexpected.length,
    unboundConstantExpressions: 0,
    unboundConfigurationReferences: 0,
    attributes,
  };
}

function configurationBase(address) {
  if (ECS_ADDRESSES.has(address)) return address.replace(/\["[^\"]+"\]$/, "");
  return address;
}

function allowedConfigurationReferences(plan, address, field) {
  if (address === "aws_lambda_alias.reviewed" && field === "function_version") {
    return plan?.variables?.stage_b_recovery_only?.value === true
      ? [
        "aws_lambda_function.broker",
        "aws_lambda_function.broker.version",
        "var.stage_b_recovery_alias_target_version",
        "var.stage_b_recovery_only",
      ]
      : CONFIGURATION_REFERENCE_RULES[address][field];
  }
  return CONFIGURATION_REFERENCE_RULES[address][field];
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
    const allowed = canonicalReferenceSet(allowedConfigurationReferences(plan, base, item.field));
    const references = canonicalReferenceSet(item.references);
    if (!exactJson(references, allowed)) throw new Error(`UNCLASSIFIED_CONFIGURATION_REFERENCES: ${address}.${item.field}`);
    return {
      ...item,
      references,
      classification: address === "aws_lambda_alias.reviewed" && item.field === "function_version"
        ? (plan?.variables?.stage_b_recovery_only?.value === true ? "REVIEWED_CONCRETE_CHANGE" : "REVIEWED_COMPUTED_CHANGE")
        : "STABLE_REQUIRED",
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
    && (unknownEnvironment === undefined
      || (Array.isArray(unknownEnvironment) && unknownEnvironment.length === 1
        && exactJson(unknownEnvironment[0], { variables: false })));
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

function assertInitialTypedDefaults(change) {
  const after = change.change?.after || {};
  if (change.address === "aws_iam_policy.broker") {
    if (after.description !== null || after.name_prefix !== null) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.unset_fields`);
    if (!after.tags_all || !exactJson(after.tags_all, after.tags)) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.tags_all`);
  }
  if (change.address === "aws_lambda_function.broker") {
    if (after.reserved_concurrent_executions !== -1 || after.skip_destroy !== false) {
      throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.defaulted_fields`);
    }
  }
  if (change.address === "aws_lambda_alias.reviewed") {
    if (after.description !== null || after.timeouts !== null || after.region !== STAGE_B.region || !Array.isArray(after.routing_config) || after.routing_config.length !== 0) {
      throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.typed_defaults`);
    }
  }
}

function assertInitialRepresentationPath(change, path) {
  if (!isBrokerInitialCreate(change)) return false;
  const field = /^([^.[\]]+)/.exec(path)?.[1];
  if (!field || !initialRepresentationOnlyPaths(change.type).has(field)) return false;
  const value = change.change?.after?.[field];
  const category = STAGE_B_TYPED_REPRESENTATION_MANIFEST[change.type]?.[field];
  if (category === "KNOWN_UNSET_NULL") {
    if (value !== null) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  } else if (category === "KNOWN_EMPTY_LIST") {
    if (!Array.isArray(value) || value.length !== 0) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  } else if (category === "KNOWN_EMPTY_OBJECT") {
    if (!isObject(value) || Array.isArray(value) || Object.keys(value).length !== 0) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  } else if (category === "PROVIDER_DEFAULTED_CONCRETE") {
    const expected = { memory_size: 128, package_type: "Zip", reserved_concurrent_executions: -1, skip_destroy: false }[field];
    if (value !== expected) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  } else if (category === "PROVIDER_NORMALIZED_CONCRETE") {
    if (field === "region" && value !== STAGE_B.region) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
    if (field === "tags_all" && !exactJson(value, change.change?.after?.tags)) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
    if (!(["region", "tags_all"].includes(field))) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  } else {
    throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.${field}`);
  }
  return true;
}

function assertBrokerPublishProviderMetadataRepresentation(change) {
  assertStageBBrokerPublishProviderMetadataRepresentation(change);
}

export const STAGE_B_BROKER_ENVIRONMENT_VARIABLES = Object.freeze([
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
  if (!variables || typeof variables !== "object" || Array.isArray(variables) || !exactObjectKeys(variables, STAGE_B_BROKER_ENVIRONMENT_VARIABLES)) {
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
  assertStageBLambdaEnvironmentSize(variables);
}

function assertInitialProviderComputedShape(change) {
  let expected = change.address === "aws_iam_policy.broker" ? BROKER_POLICY_INITIAL_PROVIDER_UNKNOWN_PATHS
    : change.address === "aws_lambda_function.broker" ? BROKER_FUNCTION_INITIAL_PROVIDER_UNKNOWN_PATHS
      : change.address === "aws_lambda_alias.reviewed" ? BROKER_ALIAS_INITIAL_PROVIDER_UNKNOWN_PATHS
        : ECS_ADDRESSES.has(change.address) ? ECS_INITIAL_PROVIDER_UNKNOWN_PATHS : null;
  if (!expected) return;
  assertInitialLambdaCreateRepresentation(change);
  assertInitialTypedDefaults(change);
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
    if (truePaths(change.change?.after_unknown).includes("policy")) throw new Error(`UNFAITHFUL_PROVIDER_COMPUTED_FIELDS: ${change.address}.policy`);
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
  if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactJson(change.change?.actions, ["update"])) {
    if (path !== "skip_destroy") throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
    return "REVIEWED_PROVIDER_NORMALIZATION";
  }
  if (path === "container_definitions") return "REVIEWED_CONCRETE_CHANGE";
  if (path === "tags.MSCQRExecTarget" || path === "tags_all.MSCQRExecTarget") {
    if (change.address !== 'aws_ecs_task_definition.candidate["backend"]'
      || !exactReviewedTaskDefinitionTags(change.address, change.change.before.tags, change.change.after.tags)
      || !exactReviewedTaskDefinitionTags(change.address, change.change.before.tags_all, change.change.after.tags_all)
      || !exactJson(change.change.before.tags, change.change.before.tags_all)
      || !exactJson(change.change.after.tags, change.change.after.tags_all)
      || exactJson(change.change.before.tags, change.change.after.tags)) {
      throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
    }
    return "REVIEWED_CONCRETE_CHANGE";
  }
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
  if (change.address === "aws_iam_role_policy.backend_ecs_exec" && ["<root>", "name", "policy", "role"].includes(path)) {
    assertStageBBackendEcsExecPolicyChange(change);
    return "REVIEWED_CONCRETE_CHANGE";
  }
  if (ECS_ADDRESSES.has(change.address)) return classifyEcsChangedPath(change, path);
  if (change.address === "aws_iam_policy.broker" && isBrokerInitialCreate(change)) {
    if (assertInitialRepresentationPath(change, path)) return "REVIEWED_PROVIDER_NORMALIZATION";
    if (BROKER_POLICY_INITIAL_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
  }
  if (change.address === "aws_iam_policy.broker" && BROKER_POLICY_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
  if (change.address === "aws_lambda_function.broker" && isBrokerInitialCreate(change)) {
    if (assertInitialRepresentationPath(change, path)) return "REVIEWED_PROVIDER_NORMALIZATION";
    if (path === BROKER_ENVIRONMENT_PLACEHOLDER_PATH) {
      assertInitialBrokerEnvironment(change);
      return "REVIEWED_COMPUTED_CHANGE";
    }
    if (BROKER_FUNCTION_INITIAL_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
    throw new Error(`UNCLASSIFIED_CHANGED_PATH: ${change.address}.${path}`);
  }
  if (change.address === "aws_lambda_function.broker" && path === "timeout") {
    assertReviewedBrokerTimeoutTransition(change);
    return "REVIEWED_CONCRETE_CHANGE";
  }
  if (change.address === "aws_lambda_function.broker" && BROKER_FUNCTION_CHANGED_PATHS.has(path)) {
    if (path === "source_code_hash") return "CONFIGURATION_BOUND_PACKAGE_DIGEST";
    if (["code_sha256", "source_code_size"].includes(path)) return "PROVIDER_COMPUTED_CODE_METADATA";
    return ["last_modified", "qualified_arn", "qualified_invoke_arn", "version"].includes(path)
      ? "DIAGNOSTIC_ONLY" : "REVIEWED_CONCRETE_CHANGE";
  }
  if (change.address === "aws_lambda_alias.reviewed" && isBrokerInitialCreate(change)) {
    if (assertInitialRepresentationPath(change, path)) return "REVIEWED_PROVIDER_NORMALIZATION";
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
  if (change.address === "aws_iam_role_policy.backend_ecs_exec" && ["id", "name_prefix"].includes(path)) return "DIAGNOSTIC_ONLY";
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
    if (["code_sha256", "source_code_size"].includes(path)) return "PROVIDER_COMPUTED_CODE_METADATA";
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
      : change.address === "aws_lambda_function.broker" ? BROKER_FUNCTION_SENSITIVE_PATHS
        : STATIC_PROFILES.has(change.address) ? new Set() : ALIAS_SENSITIVE_PATHS;
  for (const path of paths) if (!allowed.has(path)) throw new Error(`UNCLASSIFIED_${kind}_SENSITIVE_PATH: ${change.address}.${path}`);
  return paths;
}

function classifyResource(change, { terraformConfiguration, partialApplyRecovery = false, freshImagePartialApplyRecovery = false } = {}) {
  if ((partialApplyRecovery || freshImagePartialApplyRecovery) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) return freshImagePartialApplyRecovery ? STAGE_B_PLAN_SEMANTIC_PROFILES.FRESH_IMAGE_PARTIAL_APPLY_RECOVERY : STAGE_B_PLAN_SEMANTIC_PROFILES.PARTIAL_APPLY_RECOVERY;
  const actions = change?.change?.actions;
  if (ECS_ADDRESSES.has(change?.address) && change.type === "aws_ecs_task_definition" && change.mode === "managed"
    && (change.module === undefined || change.module === null)) {
    if (exactJson(actions, ECS_INITIAL_CREATE_ACTIONS)) return STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_INITIAL_CREATE;
    if (STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS.some((expected) => exactJson(actions, expected))) return STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_REVIEWED_ROLLOVER;
    if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactJson(actions, ["update"])) {
      assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
      return STAGE_B_PLAN_SEMANTIC_PROFILES.IMPORTED_BACKEND_METADATA_NORMALIZATION;
    }
  }
  const profile = BROKER_PROFILES.get(change?.address);
  const brokerProfile = profile?.profiles.find((candidate) => exactJson(actions, candidate.actions));
  if (profile && change.type === profile.type && change.mode === "managed"
    && (change.module === undefined || change.module === null) && brokerProfile) return brokerProfile.classification;
  const staticProfile = STATIC_PROFILES.get(change?.address);
  if (staticProfile && change.type === staticProfile.type && change.mode === "managed"
    && (change.module === undefined || change.module === null) && exactJson(actions, staticProfile.actions)) {
    assertStageBBackendEcsExecPolicyChange(change);
    return staticProfile.classification;
  }
  throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change?.address}`);
}

function assertBrokerActionProfile(plan, { partialApplyRecovery = false, freshImagePartialApplyRecovery = false, terraformConfiguration } = {}) {
  if (freshImagePartialApplyRecovery) {
    assertStageBFreshImagePartialApplyRecoveryPlan(plan, { terraformConfiguration });
    return;
  }
  if (partialApplyRecovery) {
    assertStageBPartialApplyRecoveryPlan(plan);
    return;
  }
  const active = plan.resource_changes.filter((change) => BROKER_ADDRESSES.has(change?.address)
    && !exactJson(change.change?.actions, ["no-op"]));
  if (active.length === 0) return;
  if (plan.variables?.stage_b_recovery_only?.value === true) {
    if (active.length !== 1 || active[0].address !== "aws_lambda_alias.reviewed" || !exactJson(active[0].change?.actions, ["update"])) throw new Error("UNCLASSIFIED_RESOURCE_ACTION: recovery-only mode permits only the reviewed alias update.");
    return;
  }
  if (active.length !== BROKER_ADDRESSES.size || !active.every((change) => exactJson(change.change?.actions, active[0].change.actions))) {
    throw new Error("UNCLASSIFIED_RESOURCE_ACTION: broker initial/update profile is not atomic.");
  }
}

function classifyReplacePaths(change, { terraformConfiguration, partialApplyRecovery = false, freshImagePartialApplyRecovery = false } = {}) {
  const paths = change.change?.replace_paths || [];
  if ((partialApplyRecovery || freshImagePartialApplyRecovery) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)) return [];
  if (isEcsInitialCreate(change) && paths.length === 0) return [];
  if (change.address === STAGE_B_IMPORTED_BACKEND_CANDIDATE_ADDRESS && exactJson(change.change?.actions, ["update"])) {
    assertStageBImportedBackendMetadataNormalization(change, { terraformConfiguration });
    if (paths.length === 0) return [];
  }
  if (ECS_ADDRESSES.has(change.address) && exactJson(paths, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)) {
    return paths.map((path) => ({ path: path.join("."), classification: "REVIEWED_REPLACEMENT_TRIGGER" }));
  }
  if (paths.length === 0 && BROKER_PROFILES.has(change.address)) return [];
  if (paths.length === 0 && STATIC_PROFILES.has(change.address)) return [];
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

export function censusStageBPlanSemantics(plan, options = {}) {
  if (!plan || !Array.isArray(plan.resource_changes)) throw new Error("Stage B semantic census requires Terraform plan resource_changes.");
  for (const change of plan.resource_changes) if (Object.hasOwn(change, "deposed")) stageBMutationInstanceIdentity(change);
  const recoveryMode = resolveStageBRecoveryMode(options);
  options = { ...options, partialApplyRecovery: recoveryMode === "PARTIAL_APPLY_RECOVERY", freshImagePartialApplyRecovery: recoveryMode === "FRESH_IMAGE_PARTIAL_APPLY_RECOVERY" };
  const manifest = assertStageBTypedRepresentationManifestComplete();
  assertStageBProviderResourceShapeUniverse();
  assertStageBProviderSemanticSnapshot();
  const staticConfiguration = assertStageBStaticConfigurationCoverage(plan, options);
  const { attributes: staticConfigurationAttributes, ...staticConfigurationCounts } = staticConfiguration;
  assertBrokerActionProfile(plan, options);
  const resources = [];
  const seenAddresses = new Set();
  for (const change of plan.resource_changes) {
    const actions = change?.change?.actions || [];
    if (exactJson(actions, ["no-op"]) || actions.length === 0) continue;
    const deposedCleanup = isStageBPartialApplyDeposedTaskDefinitionCleanup(change);
    if (!deposedCleanup || !(options.partialApplyRecovery || options.freshImagePartialApplyRecovery)) {
      if (seenAddresses.has(change.address)) throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change.address}`);
      seenAddresses.add(change.address);
    }
    const classification = classifyResource(change, options);
    assertTypedRepresentationEnvelope(change);
    assertBrokerPublishProviderMetadataRepresentation(change);
    if (change.address === "aws_lambda_function.broker" && exactJson(change.change?.actions, ["update"])) {
      const changedFields = [...new Set([...Object.keys(change.change?.before || {}), ...Object.keys(change.change?.after || {})])]
        .filter((key) => !exactJson(change.change?.before?.[key], change.change?.after?.[key]));
      if (changedFields.includes("timeout")) assertReviewedBrokerTimeoutTransition(change);
    }
    if (ECS_ADDRESSES.has(change.address) && !((options.partialApplyRecovery || options.freshImagePartialApplyRecovery) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change))) assertEcsSemanticDomain(change);
    assertInitialBrokerEnvironment(change);
    if (isBrokerInitialCreate(change) || isEcsInitialCreate(change)) assertInitialProviderComputedShape(change);
    const changedPaths = (options.partialApplyRecovery || options.freshImagePartialApplyRecovery) && isStageBPartialApplyDeposedTaskDefinitionCleanup(change)
      ? []
      : diffPaths(change.change?.before, change.change?.after).filter(Boolean).map((path) => ({ path, classification: assertClass(classifyChangedPath(change, path), "CHANGED_PATH") }));
    const afterUnknownPaths = truePaths(change.change?.after_unknown).filter(Boolean).map((path) => ({ path, classification: assertClass(classifyUnknownPath(change, path), "AFTER_UNKNOWN") }));
    const beforeSensitivePaths = assertSensitivePaths(change, "BEFORE", truePaths(change.change?.before_sensitive));
    const afterSensitivePaths = assertSensitivePaths(change, "AFTER", truePaths(change.change?.after_sensitive));
    const replacePaths = classifyReplacePaths(change, options);
    const configurationReferences = collectConfigurationReferences(plan, change.address);
    resources.push({
      address: change.address,
      mutationInstanceIdentity: stageBMutationInstanceIdentity(change, classification),
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
  if (resources.some(({ classification }) => classification === STAGE_B_PLAN_SEMANTIC_PROFILES.IMPORTED_BACKEND_METADATA_NORMALIZATION)
    && resources.some(({ classification }) => classification === STAGE_B_PLAN_SEMANTIC_PROFILES.ECS_REVIEWED_ROLLOVER)) {
    assertStageBImportedBackendRolloverActions(plan.resource_changes);
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
    unmodeledTypedAfterFields: 0,
    unmodeledAfterUnknownMarkers: 0,
    unmodeledEmptyStructures: 0,
    ...staticConfigurationCounts,
    ...manifest,
  };
  return { schemaVersion: 1, resources, staticConfigurationAttributes, counts };
}

export function assertStageBPlanSemanticCompleteness(plan, options = {}) {
  const census = censusStageBPlanSemantics(plan, options);
  if (Object.entries(census.counts).some(([key, value]) => (key.startsWith("unclassified") || key.startsWith("unfaithful") || key.startsWith("unmodeled")) && value !== 0)) {
    throw new Error("Stage B plan semantic completeness contains unclassified semantics.");
  }
  return census;
}

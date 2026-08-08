const PROVIDER_SOURCE = "registry.terraform.io/hashicorp/aws";
const PROVIDER_VERSION = "6.56.0";

const attribute = (attributePath, flags, nestingMode = null) => Object.freeze({
  attributePath,
  required: Boolean(flags.required),
  optional: Boolean(flags.optional),
  computed: Boolean(flags.computed),
  sensitive: Boolean(flags.sensitive),
  nestingMode,
});

const block = (blockPath, nestingMode, attributes, limits = {}) => Object.freeze({
  blockPath,
  nestingMode,
  minItems: limits.minItems ?? null,
  maxItems: limits.maxItems ?? null,
  attributes: Object.freeze(attributes),
});

const resource = (resourceType, attributes, blocks = []) => Object.freeze({
  resourceType,
  attributes: Object.freeze(attributes),
  blocks: Object.freeze(blocks),
});

export const STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT = Object.freeze({
  providerSource: PROVIDER_SOURCE,
  providerVersion: PROVIDER_VERSION,
  terraformSchemaCommand: "terraform providers schema -json",
  terraformSchemaJsonSha256: "0d4948a8af7ecbba0655f9b5b4f4f339eb70c4c9c98117a9079c68ecd4620fb1",
  providerBinarySha256: "9a5d52a253efb9c223e2f709749ed8b6db0d6e8b5710e6eabfed8de7b2a159fd",
  resources: Object.freeze({
    aws_iam_policy: resource("aws_iam_policy", [
      attribute("arn", { computed: true }), attribute("attachment_count", { computed: true }),
      attribute("description", { optional: true }), attribute("id", { optional: true, computed: true }),
      attribute("name", { optional: true, computed: true }), attribute("name_prefix", { optional: true, computed: true }),
      attribute("path", { optional: true }), attribute("policy", { required: true }),
      attribute("policy_id", { computed: true }), attribute("tags", { optional: true }),
      attribute("tags_all", { optional: true, computed: true }),
    ]),
    aws_lambda_function: resource("aws_lambda_function", [
      attribute("architectures", { optional: true, computed: true }), attribute("arn", { computed: true }),
      attribute("code_sha256", { optional: true, computed: true }), attribute("filename", { optional: true }),
      attribute("function_name", { required: true }), attribute("handler", { optional: true }),
      attribute("id", { optional: true, computed: true }), attribute("invoke_arn", { computed: true }),
      attribute("last_modified", { computed: true }), attribute("memory_size", { optional: true }),
      attribute("package_type", { optional: true }), attribute("publish", { optional: true }),
      attribute("qualified_arn", { computed: true }), attribute("qualified_invoke_arn", { computed: true }),
      attribute("region", { optional: true, computed: true }), attribute("response_streaming_invoke_arn", { computed: true }),
      attribute("role", { required: true }), attribute("runtime", { optional: true }),
      attribute("signing_job_arn", { computed: true }), attribute("signing_profile_version_arn", { computed: true }),
      attribute("source_code_hash", { optional: true, computed: true }), attribute("source_code_size", { computed: true }),
      attribute("tags", { optional: true }), attribute("tags_all", { optional: true, computed: true }),
      attribute("timeout", { optional: true }), attribute("version", { computed: true }),
    ], [
      block("environment", "list", [attribute("environment[].variables", { optional: true })], { maxItems: 1 }),
    ]),
    aws_lambda_alias: resource("aws_lambda_alias", [
      attribute("arn", { computed: true }), attribute("description", { optional: true }),
      attribute("function_name", { required: true }), attribute("function_version", { required: true }),
      attribute("id", { optional: true, computed: true }), attribute("invoke_arn", { computed: true }),
      attribute("name", { required: true }), attribute("region", { optional: true, computed: true }),
    ], [
      block("routing_config", "list", [attribute("routing_config[].additional_version_weights", { optional: true })], { maxItems: 1 }),
    ]),
    aws_ecs_task_definition: resource("aws_ecs_task_definition", [
      attribute("arn", { computed: true }), attribute("arn_without_revision", { computed: true }),
      attribute("container_definitions", { required: true }), attribute("cpu", { optional: true }),
      attribute("enable_fault_injection", { optional: true, computed: true }), attribute("execution_role_arn", { optional: true }),
      attribute("family", { required: true }), attribute("id", { optional: true, computed: true }),
      attribute("ipc_mode", { optional: true }), attribute("memory", { optional: true }),
      attribute("network_mode", { optional: true, computed: true }), attribute("pid_mode", { optional: true }),
      attribute("region", { optional: true, computed: true }), attribute("requires_compatibilities", { optional: true }),
      attribute("revision", { computed: true }), attribute("skip_destroy", { optional: true }),
      attribute("tags", { optional: true }), attribute("tags_all", { optional: true, computed: true }),
      attribute("task_role_arn", { optional: true }), attribute("track_latest", { optional: true }),
    ], [
      block("ephemeral_storage", "list", [attribute("ephemeral_storage[].size_in_gib", { required: true })], { maxItems: 1 }),
      block("placement_constraints", "set", [attribute("placement_constraints[].expression", { optional: true }), attribute("placement_constraints[].type", { required: true })], { maxItems: 10 }),
      block("proxy_configuration", "list", [attribute("proxy_configuration[].container_name", { required: true }), attribute("proxy_configuration[].properties", { optional: true }), attribute("proxy_configuration[].type", { optional: true })], { maxItems: 1 }),
      block("runtime_platform", "list", [attribute("runtime_platform[].cpu_architecture", { optional: true }), attribute("runtime_platform[].operating_system_family", { optional: true })], { maxItems: 1 }),
      block("volume", "set", [attribute("volume[].configure_at_launch", { optional: true, computed: true }), attribute("volume[].host_path", { optional: true }), attribute("volume[].name", { required: true })]),
      block("volume[].docker_volume_configuration", "list", [attribute("volume[].docker_volume_configuration[].autoprovision", { optional: true }), attribute("volume[].docker_volume_configuration[].driver", { optional: true, computed: true }), attribute("volume[].docker_volume_configuration[].driver_opts", { optional: true }), attribute("volume[].docker_volume_configuration[].labels", { optional: true }), attribute("volume[].docker_volume_configuration[].scope", { optional: true, computed: true })], { maxItems: 1 }),
      block("volume[].efs_volume_configuration", "list", [attribute("volume[].efs_volume_configuration[].file_system_id", { required: true }), attribute("volume[].efs_volume_configuration[].root_directory", { optional: true }), attribute("volume[].efs_volume_configuration[].transit_encryption", { optional: true }), attribute("volume[].efs_volume_configuration[].transit_encryption_port", { optional: true })], { maxItems: 1 }),
      block("volume[].fsx_windows_file_server_volume_configuration", "list", [attribute("volume[].fsx_windows_file_server_volume_configuration[].file_system_id", { required: true }), attribute("volume[].fsx_windows_file_server_volume_configuration[].root_directory", { required: true })], { maxItems: 1 }),
      block("volume[].s3files_volume_configuration", "list", [attribute("volume[].s3files_volume_configuration[].access_point_arn", { optional: true }), attribute("volume[].s3files_volume_configuration[].file_system_arn", { required: true }), attribute("volume[].s3files_volume_configuration[].root_directory", { optional: true }), attribute("volume[].s3files_volume_configuration[].transit_encryption_port", { optional: true })], { maxItems: 1 }),
    ]),
  }),
});

export const STAGE_B_PROVIDER_RESOURCE_TYPES = Object.freeze([
  "aws_iam_policy", "aws_lambda_function", "aws_lambda_alias", "aws_ecs_task_definition",
]);

const EXPECTED_ATTRIBUTE_FLAGS = Object.freeze({
  aws_iam_policy: Object.freeze({
    arn: [false, false, true], attachment_count: [false, false, true], id: [false, true, true], name: [false, true, true],
    path: [false, true, false], policy: [true, false, false], policy_id: [false, false, true], tags: [false, true, false], tags_all: [false, true, true],
  }),
  aws_lambda_function: Object.freeze({
    architectures: [false, true, true], arn: [false, false, true], code_sha256: [false, true, true], filename: [false, true, false],
    function_name: [true, false, false], handler: [false, true, false], id: [false, true, true], invoke_arn: [false, false, true],
    last_modified: [false, false, true], publish: [false, true, false], qualified_arn: [false, false, true], qualified_invoke_arn: [false, false, true],
    region: [false, true, true], response_streaming_invoke_arn: [false, false, true], role: [true, false, false], runtime: [false, true, false],
    signing_job_arn: [false, false, true], signing_profile_version_arn: [false, false, true], source_code_hash: [false, true, true], source_code_size: [false, false, true],
    tags: [false, true, false], tags_all: [false, true, true], timeout: [false, true, false], version: [false, false, true],
  }),
  aws_lambda_alias: Object.freeze({
    arn: [false, false, true], function_name: [true, false, false], function_version: [true, false, false], id: [false, true, true],
    invoke_arn: [false, false, true], name: [true, false, false], region: [false, true, true],
  }),
  aws_ecs_task_definition: Object.freeze({
    arn: [false, false, true], arn_without_revision: [false, false, true], container_definitions: [true, false, false], cpu: [false, true, false],
    enable_fault_injection: [false, true, true], execution_role_arn: [false, true, false], family: [true, false, false], id: [false, true, true],
    ipc_mode: [false, true, false], memory: [false, true, false], network_mode: [false, true, true], pid_mode: [false, true, false],
    region: [false, true, true], requires_compatibilities: [false, true, false], revision: [false, false, true], skip_destroy: [false, true, false],
    tags: [false, true, false], tags_all: [false, true, true], task_role_arn: [false, true, false], track_latest: [false, true, false],
  }),
});
const EXPECTED_BLOCK_ATTRIBUTE_FLAGS = Object.freeze({
  aws_lambda_function: Object.freeze({ "environment[].variables": [false, true, false] }),
  aws_lambda_alias: Object.freeze({ "routing_config[].additional_version_weights": [false, true, false] }),
  aws_ecs_task_definition: Object.freeze({
    "ephemeral_storage[].size_in_gib": [true, false, false],
    "placement_constraints[].expression": [false, true, false],
    "placement_constraints[].type": [true, false, false],
    "runtime_platform[].cpu_architecture": [false, true, false],
    "runtime_platform[].operating_system_family": [false, true, false],
    "volume[].configure_at_launch": [false, true, true],
    "volume[].host_path": [false, true, false],
    "volume[].name": [true, false, false],
    "volume[].docker_volume_configuration[].driver": [false, true, true],
    "volume[].docker_volume_configuration[].scope": [false, true, true],
    "volume[].efs_volume_configuration[].file_system_id": [true, false, false],
  }),
});
const EXPECTED_BLOCK_SEMANTICS = Object.freeze({
  aws_lambda_function: Object.freeze({ environment: ["list", null, 1] }),
  aws_lambda_alias: Object.freeze({ routing_config: ["list", null, 1] }),
  aws_ecs_task_definition: Object.freeze({
    ephemeral_storage: ["list", null, 1],
    placement_constraints: ["set", null, 10],
    proxy_configuration: ["list", null, 1],
    runtime_platform: ["list", null, 1],
    volume: ["set", null, null],
    "volume[].docker_volume_configuration": ["list", null, 1],
    "volume[].efs_volume_configuration": ["list", null, 1],
    "volume[].fsx_windows_file_server_volume_configuration": ["list", null, 1],
    "volume[].s3files_volume_configuration": ["list", null, 1],
  }),
});

export function assertStageBProviderSemanticSnapshot(snapshot = STAGE_B_PROVIDER_SEMANTIC_SNAPSHOT) {
  if (snapshot.providerSource !== PROVIDER_SOURCE || snapshot.providerVersion !== PROVIDER_VERSION) {
    throw new Error("PROVIDER_SCHEMA_VERSION_MISMATCH");
  }
  for (const type of STAGE_B_PROVIDER_RESOURCE_TYPES) {
    const schema = snapshot.resources?.[type];
    if (!schema || schema.resourceType !== type || schema.attributes.length === 0) throw new Error(`MISSING_PROVIDER_SCHEMA_ENTRY: ${type}`);
    const paths = [...schema.attributes.map((entry) => entry.attributePath), ...schema.blocks.flatMap((entry) => entry.attributes.map((attributeEntry) => attributeEntry.attributePath))];
    if (new Set(paths).size !== paths.length || schema.attributes.some((entry) => typeof entry.required !== "boolean" || typeof entry.optional !== "boolean" || typeof entry.computed !== "boolean" || typeof entry.sensitive !== "boolean")) throw new Error(`INVALID_PROVIDER_SCHEMA_SNAPSHOT: ${type}`);
    const actual = new Map(schema.attributes.map((entry) => [entry.attributePath, entry]));
    for (const [attributePath, [required, optional, computed]] of Object.entries(EXPECTED_ATTRIBUTE_FLAGS[type])) {
      const entry = actual.get(attributePath);
      if (!entry || entry.required !== required || entry.optional !== optional || entry.computed !== computed || entry.sensitive !== false || entry.nestingMode !== null) throw new Error(`PROVIDER_SCHEMA_SEMANTICS_CHANGED: ${type}.${attributePath}`);
    }
    const nested = new Map(schema.blocks.flatMap((entry) => entry.attributes.map((attributeEntry) => [attributeEntry.attributePath, attributeEntry])));
    for (const [blockPath, [nestingMode, minItems, maxItems]] of Object.entries(EXPECTED_BLOCK_SEMANTICS[type] || {})) {
      const entry = schema.blocks.find((candidate) => candidate.blockPath === blockPath);
      if (!entry || entry.nestingMode !== nestingMode || entry.minItems !== minItems || entry.maxItems !== maxItems) {
        throw new Error(`PROVIDER_SCHEMA_NESTING_CHANGED: ${type}.${blockPath}`);
      }
    }
    for (const [attributePath, [required, optional, computed]] of Object.entries(EXPECTED_BLOCK_ATTRIBUTE_FLAGS[type] || {})) {
      const entry = nested.get(attributePath);
      if (!entry || entry.required !== required || entry.optional !== optional || entry.computed !== computed || entry.sensitive !== false || entry.nestingMode !== null) throw new Error(`PROVIDER_SCHEMA_SEMANTICS_CHANGED: ${type}.${attributePath}`);
    }
  }
  return snapshot;
}

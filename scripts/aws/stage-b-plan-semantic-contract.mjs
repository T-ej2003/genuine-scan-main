import {
  canonicalizeEcsTaskDefinitionVolumes,
  STAGE_B_TASK_DEFINITION_FAMILIES,
  STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS,
  STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS,
} from "./stage-b-reference-audit-contract.mjs";

export const STAGE_B_PLAN_SEMANTIC_CLASSES = Object.freeze([
  "STABLE_REQUIRED",
  "REVIEWED_CONCRETE_CHANGE",
  "REVIEWED_COMPUTED_CHANGE",
  "REVIEWED_PROVIDER_NORMALIZATION",
  "REVIEWED_REPLACEMENT_TRIGGER",
  "DIAGNOSTIC_ONLY",
]);

export const STAGE_B_PLAN_SEMANTIC_PROFILES = Object.freeze({
  ECS_INITIAL_CREATE: "ECS_INITIAL_CREATE",
  ECS_REVIEWED_ROLLOVER: "ECS_REVIEWED_ROLLOVER",
});

const ECS_ADDRESSES = new Set(Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES));
const ECS_INITIAL_CREATE_ACTIONS = ["create"];
const ECS_INITIAL_CREATE_PATHS = new Set([
  "container_definitions", "cpu", "enable_fault_injection", "ephemeral_storage",
  "execution_role_arn", "family", "ipc_mode", "memory", "network_mode", "pid_mode",
  "placement_constraints", "proxy_configuration", "region", "requires_compatibilities",
  "requires_compatibilities[0]", "runtime_platform", "runtime_platform.operating_system_family",
  "runtime_platform.cpu_architecture", "skip_destroy", "task_role_arn", "track_latest",
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
  ["aws_iam_policy.broker", { actions: [["update"]], classification: "BROKER_POLICY_UPDATE" }],
  ["aws_lambda_function.broker", { actions: [["update"]], classification: "BROKER_FUNCTION_PUBLISH_UPDATE" }],
  ["aws_lambda_alias.reviewed", { actions: [["update"]], classification: "REVIEWED_RECOVERY_ALIAS_UPDATE" }],
]);
const ECS_METADATA_PATHS = new Set(["arn", "arn_without_revision", "enable_fault_injection", "id", "revision"]);
const ECS_UNKNOWN_PATHS = new Set([...ECS_METADATA_PATHS, "volume[0].configure_at_launch"]);
const ECS_SENSITIVE_PATHS = new Set(["requires_compatibilities[0]"]);
const BROKER_POLICY_CHANGED_PATHS = new Set(["policy"]);
const BROKER_POLICY_UNKNOWN_PATHS = new Set(["policy"]);
const BROKER_FUNCTION_CHANGED_PATHS = new Set([
  "environment[0].variables",
  "filename",
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

function assertInitialEcsSemanticDomain(change) {
  const after = change.change?.after || {};
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
  if (change.address === "aws_iam_policy.broker" && BROKER_POLICY_CHANGED_PATHS.has(path)) return "REVIEWED_CONCRETE_CHANGE";
  if (change.address === "aws_lambda_function.broker" && BROKER_FUNCTION_CHANGED_PATHS.has(path)) {
    return ["last_modified", "qualified_arn", "qualified_invoke_arn", "version"].includes(path)
      ? "DIAGNOSTIC_ONLY" : "REVIEWED_CONCRETE_CHANGE";
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
  if (change.address === "aws_iam_policy.broker" && BROKER_POLICY_UNKNOWN_PATHS.has(path)) return "REVIEWED_COMPUTED_CHANGE";
  if (change.address === "aws_lambda_function.broker" && BROKER_FUNCTION_UNKNOWN_PATHS.has(path)) {
    return ["environment[0].variables", "version"].includes(path) ? "REVIEWED_COMPUTED_CHANGE" : "DIAGNOSTIC_ONLY";
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
  if (profile && change.type === ({
    "aws_iam_policy.broker": "aws_iam_policy",
    "aws_lambda_function.broker": "aws_lambda_function",
    "aws_lambda_alias.reviewed": "aws_lambda_alias",
  })[change.address] && exactJson(actions, profile.actions[0])) return profile.classification;
  throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change?.address}`);
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
  if (alias?.change?.after_unknown?.function_version !== true) return;
  if (alias.change.after?.function_version !== undefined && alias.change.after?.function_version !== null) {
    throw new Error("UNCLASSIFIED_COMPUTED_CHANGE: aws_lambda_alias.reviewed.function_version");
  }
  const brokerChanges = plan.resource_changes.filter((change) => change?.address === "aws_lambda_function.broker");
  if (brokerChanges.length !== 1 || !exactJson(brokerChanges[0].change?.actions, ["update"])) {
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
  const resources = [];
  const seenAddresses = new Set();
  for (const change of plan.resource_changes) {
    const actions = change?.change?.actions || [];
    if (exactJson(actions, ["no-op"]) || actions.length === 0) continue;
    if (seenAddresses.has(change.address)) throw new Error(`UNCLASSIFIED_RESOURCE_ACTION: ${change.address}`);
    seenAddresses.add(change.address);
    const classification = classifyResource(change);
    if (ECS_ADDRESSES.has(change.address)) assertEcsSemanticDomain(change);
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

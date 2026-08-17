import crypto from "node:crypto";
import fs from "node:fs";
import { STAGE_B_MODES } from "./production-green-stage-b-contract.mjs";
import { assertStageBDeploymentEvidenceFreshness, STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS, STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS, STAGE_B_DEPLOYMENT_EVIDENCE_VALIDITY_MODEL } from "./stage-b-evidence-freshness.mjs";
import { ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";
import { STAGE_B_BACKEND_PORT_MAPPING } from "./production-green-stage-b-task-definitions.mjs";

export const STAGE_B_TASK_DEFINITION_FAMILIES = Object.freeze({
  'aws_ecs_task_definition.candidate["backend"]': "mscqr-production-rls-green-backend-candidate",
  'aws_ecs_task_definition.candidate["worker"]': "mscqr-production-rls-green-worker-candidate",
  'aws_ecs_task_definition.candidate["canary"]': "mscqr-production-full-rls-green-application-canary",
  'aws_ecs_task_definition.candidate["read_only_canary"]': "mscqr-production-full-rls-green-read-only-canary",
  'aws_ecs_task_definition.executor["full-rls-admin-bootstrap"]': "mscqr-production-full-rls-green-full-rls-admin-bootstrap",
  'aws_ecs_task_definition.executor["full-rls-admin-ownership"]': "mscqr-production-full-rls-green-full-rls-admin-ownership",
  'aws_ecs_task_definition.executor["full-rls-capability-preflight"]': "mscqr-production-full-rls-green-full-rls-capability-preflight",
  'aws_ecs_task_definition.executor["full-rls-role-provision"]': "mscqr-production-full-rls-green-full-rls-role-provision",
  'aws_ecs_task_definition.executor["full-rls-role-verify"]': "mscqr-production-full-rls-green-full-rls-role-verify",
  'aws_ecs_task_definition.executor["full-rls-rollback"]': "mscqr-production-full-rls-green-full-rls-rollback",
  'aws_ecs_task_definition.executor["full-rls-runtime-policy"]': "mscqr-production-full-rls-green-full-rls-runtime-policy",
  'aws_ecs_task_definition.executor["full-rls-verification"]': "mscqr-production-full-rls-green-full-rls-verification",
});

export const STAGE_B_TASK_DEFINITION_FAMILY_NAMES = Object.freeze(
  [...new Set(Object.values(STAGE_B_TASK_DEFINITION_FAMILIES))].sort(),
);

export const STAGE_B_REFERENCE_AUDIT_SCHEMA_VERSION = 1;
export const STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS = STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS;
export const STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS = STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS;
export const STAGE_B_REFERENCE_AUDIT_VALIDITY_MODEL = STAGE_B_DEPLOYMENT_EVIDENCE_VALIDITY_MODEL;
export const STAGE_B_BROKER_TERRAFORM_ADDRESS = "aws_lambda_function.broker";
export const STAGE_B_BROKER_TASK_DEFINITION_REFERENCE = "local.active_broker_task_definition_arns";
export const STAGE_B_ACTIVE_BROKER_TASK_DEFINITION_LOCAL_EXPRESSION = "var.stage_b_recovery_only ? var.stage_b_recovery_task_definition_arns : local.broker_task_definition_arns";
export const STAGE_B_BROKER_APPROVAL_REFERENCE = "local.broker_approval_expected";
export const STAGE_B_BROKER_APPROVAL_INPUT = "var.package_checksum_sha256";
export const STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION = "aws_ecs_task_definition.executor";
export const STAGE_B_CANDIDATE_FOR_EACH_REFERENCES = Object.freeze([
  "local.candidate_definitions_for_resources",
]);
export const STAGE_B_EXECUTOR_FOR_EACH_REFERENCES = Object.freeze([
  "local.executor_definitions_for_resources",
]);
const currentTaskDefinitionArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/([^:]+):([1-9][0-9]*)$/;

const canonicalBrokerFamily = (mode) => mode === "full-rls-application-canary"
  ? STAGE_B_TASK_DEFINITION_FAMILIES['aws_ecs_task_definition.candidate["canary"]']
  : `mscqr-production-full-rls-green-${mode}`;
const sortStrings = (values) => [...values].sort();
const sameStringSet = (left, right) => JSON.stringify(sortStrings(left)) === JSON.stringify(sortStrings(right));

function assertCurrentPredecessorReferences({ address, entry, observed }) {
  for (const [field, kind] of [["serviceReferences", "services"], ["runningTaskReferences", "runningTasks"], ["pendingTaskReferences", "pendingTasks"]]) {
    const value = entry[field];
    if (!Array.isArray(value)) throw new Error(`Stage B ${field} is malformed: ${address}`);
    if (!value.every((reference) => typeof reference === "string" && reference.length > 0) || !sameStringSet(observed[kind], value)) {
      throw new Error(`Stage B ${field} does not match authoritative runtime observations: ${address}`);
    }
  }
  if (entry.transitionalTaskReferences !== undefined
    && (!Array.isArray(entry.transitionalTaskReferences) || !sameStringSet(observed.transitionalTasks, entry.transitionalTaskReferences))) {
    throw new Error(`Stage B transitional task references do not match authoritative runtime observations: ${address}`);
  }
  if (Object.values(observed).some((references) => references.length > 0)) {
    throw new Error(`Stage B current predecessor has a live or transitional runtime reference: ${address}`);
  }
}

function normalizeEcsReferences(audit) {
  const referenceSets = [
    ["services", audit.services, "taskDefinition", "serviceName"],
    ["runningTasks", audit.runningTasks, "taskDefinitionArn", "taskArn"],
    ["pendingTasks", audit.pendingTasks, "taskDefinitionArn", "taskArn"],
    ["transitionalTasks", audit.transitionalTasks, "taskDefinitionArn", "taskArn"],
  ];
  const byArn = new Map();
  for (const [kind, items, arnKey, referenceKey] of referenceSets) {
    if (!Array.isArray(items)) throw new Error(`Stage B ${kind} observations are missing.`);
    for (const item of items) {
      if (!item || typeof item[arnKey] !== "string" || !currentTaskDefinitionArnPattern.test(item[arnKey]) || typeof item[referenceKey] !== "string" || item[referenceKey].length === 0) {
        throw new Error(`Stage B ${kind} observation is malformed.`);
      }
      const references = byArn.get(item[arnKey]) || { services: [], runningTasks: [], pendingTasks: [], transitionalTasks: [] };
      if (references[kind].includes(item[referenceKey])) throw new Error(`Stage B ${kind} observation is duplicated.`);
      references[kind].push(item[referenceKey]);
      byArn.set(item[arnKey], references);
    }
  }
  for (const references of byArn.values()) {
    for (const key of Object.keys(references)) references[key].sort();
  }
  return byArn;
}

export function normalizeStageBFreshImageRuntimeModel({ plan, audit } = {}) {
  if (!plan || typeof plan !== "object" || !audit || typeof audit !== "object") throw new Error("Stage B fresh-image runtime model inputs are missing.");
  const currentPlanReplacements = (plan.resource_changes || [])
    .filter((change) => change?.type === "aws_ecs_task_definition" && Object.hasOwn(STAGE_B_TASK_DEFINITION_FAMILIES, change.address) && !Object.hasOwn(change, "deposed"))
    .map((change) => {
      const beforeArn = change.change?.before?.arn || change.change?.before?.id;
      const family = STAGE_B_TASK_DEFINITION_FAMILIES[change.address];
      if (!currentTaskDefinitionArnPattern.test(beforeArn || "") || !Array.isArray(change.change?.actions)) throw new Error(`Stage B current replacement is malformed: ${change.address}`);
      return { address: change.address, family, beforeArn, actions: [...change.change.actions] };
    });
  if (new Set(currentPlanReplacements.map((change) => change.address)).size !== currentPlanReplacements.length || new Set(currentPlanReplacements.map((change) => change.beforeArn)).size !== currentPlanReplacements.length) {
    throw new Error("Stage B current replacement identities are duplicated.");
  }
  const referencesByTaskDefinitionArn = normalizeEcsReferences(audit);
  const liveMappings = audit.broker?.liveTaskDefinitionMappings;
  if (!Array.isArray(liveMappings)) throw new Error("Stage B broker live mappings are missing.");
  const observedMappingsByMode = new Map();
  for (const mapping of liveMappings) {
    if (!mapping || !STAGE_B_MODES.includes(mapping.mode) || typeof mapping.taskDefinitionArn !== "string" || !currentTaskDefinitionArnPattern.test(mapping.taskDefinitionArn) || observedMappingsByMode.has(mapping.mode)) throw new Error("Stage B broker live mappings are missing, unknown, or duplicated.");
    const family = currentTaskDefinitionArnPattern.exec(mapping.taskDefinitionArn)[1];
    if (family !== canonicalBrokerFamily(mapping.mode)) throw new Error(`Stage B broker live mapping family is wrong: ${mapping.mode}`);
    observedMappingsByMode.set(mapping.mode, { mode: mapping.mode, taskDefinitionArn: mapping.taskDefinitionArn, family });
  }
  if (!sameStringSet([...observedMappingsByMode.keys()], STAGE_B_MODES)) throw new Error("Stage B broker live mappings do not cover the canonical mode set.");
  const currentByFamily = new Map();
  for (const change of currentPlanReplacements) currentByFamily.set(change.family, [...(currentByFamily.get(change.family) || []), change]);
  const currentRolloverModes = STAGE_B_MODES.map((mode) => {
    const family = canonicalBrokerFamily(mode);
    const candidates = currentByFamily.get(family) || [];
    if (candidates.length !== 1) throw new Error(`Stage B canonical broker mode does not bind to exactly one current plan replacement: ${mode}`);
    const mapping = observedMappingsByMode.get(mode);
    if (mapping.taskDefinitionArn !== candidates[0].beforeArn) throw new Error(`Stage B canonical broker mapping does not match its authenticated plan predecessor: ${mode}`);
    return { ...mapping, ...candidates[0] };
  });
  const deposedCleanups = (plan.resource_changes || []).filter((change) => change?.type === "aws_ecs_task_definition" && Object.hasOwn(change, "deposed"));
  return {
    currentPlanReplacements,
    deposedCleanups,
    ecs: {
      services: audit.services,
      runningTasks: audit.runningTasks,
      pendingTasks: audit.pendingTasks,
      transitionalTasks: audit.transitionalTasks,
      referencesByTaskDefinitionArn,
    },
    broker: { canonicalRequiredModes: [...STAGE_B_MODES], observedMappingsByMode, currentRolloverModes },
  };
}

export const STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS = Object.freeze([
  Object.freeze(["create", "delete"]),
  Object.freeze(["delete", "create"]),
]);
export const STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS = Object.freeze([["container_definitions"]]);

const rotationMutableEnvironment = Object.freeze(new Map([
  ["RELEASE_GIT_SHA", "image_release_sha"],
  ["MSCQR_FULL_RLS_SOURCE_CONTRACT_SHA256", "source_contract_sha256"],
  ["MSCQR_FULL_RLS_MIGRATION_SET_DIGEST", "migration_set_digest"],
  ["MSCQR_FULL_RLS_PACKAGE_CHECKSUM_SHA256", "package_checksum_sha256"],
]));
export const STAGE_B_TASK_DEFINITION_ROTATION_IMMUTABLE_FIELDS = Object.freeze([
  "family", "network_mode", "requires_compatibilities", "cpu", "memory",
  "execution_role_arn", "task_role_arn", "runtime_platform", "volume", "ipc_mode", "pid_mode", "tags",
]);
const rotationStableFields = STAGE_B_TASK_DEFINITION_ROTATION_IMMUTABLE_FIELDS;
const backendTaskDefinitionAddress = 'aws_ecs_task_definition.candidate["backend"]';
export const STAGE_B_IMPORTED_BACKEND_ROLLOVER_ADDRESSES = Object.freeze(
  Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES).filter((address) => address !== backendTaskDefinitionAddress),
);
export const STAGE_B_IMPORTED_BACKEND_ROLLOVER_ACTIONS = Object.freeze(["create", "delete"]);
const baseTaskDefinitionTags = Object.freeze({ Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform" });
const backendTaskDefinitionTags = Object.freeze({ ...baseTaskDefinitionTags, [ECS_EXEC_OPERATOR_TASK_TAG_KEY]: ECS_EXEC_OPERATOR_TASK_TAG_VALUE });

const exactActions = (actual, expected) => JSON.stringify(actual) === JSON.stringify(expected);
const isRotationActions = (actions) => STAGE_B_TASK_DEFINITION_ROTATION_ACTIONS.some((expected) => exactActions(actions, expected));
export function assertStageBImportedBackendRolloverActions(resourceChanges) {
  if (!Array.isArray(resourceChanges)) throw new Error("Stage B imported-backend normalization requires resource changes.");
  const changesByAddress = new Map();
  for (const change of resourceChanges) {
    if (!STAGE_B_IMPORTED_BACKEND_ROLLOVER_ADDRESSES.includes(change?.address)) continue;
    if (changesByAddress.has(change.address)) throw new Error(`Stage B imported-backend rollover membership is duplicated: ${change.address}`);
    changesByAddress.set(change.address, change);
  }
  if (changesByAddress.size !== STAGE_B_IMPORTED_BACKEND_ROLLOVER_ADDRESSES.length) throw new Error("Stage B imported-backend rollover membership is incomplete.");
  for (const address of STAGE_B_IMPORTED_BACKEND_ROLLOVER_ADDRESSES) {
    if (!exactActions(changesByAddress.get(address)?.change?.actions, STAGE_B_IMPORTED_BACKEND_ROLLOVER_ACTIONS)) {
      throw new Error(`Stage B imported-backend rollover ${address} must use exact create-before-delete actions.`);
    }
  }
  return true;
}
const parsedTaskDefinitionValue = (value) => {
  if (typeof value !== "string") return value;
  try { return JSON.parse(value); } catch { return value; }
};
const stableTaskDefinitionValue = (value) => {
  if (Array.isArray(value)) return value.map(stableTaskDefinitionValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => !["arn", "id", "revision", "status", "registered_at", "registeredAt"].includes(key))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => [key, stableTaskDefinitionValue(item)]));
};
const ecsTaskDefinitionVolumeKeys = new Set([
  "configure_at_launch", "docker_volume_configuration", "efs_volume_configuration",
  "fsx_windows_file_server_volume_configuration", "host_path", "name", "s3files_volume_configuration",
]);
const ecsTaskDefinitionNestedVolumeKeys = Object.freeze([
  "docker_volume_configuration", "efs_volume_configuration",
  "fsx_windows_file_server_volume_configuration", "s3files_volume_configuration",
]);
const canonicalizeEcsTaskDefinitionNullableMode = (value, label) => {
  if (value === null || value === "") return null;
  throw new Error(`Stage B task-definition ${label} is outside the reviewed empty-provider shape.`);
};

export function canonicalizeEcsTaskDefinitionVolumes(value) {
  if (!Array.isArray(value)) throw new Error("Stage B task-definition volume must be an array.");
  const names = new Set();
  return value.map((volume, index) => {
    if (!volume || typeof volume !== "object" || Array.isArray(volume)) throw new Error(`Stage B task-definition volume[${index}] is malformed.`);
    const unknownKeys = Object.keys(volume).filter((key) => !ecsTaskDefinitionVolumeKeys.has(key));
    if (unknownKeys.length) throw new Error(`Stage B task-definition volume[${index}] has an unsupported field: ${unknownKeys[0]}.`);
    if (typeof volume.name !== "string" || volume.name.length === 0 || names.has(volume.name)) throw new Error(`Stage B task-definition volume[${index}] has a missing or duplicate name.`);
    if (volume.configure_at_launch !== undefined && volume.configure_at_launch !== false) throw new Error(`Stage B task-definition volume[${index}].configure_at_launch is outside the reviewed empty-provider shape.`);
    if (volume.host_path !== undefined && volume.host_path !== "") throw new Error(`Stage B task-definition volume[${index}].host_path is outside the reviewed empty-provider shape.`);
    for (const field of ecsTaskDefinitionNestedVolumeKeys) {
      if (volume[field] !== undefined && (!Array.isArray(volume[field]) || volume[field].length !== 0)) throw new Error(`Stage B task-definition volume[${index}].${field} is outside the reviewed empty-provider shape.`);
    }
    names.add(volume.name);
    return stableTaskDefinitionValue({
      ...volume,
      configure_at_launch: volume.configure_at_launch ?? false,
      host_path: volume.host_path ?? "",
      ...Object.fromEntries(ecsTaskDefinitionNestedVolumeKeys.map((field) => [field, volume[field] ?? []])),
    });
  });
}

const canonicalTaskDefinitionStableField = (field, value) => {
  if (field === "volume") return canonicalizeEcsTaskDefinitionVolumes(value);
  if (field === "ipc_mode" || field === "pid_mode") return canonicalizeEcsTaskDefinitionNullableMode(value, field);
  return stableTaskDefinitionValue(parsedTaskDefinitionValue(value));
};
export const exactReviewedTaskDefinitionTags = (address, before, after) => {
  const canonical = (value) => JSON.stringify(stableTaskDefinitionValue(value));
  return canonical(before) === canonical(after)
    || (address === backendTaskDefinitionAddress && canonical(before) === canonical(baseTaskDefinitionTags) && canonical(after) === canonical(backendTaskDefinitionTags));
};
const rotationContainerEmptyArrayDefaults = Object.freeze(["environment", "mountPoints", "portMappings", "systemControls", "volumesFrom"]);
const imageVariableForAddress = (address) => {
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  return address.startsWith("aws_ecs_task_definition.executor[") ? "executor_image" : `${key}_image`;
};
const digestImage = (value, label) => {
  if (typeof value !== "string" || !/^.+@sha256:[a-f0-9]{64}$/.test(value)) throw new Error(`${label} must be an immutable image digest.`);
  return value;
};

function assertRotationContainers(beforeValue, afterValue, plan, address, strict) {
  const before = parsedTaskDefinitionValue(beforeValue);
  const after = parsedTaskDefinitionValue(afterValue);
  if (!Array.isArray(before) || !Array.isArray(after) || before.length === 0 || before.length !== after.length) {
    throw new Error(`Stage B task-definition rotation container definitions are malformed: ${address}`);
  }
  const beforeByName = new Map(before.map((container) => [container?.name, container]));
  const afterByName = new Map(after.map((container) => [container?.name, container]));
  if (beforeByName.size !== before.length || afterByName.size !== after.length || [...beforeByName.keys()].some((name) => !afterByName.has(name))) {
    throw new Error(`Stage B task-definition rotation changes container identity: ${address}`);
  }
  const expectedImage = plan?.variables?.[imageVariableForAddress(address)]?.value;
  for (const [name, afterContainer] of afterByName) {
    const beforeContainer = beforeByName.get(name);
    digestImage(beforeContainer?.image, `${address}.${name} before image`);
    const actualImage = digestImage(afterContainer?.image, `${address}.${name} after image`);
    if (strict && actualImage !== expectedImage) throw new Error(`Stage B task-definition rotation image is not bound to the plan input: ${address}`);
    const beforeEnvironment = new Map((beforeContainer.environment || []).map((item) => [item?.name, item?.value]));
    const afterEnvironment = new Map((afterContainer.environment || []).map((item) => [item?.name, item?.value]));
    if (beforeEnvironment.size !== (beforeContainer.environment || []).length || afterEnvironment.size !== (afterContainer.environment || []).length
      || [...beforeEnvironment.keys()].some((name) => !afterEnvironment.has(name))) throw new Error(`Stage B task-definition rotation changes environment identity: ${address}`);
    for (const [environmentName, beforeEnvironmentValue] of beforeEnvironment) {
      const afterEnvironmentValue = afterEnvironment.get(environmentName);
      const variable = rotationMutableEnvironment.get(environmentName);
      if (!variable && beforeEnvironmentValue !== afterEnvironmentValue) throw new Error(`Stage B task-definition rotation changes an unreviewed environment value: ${address}.${environmentName}`);
      if (variable && strict && afterEnvironmentValue !== plan?.variables?.[variable]?.value) throw new Error(`Stage B task-definition rotation provenance is not bound to the plan: ${address}.${environmentName}`);
    }
    const normalize = (container) => {
      const copy = structuredClone(container);
      delete copy.image;
      for (const field of rotationContainerEmptyArrayDefaults) if (copy[field] === undefined || copy[field] === null) copy[field] = [];
      if (Array.isArray(copy.environment)) copy.environment = copy.environment.map((item) => rotationMutableEnvironment.has(item?.name) ? { ...item, value: "<reviewed-provenance>" } : item);
      if (address === backendTaskDefinitionAddress
        && JSON.stringify(beforeContainer.portMappings) === "[]"
        && JSON.stringify(stableTaskDefinitionValue(afterContainer.portMappings)) === JSON.stringify(stableTaskDefinitionValue([STAGE_B_BACKEND_PORT_MAPPING]))) copy.portMappings = "<reviewed-backend-port-mapping>";
      return stableTaskDefinitionValue(copy);
    };
    if (JSON.stringify(normalize(beforeContainer)) !== JSON.stringify(normalize(afterContainer))) throw new Error(`Stage B task-definition rotation contains an unreviewed container field change: ${address}`);
    if (JSON.stringify(stableTaskDefinitionValue(beforeContainer.secrets)) !== JSON.stringify(stableTaskDefinitionValue(afterContainer.secrets))) throw new Error(`Stage B task-definition rotation changes secret sources: ${address}`);
  }
  if (JSON.stringify(stableTaskDefinitionValue(before)) === JSON.stringify(stableTaskDefinitionValue(after))) throw new Error(`Stage B task-definition rotation has no semantic container change: ${address}`);
}

export function assertStageBTaskDefinitionRotation(change, plan, { strict = true } = {}) {
  const address = change?.address;
  const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  if (!expectedFamily || change?.type !== "aws_ecs_task_definition" || change?.mode !== "managed" || (change.module !== undefined && change.module !== null) || !isRotationActions(change.change?.actions)) throw new Error(`Stage B task-definition rotation identity or action is outside the exact root-managed contract: ${address}`);
  if (!exactActions(change.change?.replace_paths, STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)) throw new Error(`Stage B task-definition rotation replace paths are outside the exact contract: ${address}`);
  const before = change.change?.before;
  const after = change.change?.after;
  const beforeArn = before?.arn || before?.id || "";
  if (!beforeArn) throw new Error(`Stage B task-definition rollover is missing its prior task-definition ARN: ${address}`);
  const beforeIdentity = currentTaskDefinitionArnPattern.exec(beforeArn);
  if (!beforeIdentity || beforeIdentity[1] !== expectedFamily || before.family !== expectedFamily || after?.family !== expectedFamily) throw new Error(`Stage B task-definition rotation family or prior identity is invalid: ${address}`);
  const afterIdentity = after.arn === undefined || after.arn === null ? undefined : currentTaskDefinitionArnPattern.exec(after.arn);
  if (after.arn !== undefined && after.arn !== null && (!afterIdentity || afterIdentity[1] !== expectedFamily)) throw new Error(`Stage B task-definition rotation new identity is invalid: ${address}`);
  for (const field of rotationStableFields) {
    if ((field !== "volume" && before[field] === undefined) || (field !== "volume" && after[field] === undefined) || (field === "tags"
      ? !exactReviewedTaskDefinitionTags(address, before[field], after[field])
      : JSON.stringify(canonicalTaskDefinitionStableField(field, before[field])) !== JSON.stringify(canonicalTaskDefinitionStableField(field, after[field])))) {
      throw new Error(`Stage B task-definition rotation changes an immutable field: ${address}.${field}`);
    }
  }
  assertRotationContainers(before.container_definitions, after.container_definitions, plan, address, strict);
  return { address, family: expectedFamily, actions: [...change.change.actions], oldArn: beforeIdentity[0], replacePaths: STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS.map((path) => [...path]), classification: "rollover" };
}

export function isStageBTaskDefinitionRotationActionsValue(actions) {
  return isRotationActions(actions);
}

const taskDefinitionValues = parsedTaskDefinitionValue;
const taskDefinitionImageVariable = imageVariableForAddress;

export function assertStageBCurrentTaskDefinitionNoOp(change, plan, retainedArns = new Set()) {
  const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[change?.address];
  if (!expectedFamily) throw new Error(`Stage B current task-definition address is not allowlisted: ${change?.address}`);
  if (JSON.stringify(change.change?.actions || []) !== JSON.stringify(["no-op"])) throw new Error(`Stage B current task-definition retry must be no-op: ${change.address}`);
  const before = change.change?.before;
  const after = change.change?.after;
  const identity = currentTaskDefinitionArnPattern.exec(before?.arn || "");
  if (!identity || identity[1] !== expectedFamily || before.family !== expectedFamily || after?.family !== expectedFamily) throw new Error(`Stage B current task-definition no-op identity is invalid: ${change.address}`);
  if (retainedArns.has(identity[0])) throw new Error(`Stage B current task-definition no-op uses a retained ARN: ${change.address}`);
  if (JSON.stringify(stableTaskDefinitionValue(before)) !== JSON.stringify(stableTaskDefinitionValue(after))) throw new Error(`Stage B current task-definition no-op has drift: ${change.address}`);

  const variables = plan?.variables || {};
  const imageVariable = taskDefinitionImageVariable(change.address);
  const expectedImage = variables[imageVariable]?.value;
  if (!/^.+@sha256:[a-f0-9]{64}$/.test(expectedImage || "")) throw new Error(`Stage B current task-definition no-op image input is missing or mutable: ${change.address}`);
  const definitions = taskDefinitionValues(after.container_definitions);
  if (!Array.isArray(definitions) || definitions.length === 0 || !definitions.every((definition) => definition && typeof definition.image === "string")) throw new Error(`Stage B current task-definition no-op container definitions are malformed: ${change.address}`);
  if (!definitions.every((definition) => definition.image === expectedImage)) throw new Error(`Stage B current task-definition no-op image digest is stale: ${change.address}`);
  for (const [variable, pattern] of [["image_release_sha", /^[a-f0-9]{40}$/], ["source_contract_sha256", /^[a-f0-9]{64}$/], ["migration_set_digest", /^[a-f0-9]{64}$/], ["package_checksum_sha256", /^[a-f0-9]{64}$/]]) {
    if (!pattern.test(variables[variable]?.value || "")) throw new Error(`Stage B current task-definition no-op ${variable} input is missing or malformed: ${change.address}`);
  }
  const rendered = JSON.stringify(definitions);
  const key = /\["([^\"]+)"\]$/.exec(change.address)?.[1];
  if (key !== "read_only_canary" && !rendered.includes(variables.image_release_sha.value)) throw new Error(`Stage B current task-definition no-op image-release provenance is stale: ${change.address}`);
  if (["canary", "executor"].includes(key === undefined ? "executor" : (change.address.startsWith("aws_ecs_task_definition.executor[") ? "executor" : key))
    && (!rendered.includes(variables.source_contract_sha256.value) || !rendered.includes(variables.migration_set_digest.value))) {
    throw new Error(`Stage B current task-definition no-op source provenance is stale: ${change.address}`);
  }
  if (change.address.startsWith("aws_ecs_task_definition.executor[") && !rendered.includes(variables.package_checksum_sha256.value)) {
    throw new Error(`Stage B current task-definition no-op package checksum is stale: ${change.address}`);
  }

  const planned = plannedResources(plan?.planned_values?.root_module).find((resource) => resource.address === change.address);
  if (!planned?.values || planned.values.family !== expectedFamily) throw new Error(`Stage B current task-definition no-op planned values are missing: ${change.address}`);
  for (const field of ["family", "network_mode", "requires_compatibilities", "cpu", "memory", "execution_role_arn", "task_role_arn", "runtime_platform", "volume", "ipc_mode", "pid_mode", "tags", "container_definitions"]) {
    if (before[field] === undefined || after[field] === undefined || planned.values[field] === undefined) {
      throw new Error(`Stage B current task-definition no-op immutable field is missing: ${change.address}.${field}`);
    }
    if (JSON.stringify(canonicalTaskDefinitionStableField(field, taskDefinitionValues(before[field]))) !== JSON.stringify(canonicalTaskDefinitionStableField(field, taskDefinitionValues(after[field])))) {
      throw new Error(`Stage B current task-definition no-op immutable field drift: ${change.address}.${field}`);
    }
    if (JSON.stringify(canonicalTaskDefinitionStableField(field, taskDefinitionValues(after[field]))) !== JSON.stringify(canonicalTaskDefinitionStableField(field, taskDefinitionValues(planned.values[field])))) {
      throw new Error(`Stage B current task-definition no-op planned value drift: ${change.address}.${field}`);
    }
  }
  const plannedArn = after.arn || planned.values.arn || identity[0];
  const plannedIdentity = currentTaskDefinitionArnPattern.exec(plannedArn || "");
  if (!plannedIdentity || plannedIdentity[1] !== expectedFamily || plannedIdentity[0] !== identity[0]) {
    throw new Error(`Stage B current task-definition no-op planned ARN is invalid: ${change.address}`);
  }
  return { address: change.address, family: expectedFamily, arn: identity[0], currentArn: plannedIdentity[0] };
}

function configuredResources(module, resources = []) {
  for (const resource of module?.resources || []) resources.push(resource);
  for (const child of module?.child_modules || []) configuredResources(child, resources);
  return resources;
}

function plannedResources(module, resources = []) {
  for (const resource of module?.resources || []) resources.push(resource);
  for (const child of module?.child_modules || []) plannedResources(child, resources);
  return resources;
}

function parseTerraformResourceAddress(address) {
  if (typeof address !== "string") return undefined;
  const parts = address.split(".");
  if (parts.length !== 2 || parts.some((part) => part.length === 0)) return undefined;
  const [type, name] = parts;
  const instance = /^(?<name>[A-Za-z0-9_-]+)\[\"(?<key>[A-Za-z0-9_-]+)\"\]$/.exec(name);
  if (instance) return { type, name: instance.groups.name, instanceKey: instance.groups.key };
  if (!/^[A-Za-z0-9_-]+$/.test(name)) return undefined;
  return { type, name, instanceKey: undefined };
}

const samePath = (left, right) => Array.isArray(left)
  && Array.isArray(right)
  && left.length === right.length
  && left.every((value, index) => value === right[index]);

export function assertTerraformDependencyCoversAddress({ relevantAttributes, expectedResourceAddress, expectedAttribute = ["arn"] } = {}) {
  const expected = parseTerraformResourceAddress(expectedResourceAddress);
  if (!expected || !Array.isArray(expectedAttribute)) {
    throw new Error(`Terraform dependency address is malformed: ${expectedResourceAddress}`);
  }
  const match = (Array.isArray(relevantAttributes) ? relevantAttributes : []).find((item) => {
    if (!item || !Array.isArray(item.attribute)) return false;
    const observed = parseTerraformResourceAddress(item.resource);
    if (!observed || observed.type !== expected.type || observed.name !== expected.name) return false;
    if (observed.instanceKey !== undefined) {
      return observed.instanceKey === expected.instanceKey
        && (item.attribute.length === 0 || samePath(item.attribute, expectedAttribute));
    }
    return expected.instanceKey !== undefined && item.attribute.length === 0;
  });
  if (!match) throw new Error(`Terraform dependency to ${expectedResourceAddress}.${expectedAttribute.join(".")} is missing.`);
  return match;
}

function expectedExecutorAddresses() {
  return Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter((address) => address.startsWith(`${STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION}[`));
}

export function assertStageBActiveBrokerTaskDefinitionLocal(terraformConfiguration) {
  if (typeof terraformConfiguration !== "string" || terraformConfiguration.length === 0) {
    throw new Error("Active broker task-definition local source is missing.");
  }
  const assignments = [...terraformConfiguration.matchAll(/^\s*active_broker_task_definition_arns\s*=\s*(.+?)\s*$/gm)];
  if (assignments.length !== 1 || assignments[0][1].replace(/\s+/g, " ").trim() !== STAGE_B_ACTIVE_BROKER_TASK_DEFINITION_LOCAL_EXPRESSION) {
    throw new Error("Active broker task-definition local source is missing or malformed.");
  }
  return true;
}

export function assertStageBBrokerTaskDefinitionMapping(plan, terraformConfiguration) {
  if (typeof terraformConfiguration !== "string" || terraformConfiguration.length === 0) {
    throw new Error("Broker atomic rollover Terraform configuration is missing.");
  }
  assertStageBActiveBrokerTaskDefinitionLocal(terraformConfiguration);
  const normalizedConfiguration = terraformConfiguration.replace(/\s+/g, " ");
  const currentCandidateMappingExpression = /current_candidate_task_definition_arns\s*=\s*\{\s*for kind in keys\(local\.candidate_definitions\)\s*:\s*kind\s*=>\s*try\(aws_ecs_task_definition\.candidate\[kind\]\.arn, null\)\s*if try\(aws_ecs_task_definition\.candidate\[kind\]\.arn, null\) != null\s*\}/;
  const brokerMappingExpression = /broker_task_definition_arns\s*=\s*merge\s*\(\s*local\.current_executor_task_definition_arns\s*,\s*\{\s*for kind, arn in local\.current_candidate_task_definition_arns\s*:\s*"full-rls-application-canary"\s*=>\s*arn if kind == "canary"\s*\}\s*,?\s*\)/;
  if (!currentCandidateMappingExpression.test(normalizedConfiguration)
    || !brokerMappingExpression.test(normalizedConfiguration)
    || [...terraformConfiguration.matchAll(/^\s*broker_task_definition_arns\s*=/gm)].length !== 1) {
    throw new Error("Broker atomic rollover Terraform per-mode mapping is missing or malformed.");
  }
  const configuredExecutor = configuredResources(plan?.configuration?.root_module)
    .find((resource) => resource.address === STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION);
  const forEachReferences = configuredExecutor?.for_each_expression?.references;
  const familyReferences = configuredExecutor?.expressions?.family?.references;
  if (configuredExecutor?.type !== "aws_ecs_task_definition"
    || !Array.isArray(forEachReferences)
    || forEachReferences.length !== STAGE_B_EXECUTOR_FOR_EACH_REFERENCES.length
    || forEachReferences.some((reference, index) => reference !== STAGE_B_EXECUTOR_FOR_EACH_REFERENCES[index])
    || !Array.isArray(familyReferences)
    || familyReferences.filter((reference) => reference === "each.value.family").length !== 1) {
    throw new Error("Broker atomic rollover executor for_each metadata is missing or malformed.");
  }
  const planned = plannedResources(plan?.planned_values?.root_module);
  const expectedCurrentAddresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
  const currentResources = planned.filter((resource) => expectedCurrentAddresses.includes(resource?.address));
  if (currentResources.length !== expectedCurrentAddresses.length) {
    throw new Error("Broker mutation requires all twelve current task-definition mappings.");
  }
  for (const address of expectedCurrentAddresses) {
    const matches = currentResources.filter((resource) => resource.address === address);
    if (matches.length !== 1 || matches[0].type !== "aws_ecs_task_definition"
      || matches[0].values?.family !== STAGE_B_TASK_DEFINITION_FAMILIES[address]) {
      throw new Error(`Broker mutation current task-definition mapping is not exact: ${address}.`);
    }
  }
  const expectedAddresses = expectedExecutorAddresses();
  const executorResources = planned.filter((resource) => resource?.address?.startsWith(`${STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION}[`));
  if (executorResources.length !== expectedAddresses.length) throw new Error("Broker atomic rollover executor mapping is incomplete or duplicated.");
  const seen = new Set();
  for (const address of expectedAddresses) {
    const matches = executorResources.filter((resource) => resource.address === address);
    if (matches.length !== 1 || seen.has(address)) throw new Error(`Broker atomic rollover executor mapping is not exact: ${address}.`);
    seen.add(address);
    const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[address];
    const expectedKey = address.match(/\["([^"]+)"\]$/)?.[1];
    const resource = matches[0];
    if (resource.type !== "aws_ecs_task_definition"
      || resource.index !== expectedKey
      || resource.values?.family !== expectedFamily) {
      throw new Error(`Broker atomic rollover executor mapping does not match ${address}.`);
    }
  }
  const canaryAddress = 'aws_ecs_task_definition.candidate["canary"]';
  const canary = planned.find((resource) => resource.address === canaryAddress);
  if (canary?.type !== "aws_ecs_task_definition"
    || canary.index !== "canary"
    || canary.values?.family !== STAGE_B_TASK_DEFINITION_FAMILIES[canaryAddress]) {
    throw new Error("Broker atomic rollover application-canary mapping is missing or malformed.");
  }
}

export function assertStageBAtomicBrokerPlan(plan, taskDefinitionAddress, brokerMode, terraformConfiguration) {
  if (typeof brokerMode !== "string") throw new Error("Broker atomic rollover task-definition mode is missing.");
  const expectedAddress = brokerMode === "full-rls-application-canary"
    ? 'aws_ecs_task_definition.candidate["canary"]'
    : `${STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION}["${brokerMode}"]`;
  if (STAGE_B_TASK_DEFINITION_FAMILIES[expectedAddress] === undefined || expectedAddress !== taskDefinitionAddress) {
    throw new Error(`Broker atomic rollover task-definition mode does not match ${taskDefinitionAddress}.`);
  }
  const changes = Array.isArray(plan?.resource_changes) ? plan.resource_changes : [];
  const brokerChange = changes.find((change) => change.address === STAGE_B_BROKER_TERRAFORM_ADDRESS);
  if (!brokerChange || JSON.stringify(brokerChange.change?.actions) !== JSON.stringify(["update"])) {
    throw new Error("Broker atomic rollover requires aws_lambda_function.broker actions [\"update\"].");
  }
  const brokerResource = configuredResources(plan?.configuration?.root_module)
    .find((resource) => resource.address === STAGE_B_BROKER_TERRAFORM_ADDRESS);
  const environment = brokerResource?.expressions?.environment;
  const environmentBlocks = Array.isArray(environment) ? environment : [environment];
  const variableReferences = environmentBlocks.flatMap((block) => {
    const references = block?.variables?.references;
    if (references === undefined) return [];
    if (!Array.isArray(references) || !references.every((reference) => typeof reference === "string")) {
      throw new Error("Broker atomic rollover Terraform references are malformed.");
    }
    return references;
  });
  if (!variableReferences.includes(STAGE_B_BROKER_TASK_DEFINITION_REFERENCE)) {
    throw new Error(`Broker atomic rollover Terraform reference to ${STAGE_B_BROKER_TASK_DEFINITION_REFERENCE} is missing.`);
  }
  assertStageBBrokerTaskDefinitionMapping(plan, terraformConfiguration);
  const relevant = Array.isArray(plan?.relevant_attributes) ? plan.relevant_attributes : [];
  const executorAddress = taskDefinitionAddress.startsWith(`${STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION}[`);
  if (executorAddress) {
    const executorResource = configuredResources(plan?.configuration?.root_module)
      .find((resource) => resource.address === STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION);
    const executorFamilyReference = executorResource?.expressions?.family?.references;
    const hasForEachExecutor = executorResource?.type === "aws_ecs_task_definition"
      && Array.isArray(executorFamilyReference)
      && executorFamilyReference.includes("each.value.family");
    if (!hasForEachExecutor) {
      throw new Error(`Broker atomic rollover Terraform collection dependency to ${taskDefinitionAddress}.arn is missing.`);
    }
    assertTerraformDependencyCoversAddress({ relevantAttributes: relevant, expectedResourceAddress: taskDefinitionAddress });
    return;
  }
  const configuredCandidate = configuredResources(plan?.configuration?.root_module)
    .find((resource) => resource.address === "aws_ecs_task_definition.candidate");
  const candidateForEachReferences = configuredCandidate?.for_each_expression?.references;
  const candidateFamilyReferences = configuredCandidate?.expressions?.family?.references;
  const hasForEachCandidate = configuredCandidate?.type === "aws_ecs_task_definition"
    && Array.isArray(candidateForEachReferences)
    && candidateForEachReferences.length === STAGE_B_CANDIDATE_FOR_EACH_REFERENCES.length
    && candidateForEachReferences.every((reference, index) => reference === STAGE_B_CANDIDATE_FOR_EACH_REFERENCES[index]);
  if (!hasForEachCandidate) {
    throw new Error("Broker atomic rollover candidate for_each metadata is missing or malformed.");
  }
  if (relevant.some((item) => item?.resource === "aws_ecs_task_definition.candidate")) {
    if (!Array.isArray(candidateFamilyReferences) || !candidateFamilyReferences.includes("each.value.family")) {
      throw new Error(`Broker atomic rollover Terraform collection dependency to ${taskDefinitionAddress}.arn is missing.`);
    }
  }
  assertTerraformDependencyCoversAddress({ relevantAttributes: relevant, expectedResourceAddress: taskDefinitionAddress });
}

export function assertStageBCurrentRolloverReferenceBinding({ plan, change, audit, planJsonSha256, terraformConfiguration, runtimeModel } = {}) {
  const expectedFamily = STAGE_B_TASK_DEFINITION_FAMILIES[change?.address];
  if (!expectedFamily || change?.type !== "aws_ecs_task_definition") throw new Error(`Stage B rollover identity is outside the exact current task-definition contract: ${change?.address}`);
  const rotation = assertStageBTaskDefinitionRotation(change, plan, { strict: true });
  const beforeArn = change.change?.before?.arn || change.change?.before?.id;
  if (!beforeArn || beforeArn !== rotation.oldArn) throw new Error(`Stage B old task-definition ARN rejected: ${change.address}`);
  const entry = (audit?.oldTaskDefinitions || []).find((item) => item?.terraformAddress === change.address);
  if (!entry || entry.oldTaskDefinitionArn !== beforeArn || entry.classification !== "rollover") throw new Error(`Stage B reference audit rollover entry is missing or mismatched: ${change.address}`);
  if (entry.family !== expectedFamily || entry.proposedFamily !== expectedFamily || entry.sameFamilyAsReplacement !== true) throw new Error(`Stage B reference audit family mismatch: ${change.address}`);
  if (JSON.stringify(entry.replacePaths) !== JSON.stringify(STAGE_B_TASK_DEFINITION_ROTATION_REPLACE_PATHS)) throw new Error(`Stage B reference audit replace path mismatch: ${change.address}`);
  const model = runtimeModel || normalizeStageBFreshImageRuntimeModel({ plan, audit });
  const observedReferences = model.ecs.referencesByTaskDefinitionArn.get(beforeArn) || { services: [], runningTasks: [], pendingTasks: [], transitionalTasks: [] };
  assertCurrentPredecessorReferences({ address: change.address, entry, observed: observedReferences });
  const rollbackIdentity = currentTaskDefinitionArnPattern.exec(entry.rollbackArn || "");
  if (!rollbackIdentity || rollbackIdentity[1] !== expectedFamily) throw new Error(`Stage B rollback ARN is missing or malformed: ${change.address}`);
  const brokerModes = Array.isArray(entry.brokerReferenceModes) ? entry.brokerReferenceModes : undefined;
  const atomicRollovers = Array.isArray(audit.plannedAtomicBrokerRollovers) ? audit.plannedAtomicBrokerRollovers : undefined;
  const liveMappings = audit.broker?.liveTaskDefinitionMappings;
  if (!brokerModes || !atomicRollovers || !Array.isArray(liveMappings)) throw new Error(`Stage B atomic broker rollover evidence is missing: ${change.address}`);
  const expectedModes = model.broker.currentRolloverModes.filter((item) => item.address === change.address).map((item) => item.mode);
  if (!sameStringSet(expectedModes, brokerModes) || !brokerModes.every((mode) => STAGE_B_MODES.includes(mode))) throw new Error(`Stage B current broker mode evidence does not match canonical observations: ${change.address}`);
  const atomicForChange = atomicRollovers.filter((item) => item?.taskDefinitionTerraformAddress === change.address);
  if (brokerModes.length === 0) {
    if (atomicForChange.length !== 0 || entry.brokerReferenceStatus === "planned-atomic-broker-rollover-v1") throw new Error(`Stage B atomic broker rollover is unexpected: ${change.address}`);
    return rotation;
  }
  if (entry.brokerReferenceStatus !== "planned-atomic-broker-rollover-v1" || audit.allOldRevisionsUnreferenced !== false || atomicForChange.length !== brokerModes.length) throw new Error(`Stage B atomic broker rollover proof is incomplete: ${change.address}`);
  for (const mode of brokerModes) {
    const matches = atomicForChange.filter((item) => item?.mode === mode);
    if (matches.length !== 1) throw new Error(`Stage B atomic broker rollover mode is missing or duplicated: ${change.address}:${mode}`);
    const proof = matches[0];
    assertStageBAtomicBrokerPlan(plan, change.address, mode, terraformConfiguration);
    const observedMapping = model.broker.observedMappingsByMode.get(mode);
    if (!observedMapping || observedMapping.taskDefinitionArn !== beforeArn) throw new Error(`Stage B live broker mapping does not match the current predecessor: ${change.address}`);
    if (proof.brokerTerraformAddress !== STAGE_B_BROKER_TERRAFORM_ADDRESS
      || proof.taskDefinitionArnReference !== `${change.address}.arn`
      || proof.brokerEnvironmentReference !== STAGE_B_BROKER_TASK_DEFINITION_REFERENCE
      || proof.family !== expectedFamily
      || proof.oldTaskDefinitionArn !== beforeArn
      || proof.planJsonSha256 !== planJsonSha256) throw new Error(`Stage B atomic broker rollover proof does not match the plan: ${change.address}`);
  }
  return rotation;
}

function brokerResource(plan) {
  return configuredResources(plan?.configuration?.root_module)
    .find((resource) => resource.address === STAGE_B_BROKER_TERRAFORM_ADDRESS);
}

function brokerEnvironmentReferences(plan) {
  const environment = brokerResource(plan)?.expressions?.environment;
  const blocks = Array.isArray(environment) ? environment : [environment];
  return blocks.flatMap((block) => {
    const references = block?.variables?.references;
    if (references === undefined) return [];
    if (!Array.isArray(references) || !references.every((reference) => typeof reference === "string")) {
      throw new Error("Broker package transition Terraform references are malformed.");
    }
    return references;
  });
}

function brokerApprovalChecksum(environment, label) {
  const variables = environment?.[0]?.variables || {};
  const raw = variables.BROKER_APPROVAL_EXPECTED_JSON;
  if (typeof raw !== "string" || raw.length === 0) throw new Error(`${label} broker approval JSON is missing.`);
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${label} broker approval JSON is malformed.`);
  }
  if (typeof parsed?.packageChecksumSha256 !== "string") throw new Error(`${label} broker package checksum is missing.`);
  return parsed.packageChecksumSha256;
}

function assertBrokerPackagePlanCommon(plan, proof, terraformConfiguration, expectedActions) {
  if (!proof || typeof proof !== "object") throw new Error("Broker package plan proof is missing.");
  if (typeof terraformConfiguration !== "string" || terraformConfiguration.length === 0) {
    throw new Error("Broker package transition Terraform configuration is missing.");
  }
  const brokerChange = (plan?.resource_changes || []).find((change) => change.address === STAGE_B_BROKER_TERRAFORM_ADDRESS);
  if (!brokerChange || JSON.stringify(brokerChange.change?.actions) !== JSON.stringify(expectedActions)) {
    throw new Error(`Broker package plan requires aws_lambda_function.broker actions ${JSON.stringify(expectedActions)}.`);
  }
  const planChecksum = plan?.variables?.package_checksum_sha256?.value;
  const packagePath = plan?.variables?.broker_package_path?.value;
  if (!/^[a-f0-9]{64}$/.test(planChecksum || "")) throw new Error("Atomic broker package transition plan checksum is missing or malformed.");
  if (typeof packagePath !== "string" || !packagePath.startsWith("/")) throw new Error("Atomic broker package transition package path is missing or malformed.");
  if (proof.plannedReleasePackageChecksumSha256 !== planChecksum) {
    throw new Error("Broker release package checksum does not match the exact plan input.");
  }
  if (!/^[a-f0-9]{64}$/.test(proof.brokerZipFileSha256 || "")) throw new Error("Broker ZIP checksum is missing or malformed.");
  if (typeof proof.plannedBrokerSourceCodeHashBase64 !== "string" || !/^[A-Za-z0-9+/]{43}=$/.test(proof.plannedBrokerSourceCodeHashBase64)) {
    throw new Error("Broker planned source_code_hash is missing or malformed.");
  }
  let packageBytes;
  try {
    packageBytes = fs.readFileSync(packagePath);
  } catch {
    throw new Error("Expected broker package file is missing or unreadable.");
  }
  const packageFileSha256 = crypto.createHash("sha256").update(packageBytes).digest("hex");
  if (packageFileSha256 !== proof.brokerZipFileSha256) throw new Error("Broker ZIP checksum does not match the expected package bytes.");
  if (Buffer.from(proof.brokerZipFileSha256, "hex").toString("base64") !== proof.plannedBrokerSourceCodeHashBase64) {
    throw new Error("Broker ZIP checksum does not match the planned source_code_hash.");
  }
  if (proof.packagePath !== packagePath) throw new Error("Broker package path does not match the exact plan input.");
  if (proof.brokerEnvironmentReference !== STAGE_B_BROKER_APPROVAL_REFERENCE) {
    throw new Error("Broker approval local reference is missing.");
  }
  if (proof.packageInputReference !== STAGE_B_BROKER_APPROVAL_INPUT) {
    throw new Error("Broker release checksum input reference is missing.");
  }
  if (!brokerEnvironmentReferences(plan).includes(STAGE_B_BROKER_APPROVAL_REFERENCE)) {
    throw new Error("Broker approval local reference is missing from the planned environment.");
  }
  const normalizedConfiguration = terraformConfiguration.replace(/\s+/g, " ");
  if (!/packageChecksumSha256\s*=\s*var\.package_checksum_sha256/.test(normalizedConfiguration)
    || !/BROKER_APPROVAL_EXPECTED_JSON\s*=\s*jsonencode\(local\.broker_approval_expected\)/.test(normalizedConfiguration)
    || !/filename\s*=\s*var\.broker_package_path/.test(normalizedConfiguration)
    || !/source_code_hash\s*=\s*filebase64sha256\(var\.broker_package_path\)/.test(normalizedConfiguration)) {
    throw new Error("Broker Terraform checksum/package wiring is missing or malformed.");
  }
  const after = brokerChange.change?.after || {};
  if (after.filename !== packagePath) throw new Error("Broker package replacement is not in the same plan.");
  if (after.source_code_hash !== proof.plannedBrokerSourceCodeHashBase64) {
    throw new Error("Broker source_code_hash does not match the planned ZIP proof.");
  }
  if (proof.planJsonSha256 && !/^[a-f0-9]{64}$/.test(proof.planJsonSha256)) {
    throw new Error("Broker package plan SHA-256 is malformed.");
  }
  return { brokerChange, planChecksum };
}

export function assertStageBAtomicBrokerPackagePlan(plan, proof, terraformConfiguration) {
  const { brokerChange } = assertBrokerPackagePlanCommon(plan, proof, terraformConfiguration, ["update"]);
  const beforeChecksum = brokerApprovalChecksum(brokerChange.change?.before?.environment, "Plan before");
  if (proof.liveReleasePackageChecksumSha256 !== beforeChecksum || proof.planBeforeReleasePackageChecksumSha256 !== beforeChecksum) {
    throw new Error("Live release checksum does not match the broker plan before-value.");
  }
}

export function assertStageBBrokerCreatePlan(plan, proof, terraformConfiguration) {
  const { brokerChange, planChecksum } = assertBrokerPackagePlanCommon(plan, proof, terraformConfiguration, ["create"]);
  const afterChecksum = brokerApprovalChecksum(brokerChange.change?.after?.environment, "Planned create");
  if (afterChecksum !== planChecksum) throw new Error("Planned broker approval JSON does not match the release package checksum input.");
  assertStageBBrokerTaskDefinitionMapping(plan, terraformConfiguration);
}

export function assertStageBReferenceAuditFreshness(auditedAt, now = new Date()) {
  return assertStageBDeploymentEvidenceFreshness(auditedAt, { now, evidenceType: "Stage B reference audit" });
}

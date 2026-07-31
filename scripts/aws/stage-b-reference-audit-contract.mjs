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
export const STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS = 15 * 60 * 1000;
export const STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS = 60 * 1000;
export const STAGE_B_BROKER_TERRAFORM_ADDRESS = "aws_lambda_function.broker";
export const STAGE_B_BROKER_TASK_DEFINITION_REFERENCE = "local.broker_task_definition_arns";
export const STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION = "aws_ecs_task_definition.executor";

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

function expectedExecutorAddresses() {
  return Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES)
    .filter((address) => address.startsWith(`${STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION}[`));
}

export function assertStageBBrokerTaskDefinitionMapping(plan, terraformConfiguration) {
  if (typeof terraformConfiguration !== "string" || terraformConfiguration.length === 0) {
    throw new Error("Broker atomic rollover Terraform configuration is missing.");
  }
  const normalizedConfiguration = terraformConfiguration.replace(/\s+/g, " ");
  const brokerMappingExpression = /broker_task_definition_arns\s*=\s*merge\s*\(\s*\{\s*for mode, task in aws_ecs_task_definition\.executor\s*:\s*mode\s*=>\s*task\.arn\s*\}\s*,\s*\{\s*full-rls-application-canary\s*=\s*aws_ecs_task_definition\.candidate\["canary"\]\.arn\s*\}\s*\)/;
  if (!brokerMappingExpression.test(normalizedConfiguration)
    || [...terraformConfiguration.matchAll(/^\s*broker_task_definition_arns\s*=/gm)].length !== 1) {
    throw new Error("Broker atomic rollover Terraform per-mode mapping is missing or malformed.");
  }
  const configuredExecutor = configuredResources(plan?.configuration?.root_module)
    .find((resource) => resource.address === STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION);
  const forEachReferences = configuredExecutor?.for_each_expression?.references;
  const familyReferences = configuredExecutor?.expressions?.family?.references;
  if (configuredExecutor?.type !== "aws_ecs_task_definition"
    || !Array.isArray(forEachReferences)
    || forEachReferences.length !== 1
    || forEachReferences[0] !== "local.executor_definitions"
    || !Array.isArray(familyReferences)
    || familyReferences.filter((reference) => reference === "each.value.family").length !== 1) {
    throw new Error("Broker atomic rollover executor for_each metadata is missing or malformed.");
  }
  const planned = plannedResources(plan?.planned_values?.root_module);
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
    throw new Error("Broker atomic rollover Terraform reference to local.broker_task_definition_arns is missing.");
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
    const hasCollectionDependency = relevant.some((item) => item?.resource === STAGE_B_EXECUTOR_TASK_DEFINITION_COLLECTION
      && Array.isArray(item.attribute) && item.attribute.length === 0);
    if (!hasForEachExecutor || !hasCollectionDependency) {
      throw new Error(`Broker atomic rollover Terraform collection dependency to ${taskDefinitionAddress}.arn is missing.`);
    }
    return;
  }
  if (!relevant.some((item) => item?.resource === taskDefinitionAddress && JSON.stringify(item.attribute) === JSON.stringify(["arn"]))) {
    throw new Error(`Broker atomic rollover Terraform dependency to ${taskDefinitionAddress}.arn is missing.`);
  }
}

export function assertStageBReferenceAuditFreshness(auditedAt, now = new Date()) {
  const nowMs = now instanceof Date ? now.getTime() : NaN;
  if (!Number.isFinite(nowMs)) throw new Error("Stage B validation clock is malformed.");
  const auditedAtMs = Date.parse(auditedAt || "");
  if (!Number.isFinite(auditedAtMs)) throw new Error("Stage B reference audit timestamp is malformed.");
  if (auditedAtMs > nowMs + STAGE_B_REFERENCE_AUDIT_CLOCK_SKEW_MS) throw new Error("Stage B reference audit timestamp is in the future.");
  if (nowMs - auditedAtMs > STAGE_B_REFERENCE_AUDIT_MAX_AGE_MS) throw new Error("Stage B reference audit is expired.");
}

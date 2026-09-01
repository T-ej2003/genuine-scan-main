const READBACK_METADATA_FIELDS = Object.freeze(["taskDefinitionArn", "revision", "status", "registeredAt", "registeredBy", "deregisteredAt", "deleteRequestedAt", "tags", "requiresAttributes", "compatibilities"]);
const ROOT_EMPTY_DEFAULT_FIELDS = Object.freeze(["placementConstraints", "volumes"]);
const CONTAINER_EMPTY_DEFAULT_FIELDS = Object.freeze(["environment", "environmentFiles", "mountPoints", "portMappings", "systemControls", "ulimits", "volumesFrom"]);

export function normalizeEcsTaskDefinitionReadback(definition) {
  const normalized = structuredClone(definition);
  for (const field of READBACK_METADATA_FIELDS) delete normalized[field];
  // ECS documents this optional field as defaulting to false. Preserve true:
  // it enables task fault-injection endpoints and is executable configuration.
  if (normalized.enableFaultInjection === false) delete normalized.enableFaultInjection;
  for (const field of ROOT_EMPTY_DEFAULT_FIELDS) if (Array.isArray(normalized[field]) && normalized[field].length === 0) delete normalized[field];
  if (Array.isArray(normalized.containerDefinitions)) {
    normalized.containerDefinitions = normalized.containerDefinitions.map((container) => {
      const normalizedContainer = structuredClone(container);
      if (!Object.hasOwn(normalizedContainer, "cpu")) normalizedContainer.cpu = 0;
      for (const field of CONTAINER_EMPTY_DEFAULT_FIELDS) if (Array.isArray(normalizedContainer[field]) && normalizedContainer[field].length === 0) delete normalizedContainer[field];
      // ECS materializes an omitted awslogs secretOptions list as []; an actual
      // non-empty list remains part of the reviewed executable configuration.
      if (Array.isArray(normalizedContainer.logConfiguration?.secretOptions) && normalizedContainer.logConfiguration.secretOptions.length === 0) delete normalizedContainer.logConfiguration.secretOptions;
      return normalizedContainer;
    });
  }
  return normalized;
}

export function canonicalizeEcsTaskDefinition(definition) {
  const canonical = (value) => Array.isArray(value)
    ? `[${value.map(canonical).join(",")}]`
    : value && typeof value === "object"
      ? `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`
      : JSON.stringify(value);
  return canonical(normalizeEcsTaskDefinitionReadback(definition));
}

export function assertEcsTaskDefinitionReadback({ definition, taskDefinitionArn, expected, label = "ECS task definition" } = {}) {
  const match = /^arn:aws:ecs:[^:]+:[^:]+:task-definition\/([^:]+):([1-9][0-9]*)$/.exec(String(taskDefinitionArn || ""));
  if (!definition || !match || definition.taskDefinitionArn !== taskDefinitionArn
      || definition.family !== match[1] || definition.revision !== undefined && String(definition.revision) !== match[2]
      || definition.status !== "ACTIVE" || canonicalizeEcsTaskDefinition(definition) !== canonicalizeEcsTaskDefinition(expected)) {
    throw new Error(`${label} is not the exact approved execution contract.`);
  }
  return true;
}

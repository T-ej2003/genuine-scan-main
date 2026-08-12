import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

const TEMPLATE_PATH = path.resolve("infra/aws/terraform/production-green-stage-b/task-definitions/green-backend-rotation-inventory.json");
const FAMILY = "mscqr-production-rls-green-predeployment-inventory";
const DIGEST = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-predeployment-inventory:[1-9][0-9]*$/;
const ROLE = /^arn:aws:iam::368992683803:role\/mscqr-production-rls-green-(?:backend-task|backend-execution)$/;
const SECRET = /^arn:aws:secretsmanager:eu-west-2:368992683803:secret:[A-Za-z0-9/_+=.@-]+(?::[A-Za-z0-9_-]+::)?$/;
const SHA = /^[a-f0-9]{40}$/;
const ROLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

export const PREDEPLOYMENT_INVENTORY_TAG = Object.freeze({ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" });
export const PREDEPLOYMENT_INVENTORY_TAGS = Object.freeze([
  { key: "Environment", value: "production" },
  { key: "ManagedBy", value: "Terraform" },
  { key: "Component", value: "full-rls-green-stage-b" },
  PREDEPLOYMENT_INVENTORY_TAG,
]);
export const PREDEPLOYMENT_INVENTORY_COMMAND = Object.freeze(["/app/scripts/production-rotation-state-inventory.mjs"]);

const replace = (value, bindings) => Array.isArray(value) ? value.map((item) => replace(item, bindings)) : value && typeof value === "object"
  ? Object.fromEntries(Object.entries(value).map(([key, item]) => [key, replace(item, bindings)]))
  : typeof value === "string" ? value.replace(/{{([A-Z0-9_]+)}}/g, (_, key) => bindings[key] ?? (() => { throw new Error(`Missing inventory task binding: ${key}.`); })()) : value;

export function buildPreDeploymentInventoryTaskDefinition({ backendImage, releaseSha, databaseUrl, rotationInventoryRlsRole, inventoryLogGroup, inventoryTaskRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task", inventoryExecutionRoleArn = "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution" } = {}) {
  if (!DIGEST.test(backendImage || "") || !SHA.test(releaseSha || "") || !SECRET.test(databaseUrl || "") || !ROLE.test(inventoryTaskRoleArn) || !ROLE.test(inventoryExecutionRoleArn) || !ROLE_NAME.test(rotationInventoryRlsRole || "") || typeof inventoryLogGroup !== "string" || !inventoryLogGroup.startsWith("/ecs/")) throw new Error("Pre-deployment inventory task bindings are invalid.");
  const definition = replace(JSON.parse(fs.readFileSync(TEMPLATE_PATH, "utf8")), { BACKEND_IMAGE: backendImage, RELEASE_SHA: releaseSha, DATABASE_URL: databaseUrl, ROTATION_INVENTORY_RLS_ROLE: rotationInventoryRlsRole, INVENTORY_LOG_GROUP: inventoryLogGroup, INVENTORY_TASK_ROLE_ARN: inventoryTaskRoleArn, INVENTORY_EXECUTION_ROLE_ARN: inventoryExecutionRoleArn });
  const container = definition.containerDefinitions?.[0];
  if (definition.family !== FAMILY || definition.networkMode !== "awsvpc" || definition.requiresCompatibilities?.join(",") !== "FARGATE" || definition.cpu !== "256" || definition.memory !== "512" || definition.executionRoleArn !== inventoryExecutionRoleArn || definition.taskRoleArn !== inventoryTaskRoleArn || !container || container.name !== "inventory" || container.image !== backendImage || JSON.stringify(container.entryPoint) !== JSON.stringify(["node"]) || JSON.stringify(container.command) !== JSON.stringify(PREDEPLOYMENT_INVENTORY_COMMAND) || container.portMappings || container.privileged !== false || container.interactive !== false || container.pseudoTerminal !== false || container.secrets?.length !== 1 || container.secrets[0].name !== "DATABASE_URL" || container.secrets[0].valueFrom !== databaseUrl || container.environment?.find(({ name }) => name === "ROTATION_INVENTORY_APPROVED")?.value !== "true" || !container.logConfiguration?.options?.["awslogs-group"] || JSON.stringify(definition).includes("{{")) throw new Error("Pre-deployment inventory task definition is outside the reviewed contract.");
  return { taskDefinition: definition, tags: PREDEPLOYMENT_INVENTORY_TAGS };
}

export function assertPreDeploymentInventoryTaskDefinition(definition, expected = {}) {
  const payload = buildPreDeploymentInventoryTaskDefinition({ backendImage: expected.backendImage || definition?.containerDefinitions?.[0]?.image, releaseSha: expected.releaseSha || definition?.containerDefinitions?.[0]?.environment?.find(({ name }) => name === "RELEASE_GIT_SHA")?.value, databaseUrl: expected.databaseUrl || definition?.containerDefinitions?.[0]?.secrets?.find(({ name }) => name === "DATABASE_URL")?.valueFrom, rotationInventoryRlsRole: expected.rotationInventoryRlsRole || definition?.containerDefinitions?.[0]?.environment?.find(({ name }) => name === "ROTATION_INVENTORY_RLS_ROLE")?.value, inventoryLogGroup: expected.inventoryLogGroup || definition?.containerDefinitions?.[0]?.logConfiguration?.options?.["awslogs-group"], inventoryTaskRoleArn: expected.inventoryTaskRoleArn || definition?.taskRoleArn, inventoryExecutionRoleArn: expected.inventoryExecutionRoleArn || definition?.executionRoleArn });
  const readback = { ...definition };
  for (const key of ["taskDefinitionArn", "revision", "status", "registeredAt", "registeredBy", "tags", "requiresAttributes", "compatibilities"]) delete readback[key];
  if (JSON.stringify(payload.taskDefinition) !== JSON.stringify(readback)) throw new Error("Pre-deployment inventory task definition differs from the reviewed payload.");
  return true;
}

export async function registerPreDeploymentInventoryTaskDefinition({ input, register, describe = null } = {}) {
  const payload = buildPreDeploymentInventoryTaskDefinition(input);
  if (typeof register !== "function") throw new Error("Pre-deployment inventory registration adapter is required.");
  const response = await register(payload);
  const arn = response?.taskDefinition?.taskDefinitionArn || response?.taskDefinitionArn;
  if (!ARN.test(arn || "")) throw new Error("Pre-deployment inventory registration returned an unexpected task-definition ARN.");
  if (describe) {
    const registered = await describe(arn);
    if (registered?.taskDefinitionArn !== arn || registered?.family !== FAMILY || registered?.status !== "ACTIVE") throw new Error("Pre-deployment inventory task readback is invalid.");
    assertPreDeploymentInventoryTaskDefinition(registered, input);
  }
  return { ...payload, valid: true, evidenceRef: arn, evidenceSha256: createHash("sha256").update(JSON.stringify(payload)).digest("hex"), taskDefinitionArn: arn };
}

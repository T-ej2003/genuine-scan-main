import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { STAGE_B } from "./production-green-stage-b-contract.mjs";
import { registerPreDeploymentInventoryTaskDefinition } from "./production-predeployment-inventory-task.mjs";
import { canonicalBackendDatabaseSecretReference } from "./production-overlap-task-definition.mjs";

const SHA = /^[a-f0-9]{40}$/;
const ARN = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-predeployment-inventory:[1-9][0-9]*$/;

export const PREDEPLOYMENT_BROKER_LAMBDA_TIMEOUT_SECONDS = 180;
export const PREDEPLOYMENT_BROKER_OPERATION_DEADLINE_SECONDS = 100;
export const PREDEPLOYMENT_BROKER_CLEANUP_MARGIN_SECONDS = 30;
export const PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS = 150;
export const PREDEPLOYMENT_BROKER_CALLER_TIMEOUT_HEADROOM_SECONDS = PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS
  - PREDEPLOYMENT_BROKER_OPERATION_DEADLINE_SECONDS - PREDEPLOYMENT_BROKER_CLEANUP_MARGIN_SECONDS;

if (PREDEPLOYMENT_BROKER_CALLER_TIMEOUT_HEADROOM_SECONDS <= 0
  || PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS >= PREDEPLOYMENT_BROKER_LAMBDA_TIMEOUT_SECONDS) {
  throw new Error("Pre-deployment broker caller timeout contract is invalid.");
}

const parseJson = (run, args) => JSON.parse(run([...args, "--output", "json", "--no-cli-pager"]));

export function createProductionPreDeploymentInventoryAdapter({ run, sourceSha, imageDigest, config } = {}) {
  if (typeof run !== "function" || !SHA.test(sourceSha || "") || !config || !STAGE_B.brokerAliasArn) throw new Error("Pre-deployment inventory adapter configuration is required.");
  const inventorySecretArn = config.inventoryDatabaseSecretArn || config.overlapTaskInput?.databaseUrlSecretArn || canonicalBackendDatabaseSecretReference();
  const taskInput = {
    backendImage: imageDigest,
    releaseSha: sourceSha,
    databaseUrl: inventorySecretArn,
    inventoryTaskRoleArn: config.inventoryTaskRoleArn || "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
    inventoryExecutionRoleArn: config.inventoryExecutionRoleArn || "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
    rotationInventoryRlsRole: config.rotationInventoryRlsRole || config.overlapTaskInput?.secretBindings?.ROTATION_INVENTORY_RLS_ROLE,
    inventoryLogGroup: config.inventoryLogGroupName || config.overlapTaskInput?.backendLogGroup,
  };
  let registeredTaskDefinition;
  let registrationPromise;
  const getRegisteredTaskDefinition = async () => {
    if (!registrationPromise) {
      registrationPromise = registerPreDeploymentInventoryTaskDefinition({
        input: { ...taskInput },
        existingTaskDefinitionArn: config.inventoryTaskDefinitionArn,
        register: async (registration) => {
          const response = run(["ecs", "register-task-definition", "--cli-input-json", JSON.stringify({ ...registration.taskDefinition, tags: registration.tags })]);
          return typeof response === "string" ? JSON.parse(response) : response;
        },
        describe: async (arn) => parseJson(run, ["ecs", "describe-task-definition", "--task-definition", arn, "--include", "TAGS"]).taskDefinition,
      }).then((value) => {
        registeredTaskDefinition = value;
        return value;
      }).catch((error) => {
        registrationPromise = undefined;
        throw error;
      });
    }
    return registeredTaskDefinition || registrationPromise;
  };
  return {
    async run({ rotationId } = {}) {
      if (!/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "")) throw new Error("Pre-deployment inventory rotation identity is invalid.");
      const registered = await getRegisteredTaskDefinition();
      const taskDefinitionArn = registered.taskDefinitionArn;
      if (!ARN.test(taskDefinitionArn || "")) throw new Error("Pre-deployment inventory registration returned an unreviewed task definition.");
      const directory = mkdtempSync(path.join(os.tmpdir(), "mscqr-inventory-broker-"));
      const outputPath = path.join(directory, "broker-response.json");
      try {
        const brokerRequest = {
          approvalId: config.inventoryApprovalId,
          operation: "production-predeployment-rotation-inventory",
          rotationId,
          sourceSha,
          taskDefinitionArn,
        };
        const invocation = parseJson(run, ["lambda", "invoke", "--function-name", STAGE_B.brokerAliasArn, "--invocation-type", "RequestResponse", "--cli-binary-format", "raw-in-base64-out", "--cli-read-timeout", String(PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS), "--payload", JSON.stringify(brokerRequest), outputPath]);
        if (invocation.FunctionError) throw new Error("Pre-deployment inventory broker returned a function error.");
        const response = JSON.parse(readFileSync(outputPath, "utf8"));
        if (response.status !== "completed" || response.sourceSha !== sourceSha || response.rotationId !== rotationId || response.taskDefinitionArn !== taskDefinitionArn) throw new Error("Pre-deployment inventory broker evidence is not bound to this task.");
        return { inventory: response.inventory, taskArn: response.taskArn, taskDefinitionArn, sourceSha, rotationId, valid: true, evidenceRef: `predeployment-inventory:${response.taskArn}`, evidenceSha256: response.receiptSha256 || response.evidenceSha256, mutationCount: registered.mutationCount, ...(registered.mutationCount ? { mutationPayload: { operation: "RegisterTaskDefinition", taskDefinitionArn } } : {}) };
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    },
  };
}

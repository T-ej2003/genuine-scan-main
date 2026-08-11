import { selectTargetTask, executeAgainstRevalidatedTarget, requireExecuteCommandEnabled } from "./ecs-exec-target-selection.mjs";
import { ECS_EXEC_OPERATOR_TASK_TAG_KEY, ECS_EXEC_OPERATOR_TASK_TAG_VALUE } from "./production-ecs-exec-operator-contract.mjs";

export const PRODUCTION_RUNTIME_INVENTORY_COMMAND = "node /app/scripts/production-rotation-state-inventory.mjs";

const parseAggregateInventory = (output) => {
  if (typeof output !== "string" || output.length === 0 || output.length > 64 * 1024) throw new Error("Runtime inventory returned no bounded JSON.");
  let value;
  try { value = JSON.parse(output.trim()); } catch { throw new Error("Runtime inventory returned malformed JSON."); }
  return value;
};

/**
 * Production transport for bounded inventory. The only command is repository-owned;
 * the operator cannot provide a shell command or a database credential.
 */
export function createProductionRuntimeInventoryAdapter({ ecs, expected } = {}) {
  if (!ecs || typeof ecs.describeService !== "function" || typeof ecs.listTasks !== "function" || typeof ecs.describeTasks !== "function" || typeof ecs.executeCommand !== "function") throw new Error("Runtime inventory ECS adapter is incomplete.");
  return async ({ taskDefinitionArn } = {}) => {
    const service = await ecs.describeService();
    requireExecuteCommandEnabled(service);
    const listed = await ecs.listTasks();
    const described = await ecs.describeTasks({ taskArns: listed.taskArns || [], includeTags: true });
    const targetExpected = { ...expected, ...(taskDefinitionArn ? { expectedTaskDefinitionArn: taskDefinitionArn } : {}), expectedTaskTagKey: ECS_EXEC_OPERATOR_TASK_TAG_KEY, expectedTaskTagValue: ECS_EXEC_OPERATOR_TASK_TAG_VALUE };
    const selection = selectTargetTask({ tasks: described.tasks, ...targetExpected });
    const selectedTaskArn = selection.selectedTask.taskArn;
    let output;
    await executeAgainstRevalidatedTarget({
      adapter: {
        describeTasks: (request) => ecs.describeTasks(request),
        executeCommand: async ({ taskArn, container, command }) => {
          if (taskArn !== selectedTaskArn || container !== expected.containerName || command !== PRODUCTION_RUNTIME_INVENTORY_COMMAND) throw new Error("Runtime inventory command or target is outside the reviewed boundary.");
          output = await ecs.executeCommand({ taskArn, container, command });
        },
      },
      selectedTaskArn,
      expected: targetExpected,
      command: PRODUCTION_RUNTIME_INVENTORY_COMMAND,
    });
    return { inventory: parseAggregateInventory(output), taskDefinitionArn: targetExpected.expectedTaskDefinitionArn, taskArn: selectedTaskArn };
  };
}

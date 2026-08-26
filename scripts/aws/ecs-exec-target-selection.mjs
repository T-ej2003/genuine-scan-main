const executeCommandAgentConnected = (task) =>
  task?.managedAgents?.some((agent) => agent?.name === "ExecuteCommandAgent" && agent?.lastStatus === "RUNNING") === true;

const hasApprovedTaskIdentity = (task, tagKey, tagValue) =>
  Array.isArray(task?.tags) && task.tags.some((tag) => tag?.key === tagKey && tag?.value === tagValue);

const isHealthyEnough = (task) => task?.healthStatus === undefined || task.healthStatus === "HEALTHY";

export const assertSelectedTargetTask = ({ task, expectedClusterArn, expectedTaskDefinitionArn, expectedImageDigest, serviceName, containerName, expectedTaskTagKey, expectedTaskTagValue }) => {
  const container = task?.containers?.find((entry) => entry?.name === containerName);
  if (!task?.taskArn || task.clusterArn !== expectedClusterArn || task.taskDefinitionArn !== expectedTaskDefinitionArn
    || task.lastStatus !== "RUNNING" || task.group !== `service:${serviceName}` || !isHealthyEnough(task)
    || container?.imageDigest !== expectedImageDigest || !hasApprovedTaskIdentity(task, expectedTaskTagKey, expectedTaskTagValue)
    || !executeCommandAgentConnected(task)) throw new Error("selected ECS Exec target no longer satisfies the reviewed backend identity contract");
  return task;
};

export const requireExecuteCommandEnabled = (service) => {
  if (service?.enableExecuteCommand !== true) throw new Error("ECS Exec is disabled on the target service");
  return true;
};

export const assertTaskBelongsToExactPrimaryDeployment = ({ service, task, expectedTaskDefinitionArn }) => {
  const matching = (service?.deployments || []).filter((deployment) => deployment?.status === "PRIMARY" && deployment.taskDefinition === expectedTaskDefinitionArn && /^ecs-svc\/[1-9][0-9]*$/.test(deployment.id || ""));
  if (matching.length !== 1 || task?.startedBy !== matching[0].id) throw new Error("selected ECS task is not bound to one exact primary service deployment");
  return matching[0];
};

export const selectTargetTask = ({ tasks, expectedClusterArn, expectedTaskDefinitionArn, expectedImageDigest, serviceName, containerName, expectedTaskTagKey, expectedTaskTagValue }) => {
  const matching = (Array.isArray(tasks) ? tasks : []).filter((task) => {
    try {
      assertSelectedTargetTask({ task, expectedClusterArn, expectedTaskDefinitionArn, expectedImageDigest, serviceName, containerName, expectedTaskTagKey, expectedTaskTagValue });
      return true;
    } catch {
      return false;
    }
  });
  if (matching.length === 0) throw new Error("no running target task has a connected ECS Exec agent");
  matching.sort((left, right) => String(left.taskArn).localeCompare(String(right.taskArn)));
  return { selectedTask: matching[0], matchingTaskCount: matching.length };
};

export const revalidateExactTargetTask = ({ tasks, selectedTaskArn, ...expected }) => {
  if (typeof selectedTaskArn !== "string" || !selectedTaskArn) throw new Error("selected ECS Exec task ARN is required for revalidation");
  if (!Array.isArray(tasks) || tasks.length !== 1 || tasks[0]?.taskArn !== selectedTaskArn) throw new Error("selected ECS Exec task changed before final tag revalidation");
  return assertSelectedTargetTask({ task: tasks[0], ...expected });
};

export function selectAndRevalidateExactTarget({ tasks, finalTasks, ...expected }) {
  const selection = selectTargetTask({ tasks, ...expected });
  const finalTask = revalidateExactTargetTask({ tasks: finalTasks, selectedTaskArn: selection.selectedTask.taskArn, ...expected });
  return { ...selection, finalTask, selectedTaskArn: selection.selectedTask.taskArn, revalidatedTaskArn: finalTask.taskArn };
}

export async function executeAgainstRevalidatedTarget({ adapter, selectedTaskArn, expected, command }) {
  if (!adapter || typeof adapter.describeTasks !== "function" || typeof adapter.executeCommand !== "function") throw new Error("ECS Exec adapter is incomplete.");
  const response = await adapter.describeTasks({ taskArns: [selectedTaskArn], includeTags: true });
  const task = revalidateExactTargetTask({ tasks: response?.tasks, selectedTaskArn, ...expected });
  await adapter.executeCommand({ taskArn: task.taskArn, container: expected.containerName, command });
  return task;
}

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

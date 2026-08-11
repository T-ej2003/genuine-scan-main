const executeCommandAgentConnected = (task) =>
  task?.managedAgents?.some((agent) => agent?.name === "ExecuteCommandAgent" && agent?.lastStatus === "RUNNING") === true;

export const requireExecuteCommandEnabled = (service) => {
  if (service?.enableExecuteCommand !== true) throw new Error("ECS Exec is disabled on the target service");
  return true;
};

export const selectTargetTask = ({ tasks, expectedClusterArn, expectedTaskDefinitionArn, expectedImageDigest, serviceName, containerName }) => {
  const matching = (Array.isArray(tasks) ? tasks : []).filter((task) => {
    const container = task?.containers?.find((entry) => entry?.name === containerName);
    return task?.clusterArn === expectedClusterArn
      && task?.taskDefinitionArn === expectedTaskDefinitionArn
      && task?.lastStatus === "RUNNING"
      && task?.group === `service:${serviceName}`
      && container?.imageDigest === expectedImageDigest
      && executeCommandAgentConnected(task);
  });
  if (matching.length === 0) throw new Error("no running target task has a connected ECS Exec agent");
  matching.sort((left, right) => String(left.taskArn).localeCompare(String(right.taskArn)));
  return { selectedTask: matching[0], matchingTaskCount: matching.length };
};

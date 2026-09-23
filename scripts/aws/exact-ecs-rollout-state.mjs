import fs from "node:fs";
import { pathToFileURL } from "node:url";

const fail = (message) => { throw new Error(`Exact ECS rollout verification failed: ${message}`); };

export function classifyExactEcsRollout({ response, expectedTaskDefinitionArn, expectedClusterName, expectedServiceName, expectedDesiredCount }) {
  const arn = /^arn:(aws(?:-[a-z]+)?):ecs:([^:]+):(\d{12}):task-definition\/(.+):([1-9]\d*)$/.exec(expectedTaskDefinitionArn || "");
  if (!arn || typeof expectedClusterName !== "string" || !expectedClusterName || typeof expectedServiceName !== "string" || !expectedServiceName || !Number.isInteger(expectedDesiredCount) || expectedDesiredCount < 1) fail("expected rollout identity is malformed.");
  const expectedClusterArn = `arn:${arn[1]}:ecs:${arn[2]}:${arn[3]}:cluster/${expectedClusterName}`;
  const expectedServiceArn = `arn:${arn[1]}:ecs:${arn[2]}:${arn[3]}:service/${expectedClusterName}/${expectedServiceName}`;
  if (!Array.isArray(response?.failures) || response.failures.length !== 0 || !Array.isArray(response.services) || response.services.length !== 1) fail("DescribeServices response is malformed or reports a failure.");
  const service = response.services[0];
  if (service.serviceName !== expectedServiceName || service.serviceArn !== expectedServiceArn || service.clusterArn !== expectedClusterArn || service.status !== "ACTIVE") fail("service identity changed.");
  if (service.taskDefinition !== expectedTaskDefinitionArn) fail("ECS-native rollback or candidate displacement changed the service task definition.");
  if (service.desiredCount !== expectedDesiredCount) fail("service desired count changed.");
  if (!Array.isArray(service.deployments) || service.deployments.length !== 1) fail("the exact candidate is not the sole deployment.");
  const deployment = service.deployments[0];
  if (deployment.status !== "PRIMARY" || deployment.taskDefinition !== expectedTaskDefinitionArn || deployment.desiredCount !== expectedDesiredCount) fail("the exact candidate is no longer the expected PRIMARY deployment.");
  if (deployment.rolloutState === "FAILED") fail("the exact candidate rollout failed.");
  if (deployment.rolloutState === "IN_PROGRESS") return "CONTINUE";
  if (deployment.rolloutState !== "COMPLETED") fail("rollout state is missing or unrecognized.");
  if (service.runningCount !== expectedDesiredCount || service.pendingCount !== 0 || deployment.runningCount !== expectedDesiredCount || deployment.pendingCount !== 0) fail("completed rollout task counts do not match the exact desired state.");
  return "SUCCESS";
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [responsePath, expectedTaskDefinitionArn, expectedClusterName, expectedServiceName, expectedDesiredCountText] = process.argv.slice(2);
  process.stdout.write(`${classifyExactEcsRollout({
    response: JSON.parse(fs.readFileSync(responsePath, "utf8")),
    expectedTaskDefinitionArn,
    expectedClusterName,
    expectedServiceName,
    expectedDesiredCount: Number(expectedDesiredCountText),
  })}\n`);
}

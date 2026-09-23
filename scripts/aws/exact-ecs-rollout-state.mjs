import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

const fail = (message) => { throw new Error(`Exact ECS rollout verification failed: ${message}`); };
export const ROLLOUT_POLL_INTERVAL_MS = 15_000;
export const MAX_ROLLOUT_WAIT_MS = 600_000;
export const AWS_CLI_CONNECT_TIMEOUT_SECONDS = 10;
export const AWS_CLI_READ_TIMEOUT_SECONDS = 30;

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

export function waitForExactEcsRollout({
  expectedTaskDefinitionArn,
  expectedClusterName,
  expectedServiceName,
  expectedDesiredCount,
  describeServices,
  monotonicNow = () => performance.now(),
  sleep,
  classify = classifyExactEcsRollout,
  maxWaitMs = MAX_ROLLOUT_WAIT_MS,
  pollIntervalMs = ROLLOUT_POLL_INTERVAL_MS,
}) {
  if (typeof describeServices !== "function" || typeof sleep !== "function" || typeof monotonicNow !== "function" || typeof classify !== "function"
      || !Number.isFinite(maxWaitMs) || maxWaitMs <= 0 || !Number.isFinite(pollIntervalMs) || pollIntervalMs <= 0) fail("poll configuration is malformed.");
  let previousNow = -Infinity;
  const now = () => {
    const value = monotonicNow();
    if (!Number.isFinite(value) || value < 0 || value < previousNow) fail("monotonic clock is unavailable or moved backwards.");
    previousNow = value;
    return value;
  };
  const deadline = now() + maxWaitMs;
  while (true) {
    const beforeDescribe = now();
    const callBudgetMs = deadline - beforeDescribe;
    if (callBudgetMs <= 0) fail(`rollout remained IN_PROGRESS beyond ${maxWaitMs / 1000} seconds.`);
    const response = describeServices({ timeoutMs: callBudgetMs });
    const result = classify({ response, expectedTaskDefinitionArn, expectedClusterName, expectedServiceName, expectedDesiredCount });
    const afterClassification = now();
    if (afterClassification >= deadline) fail(`rollout remained IN_PROGRESS beyond ${maxWaitMs / 1000} seconds.`);
    if (result === "SUCCESS") return "SUCCESS";
    if (result !== "CONTINUE") fail(`classifier returned unexpected result ${String(result)}.`);
    sleep(Math.min(pollIntervalMs, deadline - afterClassification));
  }
}

function describeServicesWithAwsCli({ responsePath, region, clusterName, serviceName, timeoutMs }) {
  const remainingSeconds = Math.floor(timeoutMs / 1000);
  if (remainingSeconds < 1) fail("rollout deadline leaves no bounded AWS call budget.");
  const connectTimeout = Math.min(AWS_CLI_CONNECT_TIMEOUT_SECONDS, remainingSeconds);
  const readTimeout = Math.min(AWS_CLI_READ_TIMEOUT_SECONDS, remainingSeconds);
  const result = spawnSync("aws", [
    "ecs", "describe-services",
    "--region", region,
    "--cluster", clusterName,
    "--services", serviceName,
    "--cli-connect-timeout", String(connectTimeout),
    "--cli-read-timeout", String(readTimeout),
  ], { encoding: "utf8", timeout: Math.max(1, Math.floor(timeoutMs)), maxBuffer: 1024 * 1024 });
  if (result.error || result.status !== 0) fail(`DescribeServices failed within its rollout budget${result.error?.code ? ` (${result.error.code})` : ""}.`);
  fs.writeFileSync(responsePath, result.stdout);
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail("DescribeServices returned malformed JSON.");
  }
}

function sleepWithCommand(milliseconds) {
  const result = spawnSync("sleep", [String(milliseconds / 1000)]);
  if (result.error || result.status !== 0) fail("bounded rollout sleep failed.");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args[0] === "--poll") {
    const [, responsePath, region, expectedClusterName, expectedServiceName, expectedTaskDefinitionArn, expectedDesiredCountText] = args;
    process.stdout.write(`${waitForExactEcsRollout({
      expectedTaskDefinitionArn,
      expectedClusterName,
      expectedServiceName,
      expectedDesiredCount: Number(expectedDesiredCountText),
      describeServices: ({ timeoutMs }) => describeServicesWithAwsCli({ responsePath, region, clusterName: expectedClusterName, serviceName: expectedServiceName, timeoutMs }),
      sleep: sleepWithCommand,
    })}\n`);
  } else {
    const [responsePath, expectedTaskDefinitionArn, expectedClusterName, expectedServiceName, expectedDesiredCountText] = args;
    process.stdout.write(`${classifyExactEcsRollout({
      response: JSON.parse(fs.readFileSync(responsePath, "utf8")),
      expectedTaskDefinitionArn,
      expectedClusterName,
      expectedServiceName,
      expectedDesiredCount: Number(expectedDesiredCountText),
    })}\n`);
  }
}

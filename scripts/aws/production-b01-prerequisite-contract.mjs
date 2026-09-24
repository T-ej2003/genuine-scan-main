import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { assertEcsTaskDefinitionReadback } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/ecs-task-definition-readback.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";

export const B01_PREREQUISITE = Object.freeze({
  schemaVersion: 1,
  kind: "PRODUCTION_B01_PREREQUISITE_RECEIPT",
  rlsDeltaOriginSha: "0f7ae1a70eec588ef4fdcb2b53e9f42e831c4414",
  bridgeOriginSha: "e1c16977e9fdce7a19dc267ba3c816ef4ff14597",
  correctionBaseSha: "69e71ab21c847d27f8a76795a6de6f623313c8ad",
  recoveryBaseSha: "a2bed229ddfb893d4dcc53232ea5466d23d4e80a",
  environment: "production",
  migrationSetDigest: "6642442a81cd98c7a132d241fa98e50ae231510896c9da67ab70d86b050d02db",
  sourceContractSha256: "099399a7d3f4b2392acdba6c54bf1ac6a919ff60691e69d31023d32161d99e71",
  account: "368992683803",
  region: "eu-west-2",
  cluster: "mscqr-prod-euw2-main",
  executorFamily: "mscqr-production-b01-prerequisite",
  executorContainer: "production-b01-prerequisite",
  readOnlyFamily: "mscqr-production-b01-prerequisite-readonly",
  readOnlyContainer: "production-b01-prerequisite-readonly",
  eventCaptureLogGroup: "/aws/events/ecs/containerinsights/mscqr-prod-euw2-main/performance",
  legacyExpiredTaskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/a74666b43a80488c95746f4b7f789fb2",
  legacyExpiredTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b01-prerequisite:1",
  legacyExpiredDeploymentSourceSha: "69e71ab21c847d27f8a76795a6de6f623313c8ad",
  legacyExpiredRunTaskEventId: "953c6a11-ee35-4a54-aa74-b6f01d12957f",
  legacyExpiredRunTaskEventTime: "2026-09-23T22:43:02Z",
  executorImage: "368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:5b7809608386fed5c54ff2e09b0edb221664607c7cc5fb93b66b617ca08c28cc",
  predecessorSourceSha: "945692f49c6d262b0a54b9b8e4240ef4c21688eb",
  predecessorServiceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2",
  predecessorTaskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-backend-candidate:19",
  databaseIdentifier: "mscqr-production-rls-green-phase2",
  databaseName: "mscqr_production_rls_green_phase2",
  executionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
  administratorSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo:password::",
  logGroup: "/ecs/mscqr-production/full-rls-green",
  runtimePlatform: Object.freeze({ operatingSystemFamily: "LINUX", cpuArchitecture: "X86_64" }),
  maxReceiptAgeMs: 30 * 60 * 1000,
});

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
const TASK_DEFINITION = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b01-prerequisite:[1-9][0-9]*$/;

export const canonicalJson = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  return JSON.stringify(value);
};
export const canonicalSha256 = (value) => crypto.createHash("sha256").update(canonicalJson(value)).digest("hex");

export const buildB01ExecutorDefinition = (command) => ({
  family: B01_PREREQUISITE.executorFamily, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"], cpu: "1024", memory: "2048",
  executionRoleArn: B01_PREREQUISITE.executionRoleArn, runtimePlatform: B01_PREREQUISITE.runtimePlatform, volumes: [{ name: "executor-tmp" }],
  containerDefinitions: [{ name: B01_PREREQUISITE.executorContainer, image: B01_PREREQUISITE.executorImage, essential: true, entryPoint: ["node"], command,
    readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }], privileged: false,
    interactive: false, pseudoTerminal: false, environment: [{ name: "NODE_ENV", value: "production" }],
    secrets: [{ name: "MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD", valueFrom: B01_PREREQUISITE.administratorSecretArn }],
    logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": B01_PREREQUISITE.region, "awslogs-group": B01_PREREQUISITE.logGroup,
      "awslogs-stream-prefix": "b01-prerequisite" } } }],
});

export const buildB01ReadOnlyDefinition = (command) => {
  const definition = buildB01ExecutorDefinition(command);
  definition.family = B01_PREREQUISITE.readOnlyFamily;
  definition.containerDefinitions[0].name = B01_PREREQUISITE.readOnlyContainer;
  definition.containerDefinitions[0].logConfiguration.options["awslogs-stream-prefix"] = "b01-prerequisite-readonly";
  return definition;
};

export const buildB01RunTaskRequest = ({ taskDefinitionArn, deploymentSourceSha, readOnly = false }) => {
  assert.match(taskDefinitionArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b01-prerequisite(?:-readonly)?:[1-9][0-9]*$/);
  assert.match(deploymentSourceSha || "", SHA);
  return Object.freeze({ cluster: `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`,
    taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1, enableExecuteCommand: false,
    clientToken: canonicalSha256({ deploymentSourceSha, taskDefinitionArn, ...(readOnly ? { mode: "READ_ONLY" } : {}) }),
    networkConfiguration: appOnlyVerifierNetwork() });
};

export function normalizeB01RunTaskCloudTrailRequest(request, options) {
  assert.ok(request && typeof request === "object" && !Array.isArray(request));
  const expected = buildB01RunTaskRequest(options);
  assert.deepEqual(Object.keys(request).sort(), [...Object.keys(expected), "dryrun", "enableECSManagedTags"].sort());
  assert.equal(request.dryrun, false); assert.equal(request.enableECSManagedTags, false);
  const normalized = { ...request }; delete normalized.dryrun; delete normalized.enableECSManagedTags;
  assert.deepEqual(normalized, expected); return expected;
}

export function assertSemanticallyEmptyB01TaskOverrides(overrides, expectedContainer = B01_PREREQUISITE.executorContainer) {
  if (overrides === undefined) return true;
  assert.ok(overrides && typeof overrides === "object" && !Array.isArray(overrides), "B01 task overrides are malformed.");
  assert.ok(Object.keys(overrides).every((key) => key === "containerOverrides" || key === "inferenceAcceleratorOverrides"), "B01 task has an unknown runtime override.");
  if (Object.hasOwn(overrides, "inferenceAcceleratorOverrides")) assert.deepEqual(overrides.inferenceAcceleratorOverrides, []);
  if (Object.hasOwn(overrides, "containerOverrides")) {
    assert.ok(Array.isArray(overrides.containerOverrides));
    assert.ok(overrides.containerOverrides.length === 0 || overrides.containerOverrides.length === 1);
    if (overrides.containerOverrides.length === 1) assert.deepEqual(overrides.containerOverrides[0], { name: expectedContainer });
  }
  return true;
}

export function authenticateB01TerminalTaskEvents(events, { taskArn, taskDefinitionArn, launchEventTime, observationEventTime } = {}) {
  assert.ok(Array.isArray(events)); assert.match(taskArn || "", TASK); assert.match(taskDefinitionArn || "", TASK_DEFINITION);
  const launchTime = Date.parse(launchEventTime), observationTime = Date.parse(observationEventTime);
  assert.ok(Number.isFinite(launchTime)); if (observationEventTime !== undefined) assert.ok(Number.isFinite(observationTime) && observationTime >= launchTime);
  const matches = events.map((event) => JSON.parse(event.message)).filter((event) => event?.source === "aws.ecs"
    && event["detail-type"] === "ECS Task State Change" && event.detail?.taskArn === taskArn);
  assert.ok(matches.length > 0, "Durable ECS terminal evidence is unavailable.");
  const byId = new Map(); for (const event of matches) { assert.match(event.id || "", /^[0-9a-f-]{36}$/); const existing = byId.get(event.id);
    if (existing) assert.deepEqual(event, existing); else byId.set(event.id, event); }
  const ordered = [...byId.values()];
  const byVersion = new Map(); for (const event of ordered) { const version = event.detail?.version; assert.ok(Number.isInteger(version) && version > 0);
    const existing = byVersion.get(version);
    if (existing) assert.deepEqual(event, existing, "Contradictory ECS terminal evidence shares a task version."); else byVersion.set(version, event); }
  ordered.sort((left, right) => left.detail.version - right.detail.version); const event = ordered.at(-1), detail = event.detail;
  assert.equal(event.account, B01_PREREQUISITE.account); assert.equal(event.region, B01_PREREQUISITE.region); assert.deepEqual(event.resources, [taskArn]);
  const eventTime = Date.parse(event.time); assert.ok(eventTime >= launchTime); if (observationEventTime !== undefined) assert.ok(eventTime <= observationTime);
  assert.equal(detail.clusterArn, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(detail.taskArn, taskArn); assert.equal(detail.taskDefinitionArn, taskDefinitionArn); assert.equal(detail.group, `family:${B01_PREREQUISITE.executorFamily}`);
  assert.equal(detail.launchType, "FARGATE"); assert.equal(detail.desiredStatus, "STOPPED"); assert.equal(detail.lastStatus, "STOPPED");
  assert.equal(detail.containers?.length, 1); const container = detail.containers[0];
  assert.equal(container.name, B01_PREREQUISITE.executorContainer); assert.equal(container.lastStatus, "STOPPED"); assert.ok(Number.isInteger(container.exitCode));
  assert.equal(container.image, B01_PREREQUISITE.executorImage); assert.equal(container.imageDigest, B01_PREREQUISITE.executorImage.split("@")[1]);
  const body = { schemaVersion: 1, kind: "PRODUCTION_B01_TERMINAL_TASK_EVIDENCE", eventId: event.id, eventTime: event.time,
    taskArn, taskDefinitionArn, taskVersion: detail.version, containerExitCode: container.exitCode };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function collectB01TerminalTaskEvents(aws, taskArn, { launchEventTime, observationEventTime } = {}) {
  assert.equal(typeof aws, "function"); assert.match(taskArn || "", TASK);
  const startTime = Date.parse(launchEventTime), endTime = Date.parse(observationEventTime);
  assert.ok(Number.isFinite(startTime) && Number.isFinite(endTime) && endTime >= startTime, "ECS terminal evidence window is invalid.");
  const events = [], tokens = new Set(); let token;
  for (let page = 0; page < 20; page += 1) {
    const args = ["logs","filter-log-events","--region",B01_PREREQUISITE.region,"--log-group-name",B01_PREREQUISITE.eventCaptureLogGroup,
      "--filter-pattern",`\"${taskArn}\"`,"--start-time",String(startTime),"--end-time",String(endTime + 1),
      "--limit","100","--no-paginate",...(token ? ["--next-token",token] : [])];
    const response = aws(args); assert.ok(Array.isArray(response?.events) && response.events.length <= 100); events.push(...response.events);
    const next = response.nextToken; if (next === undefined) return Object.freeze(events);
    assert.ok(typeof next === "string" && next && !tokens.has(next), "ECS terminal evidence pagination is incomplete or cyclic."); tokens.add(next); token = next;
  }
  throw new Error("ECS terminal evidence exceeds the bounded page limit.");
}

export function assertB01EcsEventCapture({ logGroups, rules, targetsByRule } = {}) {
  assert.ok(Array.isArray(logGroups)); const groups = logGroups.filter(({ logGroupName }) => logGroupName === B01_PREREQUISITE.eventCaptureLogGroup);
  assert.equal(groups.length, 1); assert.ok(groups[0].retentionInDays === undefined
    || (Number.isInteger(groups[0].retentionInDays) && groups[0].retentionInDays >= 30));
  const expectedArn = `arn:aws:logs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:log-group:${B01_PREREQUISITE.eventCaptureLogGroup}`;
  if (groups[0].logGroupArn !== undefined) assert.equal(groups[0].logGroupArn, expectedArn);
  if (groups[0].arn !== undefined) assert.ok(groups[0].arn === expectedArn || groups[0].arn === `${expectedArn}:*`, "CloudWatch Logs group ARN is not canonical.");
  assert.ok(groups[0].logGroupArn !== undefined || groups[0].arn !== undefined, "CloudWatch Logs group ARN is missing.");
  assert.ok(Array.isArray(rules)); const targeted = rules.filter((rule) => (targetsByRule?.[rule.Name] || []).some((target) => target.Arn === expectedArn));
  assert.equal(targeted.length, 1, "Exact durable ECS event capture is unavailable or ambiguous.");
  const rule = targeted[0]; assert.equal(rule.State, "ENABLED"); let pattern;
  try { pattern = JSON.parse(rule.EventPattern); } catch { assert.fail("ECS event capture pattern is malformed."); }
  assert.ok(pattern && typeof pattern === "object" && !Array.isArray(pattern));
  assert.ok(Object.keys(pattern).every((key) => key === "source" || key === "detail-type"));
  assert.deepEqual(pattern.source, ["aws.ecs"]);
  if (Object.hasOwn(pattern, "detail-type")) assert.deepEqual(pattern["detail-type"], ["ECS Task State Change"]);
  const targets = targetsByRule[rule.Name]; assert.equal(targets.length, 1); assert.deepEqual(Object.keys(targets[0]).sort(), ["Arn","Id"].sort());
  assert.equal(targets[0].Arn, expectedArn);
  return Object.freeze({ logGroupName: groups[0].logGroupName, logGroupArn: expectedArn, retentionInDays: groups[0].retentionInDays,
    ruleName: rule.Name, targetId: targets[0].Id });
}

export function assertB01RunTaskRequestEvidence(evidence, { taskArn, taskDefinitionArn, deploymentSourceSha, readOnly = false } = {}) {
  assert.deepEqual(Object.keys(evidence || {}).sort(), ["cluster","count","enableExecuteCommand","eventId","eventTime","launchType","overridesPresent","requestSha256","taskArn","taskDefinitionArn"].sort());
  assert.match(evidence.eventId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/); assert.ok(Number.isFinite(Date.parse(evidence.eventTime)));
  assert.equal(evidence.taskArn, taskArn); assert.equal(evidence.taskDefinitionArn, taskDefinitionArn);
  assert.equal(evidence.cluster, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(evidence.launchType, "FARGATE"); assert.equal(evidence.count, 1); assert.equal(evidence.enableExecuteCommand, false);
  assert.equal(evidence.overridesPresent, false);
  assert.equal(evidence.requestSha256, canonicalSha256(buildB01RunTaskRequest({ taskDefinitionArn, deploymentSourceSha, readOnly })));
  return true;
}

export function assertB01AmbiguousMutationTaskQuiescent({ task, taskArn, deploymentSourceSha, runTaskRequestEvidence,
  activeMutationTaskArns = [] } = {}) {
  assert.match(taskArn || "", TASK); assert.equal(task?.taskArn, taskArn);
  assert.match(task?.taskDefinitionArn || "", TASK_DEFINITION);
  assert.equal(task?.clusterArn, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(task?.group, `family:${B01_PREREQUISITE.executorFamily}`); assert.equal(task?.launchType, "FARGATE");
  assert.equal(task?.lastStatus, "STOPPED"); assert.equal(task?.desiredStatus, "STOPPED");
  assert.equal(task?.stopCode, "EssentialContainerExited"); assert.ok(Number.isFinite(Date.parse(task?.stoppedAt)));
  assert.ok(Number.isFinite(Date.parse(task?.executionStoppedAt)));
  assert.ok(Date.parse(task.createdAt) <= Date.parse(task.executionStoppedAt));
  assert.ok(Date.parse(task.executionStoppedAt) <= Date.parse(task.stoppedAt));
  assert.equal(task?.enableExecuteCommand, false); assertSemanticallyEmptyB01TaskOverrides(task?.overrides);
  assert.deepEqual(activeMutationTaskArns, []);
  assert.equal(task?.containers?.length, 1); const container = task.containers[0];
  assert.equal(container?.name, B01_PREREQUISITE.executorContainer); assert.equal(container?.lastStatus, "STOPPED");
  assert.equal(container?.image, B01_PREREQUISITE.executorImage); assert.equal(container?.imageDigest, B01_PREREQUISITE.executorImage.split("@")[1]);
  assert.ok(Number.isInteger(container?.exitCode));
  assertB01RunTaskRequestEvidence(runTaskRequestEvidence, { taskArn, taskDefinitionArn: task.taskDefinitionArn, deploymentSourceSha });
  const body = { schemaVersion: 1, kind: "PRODUCTION_B01_AMBIGUOUS_TASK_QUIESCENCE", taskArn,
    taskDefinitionArn: task.taskDefinitionArn, deploymentSourceSha, stoppedAt: new Date(task.stoppedAt).toISOString(),
    executionStoppedAt: new Date(task.executionStoppedAt).toISOString(), runTaskRequestEvidence };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertB01ExpiredMutationTaskQuiescent({ taskArn, taskDefinitionArn, deploymentSourceSha,
  runTaskRequestEvidence, launchHistoryEvidenceSha256, terminalTaskEvidence, activeMutationTaskArns = [] } = {}) {
  assert.match(taskArn || "", TASK); assert.match(taskDefinitionArn || "", TASK_DEFINITION);
  assert.match(deploymentSourceSha || "", SHA); assert.match(launchHistoryEvidenceSha256 || "", HASH);
  assert.deepEqual(activeMutationTaskArns, []);
  const legacy = taskArn === B01_PREREQUISITE.legacyExpiredTaskArn
    && taskDefinitionArn === B01_PREREQUISITE.legacyExpiredTaskDefinitionArn
    && deploymentSourceSha === B01_PREREQUISITE.legacyExpiredDeploymentSourceSha
    && runTaskRequestEvidence?.eventId === B01_PREREQUISITE.legacyExpiredRunTaskEventId
    && Date.parse(runTaskRequestEvidence?.eventTime) === Date.parse(B01_PREREQUISITE.legacyExpiredRunTaskEventTime);
  if (terminalTaskEvidence === undefined) assert.equal(legacy, true, "Expired task lacks durable terminal evidence.");
  else { assert.equal(terminalTaskEvidence.taskArn, taskArn); assert.equal(terminalTaskEvidence.taskDefinitionArn, taskDefinitionArn);
    assert.match(terminalTaskEvidence.evidenceSha256 || "", HASH);
    assert.equal(terminalTaskEvidence.evidenceSha256, canonicalSha256((({ evidenceSha256: _, ...body }) => body)(terminalTaskEvidence))); }
  assertB01RunTaskRequestEvidence(runTaskRequestEvidence, { taskArn, taskDefinitionArn, deploymentSourceSha });
  const body = { schemaVersion: 1, kind: "PRODUCTION_B01_EXPIRED_TASK_QUIESCENCE", taskArn, taskDefinitionArn,
    deploymentSourceSha, launchHistoryEvidenceSha256, terminalTaskEvidence: terminalTaskEvidence || null,
    legacyExpiredEvidence: terminalTaskEvidence === undefined, runTaskRequestEvidence };
  return Object.freeze({ ...body, evidenceSha256: canonicalSha256(body) });
}

export function assertB01LivePredecessor({ service, taskDefinition, repository, imageDetails } = {}) {
  assert.equal(service?.serviceArn, B01_PREREQUISITE.predecessorServiceArn);
  assert.equal(service?.serviceName, "mscqr-backend-servi-euw2");
  assert.equal(service?.clusterArn, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(service?.status, "ACTIVE"); assert.equal(service?.taskDefinition, B01_PREREQUISITE.predecessorTaskDefinitionArn);
  assert.equal(service?.desiredCount, 2); assert.equal(service?.runningCount, 2); assert.equal(service?.pendingCount, 0);
  assert.equal(service?.enableExecuteCommand, true); assert.equal(service?.propagateTags, "TASK_DEFINITION");
  assert.deepEqual(service?.deploymentConfiguration?.deploymentCircuitBreaker, { enable: true, rollback: true });
  assert.equal(service?.deploymentConfiguration?.alarms?.rollback, true); assert.equal(service?.deploymentConfiguration?.alarms?.enable, true);
  assert.deepEqual([...(service?.deploymentConfiguration?.alarms?.alarmNames || [])].sort(), ["mscqr-production-backend-target-5xx", "mscqr-production-backend-unhealthy-hosts"].sort());
  assert.equal(service?.deployments?.length, 1); const deployment = service.deployments[0];
  assert.equal(deployment?.status, "PRIMARY"); assert.equal(deployment?.taskDefinition, service.taskDefinition);
  assert.equal(deployment?.desiredCount, 2); assert.equal(deployment?.runningCount, 2); assert.equal(deployment?.pendingCount, 0);
  assert.equal(deployment?.failedTasks, 0); assert.equal(deployment?.rolloutState, "COMPLETED");

  assert.equal(taskDefinition?.taskDefinitionArn, B01_PREREQUISITE.predecessorTaskDefinitionArn);
  assert.equal(taskDefinition?.family, "mscqr-production-rls-green-backend-candidate"); assert.equal(taskDefinition?.revision, 19);
  assert.equal(taskDefinition?.status, "ACTIVE"); assert.equal(taskDefinition?.networkMode, "awsvpc");
  assert.deepEqual(taskDefinition?.requiresCompatibilities, ["FARGATE"]); assert.equal(taskDefinition?.cpu, "2048"); assert.equal(taskDefinition?.memory, "4096");
  assert.equal(taskDefinition?.executionRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution");
  assert.equal(taskDefinition?.taskRoleArn, "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task");
  assert.deepEqual(taskDefinition?.runtimePlatform, B01_PREREQUISITE.runtimePlatform);
  assert.equal(taskDefinition?.containerDefinitions?.length, 1); const backend = taskDefinition.containerDefinitions[0];
  assert.equal(backend?.name, "backend"); assert.equal(backend?.image, B01_PREREQUISITE.executorImage); assert.equal(backend?.essential, true);
  assert.deepEqual(backend?.entryPoint || [], []); assert.deepEqual(backend?.command || [], []);
  assert.equal(backend?.readonlyRootFilesystem, true); assert.equal(backend?.privileged, false);

  assert.equal(repository?.repositoryArn, `arn:aws:ecr:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:repository/mscqr-backend`);
  assert.equal(repository?.repositoryName, "mscqr-backend"); assert.equal(repository?.registryId, B01_PREREQUISITE.account); assert.equal(repository?.imageTagMutability, "IMMUTABLE");
  assert.equal(imageDetails?.length, 1); assert.equal(imageDetails[0]?.imageDigest, B01_PREREQUISITE.executorImage.split("@")[1]);
  assert.deepEqual((imageDetails[0]?.imageTags || []).filter((tag) => SHA.test(tag)), [B01_PREREQUISITE.predecessorSourceSha]);
  return true;
}

const bridgeFiles = Object.freeze(new Map([
  [".github/workflows/production-deploy.yml", "BRIDGE_WORKFLOW_WIRING"],
  ["scripts/aws/apply-production-b01-prerequisite.mjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/aws/production-b01-prerequisite-contract.mjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/aws/production-b01-prerequisite-executor.cjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/aws/production-b01-prerequisite-readonly.cjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/aws/probe-production-b01-prerequisite.mjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/aws/production-b01-prerequisite-policy-state.json", "GENERATED_CONSEQUENCE_DIRECTLY_REQUIRED_BY_BRIDGE"],
  ["scripts/aws/verify-production-b01-prerequisite-handoff.mjs", "BRIDGE_DEPLOYMENT_TOOLING"],
  ["scripts/tests/production-b01-prerequisite.test.mjs", "BRIDGE_TEST"],
  ["scripts/tests/production-full-rls-package-postgres18.test.mjs", "BRIDGE_TEST"],
  ["documents/security/rls-program/production-b01-prerequisite-bridge.md", "BRIDGE_DOCUMENTATION"],
  ["package.json", "BRIDGE_DEPLOYMENT_TOOLING"],
]));

export function classifyBridgeFiles(files) {
  assert.ok(Array.isArray(files));
  const entries = files.map((file) => {
    assert.ok(typeof file === "string" && file.length > 0 && !file.includes("\0"));
    return Object.freeze({ file, classification: bridgeFiles.get(file) || "UNCLASSIFIED" });
  });
  assert.equal(new Set(entries.map(({ file }) => file)).size, entries.length, "Bridge diff contains duplicate paths.");
  assert.equal(entries.filter(({ classification }) => classification === "UNCLASSIFIED").length, 0, "Bridge diff contains an unclassified or semantic source change.");
  return Object.freeze(entries);
}

export function attestBridgeDiff({ deploymentSourceSha, repositoryRoot = process.cwd(), git = (args) => execFileSync("git", args, { cwd: repositoryRoot, encoding: "utf8" }).trim() } = {}) {
  assert.match(deploymentSourceSha || "", SHA);
  const attestRange = (base, target) => {
    git(["merge-base", "--is-ancestor", base, target]);
    const names = git(["diff", "--name-only", `${base}..${target}`]);
    const classified = classifyBridgeFiles(names ? names.split("\n") : []); assert.ok(classified.length > 0, "Bridge diff is empty.");
    const patch = git(["diff", "--binary", "--full-index", `${base}..${target}`, "--", ...classified.map(({ file }) => file)]); assert.ok(patch.length > 0, "Bridge patch is empty.");
    const hunkCounts = new Map(classified.map(({ file }) => [file, 0])); let current;
    for (const line of patch.split("\n")) { const header = /^diff --git a\/(.+) b\/(.+)$/.exec(line);
      if (header) { assert.equal(header[1], header[2]); assert.ok(hunkCounts.has(header[1]), "Bridge patch contains an unclassified path."); current = header[1]; }
      else if (line.startsWith("@@ ")) { assert.ok(current); hunkCounts.set(current, hunkCounts.get(current) + 1); } }
    const entries = Object.freeze(classified.map((entry) => { const hunkCount = hunkCounts.get(entry.file); assert.ok(hunkCount > 0, `Bridge file ${entry.file} has no classified hunk.`); return Object.freeze({ ...entry, hunkCount }); }));
    return Object.freeze({ base, target, entries, patchSha256: crypto.createHash("sha256").update(patch).digest("hex") });
  };
  assert.equal(git(["rev-parse", `${B01_PREREQUISITE.bridgeOriginSha}^1`]), B01_PREREQUISITE.rlsDeltaOriginSha, "Reviewed bridge origin does not immediately follow the RLS delta origin.");
  assert.equal(git(["rev-parse", `${B01_PREREQUISITE.correctionBaseSha}^1`]), B01_PREREQUISITE.bridgeOriginSha, "Reviewed predecessor correction does not immediately follow the bridge origin.");
  assert.equal(git(["rev-parse", `${B01_PREREQUISITE.recoveryBaseSha}^1`]), B01_PREREQUISITE.correctionBaseSha, "Reviewed recovery base does not immediately follow the predecessor correction.");
  assert.equal(git(["rev-parse", `${deploymentSourceSha}^1`]), B01_PREREQUISITE.recoveryBaseSha, "Deployment source is not the immediate protected-main expired-task recovery successor.");
  const body = { schemaVersion: 3, rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, bridgeOriginSha: B01_PREREQUISITE.bridgeOriginSha, deploymentSourceSha,
    bridge: attestRange(B01_PREREQUISITE.rlsDeltaOriginSha, B01_PREREQUISITE.bridgeOriginSha), predecessorCorrection: attestRange(B01_PREREQUISITE.bridgeOriginSha, B01_PREREQUISITE.correctionBaseSha),
    runtimeEvidence: attestRange(B01_PREREQUISITE.correctionBaseSha, B01_PREREQUISITE.recoveryBaseSha),
    recovery: attestRange(B01_PREREQUISITE.recoveryBaseSha, deploymentSourceSha) };
  return Object.freeze({ ...body, attestationSha256: canonicalSha256(body) });
}

export function buildB01PrerequisiteReceipt(input) {
  const body = {
    schemaVersion: B01_PREREQUISITE.schemaVersion, kind: B01_PREREQUISITE.kind,
    rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha,
    deploymentSourceSha: input.deploymentSourceSha,
    environment: B01_PREREQUISITE.environment,
    predecessorRlsIdentity: input.predecessorRlsIdentity,
    successorRlsIdentity: input.successorRlsIdentity,
    liveRlsIdentity: input.liveRlsIdentity,
    sourceContractSha256: B01_PREREQUISITE.sourceContractSha256,
    migrationSetDigest: B01_PREREQUISITE.migrationSetDigest,
    executorSourceSha256: input.executorSourceSha256,
    executorContractSha256: input.executorContractSha256,
    executorCommandSha256: input.executorCommandSha256,
    executionResult: input.executionResult,
    writeCount: input.writeCount,
    taskArn: input.taskArn,
    taskDefinitionArn: input.taskDefinitionArn,
    runTaskRequestEvidence: input.runTaskRequestEvidence,
    terminalTaskEvidence: input.terminalTaskEvidence,
    bridgeDiffAttestation: input.bridgeDiffAttestation,
    executedAt: input.executedAt,
    expiresAt: input.expiresAt,
  };
  return assertB01PrerequisiteReceipt({ ...body, receiptSha256: canonicalSha256(body) }, { deploymentSourceSha: input.deploymentSourceSha, bridgeDiffAttestation: input.bridgeDiffAttestation, now: Date.parse(input.executedAt) });
}

export function assertB01PrerequisiteReceipt(value, { deploymentSourceSha, bridgeDiffAttestation, now = Date.now() } = {}) {
  assert.match(deploymentSourceSha || "", SHA);
  assert.equal(value?.schemaVersion, 1); assert.equal(value?.kind, B01_PREREQUISITE.kind);
  assert.equal(value.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha);
  assert.equal(value.deploymentSourceSha, deploymentSourceSha);
  assert.equal(value.environment, B01_PREREQUISITE.environment);
  for (const key of ["predecessorRlsIdentity", "successorRlsIdentity", "liveRlsIdentity", "sourceContractSha256", "migrationSetDigest", "executorSourceSha256", "executorContractSha256", "executorCommandSha256", "receiptSha256"]) assert.match(value[key] || "", HASH, `${key} is invalid.`);
  assert.equal(value.liveRlsIdentity, value.successorRlsIdentity);
  assert.equal(value.sourceContractSha256, B01_PREREQUISITE.sourceContractSha256);
  assert.equal(value.migrationSetDigest, B01_PREREQUISITE.migrationSetDigest);
  assert.ok(value.executionResult === "APPLIED" && value.writeCount === 7 || value.executionResult === "ALREADY_CONVERGED" && value.writeCount === 0);
  assert.match(value.taskArn || "", TASK); assert.match(value.taskDefinitionArn || "", TASK_DEFINITION);
  assertB01RunTaskRequestEvidence(value.runTaskRequestEvidence, { taskArn: value.taskArn, taskDefinitionArn: value.taskDefinitionArn, deploymentSourceSha });
  assert.equal(value.terminalTaskEvidence?.taskArn, value.taskArn); assert.equal(value.terminalTaskEvidence?.taskDefinitionArn, value.taskDefinitionArn);
  assert.match(value.terminalTaskEvidence?.evidenceSha256 || "", HASH);
  assert.equal(value.terminalTaskEvidence.evidenceSha256, canonicalSha256((({ evidenceSha256: _, ...body }) => body)(value.terminalTaskEvidence)));
  assert.deepEqual(value.bridgeDiffAttestation, bridgeDiffAttestation);
  assert.equal(value.bridgeDiffAttestation?.rlsDeltaOriginSha, B01_PREREQUISITE.rlsDeltaOriginSha);
  assert.equal(value.bridgeDiffAttestation?.bridgeOriginSha, B01_PREREQUISITE.bridgeOriginSha);
  assert.equal(value.bridgeDiffAttestation?.deploymentSourceSha, deploymentSourceSha);
  assert.equal(value.bridgeDiffAttestation?.attestationSha256, canonicalSha256((({ attestationSha256: _, ...body }) => body)(value.bridgeDiffAttestation)));
  const executed = Date.parse(value.executedAt), expires = Date.parse(value.expiresAt);
  assert.ok(Number.isFinite(executed) && Number.isFinite(expires) && expires - executed === B01_PREREQUISITE.maxReceiptAgeMs && now >= executed && now < expires, "Prerequisite receipt is stale.");
  const { receiptSha256, ...body } = value; assert.equal(receiptSha256, canonicalSha256(body));
  return Object.freeze(value);
}

export function assertB01ReceiptExecutorContract(receipt, contract) {
  assert.equal(receipt.rlsDeltaOriginSha, contract.rlsDeltaOriginSha);
  assert.equal(receipt.deploymentSourceSha, contract.deploymentSourceSha);
  assert.equal(receipt.sourceContractSha256, contract.sourceContractSha256);
  assert.equal(receipt.migrationSetDigest, contract.migrationSetDigest);
  assert.equal(receipt.executorSourceSha256, contract.executorSourceSha256);
  assert.equal(receipt.executorContractSha256, canonicalSha256(contract));
  assert.equal(receipt.predecessorRlsIdentity, contract.predecessorRlsIdentity);
  assert.equal(receipt.successorRlsIdentity, contract.successorRlsIdentity);
  assert.equal(receipt.liveRlsIdentity, contract.successorRlsIdentity);
  return true;
}

export function assertB01ExecutorAwsEvidence({ receipt, task, taskDefinition, expectedExecutorSourceSha256 }) {
  assert.equal(task?.taskArn, receipt.taskArn); assert.equal(task?.taskDefinitionArn, receipt.taskDefinitionArn);
  assert.equal(task?.clusterArn, `arn:aws:ecs:${B01_PREREQUISITE.region}:${B01_PREREQUISITE.account}:cluster/${B01_PREREQUISITE.cluster}`);
  assert.equal(task?.lastStatus, "STOPPED"); assert.equal(task?.stopCode, "EssentialContainerExited");
  assert.equal(task?.enableExecuteCommand, false);
  assertB01RunTaskRequestEvidence(receipt.runTaskRequestEvidence, { taskArn: task.taskArn, taskDefinitionArn: task.taskDefinitionArn,
    deploymentSourceSha: receipt.deploymentSourceSha });
  assertSemanticallyEmptyB01TaskOverrides(task?.overrides, B01_PREREQUISITE.executorContainer);
  assert.equal(task?.containers?.length, 1); assert.equal(task.containers[0].name, B01_PREREQUISITE.executorContainer); assert.equal(task.containers[0].exitCode, 0);
  const requestedAt = Date.parse(receipt.runTaskRequestEvidence.eventTime), startedAt = Date.parse(task.startedAt), stoppedAt = Date.parse(task.stoppedAt), executedAt = Date.parse(receipt.executedAt);
  assert.ok(Number.isFinite(requestedAt) && Number.isFinite(startedAt) && Number.isFinite(stoppedAt) && requestedAt <= startedAt
    && startedAt - requestedAt < 5 * 60 * 1000 && startedAt <= executedAt && executedAt <= stoppedAt);
  assertEcsTaskDefinitionReadback({ definition: taskDefinition, taskDefinitionArn: receipt.taskDefinitionArn,
    expected: buildB01ExecutorDefinition(taskDefinition?.containerDefinitions?.find(({ name }) => name === B01_PREREQUISITE.executorContainer)?.command), label: "B01 prerequisite evidence" });
  const containers = taskDefinition?.containerDefinitions?.filter(({ name }) => name === B01_PREREQUISITE.executorContainer) || [];
  assert.equal(containers.length, 1); assert.deepEqual(containers[0].entryPoint, ["node"]);
  assert.equal(canonicalSha256(containers[0].command), receipt.executorCommandSha256);
  assert.equal(crypto.createHash("sha256").update(containers[0].command?.[1] || "").digest("hex"), expectedExecutorSourceSha256);
  assert.equal(receipt.executorSourceSha256, expectedExecutorSourceSha256);
  return true;
}

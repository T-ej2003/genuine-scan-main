import assert from "node:assert/strict";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";

export const HISTORICAL_RUNTIME_KIND = "EXACT_HISTORICAL_RUNTIME_BASELINE";
const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const family = "mscqr-production-rls-green-worker-candidate";
const taskPattern = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
const definitionPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-worker-candidate:[1-9][0-9]*$/;
const keys = (value, expected) => assert.deepEqual(Object.keys(value || {}).sort(), expected.sort());

export function assertHistoricalRuntimeReference(reference) {
  keys(reference, ["schemaVersion", "kind", "historicalGovernedDeploymentProvenance", "historicalNormalDeploymentReceipt", "repository", "recoverySourceSha", "recoveryTreeSha256", "bootstrap", "runtime", "registration", "launch", "referenceSha256"]);
  assert.equal(reference.schemaVersion, 1); assert.equal(reference.kind, HISTORICAL_RUNTIME_KIND);
  assert.equal(reference.historicalGovernedDeploymentProvenance, false); assert.equal(reference.historicalNormalDeploymentReceipt, false);
  assert.equal(reference.repository, "T-ej2003/genuine-scan-main"); assert.match(reference.recoverySourceSha, SHA); assert.match(reference.recoveryTreeSha256, HASH);
  keys(reference.bootstrap, ["generation", "componentStateSha256", "workflow", "githubRunId"]);
  assert.equal(reference.bootstrap.generation, 1); assert.match(reference.bootstrap.componentStateSha256, HASH);
  assert.equal(reference.bootstrap.workflow, "T-ej2003/genuine-scan-main/.github/workflows/bootstrap-production-component-deployment-state.yml@refs/heads/main");
  assert.match(reference.bootstrap.githubRunId, /^[1-9][0-9]*$/);
  const runtime = reference.runtime;
  keys(runtime, ["account", "region", "clusterArn", "taskArn", "taskDefinitionArn", "taskDefinitionSha256", "sourceSha", "imageDigest", "taskRoleArn", "executionRoleArn", "effectiveConfigurationSha256", "network", "createdAt"]);
  assert.equal(runtime.account, STAGE_B.account); assert.equal(runtime.region, STAGE_B.region); assert.equal(runtime.clusterArn, STAGE_B.clusterArn);
  assert.match(runtime.taskArn, taskPattern); assert.match(runtime.taskDefinitionArn, definitionPattern);
  assert.match(runtime.taskDefinitionSha256, HASH); assert.match(runtime.sourceSha, SHA); assert.match(runtime.imageDigest, /^sha256:[a-f0-9]{64}$/);
  for (const name of ["taskRoleArn", "executionRoleArn"]) assert.equal(runtime[name], `arn:aws:iam::368992683803:role/mscqr-production-rls-green-worker-${name === "taskRoleArn" ? "task" : "execution"}`);
  assert.match(runtime.effectiveConfigurationSha256, HASH); assert.ok(Number.isFinite(Date.parse(runtime.createdAt)));
  keys(runtime.network, ["eniId", "subnetId", "privateIp", "securityGroupIds", "assignPublicIp"]);
  assert.match(runtime.network.eniId, /^eni-[a-f0-9]+$/); assert.match(runtime.network.subnetId, /^subnet-[a-f0-9]+$/);
  assert.match(runtime.network.privateIp, /^\d+\.\d+\.\d+\.\d+$/); assert.equal(runtime.network.assignPublicIp, "DISABLED");
  assert.ok(runtime.network.securityGroupIds.length); assert.deepEqual(runtime.network.securityGroupIds, [...new Set(runtime.network.securityGroupIds)].sort());
  for (const id of runtime.network.securityGroupIds) assert.match(id, /^sg-[a-f0-9]+$/);
  for (const [name, operation] of [["registration", "RegisterTaskDefinition"], ["launch", "RunTask"]]) {
    const event = reference[name]; keys(event, ["eventId", "eventTime", "eventSha256", "actorArn", "mfaAuthenticated", "operation"]);
    assert.match(event.eventId, /^[a-f0-9-]{36}$/); assert.match(event.eventSha256, HASH); assert.ok(Number.isFinite(Date.parse(event.eventTime)));
    assert.equal(event.actorArn, "arn:aws:iam::368992683803:root"); assert.equal(event.mfaAuthenticated, true); assert.equal(event.operation, operation);
  }
  const { referenceSha256, ...body } = reference;
  assert.equal(referenceSha256, canonicalSha256(body), "Historical runtime reference integrity changed");
  return reference;
}

// Hash the complete definition/configuration rather than publishing environment
// values. Secrets remain ARN references in that hash; no secret value is read.
export function readHistoricalRuntimeIdentity({ reader, taskArn, authenticatePublication = true }) {
  assert.match(taskArn || "", taskPattern);
  const described = reader.describeTasks([taskArn]); assert.equal(described.failures?.length, 0); assert.equal(described.tasks?.length, 1);
  const task = described.tasks[0]; assert.equal(task.taskArn, taskArn); assert.equal(task.clusterArn, STAGE_B.clusterArn);
  assert.equal(task.lastStatus, "RUNNING"); assert.equal(task.desiredStatus, "RUNNING"); assert.ok(!String(task.group).startsWith("service:"));
  assert.match(task.taskDefinitionArn, definitionPattern);
  const response = reader.describeTaskDefinition(task.taskDefinitionArn), definition = response.taskDefinition;
  assert.equal(definition.taskDefinitionArn, task.taskDefinitionArn); assert.equal(definition.family, family); assert.equal(definition.status, "ACTIVE");
  const worker = definition.containerDefinitions?.filter(({ name }) => name === "worker"); assert.equal(worker?.length, 1);
  assert.equal(definition.networkMode, "awsvpc"); assert.equal(task.launchType, "FARGATE");
  assert.deepEqual(worker[0].entryPoint, ["node", "dist/worker.js"]);
  assert.equal(worker[0].essential, true); assert.notEqual(worker[0].privileged, true);
  const match = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-worker@(sha256:[a-f0-9]{64})$/.exec(worker[0].image); assert.ok(match, "Historical worker requires an immutable image");
  const containers = task.containers?.filter(({ name }) => name === "worker"); assert.equal(containers?.length, 1); assert.equal(containers[0].imageDigest, match[1]);
  const environment = new Map(worker[0].environment?.map(({ name, value }) => [name, value]));
  const sourceSha = environment.get("RELEASE_GIT_SHA") || environment.get("GIT_SHA"); assert.match(sourceSha || "", SHA);
  for (const name of ["RELEASE_GIT_SHA", "GIT_SHA"]) if (environment.has(name)) assert.equal(environment.get(name), sourceSha);
  if (authenticatePublication) {
  const images = reader.describeImages("mscqr-worker", match[1]).imageDetails; assert.equal(images?.length, 1);
  const repositories = reader.describeRepositories(["mscqr-worker"]).repositories; assert.equal(repositories?.length, 1);
  assert.equal(repositories[0].registryId, STAGE_B.account); assert.equal(repositories[0].repositoryName, "mscqr-worker"); assert.equal(repositories[0].imageTagMutability, "IMMUTABLE"); assert.equal((repositories[0].imageTagMutabilityExclusionFilters || []).length, 0);
  assert.equal(images[0].imageDigest, match[1]); assert.equal(images[0].registryId, STAGE_B.account); assert.equal(images[0].repositoryName, "mscqr-worker");
  assert.ok(images[0].imageTags?.includes(sourceSha), "Historical image lacks its authenticated source binding");
  }
  const eniAttachments = task.attachments?.filter(({ type }) => type === "ElasticNetworkInterface"); assert.equal(eniAttachments?.length, 1);
  const attachment = Object.fromEntries(eniAttachments[0].details.map(({ name, value }) => [name, value]));
  const interfaces = reader.describeNetworkInterfaces([attachment.networkInterfaceId]).NetworkInterfaces; assert.equal(interfaces?.length, 1);
  const eni = interfaces[0]; assert.equal(eni.NetworkInterfaceId, attachment.networkInterfaceId); assert.equal(eni.SubnetId, attachment.subnetId); assert.equal(eni.PrivateIpAddress, attachment.privateIPv4Address); assert.ok(!eni.Association?.PublicIp);
  const overrides = task.overrides || {};
  for (const override of overrides.containerOverrides || []) {
    assert.equal(override.name, "worker");
    if (override.command) assert.deepEqual(override.command, worker[0].command || [], "Historical override cannot change worker purpose");
    for (const entry of override.environment || []) if (["RELEASE_GIT_SHA", "GIT_SHA"].includes(entry.name)) assert.equal(entry.value, sourceSha);
  }
  assert.equal(overrides.taskRoleArn || definition.taskRoleArn, definition.taskRoleArn); assert.equal(overrides.executionRoleArn || definition.executionRoleArn, definition.executionRoleArn);
  // Volatile ECS timestamps/status are verified separately, never hashed into
  // the stable identity used by approval and subsequent generation readbacks.
  const { registeredAt, registeredBy, status, ...contents } = definition;
  return {
    runtime: { account: STAGE_B.account, region: STAGE_B.region, clusterArn: STAGE_B.clusterArn, taskArn, taskDefinitionArn: task.taskDefinitionArn,
      taskDefinitionSha256: canonicalSha256(contents), sourceSha, imageDigest: match[1], taskRoleArn: definition.taskRoleArn, executionRoleArn: definition.executionRoleArn,
      effectiveConfigurationSha256: canonicalSha256({ containers: definition.containerDefinitions, overrides, launchType: task.launchType, platformVersion: task.platformVersion }),
      network: { eniId: eni.NetworkInterfaceId, subnetId: eni.SubnetId, privateIp: eni.PrivateIpAddress, securityGroupIds: eni.Groups.map(({ GroupId }) => GroupId).sort(), assignPublicIp: "DISABLED" }, createdAt: new Date(task.createdAt).toISOString() }, definition,
  };
}

function associatedEvent({ reader, operation, timestamp, matches }) {
  const time = Date.parse(timestamp); assert.ok(Number.isFinite(time));
  const events = reader.lookupEvents(operation, new Date(time - 300_000).toISOString(), new Date(time + 300_000).toISOString());
  const matching = events.map(({ CloudTrailEvent }) => JSON.parse(CloudTrailEvent)).filter(matches);
  assert.equal(matching.length, 1, `Historical ${operation} must have one exact CloudTrail association`);
  const event = matching[0]; assert.equal(event.eventName, operation); assert.equal(event.eventSource, "ecs.amazonaws.com"); assert.equal(event.awsRegion, STAGE_B.region); assert.equal(event.recipientAccountId, STAGE_B.account);
  assert.ok(!event.errorCode); assert.equal(event.userIdentity?.type, "Root"); assert.equal(event.userIdentity?.arn, `arn:aws:iam::${STAGE_B.account}:root`);
  assert.equal(String(event.userIdentity?.sessionContext?.attributes?.mfaAuthenticated), "true");
  assert.ok(Math.abs(Date.parse(event.eventTime) - time) <= 300_000);
  return { eventId: event.eventID, eventTime: event.eventTime, eventSha256: canonicalSha256(event), actorArn: event.userIdentity.arn, mfaAuthenticated: true, operation };
}

export function prepareHistoricalRuntimeReference({ reader, taskArn, componentState, componentStateSha256, recoverySourceSha, recoveryTreeSha256, isProtectedSource }) {
  assert.equal(componentState.generation, 1); assert.equal(componentState.updatedByLane, "BOOTSTRAP"); assert.equal(componentState.normalDeploymentReceipt, undefined); assert.equal(componentState.historicalRuntimeRetention, undefined);
  const imageReader = reader.historicalImageReader || reader;
  const { runtime, definition } = readHistoricalRuntimeIdentity({ reader: { ...reader, describeImages: imageReader.describeImages, describeRepositories: imageReader.describeRepositories }, taskArn });
  assert.equal(typeof isProtectedSource, "function"); assert.equal(isProtectedSource(runtime.sourceSha, recoverySourceSha), true);
  assert.ok(Date.parse(runtime.createdAt) < Date.parse(componentState.updatedAt), "Only pre-bootstrap runtime can acquire an initial baseline");
  const registration = associatedEvent({ reader, operation: "RegisterTaskDefinition", timestamp: definition.registeredAt, matches: (event) => event.responseElements?.taskDefinition?.taskDefinitionArn === runtime.taskDefinitionArn });
  assert.equal(registration.actorArn, definition.registeredBy);
  const launch = associatedEvent({ reader, operation: "RunTask", timestamp: runtime.createdAt, matches: (event) => event.responseElements?.tasks?.some(({ taskArn: arn, taskDefinitionArn, clusterArn }) => arn === taskArn && taskDefinitionArn === runtime.taskDefinitionArn && clusterArn === runtime.clusterArn) });
  const body = { schemaVersion: 1, kind: HISTORICAL_RUNTIME_KIND, historicalGovernedDeploymentProvenance: false, historicalNormalDeploymentReceipt: false, repository: "T-ej2003/genuine-scan-main", recoverySourceSha, recoveryTreeSha256,
    bootstrap: { generation: 1, componentStateSha256, workflow: componentState.updatedByWorkflow, githubRunId: String(componentState.githubRunId) }, runtime, registration, launch };
  return assertHistoricalRuntimeReference({ ...body, referenceSha256: canonicalSha256(body) });
}

export function verifyHistoricalRuntimeLive({ reference, reader }) {
  assertHistoricalRuntimeReference(reference);
  // The signed initial proof already authenticates immutable image/source.
  // Later mutable ECR tags cannot override it; verify the running digest and
  // complete task-definition/configuration identity instead.
  assert.equal(canonicalJson(readHistoricalRuntimeIdentity({ reader, taskArn: reference.runtime.taskArn, authenticatePublication: false }).runtime), canonicalJson(reference.runtime), "Retained historical runtime identity changed");
  return true;
}

// A family rename cannot hide a second worker from the exact-object census.
// Only standalone tasks need this purpose check; service identities retain
// their existing deployment verification contract.
export function historicalWorkerTasks({ tasks, reader }) {
  const definitions = new Map();
  return tasks.filter((task) => {
    if (task.taskDefinitionArn?.includes(`:task-definition/${family}:`)) return true;
    if (String(task.group).startsWith("service:")) return false;
    if (!definitions.has(task.taskDefinitionArn)) {
      const definition = reader.describeTaskDefinition(task.taskDefinitionArn).taskDefinition;
      assert.equal(definition.taskDefinitionArn, task.taskDefinitionArn);
      definitions.set(task.taskDefinitionArn, definition);
    }
    const definition = definitions.get(task.taskDefinitionArn);
    return definition.taskRoleArn === `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-green-worker-task`
      || definition.containerDefinitions?.some((container) => container.name === "worker" || String(container.image).includes("/mscqr-worker") || [...(container.entryPoint || []), ...(container.command || [])].includes("dist/worker.js"));
  });
}

export function matchesHistoricalRuntimeTask(reference, task) {
  if (!reference) return false;
  assertHistoricalRuntimeReference(reference);
  return task?.taskArn === reference.runtime.taskArn && task?.taskDefinitionArn === reference.runtime.taskDefinitionArn && task.lastStatus === "RUNNING" && task.desiredStatus === "RUNNING" && !String(task.group).startsWith("service:");
}

export function assertHistoricalRuntimeRetention(retention) {
  keys(retention, ["schemaVersion", "status", "reference", "authority", "closure"]);
  assert.equal(retention.schemaVersion, 1); assert.equal(retention.status, "RETAINED", "No governed worker-successor closure contract exists; supersession is unavailable");
  assertHistoricalRuntimeReference(retention.reference);
  keys(retention.closure, ["sourceSha", "workflow", "githubRunId", "generation"]);
  assert.equal(retention.closure.sourceSha, retention.reference.recoverySourceSha);
  assert.equal(retention.closure.workflow, "T-ej2003/genuine-scan-main/.github/workflows/release-gate.yml@refs/heads/main");
  assert.match(retention.closure.githubRunId, /^[1-9][0-9]*$/); assert.ok(Number.isSafeInteger(retention.closure.generation) && retention.closure.generation > 1);
  keys(retention.authority, ["referenceSha256", "binding", "signatureBase64"]);
  assert.equal(typeof retention.authority.binding, "object"); assert.match(retention.authority.signatureBase64 || "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.equal(retention.authority.referenceSha256, retention.reference.referenceSha256);
  return retention;
}

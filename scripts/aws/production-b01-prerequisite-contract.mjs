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
  assert.equal(git(["rev-parse", `${deploymentSourceSha}^1`]), B01_PREREQUISITE.correctionBaseSha, "Deployment source is not the immediate protected-main runtime-evidence successor.");
  const body = { schemaVersion: 2, rlsDeltaOriginSha: B01_PREREQUISITE.rlsDeltaOriginSha, bridgeOriginSha: B01_PREREQUISITE.bridgeOriginSha, deploymentSourceSha,
    bridge: attestRange(B01_PREREQUISITE.rlsDeltaOriginSha, B01_PREREQUISITE.bridgeOriginSha), predecessorCorrection: attestRange(B01_PREREQUISITE.bridgeOriginSha, B01_PREREQUISITE.correctionBaseSha),
    correction: attestRange(B01_PREREQUISITE.correctionBaseSha, deploymentSourceSha) };
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

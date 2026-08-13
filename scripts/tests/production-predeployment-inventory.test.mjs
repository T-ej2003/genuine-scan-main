import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import test from "node:test";
import { createProductionPreDeploymentInventoryAdapter, PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS, PREDEPLOYMENT_BROKER_CALLER_TIMEOUT_HEADROOM_SECONDS } from "../aws/production-predeployment-inventory-adapter.mjs";
import { assertPreDeploymentInventoryResult, createPreDeploymentInventoryHandler, createPreDeploymentOperationIdentity, preDeploymentOperationKey, validatePreDeploymentInventoryConfiguration, PREDEPLOYMENT_INVENTORY_LAMBDA_TIMEOUT_SECONDS, PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS, PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS, PREDEPLOYMENT_INVENTORY_TOTAL_REQUEST_BUDGET_MS } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { buildPreDeploymentInventoryTaskDefinition, PREDEPLOYMENT_INVENTORY_TAG } from "../aws/production-predeployment-inventory-task.mjs";
import { assertBoundedRotationInventory, ROTATION_INVENTORY_CATEGORIES } from "../security/production-runtime-rotation-inventory.mjs";
import { STAGE_B, STAGE_B_APPROVAL_ALGORITHM, STAGE_B_MODES, STAGE_B_TASK_TEMPLATE_KEYS, stageBApprovalIdForReleaseSha } from "../aws/production-green-stage-b-contract.mjs";

const sourceSha = "a".repeat(40);
const approvalId = stageBApprovalIdForReleaseSha(sourceSha);
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"b".repeat(64)}`;
const inventory = Object.fromEntries(ROTATION_INVENTORY_CATEGORIES.map((name) => [name,
  ["printerTestQrArtifacts", "legacyImmutableAuditArtifacts"].includes(name) ? { status: "NOT_APPLICABLE", reason: "not persisted" }
    : name === "oauthState" ? { persisted: false, maxTtlSeconds: 900 }
      : name === "oauthExchange" ? { persisted: false, maxTtlSeconds: 600 }
        : name === "printedQrCompatibility" ? { maxConfiguredTtlSeconds: 31536000 }
          : name === "qrArtifacts" ? { count: 0, maxExpiry: null, issuanceModes: {}, keyVersions: { status: "NOT_APPLICABLE", reason: "none" } }
            : name === "artifactRecords" ? { count: 0, maxFinishedAt: null, signatureAlgorithms: {} }
              : name === "legacyComplianceArtifacts" ? { count: 0, maxFinishedAt: null }
                : ["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification"].includes(name) ? { count: 0, maxExpiry: null }
                  : { count: 0 }]));

const config = {
  inventoryApprovalId: stageBApprovalIdForReleaseSha(sourceSha),
  rotationInventoryRlsRole: "mscqr_prod_rls_read",
  inventoryLogGroupName: "/ecs/mscqr-production/rls-green-backend",
  inventoryPrivateSubnetIds: ["subnet-068d949017bd2ce45", "subnet-07e0a76e3a5241138"],
  inventorySecurityGroupIds: ["sg-051a24aedff773761"],
  inventoryDatabaseUrlArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh",
  inventoryRlsRole: "mscqr_prod_rls_read",
  overlapTaskInput: { backendLogGroup: "/ecs/mscqr-production/rls-green-backend", secretBindings: { ROTATION_INVENTORY_RLS_ROLE: "mscqr_prod_rls_read" } },
};

const brokerTaskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:19";
const brokerTaskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/inventory-19";
const brokerTags = [{ key: "Component", value: "full-rls-green-stage-b" }, { key: "Environment", value: "production" }, { key: "ManagedBy", value: "Terraform" }, { key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }];
const brokerConfig = {
  ...config,
  clusterArn: STAGE_B.clusterArn,
  approvalSecretArn: STAGE_B.approvalSecretArn,
  inventoryTaskDefinitionFamilyArn: `${brokerTaskDefinitionArn.slice(0, brokerTaskDefinitionArn.lastIndexOf(":"))}:1`,
  inventoryImageDigest: image,
  inventoryTaskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
  inventoryExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
  inventoryPrivateSubnetIds: config.inventoryPrivateSubnetIds,
  inventorySecurityGroupIds: config.inventorySecurityGroupIds,
  inventoryAssignPublicIp: "DISABLED",
  inventoryLogGroupName: config.inventoryLogGroupName,
  approvalExpected: { releaseSha: sourceSha, approvalId: stageBApprovalIdForReleaseSha(sourceSha) },
};
const brokerApproval = {
  schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region, releaseSha: sourceSha,
  backendImageDigest: image, workerImageDigest: image.replace("mscqr-backend", "mscqr-worker"), executorImageDigest: image, canaryImageDigest: image,
  sourceContractSha256: "c".repeat(64), migrationSetDigest: "d".repeat(64), packageChecksumSha256: "e".repeat(64), deploymentId: "phase2",
  greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2", administratorIdentity: "mscqr_prod_admin",
  databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
  checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker",
  deployerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer", executorIdentity: STAGE_B.executorRoleArn,
  approvalId: stageBApprovalIdForReleaseSha(sourceSha), ticketId: "CHG-STAGE-B-0001", issuedAt: "2026-07-29T11:55:00.000Z", expiresAt: "2026-07-29T13:00:00.000Z",
  nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM, brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1", signatureBase64: "AA==",
  taskDefinitionArns: Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${mode}:1`])),
  taskDefinitionTemplateHashes: Object.fromEntries(STAGE_B_TASK_TEMPLATE_KEYS.map((key) => [key, "f".repeat(64)])),
};
const brokerDefinition = () => ({ ...buildPreDeploymentInventoryTaskDefinition({ backendImage: image, releaseSha: sourceSha, databaseUrl: config.inventoryDatabaseUrlArn, rotationInventoryRlsRole: config.inventoryRlsRole, inventoryLogGroup: config.inventoryLogGroupName }).taskDefinition, taskDefinitionArn: brokerTaskDefinitionArn, status: "ACTIVE" });
function makeBrokerHandler({ definition = brokerDefinition(), tags = brokerTags, readApproval = async () => brokerApproval, describeTaskDefinition = async () => ({ taskDefinition: definition, tags }), describeTasks = async () => ({ tasks: [{ taskArn: brokerTaskArn, taskDefinitionArn: brokerTaskDefinitionArn, lastStatus: "STOPPED", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: sourceSha }, { key: "RotationId", value: "rotation-1" }], containers: [{ name: "inventory", exitCode: 0 }] }] }), runTask = async () => ({ failures: [], tasks: [{ taskArn: brokerTaskArn }] }), verifySignature = async () => true, claimPreDeploymentOperation = async () => {}, releasePreDeploymentOperation = async () => {}, markPreDeploymentLaunchUncertain = async () => {}, recordPreDeploymentTaskStarted = async () => {}, recordPreDeploymentCompleted = async () => {}, stopTask, now = () => new Date("2026-07-29T12:00:00.000Z"), monotonicNow = () => 0, sleep = async () => {} } = {}) {
  const calls = [];
  const cleanup = stopTask || (async (request) => { calls.push(["stopTask", request]); });
  const handler = createPreDeploymentInventoryHandler({
    config: brokerConfig, readApproval, verifySignature,
    claimPreDeploymentOperation, releasePreDeploymentOperation, markPreDeploymentLaunchUncertain, recordPreDeploymentTaskStarted, recordPreDeploymentCompleted,
    describeTaskDefinition,
    runTask: async (request) => { calls.push(["runTask", request]); return runTask(request); },
    describeTasks: async (request) => { calls.push(["describeTasks", request]); return describeTasks(request); },
    describeLogStreams: async (request) => { calls.push(["describeLogStreams", request]); return { logStreams: [{ logStreamName: "predeployment-inventory/inventory/inventory-19" }] }; },
    getLogEvents: async (request) => { calls.push(["getLogEvents", request]); return { events: [{ message: JSON.stringify(inventory) }] }; },
    stopTask: cleanup, now, monotonicNow, sleep,
  });
  return { handler, calls };
}

test("predeployment task is fixed, terminating, and not a governed ECS Exec target", () => {
  const { taskDefinition, tags } = buildPreDeploymentInventoryTaskDefinition({ backendImage: image, releaseSha: sourceSha, databaseUrl: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh", rotationInventoryRlsRole: "mscqr_prod_rls_read", inventoryLogGroup: config.inventoryLogGroupName });
  assert.deepEqual(taskDefinition.containerDefinitions[0].entryPoint, ["node"]);
  assert.deepEqual(taskDefinition.containerDefinitions[0].command, ["/app/scripts/production-rotation-state-inventory.mjs"]);
  assert.equal(taskDefinition.containerDefinitions[0].portMappings, undefined);
  assert.equal(tags.some((tag) => tag.key === PREDEPLOYMENT_INVENTORY_TAG.key && tag.value === PREDEPLOYMENT_INVENTORY_TAG.value), true);
  assert.equal(tags.some((tag) => tag.key === "MSCQRExecTarget"), false);
});

test("production predeployment adapter registers then invokes only the reviewed broker operation", async () => {
  const calls = [];
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:19";
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/inventory-19";
  let registeredDefinition;
  let registeredTags;
  const adapter = createProductionPreDeploymentInventoryAdapter({ run: (args) => {
    calls.push(args);
    if (args[0] === "ecs" && args[1] === "register-task-definition") {
      const payload = JSON.parse(args[3]);
      const { tags, ...definition } = payload;
      registeredDefinition = definition;
      registeredTags = tags;
      return JSON.stringify({ taskDefinition: { ...registeredDefinition, taskDefinitionArn }, tags });
    }
    if (args[0] === "ecs" && args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...registeredDefinition, taskDefinitionArn, status: "ACTIVE" }, tags: registeredTags });
    if (args[0] === "lambda" && args[1] === "invoke") {
      writeFileSync(args.at(-4), JSON.stringify({ status: "completed", sourceSha, rotationId: "rotation-1", taskDefinitionArn, taskArn, inventory }));
      return JSON.stringify({ StatusCode: 200 });
    }
    throw new Error(`unexpected command: ${args.join(" ")}`);
  }, sourceSha, imageDigest: image, config });
  const result = await adapter.run({ rotationId: "rotation-1" });
  assertBoundedRotationInventory(result.inventory);
  assert.equal(result.taskDefinitionArn, taskDefinitionArn);
  assert.equal(calls.filter(([service, operation]) => service === "lambda" && operation === "invoke").length, 1);
  const invoke = calls.find(([service, operation]) => service === "lambda" && operation === "invoke");
  assert.match(invoke.join(" "), /production-rls-approval-broker:reviewed/);
  assert.deepEqual(invoke.slice(invoke.indexOf("--cli-read-timeout"), invoke.indexOf("--payload")), ["--cli-read-timeout", String(PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS)]);
  assert.equal(PREDEPLOYMENT_BROKER_CALLER_TIMEOUT_HEADROOM_SECONDS, 20);
  assert.doesNotMatch(invoke.join(" "), /ExecuteCommand|--overrides|MSCQRExecTarget/);
});

test("cutover predeployment adapter uses the authorized full image and rejects the bare digest", async () => {
  const bareDigest = "sha256:" + "b".repeat(64);
  const runtimeConfig = { ...config, backendImageDigest: bareDigest, overlapTaskInput: { ...config.overlapTaskInput, backendImage: image } };
  const registration = async (imageDigest) => {
    let registeredDefinition;
    const adapter = createProductionPreDeploymentInventoryAdapter({
      run: (args) => {
        if (args[0] === "ecs" && args[1] === "register-task-definition") {
          const payload = JSON.parse(args[3]);
          registeredDefinition = payload;
          return JSON.stringify({ taskDefinition: { ...payload, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:23" } });
        }
        if (args[0] === "ecs" && args[1] === "describe-task-definition") return JSON.stringify({ taskDefinition: { ...registeredDefinition, taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:23", status: "ACTIVE" } });
        if (args[0] === "lambda" && args[1] === "invoke") {
          writeFileSync(args.at(-4), JSON.stringify({ status: "completed", sourceSha, rotationId: "rotation-1", taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:23", taskArn: "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/inventory-23", inventory }));
          return JSON.stringify({ StatusCode: 200 });
        }
        throw new Error(`unexpected command: ${args.join(" ")}`);
      },
      sourceSha,
      imageDigest,
      config: runtimeConfig,
    });
    const result = await adapter.run({ rotationId: "rotation-1" });
    return { result, registeredDefinition };
  };

  await assert.rejects(() => registration(runtimeConfig.backendImageDigest), /Pre-deployment inventory task bindings are invalid/);
  await assert.rejects(() => registration(undefined), /Pre-deployment inventory task bindings are invalid/);
  const { result, registeredDefinition } = await registration(runtimeConfig.overlapTaskInput.backendImage);
  assert.equal(result.valid, true);
  assert.equal(result.taskDefinitionArn.endsWith(":23"), true);
  assert.equal(registeredDefinition.containerDefinitions[0].image, image);
  assert.doesNotMatch(registeredDefinition.containerDefinitions[0].image, /:latest$/);
});

test("real broker handler runs one bounded task and reads only its exact log stream", async () => {
  const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:19";
  const taskArn = "arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/inventory-19";
  const taskDefinitions = Object.fromEntries(STAGE_B_MODES.map((mode) => [mode, `arn:aws:ecs:eu-west-2:368992683803:task-definition/${mode}:1`]));
  const approval = {
    schemaVersion: 2, environment: "production", account: STAGE_B.account, region: STAGE_B.region, releaseSha: sourceSha,
    backendImageDigest: image, workerImageDigest: image.replace("mscqr-backend", "mscqr-worker"), executorImageDigest: image,
    canaryImageDigest: image, sourceContractSha256: "c".repeat(64), migrationSetDigest: "d".repeat(64), packageChecksumSha256: "e".repeat(64),
    deploymentId: "phase2", greenDatabaseIdentifier: STAGE_B.greenDatabaseIdentifier, greenDatabaseName: "mscqr_production_rls_green_phase2",
    administratorIdentity: "mscqr_prod_admin", databaseSecurityGroupId: STAGE_B.databaseSecurityGroupId, executorSecurityGroupId: STAGE_B.executorSecurityGroupId,
    checkerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-rls-independent-checker/checker", deployerIdentity: "arn:aws:sts::368992683803:assumed-role/mscqr-production-release-deployer/deployer",
    executorIdentity: STAGE_B.executorRoleArn, approvalId, ticketId: "CHG-STAGE-B-0001", issuedAt: "2026-07-29T11:55:00.000Z", expiresAt: "2026-07-29T13:00:00.000Z",
    nonce: "12345678-1234-1234-1234-123456789abc", signatureAlgorithm: STAGE_B_APPROVAL_ALGORITHM, brokerAliasArn: STAGE_B.brokerAliasArn, brokerVersion: "1",
    taskDefinitionArns: taskDefinitions, taskDefinitionTemplateHashes: Object.fromEntries(STAGE_B_TASK_TEMPLATE_KEYS.map((key) => [key, "f".repeat(64)])), signatureBase64: "AA==",
  };
  const handlerCalls = [];
  let describeCount = 0;
  const handlerConfig = {
    ...config,
    clusterArn: STAGE_B.clusterArn,
    approvalSecretArn: STAGE_B.approvalSecretArn,
    inventoryTaskDefinitionFamilyArn: `${taskDefinitionArn.slice(0, taskDefinitionArn.lastIndexOf(":"))}:1`,
    inventoryImageDigest: image,
    inventoryTaskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
    inventoryExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
    inventoryDatabaseUrlArn: config.inventoryDatabaseUrlArn,
    inventoryRlsRole: config.inventoryRlsRole,
    inventoryPrivateSubnetIds: config.inventoryPrivateSubnetIds,
    inventorySecurityGroupIds: config.inventorySecurityGroupIds,
    inventoryAssignPublicIp: "DISABLED",
    inventoryLogGroupName: config.inventoryLogGroupName,
    approvalExpected: { releaseSha: sourceSha, sourceContractSha256: approval.sourceContractSha256, migrationSetDigest: approval.migrationSetDigest, packageChecksumSha256: approval.packageChecksumSha256, deploymentId: "phase2", approvalId },
  };
  const handler = createPreDeploymentInventoryHandler({
    config: handlerConfig,
    readApproval: async () => approval,
    verifySignature: async () => true,
    runTask: async (request) => { handlerCalls.push(["runTask", request]); return { failures: [], tasks: [{ taskArn }] }; },
    describeTaskDefinition: async (arn) => ({ taskDefinition: { ...buildPreDeploymentInventoryTaskDefinition({ backendImage: image, releaseSha: sourceSha, databaseUrl: config.inventoryDatabaseUrlArn, rotationInventoryRlsRole: config.inventoryRlsRole, inventoryLogGroup: config.inventoryLogGroupName }).taskDefinition, taskDefinitionArn: arn, status: "ACTIVE" }, tags: [{ key: "Component", value: "full-rls-green-stage-b" }, { key: "Environment", value: "production" }, { key: "ManagedBy", value: "Terraform" }, { key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }] }),
    describeTasks: async (request) => { handlerCalls.push(["describeTasks", request]); describeCount += 1; return { tasks: [{ taskArn, taskDefinitionArn, lastStatus: describeCount === 1 ? "RUNNING" : "STOPPED", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: sourceSha }, { key: "RotationId", value: "rotation-1" }], containers: [{ name: "inventory", exitCode: describeCount === 1 ? undefined : 0 }] }] }; },
    describeLogStreams: async (request) => { handlerCalls.push(["describeLogStreams", request]); return { logStreams: [{ logStreamName: "predeployment-inventory/inventory/inventory-19" }] }; },
    getLogEvents: async (request) => { handlerCalls.push(["getLogEvents", request]); return { events: [{ message: JSON.stringify(inventory) }] }; },
    stopTask: async (request) => { handlerCalls.push(["stopTask", request]); },
    now: () => new Date("2026-07-29T12:00:00.000Z"),
    sleep: async () => {},
  });
  const result = await handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn });
  assert.equal(result.status, "completed");
  assertBoundedRotationInventory(result.inventory);
  assert.deepEqual(handlerCalls[0][0], "runTask");
  assert.equal(handlerCalls.filter(([name]) => name === "runTask").length, 1);
  assert.deepEqual(handlerCalls[0][1].networkConfiguration.awsvpcConfiguration, { subnets: [...config.inventoryPrivateSubnetIds].sort(), securityGroups: config.inventorySecurityGroupIds, assignPublicIp: "DISABLED" });
  assert.equal(handlerCalls[0][1].launchType, "FARGATE");
  assert.equal("overrides" in handlerCalls[0][1], false);
  assert.equal(handlerCalls.find(([name]) => name === "getLogEvents")[1].logStreamName, "predeployment-inventory/inventory/inventory-19");
  const nestedOnlyHandler = createPreDeploymentInventoryHandler({
    config: handlerConfig,
    readApproval: async () => approval,
    verifySignature: async () => true,
    describeTaskDefinition: async () => ({ taskDefinition: { ...buildPreDeploymentInventoryTaskDefinition({ backendImage: image, releaseSha: sourceSha, databaseUrl: config.inventoryDatabaseUrlArn, rotationInventoryRlsRole: config.inventoryRlsRole, inventoryLogGroup: config.inventoryLogGroupName }).taskDefinition, taskDefinitionArn, status: "ACTIVE", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }] } }),
    runTask: async () => { throw new Error("RunTask must not be reached for nested-only tags."); },
    describeTasks: async () => ({ tasks: [] }),
    describeLogStreams: async () => ({ logStreams: [] }),
    getLogEvents: async () => ({ events: [] }),
    stopTask: async () => {},
    now: () => new Date("2026-07-29T12:00:00.000Z"),
  });
  await assert.rejects(() => nestedOnlyHandler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn }), /top-level tags/);
});

test("predeployment operation identity is release-bound and task-definition changes fail closed", () => {
  const identity = createPreDeploymentOperationIdentity({ approvalId, releaseSha: sourceSha, rotationId: "rotation-1", taskDefinitionArn: brokerTaskDefinitionArn, imageDigest: image });
  assert.equal(preDeploymentOperationKey(identity), preDeploymentOperationKey({ ...identity, taskDefinitionArn: `${brokerTaskDefinitionArn.slice(0, -2)}20` }));
  assert.notEqual(preDeploymentOperationKey(identity), preDeploymentOperationKey({ ...identity, rotationId: "rotation-2" }));
  assert.equal(identity.taskDefinitionArn, brokerTaskDefinitionArn);
});

test("predeployment replay claim is after authorization and prevents concurrent and completed retries", async () => {
  const claims = new Set();
  let releaseRun;
  let runStarted;
  const started = new Promise((resolve) => { runStarted = resolve; });
  const waitingRun = new Promise((resolve) => { releaseRun = resolve; });
  let runCount = 0;
  const { handler, calls } = makeBrokerHandler({
    runTask: async () => { runCount += 1; runStarted(); await waitingRun; return { failures: [], tasks: [{ taskArn: brokerTaskArn }] }; },
    claimPreDeploymentOperation: async ({ operationKey }) => { if (claims.has(operationKey)) throw new Error("replay claim already exists"); claims.add(operationKey); },
  });
  const event = { approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn };
  const first = handler(event);
  await started;
  await assert.rejects(() => handler(event), /replay claim already exists/);
  releaseRun();
  await first;
  await assert.rejects(() => handler(event), /replay claim already exists/);
  assert.equal(runCount, 1);
  assert.equal(calls.filter(([kind]) => kind === "runTask").length, 1);
});

test("predeployment deadline starts at request entry and blocks slow authorization, inspection, and claims", async () => {
  let clock = 0;
  let launches = 0;
  const event = { approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn };
  const slowAuthorization = makeBrokerHandler({
    monotonicNow: () => clock,
    verifySignature: async () => { clock = PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + 1; return true; },
    runTask: async () => { launches += 1; return { failures: [], tasks: [{ taskArn: brokerTaskArn }] }; },
  });
  await assert.rejects(() => slowAuthorization.handler(event), /PREDEPLOYMENT_INVENTORY_TIMEOUT=true/);
  assert.equal(slowAuthorization.calls.filter(([kind]) => kind === "runTask").length, 0);

  clock = 0;
  const slowInspection = makeBrokerHandler({
    monotonicNow: () => clock,
    describeTaskDefinition: async () => { clock = PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + 1; return { taskDefinition: brokerDefinition(), tags: brokerTags }; },
    runTask: async () => { launches += 1; return { failures: [], tasks: [{ taskArn: brokerTaskArn }] }; },
  });
  await assert.rejects(() => slowInspection.handler(event), /PREDEPLOYMENT_INVENTORY_TIMEOUT=true/);
  assert.equal(slowInspection.calls.filter(([kind]) => kind === "runTask").length, 0);

  clock = 0;
  const slowClaim = makeBrokerHandler({
    monotonicNow: () => clock,
    claimPreDeploymentOperation: async () => { clock = PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + 1; },
    runTask: async () => { launches += 1; return { failures: [], tasks: [{ taskArn: brokerTaskArn }] }; },
  });
  await assert.rejects(() => slowClaim.handler(event), /PREDEPLOYMENT_INVENTORY_TIMEOUT=true/);
  assert.equal(slowClaim.calls.filter(([kind]) => kind === "runTask").length, 0);
  assert.equal(launches, 0);
});

test("maximum bounded execution leaves caller response headroom and cleanup inside the total budget", async () => {
  let clock = 0;
  let polls = 0;
  const handler = makeBrokerHandler({
    monotonicNow: () => clock,
    describeTasks: async () => {
      polls += 1;
      return { tasks: [{ taskArn: brokerTaskArn, taskDefinitionArn: brokerTaskDefinitionArn, lastStatus: polls === 2 ? "STOPPED" : "RUNNING", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: sourceSha }, { key: "RotationId", value: "rotation-1" }], containers: [{ name: "inventory", exitCode: polls === 2 ? 0 : undefined }] }] };
    },
    sleep: async () => { clock += 79_000; },
    stopTask: async () => { clock += PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS; },
  });
  await assert.doesNotReject(() => handler.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }));
  assert.equal(handler.calls.filter(([kind]) => kind === "runTask").length, 1);
  assert.ok(clock < 150_000);
  assert.equal(PREDEPLOYMENT_INVENTORY_TOTAL_REQUEST_BUDGET_MS, PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS);
});

test("known pre-launch failure releases only the unlaunched claim", async () => {
  let released = 0;
  let uncertain = 0;
  const knownFailure = makeBrokerHandler({
    runTask: async () => ({ failures: [{ reason: "capacity" }], tasks: [] }),
    releasePreDeploymentOperation: async () => { released += 1; },
    markPreDeploymentLaunchUncertain: async () => { uncertain += 1; },
  });
  await assert.rejects(() => knownFailure.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /did not start exactly once/);
  assert.equal(released, 1);
  assert.equal(uncertain, 0);
  assert.equal(knownFailure.calls.filter(([kind]) => kind === "runTask").length, 1);

  released = 0;
  uncertain = 0;
  const ambiguousFailure = makeBrokerHandler({
    runTask: async () => ({ failures: [{ reason: "partial" }], tasks: [{ taskArn: brokerTaskArn }] }),
    releasePreDeploymentOperation: async () => { released += 1; },
    markPreDeploymentLaunchUncertain: async () => { uncertain += 1; },
  });
  await assert.rejects(() => ambiguousFailure.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /did not start exactly once/);
  assert.equal(released, 0);
  assert.equal(uncertain, 1);
  assert.equal(ambiguousFailure.calls.filter(([kind]) => kind === "runTask").length, 1);
});

test("post-launch failure and cleanup failure retain the claim for reconciliation", async () => {
  let uncertain = 0;
  const failure = makeBrokerHandler({
    describeTasks: async () => { throw new Error("DescribeTasks unavailable"); },
    markPreDeploymentLaunchUncertain: async () => { uncertain += 1; },
  });
  await assert.rejects(() => failure.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /DescribeTasks unavailable/);
  assert.equal(uncertain, 1);
  assert.equal(failure.calls.filter(([kind]) => kind === "runTask").length, 1);

  uncertain = 0;
  const cleanup = makeBrokerHandler({
    stopTask: async () => { throw new Error("StopTask denied"); },
    markPreDeploymentLaunchUncertain: async () => { uncertain += 1; },
  });
  await assert.rejects(() => cleanup.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /cleanup failed/);
  assert.equal(uncertain, 1);
  assert.equal(cleanup.calls.filter(([kind]) => kind === "runTask").length, 1);
});

test("authorization failures perform no replay mutation or ECS launch", async () => {
  let claims = 0;
  let launches = 0;
  const { handler } = makeBrokerHandler({
    definition: { ...brokerDefinition(), containerDefinitions: [{ ...brokerDefinition().containerDefinitions[0], privileged: true }] },
    claimPreDeploymentOperation: async () => { claims += 1; },
    runTask: async () => { launches += 1; return { failures: [], tasks: [{ taskArn: brokerTaskArn }] }; },
  });
  await assert.rejects(() => handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /exact approved execution contract/);
  assert.equal(claims, 0);
  assert.equal(launches, 0);
});

test("complete task-definition validation rejects sidecars and execution-capability injection before RunTask", async () => {
  const mutations = [
    ["sidecar", (definition) => ({ ...definition, containerDefinitions: [...definition.containerDefinitions, { name: "sidecar", image, essential: true }] })],
    ["environment", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], environment: [...definition.containerDefinitions[0].environment, { name: "UNREVIEWED", value: "x" }] }] })],
    ["secrets", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], secrets: [...definition.containerDefinitions[0].secrets, { name: "UNREVIEWED", valueFrom: config.inventoryDatabaseUrlArn }] }] })],
    ["privileged", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], privileged: true }] })],
    ["capabilities", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], linuxParameters: { capabilities: { add: ["SYS_ADMIN"] } } }] })],
    ["log target", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], logConfiguration: { ...definition.containerDefinitions[0].logConfiguration, options: { ...definition.containerDefinitions[0].logConfiguration.options, "awslogs-group": "/unreviewed" } } }] })],
    ["image", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], image: image.replace(/b+$/, "c".repeat(64)) }] })],
    ["command", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], command: ["/bin/sh"] }] })],
    ["entryPoint", (definition) => ({ ...definition, containerDefinitions: [{ ...definition.containerDefinitions[0], entryPoint: ["/bin/sh"] }] })],
    ["task role", (definition) => ({ ...definition, taskRoleArn: "arn:aws:iam::368992683803:role/unreviewed" })],
    ["execution role", (definition) => ({ ...definition, executionRoleArn: "arn:aws:iam::368992683803:role/unreviewed" })],
  ];
  for (const [name, mutate] of mutations) {
    const { handler, calls } = makeBrokerHandler({ definition: mutate(brokerDefinition()) });
    await assert.rejects(() => handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /exact approved execution contract|task definition/);
    assert.equal(calls.filter(([kind]) => kind === "runTask").length, 0, `${name} reached RunTask`);
  }
});

test("bounded Fargate polling allows slow startup and cleans up at the broker deadline", async () => {
  let clock = Date.parse("2026-07-29T12:00:00.000Z");
  let polls = 0;
  const slow = makeBrokerHandler({
    now: () => new Date(clock),
    sleep: async (milliseconds) => { clock += milliseconds; },
    describeTasks: async () => {
      polls += 1;
      const stopped = polls === 17;
      return { tasks: [{ taskArn: brokerTaskArn, taskDefinitionArn: brokerTaskDefinitionArn, lastStatus: stopped ? "STOPPED" : "RUNNING", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: sourceSha }, { key: "RotationId", value: "rotation-1" }], containers: [{ name: "inventory", exitCode: stopped ? 0 : undefined }] }] };
    },
  });
  await assert.doesNotReject(() => slow.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }));
  assert.ok(clock > 30_000);
  assert.equal(slow.calls.filter(([kind]) => kind === "runTask").length, 1);

  clock = Date.parse("2026-07-29T12:00:00.000Z");
  polls = 0;
  const timeout = makeBrokerHandler({
    now: () => new Date(clock),
    sleep: async (milliseconds) => { clock += milliseconds; },
    describeTasks: async () => {
      polls += 1;
      return { tasks: [{ taskArn: brokerTaskArn, taskDefinitionArn: brokerTaskDefinitionArn, lastStatus: "RUNNING", tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: sourceSha }, { key: "RotationId", value: "rotation-1" }], containers: [{ name: "inventory" }] }] };
    },
  });
  await assert.rejects(() => timeout.handler({ approvalId, operation: "production-predeployment-rotation-inventory", rotationId: "rotation-1", sourceSha, taskDefinitionArn: brokerTaskDefinitionArn }), /PREDEPLOYMENT_INVENTORY_TIMEOUT=true/);
  assert.ok(polls <= 30);
  assert.equal(timeout.calls.filter(([kind]) => kind === "stopTask").length, 1);
});

test("brokered transport validates every inventory category and supported metadata shape", () => {
  assert.doesNotThrow(() => assertPreDeploymentInventoryResult(inventory));
  for (const invalid of [
    { ...inventory, unknownCategory: { count: 0 } },
    (() => { const value = structuredClone(inventory); delete value.oauthState; return value; })(),
    (() => { const value = structuredClone(inventory); value.refreshSessions.count = -1; return value; })(),
    (() => { const value = structuredClone(inventory); value.oauthState.count = 0; return value; })(),
    (() => { const value = structuredClone(inventory); value.qrArtifacts.issuanceModes.token = 1; return value; })(),
    (() => { const value = structuredClone(inventory); value.artifactRecords.signatureAlgorithms.ed25519 = "1"; return value; })(),
  ]) assert.throws(() => assertPreDeploymentInventoryResult(invalid));
});

test("broker configuration fixes cluster, task, network, roles, and log scope", () => {
  const valid = {
    clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main",
    inventoryTaskDefinitionFamilyArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:1",
    inventoryImageDigest: image,
    inventoryTaskRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-task",
    inventoryExecutionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-rls-green-backend-execution",
    inventoryDatabaseUrlArn: config.inventoryDatabaseUrlArn,
    inventoryRlsRole: config.inventoryRlsRole,
    inventoryPrivateSubnetIds: config.inventoryPrivateSubnetIds,
    inventorySecurityGroupIds: config.inventorySecurityGroupIds,
    inventoryAssignPublicIp: "DISABLED",
    inventoryLogGroupName: config.inventoryLogGroupName,
  };
  assert.doesNotThrow(() => validatePreDeploymentInventoryConfiguration(valid));
  for (const field of ["inventoryTaskDefinitionFamilyArn", "inventoryImageDigest", "inventoryTaskRoleArn", "inventoryExecutionRoleArn", "inventoryLogGroupName"]) {
    assert.throws(() => validatePreDeploymentInventoryConfiguration({ ...valid, [field]: "unreviewed" }));
  }
  assert.throws(() => validatePreDeploymentInventoryConfiguration({ ...valid, inventoryPrivateSubnetIds: ["subnet-unreviewed"] }));
  assert.throws(() => validatePreDeploymentInventoryConfiguration({ ...valid, inventorySecurityGroupIds: ["sg-unreviewed"] }));
  assert.throws(() => validatePreDeploymentInventoryConfiguration({ ...valid, inventoryAssignPublicIp: "ENABLED" }));
});

test("broker source policy contains only the bounded inventory capability", () => {
  const source = readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  assert.match(source, /Sid\s+=\s+"RunOnlyApprovedPreDeploymentInventory"[\s\S]*?ecs:RunTask/);
  assert.match(source, /Sid\s+=\s+"DescribeOnlyPreDeploymentInventoryTaskDefinitions"[\s\S]*?Action\s+=\s+\["ecs:DescribeTaskDefinition"\][\s\S]*?Resource\s+=\s+"\*"/);
  assert.match(source, /Sid\s+=\s+"DescribeOnlyPreDeploymentInventoryTaskDefinitions"[\s\S]*?Condition\s*=\s+\{\s*StringEquals\s*=\s+\{\s*"aws:RequestedRegion"\s*=\s+var\.aws_region\s*\}\s*\}/);
  assert.match(source, /Sid\s+=\s+"ReadAndStopOnlyPreDeploymentInventory"[\s\S]*?ecs:DescribeTasks[\s\S]*?ecs:StopTask/);
  assert.doesNotMatch(source, /Sid\s+=\s+"ReadAndStopOnlyPreDeploymentInventory"[\s\S]*?ecs:DescribeTaskDefinition/);
  assert.match(source, /Sid\s+=\s+"ReadOnlyPreDeploymentInventoryLogs"[\s\S]*?logs:DescribeLogStreams[\s\S]*?logs:GetLogEvents/);
  assert.match(source, /Sid\s+=\s+"PassOnlyApprovedTaskRoles"[\s\S]*?aws_iam_role\.task\["backend"\]\.arn[\s\S]*?aws_iam_role\.execution\["backend"\]\.arn/);
  const runTaskStatement = source.slice(source.indexOf('Sid      = "RunOnlyApprovedPreDeploymentInventory"'), source.indexOf('Sid      = "DescribeOnlyPreDeploymentInventoryTaskDefinitions"'));
  assert.doesNotMatch(runTaskStatement, /Resource\s*=\s*"\*"/);
  assert.match(readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"), /register-predeployment-inventory-task-definition/);
  assert.match(readFileSync("documents/ops/iam/MSCQRProductionGreenStageBPermissionManifest-v1.json", "utf8"), /invoke-predeployment-inventory-broker/);
  assert.match(readFileSync("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs", "utf8"), /PREDEPLOYMENT_INVENTORY_OPERATION/);
  assert.match(readFileSync("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs", "utf8"), /DescribeTaskDefinitionCommand\(\{ taskDefinition, include: \["TAGS"\] \}\)/);
  assert.match(readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8"), /timeout\s+=\s+180/);
  assert.ok(PREDEPLOYMENT_INVENTORY_LAMBDA_TIMEOUT_SECONDS * 1000 > PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS);
  assert.equal(PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS, 150);
  assert.ok(PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS > (PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS) / 1000);
  assert.notEqual(PREDEPLOYMENT_BROKER_CALLER_READ_TIMEOUT_SECONDS, 0);
});

test("broker SDK clients are fixed to the reviewed production region and endpoint", () => {
  const source = readFileSync("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs", "utf8");
  assert.match(source, /new ECSClient\(\{ region: STAGE_B\.region \}\)/);
  assert.match(source, /new CloudWatchLogsClient\(\{ region: STAGE_B\.region \}\)/);
  assert.doesNotMatch(source, /endpoint\s*:/i);
  assert.doesNotMatch(source, /AWS_ENDPOINT_URL|AWS_REGION\s*\}|process\.env\.AWS_REGION/);
});

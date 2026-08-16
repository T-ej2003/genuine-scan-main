import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
const { assertBrokerApprovalValidationRequest, assertBrokerRequest, hasCompleteStageBTaskMaps, STAGE_B, STAGE_B_MODES, validateStageBApproval } = await import(
  process.env.AWS_LAMBDA_FUNCTION_NAME ? "./stage-b-contract.mjs" : "../../../../../scripts/aws/production-green-stage-b-contract.mjs"
);

const taskArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-(?:full-rls-green|rls-green)-(?:[a-z0-9-]+):[1-9][0-9]*$/;
export const PREDEPLOYMENT_INVENTORY_OPERATION = "production-predeployment-rotation-inventory";
export const PREDEPLOYMENT_INVENTORY_POLL_ATTEMPTS = 30;
export const PREDEPLOYMENT_INVENTORY_POLL_INTERVAL_MS = 2_000;
export const PREDEPLOYMENT_INVENTORY_LOG_RETRIEVAL_BUDGET_MS = 20_000;
export const PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS = 30_000;
export const PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS = 100_000;
export const PREDEPLOYMENT_INVENTORY_TOTAL_REQUEST_BUDGET_MS = PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS + PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS;
export const PREDEPLOYMENT_INVENTORY_LAMBDA_TIMEOUT_SECONDS = 180;
export const PREDEPLOYMENT_INVENTORY_REPLAY_MODE = "production-predeployment-rotation-inventory";
const inventoryTaskArnPattern = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-rls-green-predeployment-inventory:[1-9][0-9]*$/;
const inventoryTaskDefinitionTags = Object.freeze({ Component: "full-rls-green-stage-b", Environment: "production", ManagedBy: "Terraform", MSCQRPreDeploymentInventory: "rotation-inventory" });
const inventoryTaskDefinitionFamily = "mscqr-production-rls-green-predeployment-inventory";
const inventoryDatabaseUrlArn = "arn:aws:secretsmanager:eu-west-2:368992683803:secret:mscqr/production/rls-green/phase2/database-url/app-XNeSfh";
const inventoryRlsRole = "mscqr_prod_rls_read";
const inventoryTaskRoleArn = `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-green-backend-task`;
const inventoryExecutionRoleArn = `arn:aws:iam::${STAGE_B.account}:role/mscqr-production-rls-green-backend-execution`;
const exact = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const canonicalize = (value) => Array.isArray(value) ? value.map(canonicalize) : value && typeof value === "object" ? Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, child]) => [key, canonicalize(child)])) : value;
const exactJson = (left, right) => JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
const brokerReceipt = (value) => ({ ...value, receiptSha256: crypto.createHash("sha256").update(`${JSON.stringify(value)}\n`).digest("hex") });

export function createPreDeploymentOperationIdentity({ approvalId, releaseSha, rotationId, operation = PREDEPLOYMENT_INVENTORY_OPERATION, taskDefinitionArn, imageDigest } = {}) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(approvalId || "") || !/^[a-f0-9]{40}$/.test(releaseSha || "")
    || !/^[A-Za-z0-9._-]{8,128}$/.test(rotationId || "") || operation !== PREDEPLOYMENT_INVENTORY_OPERATION
    || !inventoryTaskArnPattern.test(taskDefinitionArn || "") || !/^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/.test(imageDigest || "")) {
    throw new Error("Pre-deployment inventory operation identity is outside the reviewed contract.");
  }
  return Object.freeze({ approvalId, releaseSha, rotationId, operation, taskDefinitionArn, imageDigest });
}

export function preDeploymentOperationKey(identity) {
  const { approvalId, releaseSha, rotationId, operation, imageDigest } = createPreDeploymentOperationIdentity(identity);
  const logicalIdentity = JSON.stringify({ approvalId, releaseSha, rotationId, operation, imageDigest });
  return `${PREDEPLOYMENT_INVENTORY_REPLAY_MODE}#${crypto.createHash("sha256").update(logicalIdentity).digest("hex")}`;
}

export function validateBrokerConfiguration(config) {
  if (!config || config.clusterArn !== STAGE_B.clusterArn || config.approvalSecretArn !== STAGE_B.approvalSecretArn
      || config.executorSecurityGroupId !== STAGE_B.executorSecurityGroupId || !Array.isArray(config.privateSubnetIds)
      || [...config.privateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")
      || !hasCompleteStageBTaskMaps(config.taskDefinitionArns, config.templateHashes)
      || STAGE_B_MODES.some((mode) => !taskArnPattern.test(config.taskDefinitionArns[mode] || ""))) {
    throw new Error("Stage B broker configuration is outside the reviewed contract.");
  }
  return config;
}

export function createHandler({ config, readApproval, verifySignature, claimApproval, releaseApproval = async () => {}, markLaunchUncertain = async () => {}, recordTaskStarted = async () => {}, runTask, writeReceipt = async () => {}, now = () => new Date() }) {
  validateBrokerConfiguration(config);
  return async (event, context = {}) => {
    if (event?.operation === "validate-approval") {
      const request = assertBrokerApprovalValidationRequest(event);
      const rawApproval = await readApproval(STAGE_B.approvalSecretArn);
      const approval = await validateStageBApproval(rawApproval, { ...config.approvalExpected, images: config.images }, { now: now(), verifySignature });
      const approvalSha256 = crypto.createHash("sha256").update(Buffer.from(rawApproval, "utf8")).digest("hex");
      if (approval.approval.approvalId !== request.approvalId || approval.approval.releaseSha !== request.sourceSha || approvalSha256 !== request.approvalSha256) {
        throw new Error("Stage B approval publication proof is not bound to the current broker approval.");
      }
      return { status: "validated", approvalId: approval.approval.approvalId, sourceSha: approval.approval.releaseSha, approvalContractSha256: approval.approvalContractSha256, approvalSha256 };
    }
    const request = assertBrokerRequest(event);
    const approval = await validateStageBApproval(await readApproval(STAGE_B.approvalSecretArn), {
      ...config.approvalExpected,
      images: config.images,
    }, { now: now(), verifySignature, allowExpiredRollback: request.mode === "full-rls-rollback", requestedMode: request.mode });
    if (approval.approval.approvalId !== request.approvalId || !exact(approval.approval.taskDefinitionTemplateHashes, config.templateHashes)
        || !exact(approval.approval.taskDefinitionArns, config.taskDefinitionArns)) {
      throw new Error("Stage B broker request is not bound to the signed approval.");
    }
    const taskDefinition = config.taskDefinitionArns[request.mode];
    await claimApproval({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode, expiresAt: approval.approval.expiresAt });
    const networkConfiguration = { awsvpcConfiguration: {
      subnets: [...config.privateSubnetIds].sort(), securityGroups: [STAGE_B.executorSecurityGroupId], assignPublicIp: "DISABLED",
    } };
    let response;
    try {
      response = await runTask({ cluster: STAGE_B.clusterArn, taskDefinition, launchType: "FARGATE", count: 1, networkConfiguration });
    } catch {
      await markLaunchUncertain({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode });
      throw new Error("Stage B broker launch outcome is uncertain; the approval remains blocked pending reviewed ECS reconciliation.");
    }
    if ((response.failures || []).length || response.tasks?.length !== 1) {
      await releaseApproval({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode });
      throw new Error("Stage B broker did not start exactly one fixed task; the approval claim was released.");
    }
    const taskArn = response.tasks[0]?.taskArn;
    if (!String(taskArn).startsWith(STAGE_B.clusterArn.replace(":cluster/", ":task/") + "/")) throw new Error("Stage B broker task escaped the approved cluster.");
    await recordTaskStarted({ approvalId: approval.approval.approvalId, nonce: approval.approval.nonce, mode: request.mode, taskArn });
    const receipt = brokerReceipt({ schemaVersion: 1, environment: "production", event: "stage-b-broker-start", approvalId: request.approvalId, mode: request.mode, taskArn, taskDefinitionArn: taskDefinition, approvalContractSha256: approval.approvalContractSha256, completedAt: now().toISOString(), nonce: crypto.randomUUID() });
    await writeReceipt(receipt);
    return { status: "started", mode: request.mode, approvalId: request.approvalId, taskArn, taskDefinitionArn: taskDefinition, approvalContractSha256: approval.approvalContractSha256 };
  };
}

const INVENTORY_KEYS = Object.freeze(["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification", "qrArtifacts", "printerTestQrArtifacts", "artifactRecords", "legacyComplianceArtifacts", "legacyImmutableAuditArtifacts", "oauthState", "oauthExchange", "printedQrCompatibility"]);
const sensitive = /DATABASE_URL|password|secret|token|credential|private.?key|sessionToken|accessKey/i;
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const exactKeys = (value, keys) => isRecord(value) && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
const assertCount = (name, value) => { if (!Number.isInteger(value) || value < 0) throw new Error(`Pre-deployment inventory count is invalid: ${name}`); };
const assertTimestamp = (name, value) => { if (value !== null && (typeof value !== "string" || Number.isNaN(Date.parse(value)))) throw new Error(`Pre-deployment inventory timestamp is invalid: ${name}`); };
const assertCountMap = (name, value) => { if (!isRecord(value) || Object.entries(value).some(([key, count]) => !key || !Number.isInteger(count) || count < 0)) throw new Error(`Pre-deployment inventory count map is invalid: ${name}`); };
const assertNotApplicable = (name, value) => { if (!exactKeys(value, ["status", "reason"]) || value.status !== "NOT_APPLICABLE" || typeof value.reason !== "string" || !value.reason) throw new Error(`Pre-deployment inventory classification is invalid: ${name}`); };
const assertNoSensitiveKeys = (value) => {
  if (isRecord(value)) for (const [key, nested] of Object.entries(value)) { if (sensitive.test(key)) throw new Error("Pre-deployment inventory result contains sensitive output."); assertNoSensitiveKeys(nested); }
  else if (Array.isArray(value)) for (const nested of value) assertNoSensitiveKeys(nested);
};
const exactTags = (tags, expected) => Array.isArray(tags) && tags.length === Object.keys(expected).length && Object.fromEntries(tags.map(({ key, value }) => [key, value])) && Object.entries(expected).every(([key, value]) => tags.some((tag) => tag?.key === key && tag?.value === value));
export const assertPreDeploymentInventoryResult = (value) => {
  if (!isRecord(value) || Object.keys(value).sort().join(",") !== [...INVENTORY_KEYS].sort().join(",")) throw new Error("Pre-deployment inventory result is malformed or incomplete.");
  for (const nested of Object.values(value)) assertNoSensitiveKeys(nested);
  const countExpiry = ["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification"];
  for (const key of countExpiry) { if (!exactKeys(value[key], ["count", "maxExpiry"])) throw new Error(`Pre-deployment inventory fields are invalid: ${key}`); assertCount(key, value[key].count); assertTimestamp(`${key}.maxExpiry`, value[key].maxExpiry); }
  if (!exactKeys(value.qrArtifacts, ["count", "maxExpiry", "issuanceModes", "keyVersions"])) throw new Error("Pre-deployment inventory fields are invalid: qrArtifacts");
  assertCount("qrArtifacts", value.qrArtifacts.count); assertTimestamp("qrArtifacts.maxExpiry", value.qrArtifacts.maxExpiry); assertCountMap("qrArtifacts.issuanceModes", value.qrArtifacts.issuanceModes); assertNotApplicable("qrArtifacts.keyVersions", value.qrArtifacts.keyVersions);
  if (!exactKeys(value.artifactRecords, ["count", "maxFinishedAt", "signatureAlgorithms"])) throw new Error("Pre-deployment inventory fields are invalid: artifactRecords");
  assertCount("artifactRecords", value.artifactRecords.count); assertTimestamp("artifactRecords.maxFinishedAt", value.artifactRecords.maxFinishedAt); assertCountMap("artifactRecords.signatureAlgorithms", value.artifactRecords.signatureAlgorithms);
  if (!exactKeys(value.legacyComplianceArtifacts, ["count", "maxFinishedAt"])) throw new Error("Pre-deployment inventory fields are invalid: legacyComplianceArtifacts");
  assertCount("legacyComplianceArtifacts", value.legacyComplianceArtifacts.count); assertTimestamp("legacyComplianceArtifacts.maxFinishedAt", value.legacyComplianceArtifacts.maxFinishedAt);
  for (const key of ["printerTestQrArtifacts", "legacyImmutableAuditArtifacts"]) assertNotApplicable(key, value[key]);
  for (const key of ["oauthState", "oauthExchange"]) { if (!exactKeys(value[key], ["persisted", "maxTtlSeconds"]) || typeof value[key].persisted !== "boolean") throw new Error(`Pre-deployment inventory fields are invalid: ${key}`); assertCount(`${key}.maxTtlSeconds`, value[key].maxTtlSeconds); }
  if (!exactKeys(value.printedQrCompatibility, ["maxConfiguredTtlSeconds"])) throw new Error("Pre-deployment inventory fields are invalid: printedQrCompatibility");
  assertCount("printedQrCompatibility.maxConfiguredTtlSeconds", value.printedQrCompatibility.maxConfiguredTtlSeconds);
  return value;
};

export function validatePreDeploymentInventoryConfiguration(config) {
  if (!config || config.clusterArn !== STAGE_B.clusterArn || config.inventoryTaskDefinitionArn && !inventoryTaskArnPattern.test(config.inventoryTaskDefinitionArn)
      || config.inventoryImageDigest && !/^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/.test(config.inventoryImageDigest)
      || !Array.isArray(config.inventoryPrivateSubnetIds) || [...config.inventoryPrivateSubnetIds].sort().join(",") !== [...STAGE_B.privateSubnetIds].sort().join(",")
      || !Array.isArray(config.inventorySecurityGroupIds) || config.inventorySecurityGroupIds.length !== 1 || config.inventorySecurityGroupIds[0] !== STAGE_B.executorSecurityGroupId
      || config.inventoryAssignPublicIp !== "DISABLED" || !inventoryTaskArnPattern.test(config.inventoryTaskDefinitionFamilyArn || "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-rls-green-predeployment-inventory:1")
      || config.inventoryTaskRoleArn !== inventoryTaskRoleArn
      || config.inventoryExecutionRoleArn !== inventoryExecutionRoleArn
      || config.inventoryDatabaseUrlArn !== inventoryDatabaseUrlArn
      || config.inventoryRlsRole !== inventoryRlsRole
      || config.inventoryLogGroupName !== STAGE_B.inventoryLogGroupName) throw new Error("Pre-deployment inventory broker configuration is outside the reviewed contract.");
  return config;
}

function assertExactInventoryTaskDefinition({ definition, taskDefinitionArn, sourceSha, config }) {
  const container = definition?.containerDefinitions?.[0];
  const expected = {
    family: inventoryTaskDefinitionFamily,
    networkMode: "awsvpc",
    requiresCompatibilities: ["FARGATE"],
    cpu: "256",
    memory: "512",
    executionRoleArn: config.inventoryExecutionRoleArn,
    taskRoleArn: config.inventoryTaskRoleArn,
    containerDefinitions: [{
      name: "inventory",
      image: config.inventoryImageDigest,
      essential: true,
      entryPoint: ["node"],
      command: ["/app/scripts/production-rotation-state-inventory.mjs"],
      readonlyRootFilesystem: true,
      privileged: false,
      interactive: false,
      pseudoTerminal: false,
      environment: [
        { name: "RELEASE_GIT_SHA", value: sourceSha },
        { name: "ROTATION_INVENTORY_APPROVED", value: "true" },
        { name: "ROTATION_INVENTORY_RLS_ROLE", value: inventoryRlsRole },
      ],
      secrets: [{ name: "DATABASE_URL", valueFrom: inventoryDatabaseUrlArn }],
      logConfiguration: {
        logDriver: "awslogs",
        options: { "awslogs-region": STAGE_B.region, "awslogs-group": config.inventoryLogGroupName, "awslogs-stream-prefix": "predeployment-inventory" },
      },
    }],
  };
  const normalized = { ...definition };
  for (const key of ["taskDefinitionArn", "revision", "status", "registeredAt", "registeredBy", "tags", "requiresAttributes", "compatibilities"]) delete normalized[key];
  if (!definition || definition.taskDefinitionArn !== taskDefinitionArn || definition.status !== "ACTIVE" || !container || !exactJson(normalized, expected)) throw new Error("Pre-deployment inventory task definition is not the exact approved execution contract.");
  return true;
}

export function createPreDeploymentInventoryHandler({ config, readApproval, verifySignature, claimPreDeploymentOperation = async () => {}, releasePreDeploymentOperation = async () => {}, markPreDeploymentLaunchUncertain = async () => {}, recordPreDeploymentTaskStarted = async () => {}, recordPreDeploymentCompleted = async () => {}, runTask, describeTaskDefinition, describeTasks, describeLogStreams, getLogEvents, stopTask, now = () => new Date(), monotonicNow = () => performance.now(), sleep = async (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)) }) {
  validatePreDeploymentInventoryConfiguration(config);
  return async (event, context = {}) => {
    const requestStartMs = monotonicNow();
    const lambdaDeadlineMs = typeof context.getRemainingTimeInMillis === "function"
      ? requestStartMs + Math.max(0, context.getRemainingTimeInMillis())
      : Number.POSITIVE_INFINITY;
    const requestDeadlineMs = Math.min(requestStartMs + PREDEPLOYMENT_INVENTORY_TOTAL_REQUEST_BUDGET_MS, lambdaDeadlineMs);
    const operationDeadlineMs = Math.min(requestStartMs + PREDEPLOYMENT_INVENTORY_OPERATION_DEADLINE_MS, requestDeadlineMs - PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS);
    const timeoutError = (label) => new Error(`PREDEPLOYMENT_INVENTORY_TIMEOUT=true (${label}).`);
    const assertBeforeDeadline = (deadline, label, requiredMs = 0) => {
      if (monotonicNow() + requiredMs > deadline) throw timeoutError(label);
    };
    const runWithinDeadline = async (label, operation, deadline) => {
      assertBeforeDeadline(deadline, label);
      const remainingMs = Math.max(0, deadline - monotonicNow());
      let timer;
      try {
        const result = await Promise.race([
          Promise.resolve().then(operation),
          new Promise((_, reject) => { timer = setTimeout(() => reject(timeoutError(label)), remainingMs); }),
        ]);
        assertBeforeDeadline(deadline, label);
        return result;
      } finally {
        clearTimeout(timer);
      }
    };
    if (!event || typeof event !== "object" || Object.keys(event).sort().join(",") !== "approvalId,operation,rotationId,sourceSha,taskDefinitionArn" || event.operation !== PREDEPLOYMENT_INVENTORY_OPERATION || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/.test(event.approvalId || "") || !/^[A-Za-z0-9._-]{8,128}$/.test(event.rotationId || "") || !/^[a-f0-9]{40}$/.test(event.sourceSha || "") || !inventoryTaskArnPattern.test(event.taskDefinitionArn || "")) throw new Error("Pre-deployment inventory broker request is outside the reviewed contract.");
    const approval = await runWithinDeadline("approval authorization", async () => validateStageBApproval(await readApproval(config.approvalSecretArn), { ...config.approvalExpected, approvalId: event.approvalId }, { now: now(), verifySignature }), operationDeadlineMs);
    if (approval.approval.releaseSha !== event.sourceSha || approval.approval.backendImageDigest !== config.inventoryImageDigest) throw new Error("Pre-deployment inventory request is not bound to the signed release/image.");
    const definitionResponse = await runWithinDeadline("task-definition authorization", () => describeTaskDefinition(event.taskDefinitionArn), operationDeadlineMs);
    const definition = definitionResponse?.taskDefinition;
    if (!definition || !exactTags(definitionResponse.tags, inventoryTaskDefinitionTags)) throw new Error("Pre-deployment inventory task definition response is missing the reviewed top-level tags.");
    assertExactInventoryTaskDefinition({ definition, taskDefinitionArn: event.taskDefinitionArn, sourceSha: event.sourceSha, config });
    const operationIdentity = createPreDeploymentOperationIdentity({ approvalId: event.approvalId, releaseSha: event.sourceSha, rotationId: event.rotationId, operation: event.operation, taskDefinitionArn: event.taskDefinitionArn, imageDigest: config.inventoryImageDigest });
    const operationKey = preDeploymentOperationKey(operationIdentity);
    const replay = { ...operationIdentity, operationKey, nonce: approval.approval.nonce, expiresAt: approval.approval.expiresAt };
    await runWithinDeadline("replay claim", () => claimPreDeploymentOperation(replay), operationDeadlineMs);
    const networkConfiguration = { awsvpcConfiguration: { subnets: [...config.inventoryPrivateSubnetIds].sort(), securityGroups: [...config.inventorySecurityGroupIds].sort(), assignPublicIp: "DISABLED" } };
    let launchMayHaveOccurred = false;
    let launchAttempted = false;
    let uncertaintyRecorded = false;
    let taskArn;
    let cleanupAttempted = false;
    const stopTaskBounded = async () => {
      if (typeof stopTask !== "function") throw new Error("Pre-deployment inventory cleanup authority is missing.");
      let cleanupSettled = false;
      let cleanupError;
      cleanupAttempted = true;
      const cleanupDeadlineMs = Math.min(requestDeadlineMs, monotonicNow() + PREDEPLOYMENT_INVENTORY_CLEANUP_MARGIN_MS);
      try {
        await runWithinDeadline("cleanup", () => stopTask({ cluster: config.clusterArn, task: taskArn, reason: "pre-deployment inventory complete" }), cleanupDeadlineMs);
        cleanupSettled = true;
      } catch (error) {
        cleanupSettled = true;
        cleanupError = error;
      }
      if (!cleanupSettled) throw new Error("Pre-deployment inventory cleanup exceeded its bounded margin.");
      if (cleanupError) throw new Error("Pre-deployment inventory cleanup failed; the launched task remains bound for reconciliation.");
    };
    try {
      let launched;
      try {
        assertBeforeDeadline(operationDeadlineMs, "RunTask");
        launchAttempted = true;
        launchMayHaveOccurred = true;
        launched = await runWithinDeadline("RunTask", () => runTask({ cluster: config.clusterArn, taskDefinition: event.taskDefinitionArn, launchType: "FARGATE", count: 1, networkConfiguration, tags: [{ key: "MSCQRPreDeploymentInventory", value: "rotation-inventory" }, { key: "ReleaseSha", value: event.sourceSha }, { key: "RotationId", value: event.rotationId }] }), operationDeadlineMs);
      } catch (error) {
        if (!launchAttempted) {
          await runWithinDeadline("pre-launch claim release", () => releasePreDeploymentOperation(replay), requestDeadlineMs).catch(() => {});
          launchMayHaveOccurred = false;
          throw error;
        }
        await runWithinDeadline("launch uncertainty record", () => markPreDeploymentLaunchUncertain({ ...replay }), requestDeadlineMs).catch(() => {});
        uncertaintyRecorded = true;
        throw new Error("Pre-deployment inventory launch outcome is uncertain; the operation remains blocked pending reviewed ECS reconciliation.");
      }
      if ((launched.failures || []).length || launched.tasks?.length !== 1 || !launched.tasks[0]?.taskArn) {
        if (launched.tasks?.length) {
          await runWithinDeadline("launch uncertainty record", () => markPreDeploymentLaunchUncertain({ ...replay, taskArns: launched.tasks.map(({ taskArn: arn }) => arn).filter(Boolean) }), requestDeadlineMs);
          uncertaintyRecorded = true;
        } else {
          await runWithinDeadline("pre-launch claim release", () => releasePreDeploymentOperation(replay), requestDeadlineMs);
          launchMayHaveOccurred = false;
        }
        throw new Error("Pre-deployment inventory task did not start exactly once.");
      }
      taskArn = launched.tasks[0].taskArn;
      await runWithinDeadline("task-start recording", () => recordPreDeploymentTaskStarted({ ...replay, taskArn }), requestDeadlineMs);
      let task;
      for (let attempt = 0; attempt < PREDEPLOYMENT_INVENTORY_POLL_ATTEMPTS; attempt += 1) {
        assertBeforeDeadline(operationDeadlineMs, "task polling");
        const described = await runWithinDeadline("task polling", () => describeTasks({ cluster: config.clusterArn, tasks: [taskArn], include: ["TAGS"] }), operationDeadlineMs);
        task = described.tasks?.[0];
        if (!task || task.taskArn !== taskArn || task.taskDefinitionArn !== event.taskDefinitionArn || !exactTags(task.tags, { MSCQRPreDeploymentInventory: "rotation-inventory", ReleaseSha: event.sourceSha, RotationId: event.rotationId })) throw new Error("Pre-deployment inventory task identity or tags changed.");
        if (task.lastStatus === "STOPPED") break;
        assertBeforeDeadline(operationDeadlineMs, "task polling wait", PREDEPLOYMENT_INVENTORY_POLL_INTERVAL_MS);
        await runWithinDeadline("task polling wait", () => sleep(PREDEPLOYMENT_INVENTORY_POLL_INTERVAL_MS), operationDeadlineMs);
      }
      const exitCode = task?.containers?.find(({ name }) => name === "inventory")?.exitCode;
      if (task?.lastStatus !== "STOPPED") throw new Error("PREDEPLOYMENT_INVENTORY_TIMEOUT=true (task did not stop within the broker deadline).");
      if (exitCode !== 0) throw new Error("Pre-deployment inventory task did not exit successfully.");
      assertBeforeDeadline(operationDeadlineMs, "log retrieval", PREDEPLOYMENT_INVENTORY_LOG_RETRIEVAL_BUDGET_MS);
      const streams = await runWithinDeadline("log stream discovery", () => describeLogStreams({ logGroupName: config.inventoryLogGroupName, logStreamNamePrefix: "predeployment-inventory/inventory/" }), operationDeadlineMs);
      const taskId = taskArn.split("/").at(-1);
      const matchingStreams = (streams.logStreams || []).filter(({ logStreamName }) => logStreamName?.endsWith(`/${taskId}`));
      if (matchingStreams.length !== 1) throw new Error("Pre-deployment inventory result stream is missing or ambiguous.");
      const stream = matchingStreams[0];
      assertBeforeDeadline(operationDeadlineMs, "inventory result retrieval");
      const logs = await runWithinDeadline("inventory result retrieval", () => getLogEvents({ logGroupName: config.inventoryLogGroupName, logStreamName: stream.logStreamName, startFromHead: true }), operationDeadlineMs);
      if (!Array.isArray(logs.events) || logs.events.length > 100) throw new Error("Pre-deployment inventory result is oversized.");
      const lines = (logs.events || []).map(({ message }) => String(message || "")).filter((line) => line.trim().startsWith("{"));
      if (lines.length !== 1 || Buffer.byteLength(lines[0], "utf8") > 128 * 1024) throw new Error("Pre-deployment inventory result is not exactly one bounded structured record.");
      const inventory = assertPreDeploymentInventoryResult(JSON.parse(lines[0]));
      await stopTaskBounded();
      await runWithinDeadline("completion recording", () => recordPreDeploymentCompleted({ ...replay, taskArn }), requestDeadlineMs);
      return { status: "completed", operation: PREDEPLOYMENT_INVENTORY_OPERATION, taskArn, taskDefinitionArn: event.taskDefinitionArn, sourceSha: event.sourceSha, rotationId: event.rotationId, inventory };
    } catch (error) {
      if (taskArn && !cleanupAttempted) await stopTaskBounded().catch(() => {});
      if (launchMayHaveOccurred && !uncertaintyRecorded) {
        await runWithinDeadline("launch uncertainty record", () => markPreDeploymentLaunchUncertain({ ...replay, ...(taskArn ? { taskArn } : {}) }), requestDeadlineMs).catch(() => {});
      }
      throw error;
    }
  };
}

const parse = (env, name, fallback) => JSON.parse(env[name] || fallback);
export function createBrokerRuntimeConfig(env = process.env) {
  const privateSubnetIds = parse(env, "BROKER_PRIVATE_SUBNETS_JSON", "[]");
  const images = parse(env, "BROKER_IMAGES_JSON", "{}");
  return {
    clusterArn: env.BROKER_CLUSTER_ARN,
    approvalSecretArn: env.BROKER_APPROVAL_SECRET_ARN,
    executorSecurityGroupId: env.BROKER_EXECUTOR_SECURITY_GROUP_ID,
    privateSubnetIds,
    taskDefinitionArns: parse(env, "BROKER_TASK_DEFINITIONS_JSON", "{}"),
    templateHashes: parse(env, "BROKER_TASK_TEMPLATE_HASHES_JSON", "{}"),
    approvalExpected: parse(env, "BROKER_APPROVAL_EXPECTED_JSON", "{}"),
    images,
    replayTable: env.BROKER_REPLAY_TABLE,
    receiptBucket: env.BROKER_RECEIPT_BUCKET,
    inventoryTaskDefinitionFamilyArn: `arn:aws:ecs:${STAGE_B.region}:${STAGE_B.account}:task-definition/${inventoryTaskDefinitionFamily}:1`,
    inventoryImageDigest: images.backendImageDigest,
    inventoryTaskRoleArn,
    inventoryExecutionRoleArn,
    inventoryDatabaseUrlArn,
    inventoryRlsRole,
    inventoryPrivateSubnetIds: privateSubnetIds,
    inventorySecurityGroupIds: [STAGE_B.executorSecurityGroupId],
    inventoryAssignPublicIp: "DISABLED",
    inventoryLogGroupName: STAGE_B.inventoryLogGroupName,
  };
}

export async function handler(event, context) {
  const config = createBrokerRuntimeConfig();
  if (!/^[A-Za-z0-9._-]{3,255}$/.test(config.replayTable || "") || config.receiptBucket !== STAGE_B.receiptBucket) throw new Error("Stage B broker storage is outside the reviewed contract.");
  const [{ ECSClient, RunTaskCommand, DescribeTaskDefinitionCommand, DescribeTasksCommand, StopTaskCommand }, { SecretsManagerClient, GetSecretValueCommand }, { KMSClient, VerifyCommand }, { DynamoDBClient, PutItemCommand, DeleteItemCommand, UpdateItemCommand }, { S3Client, PutObjectCommand }, { CloudWatchLogsClient, DescribeLogStreamsCommand, GetLogEventsCommand }] = await Promise.all([
    import("@aws-sdk/client-ecs"), import("@aws-sdk/client-secrets-manager"), import("@aws-sdk/client-kms"), import("@aws-sdk/client-dynamodb"), import("@aws-sdk/client-s3"), import("@aws-sdk/client-cloudwatch-logs"),
  ]);
  const ecs = new ECSClient({ region: STAGE_B.region }); const secrets = new SecretsManagerClient({ region: STAGE_B.region });
  const kms = new KMSClient({ region: STAGE_B.region }); const dynamo = new DynamoDBClient({ region: STAGE_B.region }); const s3 = new S3Client({ region: STAGE_B.region });
  const readApproval = async (id) => {
      const response = await secrets.send(new GetSecretValueCommand({ SecretId: id, VersionStage: "AWSCURRENT" }));
      if (!response.SecretString) throw new Error("Stage B approval artifact is missing.");
      return response.SecretString;
  };
  const verifySignature = async ({ keyId, message, signature }) => (await kms.send(new VerifyCommand({ KeyId: keyId, Message: message, MessageType: "RAW", Signature: signature, SigningAlgorithm: "RSASSA_PSS_SHA_256" }))).SignatureValid === true;
  const clients = {
    config,
    readApproval,
    verifySignature,
    claimApproval: async ({ approvalId, nonce, mode, expiresAt }) => dynamo.send(new PutItemCommand({
      TableName: config.replayTable, Item: { approvalMode: { S: `${approvalId}#${mode}` }, approvalNonce: { S: nonce }, launchState: { S: "claimed" }, expiresAt: { N: String(Math.floor(Date.parse(expiresAt) / 1000)) } }, ConditionExpression: "attribute_not_exists(approvalMode)",
    })),
    releaseApproval: ({ approvalId, nonce, mode }) => dynamo.send(new DeleteItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" } },
    })),
    markLaunchUncertain: ({ approvalId, nonce, mode }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, UpdateExpression: "SET launchState = :state", ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" }, ":state": { S: "launch-uncertain" } },
    })),
    recordTaskStarted: ({ approvalId, nonce, mode, taskArn }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: `${approvalId}#${mode}` } }, UpdateExpression: "SET launchState = :state, taskArn = :taskArn", ConditionExpression: "approvalNonce = :nonce AND launchState = :claimed", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":claimed": { S: "claimed" }, ":state": { S: "started" }, ":taskArn": { S: taskArn } },
    })),
    claimPreDeploymentOperation: ({ operationKey, approvalId, releaseSha, rotationId, operation, taskDefinitionArn, imageDigest, nonce, expiresAt }) => dynamo.send(new PutItemCommand({
      TableName: config.replayTable,
      Item: {
        approvalMode: { S: operationKey }, approvalId: { S: approvalId }, releaseSha: { S: releaseSha }, rotationId: { S: rotationId }, operation: { S: operation },
        taskDefinitionArn: { S: taskDefinitionArn }, imageDigest: { S: imageDigest }, operationIdentitySha256: { S: crypto.createHash("sha256").update(JSON.stringify({ approvalId, releaseSha, rotationId, operation, taskDefinitionArn, imageDigest })).digest("hex") },
        approvalNonce: { S: nonce }, launchState: { S: "launching" }, expiresAt: { N: String(Math.floor(Date.parse(expiresAt) / 1000)) },
      },
      ConditionExpression: "attribute_not_exists(approvalMode)",
    })),
    releasePreDeploymentOperation: ({ operationKey, nonce }) => dynamo.send(new DeleteItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: operationKey } }, ConditionExpression: "approvalNonce = :nonce AND launchState = :launching", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":launching": { S: "launching" } },
    })),
    markPreDeploymentLaunchUncertain: ({ operationKey, nonce, taskArn, taskArns }) => {
      const attributes = { ":nonce": { S: nonce }, ":launching": { S: "launching" }, ":launched": { S: "launched" }, ":state": { S: "launch-uncertain" } };
      const updates = ["launchState = :state"];
      if (taskArn) { updates.push("taskArn = :taskArn"); attributes[":taskArn"] = { S: taskArn }; }
      if (taskArns?.length) { updates.push("taskArns = :taskArns"); attributes[":taskArns"] = { SS: taskArns }; }
      return dynamo.send(new UpdateItemCommand({ TableName: config.replayTable, Key: { approvalMode: { S: operationKey } }, UpdateExpression: `SET ${updates.join(", ")}`, ConditionExpression: "approvalNonce = :nonce AND launchState IN (:launching, :launched)", ExpressionAttributeValues: attributes }));
    },
    recordPreDeploymentTaskStarted: ({ operationKey, nonce, taskArn }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: operationKey } }, UpdateExpression: "SET launchState = :state, taskArn = :taskArn", ConditionExpression: "approvalNonce = :nonce AND launchState = :launching", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":launching": { S: "launching" }, ":state": { S: "launched" }, ":taskArn": { S: taskArn } },
    })),
    recordPreDeploymentCompleted: ({ operationKey, nonce, taskArn }) => dynamo.send(new UpdateItemCommand({
      TableName: config.replayTable, Key: { approvalMode: { S: operationKey } }, UpdateExpression: "SET launchState = :state, taskArn = :taskArn", ConditionExpression: "approvalNonce = :nonce AND launchState = :launched", ExpressionAttributeValues: { ":nonce": { S: nonce }, ":launched": { S: "launched" }, ":state": { S: "succeeded" }, ":taskArn": { S: taskArn } },
    })),
    runTask: (request) => ecs.send(new RunTaskCommand(request)),
    writeReceipt: (receipt) => s3.send(new PutObjectCommand({ Bucket: config.receiptBucket, Key: `rls-broker-receipts/${receipt.approvalId}/${receipt.mode}/${receipt.nonce}.json`, Body: `${JSON.stringify(receipt)}\n`, ContentType: "application/json", ServerSideEncryption: "AES256", IfNoneMatch: "*" })),
  };
  if (event?.operation === PREDEPLOYMENT_INVENTORY_OPERATION) {
    const logs = new CloudWatchLogsClient({ region: STAGE_B.region });
    return createPreDeploymentInventoryHandler({ ...clients, runTask: (request) => ecs.send(new RunTaskCommand(request)), describeTaskDefinition: (taskDefinition) => ecs.send(new DescribeTaskDefinitionCommand({ taskDefinition, include: ["TAGS"] })), describeTasks: (request) => ecs.send(new DescribeTasksCommand(request)), describeLogStreams: (request) => logs.send(new DescribeLogStreamsCommand(request)), getLogEvents: (request) => logs.send(new GetLogEventsCommand(request)), stopTask: (request) => ecs.send(new StopTaskCommand(request)) })(event, context);
  }
  return createHandler({ ...clients })(event, context);
}

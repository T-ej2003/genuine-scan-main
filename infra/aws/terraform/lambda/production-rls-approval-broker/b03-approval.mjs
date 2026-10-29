import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { assertEcsTaskDefinitionReadback, normalizeEcsTaskDefinitionReadback } from "./ecs-task-definition-readback.mjs";

const { canonicalJson, canonicalSha256, STAGE_B } = await import(
  process.env.AWS_LAMBDA_FUNCTION_NAME ? "./stage-b-contract.mjs" : "../../../../../scripts/aws/production-green-stage-b-contract.mjs"
);

const SHA = /^[a-f0-9]{40}$/;
const HASH = /^[a-f0-9]{64}$/;
const IMAGE = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const TASK = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b03-incremental:[1-9][0-9]*$/;
const fields = Object.freeze([
  "schemaVersion", "operation", "account", "region", "clusterArn", "approvalId", "sourceSha",
  "backendImage", "taskDefinitionArn", "taskDefinitionSha256", "packageSha256", "database",
  "databaseHostname", "predecessorCatalogue", "successorCatalogue", "ticketId", "checkerIdentity",
  "issuedAt", "expiresAt", "nonce",
]);
const exactKeys = (value, expected) => value && typeof value === "object" && !Array.isArray(value)
  && Object.keys(value).sort().join(",") === [...expected].sort().join(",");

export function encodeB03Approval(request) {
  assert.ok(exactKeys(request, ["operation", "approval", "package"]));
  assert.equal(request.operation, "b03-incremental");
  const bytes = Buffer.from(canonicalJson(request.package));
  assert.ok(bytes.length <= 96 * 1024);
  const packageGzipBase64 = gzipSync(bytes, { level: 9, mtime: 0 }).toString("base64");
  assert.ok(packageGzipBase64.length <= 32768);
  return Buffer.from(`${canonicalJson({ schemaVersion: 1, operation: request.operation, approval: request.approval, packageGzipBase64 })}\n`);
}

export function decodeB03Approval(bytes) {
  assert.ok(Buffer.byteLength(bytes) <= 65536, "B03 approval exceeds Secrets Manager transport limit");
  const artifact = JSON.parse(bytes.toString());
  assert.ok(exactKeys(artifact, ["schemaVersion", "operation", "approval", "packageGzipBase64"]));
  assert.equal(artifact.schemaVersion, 1); assert.equal(artifact.operation, "b03-incremental");
  assert.match(artifact.packageGzipBase64 || "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(artifact.packageGzipBase64.length <= 32768);
  const pkg = JSON.parse(gunzipSync(Buffer.from(artifact.packageGzipBase64, "base64"), { maxOutputLength: 96 * 1024 }));
  const request = { operation: artifact.operation, approval: artifact.approval, package: pkg };
  assert.ok(encodeB03Approval(request).equals(Buffer.from(bytes)), "B03 publication must use canonical bytes");
  return request;
}

export function b03PublicationRequest(approvalBytes, operation = "b03-incremental") {
  const { approval } = decodeB03Approval(approvalBytes);
  assert.ok(["b03-incremental", "validate-b03-approval"].includes(operation));
  return { operation, approvalId: approval.approvalId, sourceSha: approval.sourceSha, approvalSha256: canonicalSha256Bytes(approvalBytes) };
}
const canonicalSha256Bytes = bytes => createHash("sha256").update(bytes).digest("hex");

export async function authenticatePublishedB03(event, { readApproval, ...options }) {
  assert.ok(exactKeys(event, ["operation", "approvalId", "sourceSha", "approvalSha256"]));
  assert.ok(["b03-incremental", "validate-b03-approval"].includes(event.operation));
  assert.match(event.sourceSha || "", SHA); assert.match(event.approvalSha256 || "", HASH);
  assert.match(event.approvalId || "", /^APR-B03-[a-f0-9]{40}-[a-f0-9-]{16,64}$/);
  const bytes = Buffer.from(await readApproval(STAGE_B.approvalSecretArn));
  assert.equal(canonicalSha256Bytes(bytes), event.approvalSha256, "B03 published artifact was replaced");
  const request = decodeB03Approval(bytes);
  assert.equal(request.approval.approvalId, event.approvalId); assert.equal(request.approval.sourceSha, event.sourceSha);
  return authenticateB03BrokerRequest(request, options);
}

export const B03_BROKER = Object.freeze({
  mode: "b03-incremental", database: "mscqr_production_rls_green_phase2",
  family: "mscqr-production-b03-incremental", container: "production-b03-incremental",
  executionRoleArn: "arn:aws:iam::368992683803:role/mscqr-production-full-rls-green-executor-execution",
  administratorSecretArn: "arn:aws:secretsmanager:eu-west-2:368992683803:secret:rds!db-70d459ec-4f6f-45da-aafc-618e83d660a1-Dy9GLo:password::",
});

export function b03ApprovalMessage(approval) {
  assert.ok(exactKeys(approval, [...fields, "signatureBase64"]));
  const bytes = Buffer.from(canonicalJson(Object.fromEntries(fields.map((field) => [field, approval[field]]))));
  assert.ok(bytes.length <= 4096, "B03 approval exceeds the KMS RAW message limit");
  return bytes;
}
export const b03TaskDefinitionSha256 = task => canonicalSha256(normalizeEcsTaskDefinitionReadback(task));

export function buildB03ExecutorDefinition({ sourceSha, backendImage, package: pkg, databaseHostname }) {
  assert.match(sourceSha || "", SHA); assert.match(backendImage || "", IMAGE);
  assert.match(databaseHostname || "", /^[a-z0-9.-]+$/);
  assert.equal(pkg?.sourceSha, sourceSha);
  const bytes = Buffer.from(canonicalJson(pkg));
  assert.ok(bytes.length <= 96 * 1024);
  const encoded = gzipSync(bytes, { level: 9, mtime: 0 }).toString("base64");
  assert.ok(encoded.length <= 32768, "B03 executor transport exceeds ECS limit");
  const value = { family: B03_BROKER.family, networkMode: "awsvpc", requiresCompatibilities: ["FARGATE"],
    cpu: "1024", memory: "2048", executionRoleArn: B03_BROKER.executionRoleArn,
    runtimePlatform: STAGE_B.taskRuntimePlatform, volumes: [{ name: "executor-tmp" }],
    containerDefinitions: [{ name: B03_BROKER.container, image: backendImage, essential: true,
      entryPoint: ["/usr/bin/env", "-u", "NODE_OPTIONS", "-u", "NODE_PATH", "-u", "LD_PRELOAD", "/usr/local/bin/node",
        "scripts/aws/production-b03-delta-executor.cjs", encoded, canonicalSha256(pkg), databaseHostname], command: [],
      readonlyRootFilesystem: true, mountPoints: [{ sourceVolume: "executor-tmp", containerPath: "/tmp", readOnly: false }],
      privileged: false, interactive: false, pseudoTerminal: false,
      environment: [{ name: "NODE_ENV", value: "production" }, { name: "RELEASE_GIT_SHA", value: sourceSha }],
      secrets: [{ name: "MSCQR_B03_DELTA_ADMIN_PASSWORD", valueFrom: B03_BROKER.administratorSecretArn }],
      logConfiguration: { logDriver: "awslogs", options: { "awslogs-region": "eu-west-2", "awslogs-group": STAGE_B.executorLogGroupName,
        "awslogs-stream-prefix": "b03-incremental" } } }] };
  assert.ok(Buffer.byteLength(JSON.stringify(value)) < 60 * 1024, "B03 task definition exceeds safe ECS budget");
  return value;
}

export async function authenticateB03BrokerRequest(event, { now = new Date(), verifySignature, describeTaskDefinition } = {}) {
  assert.ok(exactKeys(event, ["operation", "approval", "package"]));
  assert.equal(event.operation, B03_BROKER.mode);
  const approval = event.approval, pkg = event.package;
  assert.ok(exactKeys(approval, [...fields, "signatureBase64"]));
  assert.equal(approval.schemaVersion, 1); assert.equal(approval.operation, "PRODUCTION_B03_BROKER_APPROVAL");
  assert.equal(approval.account, STAGE_B.account); assert.equal(approval.region, STAGE_B.region);
  assert.equal(approval.clusterArn, STAGE_B.clusterArn); assert.equal(approval.database, B03_BROKER.database);
  assert.match(approval.sourceSha || "", SHA); assert.match(approval.backendImage || "", IMAGE);
  assert.match(approval.taskDefinitionArn || "", TASK);
  assert.match(approval.taskDefinitionSha256 || "", HASH); assert.match(approval.packageSha256 || "", HASH);
  assert.match(approval.ticketId || "", /^[A-Za-z0-9][A-Za-z0-9._:/-]{5,127}$/);
  assert.match(approval.nonce || "", /^[a-f0-9-]{16,64}$/);
  assert.equal(approval.approvalId, `APR-B03-${approval.sourceSha}-${approval.nonce}`);
  assert.match(approval.checkerIdentity || "", /^arn:aws:sts::368992683803:assumed-role\/mscqr-production-rls-independent-checker\/[A-Za-z0-9+=,.@_-]{2,64}$/);
  assert.match(approval.databaseHostname || "", /^[a-z0-9.-]+$/);
  assert.ok(approval.databaseHostname.length <= 253 && approval.databaseHostname.split(".").every(label => label.length > 0 && label.length <= 63));
  const issued = Date.parse(approval.issuedAt), expires = Date.parse(approval.expiresAt);
  assert.ok(Number.isFinite(issued) && Number.isFinite(expires) && issued <= now.getTime() + 300_000
    && expires > now.getTime() && expires > issued && expires - issued <= 1_800_000, "B03 authorization expired or malformed");
  for (const catalogue of [approval.predecessorCatalogue, approval.successorCatalogue]) {
    assert.ok(exactKeys(catalogue, ["routines", "tables", "policies", "schemas", "roles"]));
    for (const value of Object.values(catalogue)) assert.match(value, HASH);
  }
  assert.ok(pkg && Buffer.byteLength(canonicalJson(pkg)) <= 96 * 1024);
  const { packageSha256, ...body } = pkg;
  assert.equal(packageSha256, canonicalSha256(body));
  assert.equal(pkg.kind, "PRODUCTION_B03_INCREMENTAL_PACKAGE"); assert.equal(pkg.schemaVersion, 1);
  assert.equal(pkg.predecessorSourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.equal(pkg.mutations?.length, 44);
  assert.ok(pkg.mutations.every((item) => exactKeys(item, ["owner", "sql"])
    && ["auth", "schema"].includes(item.owner) && typeof item.sql === "string" && item.sql.length < 10000));
  assert.equal(pkg.sourceSha, approval.sourceSha); assert.equal(pkg.packageSha256, approval.packageSha256);
  assert.equal(canonicalJson(pkg.predecessorCatalogue), canonicalJson(approval.predecessorCatalogue));
  assert.equal(canonicalJson(pkg.successorCatalogue), canonicalJson(approval.successorCatalogue));
  assert.ok(typeof verifySignature === "function" && await verifySignature({
    keyId: STAGE_B.approvalKmsKeyArn, message: b03ApprovalMessage(approval),
    signature: Buffer.from(approval.signatureBase64 || "", "base64"),
  }), "B03 authorization KMS signature failed");
  assert.equal(typeof describeTaskDefinition, "function");
  const observed = await describeTaskDefinition(approval.taskDefinitionArn);
  const task = observed?.taskDefinition || observed;
  const expected = buildB03ExecutorDefinition({ sourceSha: approval.sourceSha, backendImage: approval.backendImage,
    package: pkg, databaseHostname: approval.databaseHostname });
  assertEcsTaskDefinitionReadback({ definition: task, taskDefinitionArn: approval.taskDefinitionArn,
    expected, label: "B03 broker executor" });
  assert.equal(b03TaskDefinitionSha256(task), approval.taskDefinitionSha256);
  assert.deepEqual((observed?.tags || []).toSorted((left, right) => left.key.localeCompare(right.key)),
    [{ key: "Component", value: "b03-incremental-release" },
      { key: "Environment", value: "production" }, { key: "ManagedBy", value: "Terraform" }]);
  return { approval, approvalContractSha256: canonicalSha256(JSON.parse(b03ApprovalMessage(approval))) };
}

// B03 approvals expire within 30 minutes, inside ECS's minimum one-hour
// RunTask token lifetime. Reconciliation always uses the original parameters.
export async function launchB03Task({ authorization, request, claim, readClaim, runTask, recordTask, writeReceipt, recordReceipt = async () => {} }) {
  const { approval, approvalContractSha256 } = authorization;
  const requestSha256 = canonicalSha256(request);
  const identity = { approvalId: approval.approvalId, nonce: approval.nonce, mode: B03_BROKER.mode,
    expiresAt: approval.expiresAt, approvalContractSha256, requestSha256 };
  let prior;
  try { await claim(identity); } catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
    prior = await readClaim(`${approval.approvalId}#${B03_BROKER.mode}`);
    assert.equal(prior?.approvalNonce, approval.nonce);
    assert.equal(prior?.approvalContractSha256, approvalContractSha256);
    assert.equal(prior?.requestSha256, requestSha256);
    assert.ok(["claimed", "started"].includes(prior?.launchState));
  }
  // RunTask with the same token and exact parameters returns the original task,
  // including after a lost response; it cannot launch a replacement in this window.
  const response = prior?.taskArn ? { tasks: [{ taskArn: prior.taskArn }] } : await runTask(request);
  assert.deepEqual(response.failures || [], []);
  assert.equal(response.tasks?.length, 1);
  const taskArn = response.tasks[0].taskArn;
  assert.match(taskArn || "", /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/);
  await recordTask({ ...identity, taskArn });
  const originalReceipt = row => {
    const value = JSON.parse(row?.launchReceiptJson || "null");
    assert.equal(value?.taskArn, taskArn); assert.equal(value.taskDefinitionArn, approval.taskDefinitionArn);
    assert.equal(value.approvalContractSha256, approvalContractSha256); assert.equal(value.requestSha256, requestSha256);
    return { status: "started", ...value };
  };
  if (prior?.launchReceiptJson) return originalReceipt(prior);
  const receipt = { schemaVersion: 1, environment: "production", event: "b03-broker-start", mode: B03_BROKER.mode,
    approvalId: approval.approvalId, taskArn, taskDefinitionArn: approval.taskDefinitionArn,
    approvalContractSha256, requestSha256, nonce: cryptoNonce() };
  await writeReceipt(receipt);
  try { await recordReceipt({ ...identity, taskArn, launchReceiptJson: JSON.stringify(receipt) }); }
  catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
    return originalReceipt(await readClaim(`${approval.approvalId}#${B03_BROKER.mode}`));
  }
  return { status: "started", ...receipt };
}

const cryptoNonce = () => globalThis.crypto.randomUUID();

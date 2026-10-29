import assert from "node:assert/strict";
import crypto from "node:crypto";
import { canonicalJson, canonicalSha256, STAGE_B } from "./production-green-stage-b-contract.mjs";
import { appOnlyVerifierNetwork } from "./production-app-only-policy.mjs";
import { B03_BROKER, buildB03ExecutorDefinition } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/b03-approval.mjs";
import { assertAuthenticatedB03Receipt } from "./production-b03-completion.mjs";
export { buildB03ExecutorDefinition };

const source = /^[a-f0-9]{40}$/;
const hash = /^[a-f0-9]{64}$/;
const image = /^368992683803\.dkr\.ecr\.eu-west-2\.amazonaws\.com\/mscqr-backend@sha256:[a-f0-9]{64}$/;
const task = /^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[a-f0-9]{32}$/;
const definition = /^arn:aws:ecs:eu-west-2:368992683803:task-definition\/mscqr-production-b03-incremental:[1-9][0-9]*$/;
export const B03_RELEASE = Object.freeze({
  ...B03_BROKER, mode: "B03_INCREMENTAL_EXISTING_DATABASE", administrator: "mscqr_prod_admin",
  cluster: STAGE_B.clusterArn, logGroup: STAGE_B.executorLogGroupName,
});
const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

export function b03RunTaskRequest({ taskDefinitionArn, sourceSha, packageSha256 }) {
  assert.match(taskDefinitionArn || "", definition); assert.match(sourceSha || "", source); assert.match(packageSha256 || "", hash);
  return { cluster: B03_RELEASE.cluster, taskDefinition: taskDefinitionArn, launchType: "FARGATE", count: 1,
    enableExecuteCommand: false, clientToken: canonicalSha256({ sourceSha, packageSha256, taskDefinitionArn }),
    networkConfiguration: appOnlyVerifierNetwork() };
}

export function authenticateB03ExecutorResult({ message, pkg, sourceSha }) {
  assert.ok(typeof message === "string" && Buffer.byteLength(message) < 4096);
  const value = JSON.parse(message), { evidenceSha256, ...body } = value;
  assert.equal(evidenceSha256, canonicalSha256(body));
  assert.equal(body.schemaVersion, 1); assert.equal(body.kind, "PRODUCTION_B03_INCREMENTAL_RESULT");
  assert.equal(body.sourceSha, sourceSha); assert.equal(body.packageSha256, pkg.packageSha256);
  assert.equal(body.database, B03_RELEASE.database); assert.equal(body.databaseRole, B03_RELEASE.administrator);
  assert.deepEqual(body.successorCatalogue, pkg.successorCatalogue);
  assert.ok(body.status === "APPLIED" && body.writeCount === 44 || body.status === "ALREADY_CONVERGED" && body.writeCount === 0);
  return value;
}

export function buildB03ReleaseReceipt({ sourceSha, backendImage, approvalId, approvalEvidence, pkg, taskArn, taskDefinitionArn,
  taskState, result, workflowRunId, releaseTrainRunId, verifiedAt }) {
  assert.match(sourceSha || "", source); assert.match(backendImage || "", image);
  assert.match(taskArn || "", task); assert.match(taskDefinitionArn || "", definition);
  assert.equal(taskState?.taskArn, taskArn); assert.equal(taskState?.taskDefinitionArn, taskDefinitionArn);
  assert.equal(taskState?.lastStatus, "STOPPED"); assert.equal(taskState?.containers?.length, 1);
  assert.equal(taskState.containers[0].name, B03_RELEASE.container); assert.equal(taskState.containers[0].exitCode, 0);
  assert.equal(taskState.containers[0].image, backendImage);
  assert.equal(taskState.containers[0].imageDigest, backendImage.split("@")[1]);
  authenticateB03ExecutorResult({ message: JSON.stringify(result), pkg, sourceSha });
  assert.match(String(workflowRunId || ""), /^[1-9][0-9]*$/); assert.match(String(releaseTrainRunId || ""), /^[1-9][0-9]*$/);
  assert.equal(approvalEvidence?.sourceSha, sourceSha); assert.equal(String(approvalEvidence.workflowRunId), String(workflowRunId));
  assert.equal(approvalEvidence?.environment, "production"); assert.ok(approvalEvidence.actualApproval);
  assert.ok(Date.parse(verifiedAt) >= Date.parse(approvalEvidence.observedAt));
  const body = { schemaVersion: 3, environment: "production", installationMode: B03_RELEASE.mode, releaseSha: sourceSha,
    images: { backend: backendImage }, approvalId, productionApprovalSha256: approvalEvidence.evidenceSha256,
    predecessorSourceSha: pkg.predecessorSourceSha, predecessorRequirementsSha256: pkg.predecessorRequirementsSha256,
    successorRequirementsSha256: pkg.successorRequirementsSha256, predecessorCatalogue: pkg.predecessorCatalogue,
    successorCatalogue: pkg.successorCatalogue, packageSha256: pkg.packageSha256, database: B03_RELEASE.database,
    taskArn, taskDefinitionArn, taskResult: result, workflowRunId: String(workflowRunId), releaseTrainRunId: String(releaseTrainRunId),
    approvedAt: approvalEvidence.observedAt, verifiedAt };
  return { ...body, receiptBundleSha256: sha256(`${JSON.stringify(body)}\n`) };
}

export function assertB03ReleaseReceipt(receipt, { sourceSha, imageDigest, approvalId, workflowRunId } = {}) {
  if (receipt?.schemaVersion === 4) {
    const result = assertAuthenticatedB03Receipt(receipt, { sourceSha, imageDigest, workflowRunId });
    assert.equal(result, approvalId); return result;
  }
  throw new Error("Self-hashed legacy B03 receipts are not authenticated");
}

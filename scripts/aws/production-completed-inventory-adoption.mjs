import { createHash } from "node:crypto";
import { assertAbsentInventoryRecoveryPayload, assertPreDeploymentInventoryResult, assertPreDeploymentReplayRow, createPreDeploymentOperationIdentity, inventoryCompletionKey, preDeploymentOperationIdentitySha256, preDeploymentOperationKey } from "../../infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs";
import { canonicalJson, COMPLETED_INVENTORY_PREDECESSOR, PRESERVED_INVENTORY_PREDECESSOR, STAGE_B, validateStageBApproval } from "./production-green-stage-b-contract.mjs";
import { assertPreDeploymentInventoryTaskDefinition, PREDEPLOYMENT_INVENTORY_TAGS } from "./production-predeployment-inventory-task.mjs";

const hash = value => createHash("sha256").update(value).digest("hex");
const digest = value => hash(canonicalJson(value));
const SHA256 = /^[a-f0-9]{64}$/;
const PURPOSE = "adopt-completed-predeployment-inventory";

export function assertCompletedInventoryAdoptionPayload(payload, { config, configSha256, now = new Date() } = {}) {
  const crossSource = payload?.schemaVersion === 3 || payload?.schemaVersion === 4;
  const changedImage = payload?.schemaVersion === 4;
  const fields = ["schemaVersion", "purpose", "sourceSha", "imageReleaseSha", "rotationId", "approvalId", "taskDefinitionArn", "imageDigest", "originalConfigSha256", "continuationConfigSha256", "operationKey", "operationIdentitySha256", payload?.schemaVersion >= 2 ? "completionReceiptSha256" : "replayRowSha256", "taskArn", "inventorySha256", "inventory", "issuedAt", "expiresAt", ...(crossSource ? ["continuationSourceSha", "currentApproval"] : []), ...(changedImage ? ["continuationImageReleaseSha", "continuationImageDigest"] : [])];
  if (!payload || Object.keys(payload).sort().join(",") !== fields.sort().join(",") || ![1, 2, 3, 4].includes(payload.schemaVersion) || payload.purpose !== PURPOSE
      || !config || config.completedInventoryAdoptionRequired !== true || payload.sourceSha !== (crossSource ? config.completedInventoryPredecessorSourceSha : config.sourceSha)
      || (crossSource && (payload.continuationSourceSha !== config.sourceSha || payload.sourceSha === config.sourceSha || !payload.currentApproval))
      || (!crossSource && config.completedInventoryPredecessorSourceSha !== undefined)
      || (changedImage ? payload.continuationImageReleaseSha !== config.imageReleaseSha || payload.continuationImageDigest !== config.overlapTaskInput?.backendImage
        || (payload.imageReleaseSha === config.imageReleaseSha && payload.imageDigest === config.overlapTaskInput?.backendImage)
        || payload.originalConfigSha256 !== config.rotationSuccessor?.predecessorConfigSha256
        || payload.inventorySha256 !== config.rotationSuccessor?.inventoryEvidenceSha256
        : payload.imageReleaseSha !== config.imageReleaseSha || payload.imageDigest !== config.overlapTaskInput?.backendImage)
      || payload.rotationId !== config.rotationId || (!crossSource && payload.approvalId !== config.inventoryApprovalId)
      || payload.taskDefinitionArn !== config.inventoryTaskDefinitionArn
      || payload.continuationConfigSha256 !== configSha256 || !SHA256.test(payload.originalConfigSha256 || "")
      || !SHA256.test((payload.schemaVersion >= 2 ? payload.completionReceiptSha256 : payload.replayRowSha256) || "") || !SHA256.test(payload.operationIdentitySha256 || "")
      || !SHA256.test(payload.inventorySha256 || "") || !Number.isFinite(Date.parse(payload.issuedAt))
      || !Number.isFinite(Date.parse(payload.expiresAt)) || Date.parse(payload.expiresAt) <= now.getTime()
      || Date.parse(payload.issuedAt) > now.getTime() + 300_000 || Date.parse(payload.expiresAt) - Date.parse(payload.issuedAt) > 1_800_000) {
    throw new Error("Completed inventory adoption identity or lifetime is invalid.");
  }
  const identity = createPreDeploymentOperationIdentity({ approvalId: payload.approvalId, releaseSha: payload.sourceSha, imageReleaseSha: payload.imageReleaseSha, rotationId: payload.rotationId, operation: "production-predeployment-rotation-inventory", taskDefinitionArn: payload.taskDefinitionArn, imageDigest: payload.imageDigest });
  if (payload.operationKey !== preDeploymentOperationKey(identity) || payload.operationIdentitySha256 !== preDeploymentOperationIdentitySha256(identity) || payload.inventorySha256 !== hash(JSON.stringify(payload.inventory)) || !/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/.test(payload.taskArn || "")) throw new Error("Completed inventory adoption operation or result changed.");
  assertPreDeploymentInventoryResult(payload.inventory);
  return payload;
}

export async function authenticateFreshInventoryCompletionReceipt(row, { config, verifySignature, now = new Date() }) {
  const fields = ["approvalMode", "operationKey", "operationIdentitySha256", "predecessorOperationKey", "recoveryEvidenceSha256", "approvalNonce", "approvalContractSha256", "signedApproval", "sourceSha", "imageReleaseSha", "rotationId", "taskDefinitionArn", "imageDigest", "taskArn", "inventoryJson", "inventorySha256", "completedAt"];
  if (!row || Object.keys(row).sort().join(",") !== fields.sort().join(",") || (!config?.completedInventoryAdoptionRequired && canonicalJson(config?.newInventoryAfterCompleted) !== canonicalJson(COMPLETED_INVENTORY_PREDECESSOR))
      || !Number.isFinite(Date.parse(row.completedAt)) || Date.parse(row.completedAt) > now.getTime() + 300_000 || row.predecessorOperationKey !== COMPLETED_INVENTORY_PREDECESSOR.operationKey
      || row.recoveryEvidenceSha256 !== COMPLETED_INVENTORY_PREDECESSOR.recoveryEvidenceSha256
      || row.sourceSha !== config.sourceSha || row.imageReleaseSha !== config.imageReleaseSha || row.rotationId !== config.rotationId
      || row.taskDefinitionArn !== config.inventoryTaskDefinitionArn || row.imageDigest !== config.overlapTaskInput?.backendImage
      || !/^arn:aws:ecs:eu-west-2:368992683803:task\/mscqr-prod-euw2-main\/[A-Za-z0-9_-]+$/.test(row.taskArn || "")) throw new Error("Durable inventory completion identity is invalid.");
  const approval = await validateStageBApproval(row.signedApproval, { releaseSha: row.sourceSha, images: { backendImageDigest: row.imageDigest } }, { now: new Date(row.completedAt), verifySignature });
  if (approval.approval.ticketId !== config.ticket || Date.parse(approval.approval.issuedAt) > Date.parse(row.completedAt)) throw new Error("Durable inventory completion ticket or authorization timing differs.");
  const identity = createPreDeploymentOperationIdentity({ approvalId: approval.approval.approvalId, releaseSha: row.sourceSha, imageReleaseSha: row.imageReleaseSha, rotationId: row.rotationId, taskDefinitionArn: row.taskDefinitionArn, imageDigest: row.imageDigest });
  if (approval.approval.approvalId !== config.inventoryApprovalId || row.approvalMode !== inventoryCompletionKey(row.operationKey) || row.operationKey !== preDeploymentOperationKey(identity)
      || row.operationIdentitySha256 !== preDeploymentOperationIdentitySha256(identity) || row.approvalNonce !== approval.approval.nonce
      || row.approvalContractSha256 !== approval.approvalContractSha256 || row.sourceSha === COMPLETED_INVENTORY_PREDECESSOR.sourceSha) throw new Error("Durable inventory completion approval differs.");
  const inventory = assertPreDeploymentInventoryResult(JSON.parse(row.inventoryJson));
  if (row.inventoryJson !== canonicalJson(inventory) || row.inventorySha256 !== hash(row.inventoryJson)) throw new Error("Durable inventory completion result changed.");
  return { inventory, identity, receiptSha256: digest(row) };
}

export async function buildFreshInventoryAdoptionEvidence({ originalConfig, originalConfigSha256, continuationConfig, continuationConfigSha256, completionReceipt, currentApproval, proveDescendant, now = new Date(), verifySignature, sign }) {
  const crossSource = originalConfig?.sourceSha !== continuationConfig?.sourceSha;
  if (!SHA256.test(originalConfigSha256 || "") || !SHA256.test(continuationConfigSha256 || "")
      || canonicalJson(originalConfig?.newInventoryAfterCompleted) !== canonicalJson(COMPLETED_INVENTORY_PREDECESSOR)
      || (crossSource ? continuationConfig?.completedInventoryPredecessorSourceSha !== originalConfig.sourceSha
        || proveDescendant?.({ ancestorSha: originalConfig.sourceSha, descendantSha: continuationConfig?.sourceSha }) !== true
        : continuationConfig?.completedInventoryPredecessorSourceSha !== undefined)
      || originalConfig.rotationId !== continuationConfig.rotationId || originalConfig.ticket !== continuationConfig.ticket
      || (!crossSource && (originalConfig.imageReleaseSha !== continuationConfig.imageReleaseSha || originalConfig.inventoryApprovalId !== continuationConfig.inventoryApprovalId))
      || originalConfig.inventoryTaskDefinitionArn !== continuationConfig.inventoryTaskDefinitionArn
      || (!crossSource && originalConfig.overlapTaskInput?.backendImage !== continuationConfig.overlapTaskInput?.backendImage)) throw new Error("Fresh inventory adoption config lineage differs.");
  const { inventory, identity, receiptSha256 } = await authenticateFreshInventoryCompletionReceipt(completionReceipt, { config: originalConfig, verifySignature });
  if (identity.approvalId !== originalConfig.inventoryApprovalId) throw new Error("Fresh inventory approval ID differs.");
  const changedImage = crossSource && (originalConfig.imageReleaseSha !== continuationConfig.imageReleaseSha || originalConfig.overlapTaskInput?.backendImage !== continuationConfig.overlapTaskInput?.backendImage);
  if (crossSource) await validateStageBApproval(currentApproval, { releaseSha: continuationConfig.sourceSha, ticketId: continuationConfig.ticket, approvalId: continuationConfig.inventoryApprovalId, images: { backendImageDigest: changedImage ? continuationConfig.overlapTaskInput.backendImage : identity.imageDigest } }, { now, verifySignature });
  const payload = { schemaVersion: changedImage ? 4 : crossSource ? 3 : 2, purpose: PURPOSE, sourceSha: identity.releaseSha, ...(crossSource ? { continuationSourceSha: continuationConfig.sourceSha, currentApproval } : {}), ...(changedImage ? { continuationImageReleaseSha: continuationConfig.imageReleaseSha, continuationImageDigest: continuationConfig.overlapTaskInput.backendImage } : {}), imageReleaseSha: identity.imageReleaseSha, rotationId: identity.rotationId,
    approvalId: identity.approvalId, taskDefinitionArn: identity.taskDefinitionArn, imageDigest: identity.imageDigest, originalConfigSha256,
    continuationConfigSha256, operationKey: preDeploymentOperationKey(identity), operationIdentitySha256: preDeploymentOperationIdentitySha256(identity),
    completionReceiptSha256: receiptSha256, taskArn: completionReceipt.taskArn, inventorySha256: hash(JSON.stringify(inventory)), inventory,
    issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 1_800_000).toISOString() };
  assertCompletedInventoryAdoptionPayload(payload, { config: continuationConfig, configSha256: continuationConfigSha256, now });
  const signatureBase64 = await sign({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(payload)) });
  const evidence = { payload, signatureBase64 };
  await authenticateCompletedInventoryAdoptionEvidence(evidence, { config: continuationConfig, configSha256: continuationConfigSha256, now, proveDescendant }, verifySignature);
  return evidence;
}

export async function authenticateCompletedInventoryAdoptionEvidence(evidence, expected, verifySignature) {
  if (!evidence || Object.keys(evidence).sort().join(",") !== "payload,signatureBase64" || !/^[A-Za-z0-9+/]+={0,2}$/.test(evidence.signatureBase64 || "") || typeof verifySignature !== "function") throw new Error("Completed inventory adoption envelope is invalid.");
  const payload = assertCompletedInventoryAdoptionPayload(evidence.payload, expected);
  if (payload.schemaVersion === 3 || payload.schemaVersion === 4) {
    if (expected.proveDescendant?.({ ancestorSha: payload.sourceSha, descendantSha: payload.continuationSourceSha }) !== true) throw new Error("Completed inventory successor ancestry is not authenticated.");
    await validateStageBApproval(payload.currentApproval, { releaseSha: payload.continuationSourceSha, ticketId: expected.config.ticket, approvalId: expected.config.inventoryApprovalId, images: { backendImageDigest: payload.schemaVersion === 4 ? payload.continuationImageDigest : payload.imageDigest } }, { now: expected.now || new Date(), verifySignature });
  }
  if (!await verifySignature({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(payload)), signature: Buffer.from(evidence.signatureBase64, "base64") })) throw new Error("Completed inventory adoption signature is invalid.");
  return payload;
}

export async function buildCompletedInventoryAdoptionEvidence({ originalConfig, originalConfigSha256, continuationConfig, continuationConfigSha256, approval, recoveryEvidence, replayRow, task, taskDefinition, logEvents, now = new Date(), verifySignature, sign } = {}) {
  if (typeof verifySignature !== "function" || typeof sign !== "function" || !SHA256.test(originalConfigSha256 || "") || !SHA256.test(continuationConfigSha256 || "")
      || originalConfig?.sourceSha !== continuationConfig?.sourceSha || originalConfig?.rotationId !== continuationConfig?.rotationId
      || originalConfig?.imageReleaseSha !== continuationConfig?.imageReleaseSha || originalConfig?.inventoryApprovalId !== continuationConfig?.inventoryApprovalId
      || originalConfig?.inventoryTaskDefinitionArn !== continuationConfig?.inventoryTaskDefinitionArn
      || originalConfig?.overlapTaskInput?.backendImage !== continuationConfig?.overlapTaskInput?.backendImage) throw new Error("Inventory adoption config lineage differs.");
  const identity = createPreDeploymentOperationIdentity({ approvalId: originalConfig.inventoryApprovalId, releaseSha: originalConfig.sourceSha, imageReleaseSha: originalConfig.imageReleaseSha, rotationId: originalConfig.rotationId, operation: "production-predeployment-rotation-inventory", taskDefinitionArn: originalConfig.inventoryTaskDefinitionArn, imageDigest: originalConfig.overlapTaskInput.backendImage });
  if (!Number.isFinite(Date.parse(task?.startedAt)) || !Number.isFinite(Date.parse(task?.stoppedAt)) || Date.parse(task.stoppedAt) < Date.parse(task.startedAt)) throw new Error("Completed inventory task timing is invalid.");
  const proof = assertPreDeploymentReplayRow(replayRow, identity);
  assertAbsentInventoryRecoveryPayload(recoveryEvidence?.payload, { sourceSha: identity.releaseSha, imageReleaseSha: identity.imageReleaseSha, rotationId: identity.rotationId, configSha256: originalConfigSha256 }, new Date(task?.startedAt));
  if (proof.launchState !== "succeeded" || !proof.taskArn || replayRow.predecessorOperationKey !== preDeploymentOperationKey(PRESERVED_INVENTORY_PREDECESSOR) || replayRow.recoveryEvidenceSha256 !== digest(recoveryEvidence)
      || recoveryEvidence?.payload?.sourceSha !== identity.releaseSha || recoveryEvidence.payload.imageReleaseSha !== identity.imageReleaseSha
      || recoveryEvidence.payload.rotationId !== identity.rotationId || recoveryEvidence.payload.configSha256 !== originalConfigSha256
      || Date.parse(recoveryEvidence.payload.issuedAt) > Date.parse(task?.startedAt)
      || Date.parse(recoveryEvidence.payload.expiresAt) <= Date.parse(task?.startedAt)
      || !await verifySignature({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(recoveryEvidence.payload)), signature: Buffer.from(recoveryEvidence.signatureBase64 || "", "base64") })) throw new Error("Completed inventory predecessor recovery is unauthenticated.");
  const authorized = await validateStageBApproval(approval, { releaseSha: identity.releaseSha, approvalId: identity.approvalId, images: { backendImageDigest: identity.imageDigest } }, { now: new Date(task.startedAt), verifySignature });
  if (authorized.approval.nonce !== replayRow.approvalNonce || task?.taskArn !== proof.taskArn || task.clusterArn !== STAGE_B.clusterArn
      || task.taskDefinitionArn !== identity.taskDefinitionArn || task.lastStatus !== "STOPPED" || task.stopCode !== "EssentialContainerExited"
      || task.containers?.length !== 1 || task.containers[0].name !== "inventory" || task.containers[0].exitCode !== 0
      || task.containers[0].image !== identity.imageDigest || task.tags?.length !== 3
      || ![["MSCQRPreDeploymentInventory", "rotation-inventory"], ["ReleaseSha", identity.releaseSha], ["RotationId", identity.rotationId]].every(([key, value]) => task.tags.some(tag => tag.key === key && tag.value === value))) throw new Error("Completed inventory task differs from the authenticated claim.");
  assertPreDeploymentInventoryTaskDefinition(taskDefinition, { backendImage: identity.imageDigest, releaseSha: identity.imageReleaseSha, databaseUrl: originalConfig.inventoryDatabaseSecretArn, rotationInventoryOperation: originalConfig.rotationInventoryOperation, inventoryLogGroup: originalConfig.inventoryLogGroupName, inventoryTaskRoleArn: originalConfig.inventoryTaskRoleArn, inventoryExecutionRoleArn: originalConfig.inventoryExecutionRoleArn });
  if (taskDefinition.taskDefinitionArn !== identity.taskDefinitionArn || taskDefinition.status !== "ACTIVE"
      || canonicalJson([...(taskDefinition.tags || [])].sort((a, b) => a.key.localeCompare(b.key))) !== canonicalJson([...PREDEPLOYMENT_INVENTORY_TAGS].sort((a, b) => a.key.localeCompare(b.key)))
      || !Array.isArray(logEvents) || logEvents.length !== 1) throw new Error("Completed inventory definition or output is ambiguous.");
  const inventory = assertPreDeploymentInventoryResult(JSON.parse(logEvents[0].message));
  const payload = { schemaVersion: 1, purpose: PURPOSE, sourceSha: identity.releaseSha, imageReleaseSha: identity.imageReleaseSha, rotationId: identity.rotationId, approvalId: identity.approvalId, taskDefinitionArn: identity.taskDefinitionArn, imageDigest: identity.imageDigest, originalConfigSha256, continuationConfigSha256, operationKey: preDeploymentOperationKey(identity), operationIdentitySha256: replayRow.operationIdentitySha256, replayRowSha256: digest(replayRow), taskArn: proof.taskArn, inventorySha256: hash(JSON.stringify(inventory)), inventory, issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + 1_800_000).toISOString() };
  assertCompletedInventoryAdoptionPayload(payload, { config: continuationConfig, configSha256: continuationConfigSha256, now });
  const signatureBase64 = await sign({ keyId: STAGE_B.approvalKmsKeyArn, message: Buffer.from(canonicalJson(payload)) });
  const evidence = { payload, signatureBase64 };
  await authenticateCompletedInventoryAdoptionEvidence(evidence, { config: continuationConfig, configSha256: continuationConfigSha256, now }, verifySignature);
  return evidence;
}

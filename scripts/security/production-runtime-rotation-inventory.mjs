import { createHash } from "node:crypto";

export const ROTATION_INVENTORY_CATEGORIES = Object.freeze([
  "refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification", "qrArtifacts", "printerTestQrArtifacts", "artifactRecords", "legacyComplianceArtifacts", "legacyImmutableAuditArtifacts", "oauthState", "oauthExchange", "printedQrCompatibility",
]);

export function assertBoundedRotationInventory(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...ROTATION_INVENTORY_CATEGORIES].sort().join(",")) throw new Error("Rotation inventory categories are incomplete or unclassified.");
  for (const [name, entry] of Object.entries(value)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`${name} inventory is malformed.`);
    if (entry.status === "NOT_APPLICABLE") {
      if (typeof entry.reason !== "string" || !entry.reason) throw new Error(`${name} not-applicable classification lacks a reason.`);
      continue;
    }
    if (!Number.isInteger(entry.count) || entry.count < 0) throw new Error(`${name} inventory count is invalid.`);
    if (Object.keys(entry).some((key) => /token|secret|password|payload|email|user/i.test(key))) throw new Error(`${name} inventory leaks sensitive fields.`);
  }
  return true;
}

// execute runs inside the approved application/RLS runtime boundary. It receives
// no database URL from the operator and returns only the existing aggregate JSON.
export async function produceRuntimeRotationInventory({ execute, sourceSha, rotationId, taskDefinitionArn, registeredTaskDefinitionArn } = {}) {
  if (typeof execute !== "function" || !/^[a-f0-9]{40}$/.test(sourceSha || "") || typeof rotationId !== "string" || !rotationId || (taskDefinitionArn !== undefined && typeof taskDefinitionArn !== "string")) throw new Error("Runtime inventory inputs are invalid.");
  const result = await execute({ sourceSha, rotationId, taskDefinitionArn });
  const value = result?.inventory && typeof result.inventory === "object" ? result.inventory : result;
  assertBoundedRotationInventory(value);
  const bytes = Buffer.from(JSON.stringify(value));
  return { valid: true, evidenceRef: `runtime-inventory:${rotationId}`, evidenceSha256: createHash("sha256").update(bytes).digest("hex"), inventory: value, ...(typeof result?.taskDefinitionArn === "string" ? { taskDefinitionArn: result.taskDefinitionArn } : {}), ...(typeof result?.taskArn === "string" ? { taskArn: result.taskArn } : {}), ...(typeof registeredTaskDefinitionArn === "string" ? { registeredTaskDefinitionArn } : {}) };
}

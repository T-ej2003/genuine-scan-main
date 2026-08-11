import { createHash } from "node:crypto";

export const ROTATION_INVENTORY_CATEGORIES = Object.freeze([
  "refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification", "qrArtifacts", "printerTestQrArtifacts", "artifactRecords", "legacyComplianceArtifacts", "legacyImmutableAuditArtifacts", "oauthState", "oauthExchange", "printedQrCompatibility",
]);

const COUNT_EXPIRY_CATEGORIES = new Set(["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification"]);
const ROTATION_ENTRY_FIELDS = Object.freeze({
  qrArtifacts: Object.freeze({ count: "count", maxExpiry: "timestamp", issuanceModes: "counts", keyVersions: "notApplicable" }),
  artifactRecords: Object.freeze({ count: "count", maxFinishedAt: "timestamp", signatureAlgorithms: "counts" }),
  legacyComplianceArtifacts: Object.freeze({ count: "count", maxFinishedAt: "timestamp" }),
  oauthState: Object.freeze({ persisted: "boolean", maxTtlSeconds: "integer" }),
  oauthExchange: Object.freeze({ persisted: "boolean", maxTtlSeconds: "integer" }),
  printedQrCompatibility: Object.freeze({ maxConfiguredTtlSeconds: "integer" }),
});

const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const assertExactFields = (name, entry, fields) => {
  if (Object.keys(entry).sort().join(",") !== Object.keys(fields).sort().join(",")) throw new Error(`${name} inventory metadata is malformed.`);
};
const assertInteger = (name, key, value) => {
  if (!Number.isInteger(value) || value < 0) throw new Error(`${name}.${key} metadata is invalid.`);
};
const assertTimestamp = (name, key, value) => {
  if (value !== null && (typeof value !== "string" || Number.isNaN(Date.parse(value)))) throw new Error(`${name}.${key} metadata is invalid.`);
};
const assertCounts = (name, key, value) => {
  if (!isRecord(value) || Object.entries(value).some(([mode, count]) => !mode || !Number.isInteger(count) || count < 0)) throw new Error(`${name}.${key} metadata is invalid.`);
};
const assertNoSensitiveKeys = (name, value) => {
  if (isRecord(value)) {
    for (const [key, nested] of Object.entries(value)) {
      if (/token|secret|password|payload|credential|databaseurl/i.test(key)) throw new Error(`${name} inventory leaks sensitive fields.`);
      assertNoSensitiveKeys(name, nested);
    }
  } else if (Array.isArray(value)) for (const nested of value) assertNoSensitiveKeys(name, nested);
};

export function assertBoundedRotationInventory(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).sort().join(",") !== [...ROTATION_INVENTORY_CATEGORIES].sort().join(",")) throw new Error("Rotation inventory categories are incomplete or unclassified.");
  for (const [name, entry] of Object.entries(value)) {
    if (!isRecord(entry)) throw new Error(`${name} inventory is malformed.`);
    assertNoSensitiveKeys(name, entry);
    if (entry.status === "NOT_APPLICABLE") {
      assertExactFields(name, entry, { status: "status", reason: "reason" });
      if (typeof entry.reason !== "string" || !entry.reason) throw new Error(`${name} not-applicable classification lacks a reason.`);
      continue;
    }
    const fields = COUNT_EXPIRY_CATEGORIES.has(name) ? { count: "count", maxExpiry: "timestamp" } : ROTATION_ENTRY_FIELDS[name];
    if (!fields) throw new Error(`${name} inventory category is unclassified.`);
    assertExactFields(name, entry, fields);
    for (const [key, type] of Object.entries(fields)) {
      if (type === "count" || type === "integer") assertInteger(name, key, entry[key]);
      if (type === "timestamp") assertTimestamp(name, key, entry[key]);
      if (type === "boolean" && typeof entry[key] !== "boolean") throw new Error(`${name}.${key} metadata is invalid.`);
      if (type === "counts") assertCounts(name, key, entry[key]);
      if (type === "notApplicable") {
        assertExactFields(`${name}.${key}`, entry[key], { status: "status", reason: "reason" });
        if (entry[key].status !== "NOT_APPLICABLE" || typeof entry[key].reason !== "string" || !entry[key].reason) throw new Error(`${name}.${key} metadata is invalid.`);
      }
    }
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

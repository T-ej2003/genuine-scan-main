import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertBoundedRotationInventory, ROTATION_INVENTORY_CATEGORIES } from "../security/production-runtime-rotation-inventory.mjs";
const source = readFileSync("scripts/security/production-rotation-state-inventory.mjs", "utf8");
test("rotation inventory is bounded read-only metadata and never selects secret values", () => {
  assert.match(source, /SET TRANSACTION READ ONLY/); assert.match(source, /SET LOCAL ROLE/);
  for (const forbidden of ["tokenHash", "proofBindingTokenHash", "DATABASE_URL.*console", "secretValue"]) assert.doesNotMatch(source, new RegExp(forbidden, "i"));
  for (const name of ["refreshSessions", "adminSessions", "customerSessions", "customerVerificationState", "activeInvites", "resetTokens", "emailVerification", "qrArtifacts", "printerTestQrArtifacts", "artifactRecords", "legacyComplianceArtifacts", "legacyImmutableAuditArtifacts", "oauthState"]) assert.match(source, new RegExp(name));
  assert.match(source, /keyVersions.*NOT_APPLICABLE/);
  assert.match(source, /signatureAlgorithms/);
  assert.match(source, /AuditLog has no legacy-artifact marker/);
});

const countExpiry = { count: 0, maxExpiry: null };
const inventoryFixture = Object.fromEntries(ROTATION_INVENTORY_CATEGORIES.map((name) => [name,
  ["printerTestQrArtifacts", "legacyImmutableAuditArtifacts"].includes(name) ? { status: "NOT_APPLICABLE", reason: "not persisted by this schema" }
    : ["oauthState", "oauthExchange"].includes(name) ? { persisted: false, maxTtlSeconds: name === "oauthState" ? 900 : 600 }
      : name === "printedQrCompatibility" ? { maxConfiguredTtlSeconds: 31536000 }
        : name === "qrArtifacts" ? { count: 0, maxExpiry: null, issuanceModes: {}, keyVersions: { status: "NOT_APPLICABLE", reason: "no persisted key version" } }
          : name === "artifactRecords" ? { count: 0, maxFinishedAt: null, signatureAlgorithms: {} }
            : name === "legacyComplianceArtifacts" ? { count: 0, maxFinishedAt: null }
              : countExpiry]));

test("every SQL-emitted inventory category matches its explicit schema", () => {
  assert.doesNotThrow(() => assertBoundedRotationInventory(inventoryFixture));
});

test("inventory schema rejects malformed category shapes and sensitive fields", () => {
  const cases = [
    (value) => { value.refreshSessions.count = -1; },
    (value) => { value.oauthState.maxTtlSeconds = "900"; },
    (value) => { value.printedQrCompatibility.extra = true; },
    (value) => { value.qrArtifacts.keyVersions.reason = ""; },
    (value) => { value.artifactRecords.signatureAlgorithms.Ed25519 = -1; },
    (value) => { value.legacyComplianceArtifacts.secretValue = "forbidden"; },
  ];
  for (const mutate of cases) {
    const value = structuredClone(inventoryFixture);
    mutate(value);
    assert.throws(() => assertBoundedRotationInventory(value));
  }
  const unknown = { ...structuredClone(inventoryFixture), unknown: { count: 0 } };
  delete unknown.refreshSessions;
  assert.throws(() => assertBoundedRotationInventory(unknown));
});

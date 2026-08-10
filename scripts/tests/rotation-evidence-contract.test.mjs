import assert from "node:assert/strict";
import test from "node:test";
import { validateRotationEvidence } from "../security/rotation-evidence-contract.mjs";

const sha = "a".repeat(40);
const fresh = {
  evidenceVersion: 2,
  rotationId: "rotation-2026-08-10",
  recordedAt: "2026-08-10T00:00:00.000Z",
  sourceSha: sha,
  approvedBy: "security@example.com",
  approverRole: "Security Lead",
  reason: "Scheduled production security rotation",
  ticket: "SEC-ROT-2026-08",
  environment: "production",
  cleanupWindowComplete: true,
  cleanupCompletedAt: "2026-08-10T12:00:00.000Z",
  cleanupVerifiedBy: "ops@example.com",
  cleanupEvidenceRef: "https://github.com/example/run/1",
  linkedDeployShas: [sha, "b".repeat(40)],
  verificationRefs: ["https://github.com/example/run/1"],
  families: [
    { name: "jwt_secrets", rotatedAt: "2026-08-10T00:00:00.000Z", operator: "ops@example.com", method: "dual-slot", currentVersionId: "jwt-version-123", previousVersionId: "jwt-version-456", verificationRef: "https://github.com/example/run/1" },
    { name: "qr_signing_keys", rotatedAt: "2026-08-10T00:00:00.000Z", operator: "ops@example.com", method: "dual-slot", currentVersionId: "qr-version-123", previousVersionId: "qr-version-456", currentKeyVersion: "current-v2", previousKeyVersion: "old-v1", verificationRef: "https://github.com/example/run/1" },
  ],
};

test("fresh machine-verifiable evidence passes", () => {
  assert.deepEqual(validateRotationEvidence(fresh, { now: Date.parse("2026-08-10T12:00:00.000Z") }), []);
});

test("stale and future evidence fail", () => {
  assert.match(validateRotationEvidence(fresh, { now: Date.parse("2026-12-09T00:00:00.000Z") }).join("\n"), /stale/);
  assert.match(validateRotationEvidence({ ...fresh, recordedAt: "2026-12-10T00:00:00.000Z" }, { now: Date.parse("2026-08-10T00:00:00.000Z") }).join("\n"), /future/);
  assert.match(validateRotationEvidence({ ...fresh, families: fresh.families.map((family) => ({ ...family, rotatedAt: "2026-12-10T00:00:00.000Z" })) }, { now: Date.parse("2026-08-10T00:00:00.000Z") }).join("\n"), /rotatedAt.*future/);
});

test("placeholder references and incomplete cleanup fail", () => {
  const invalid = { ...fresh, cleanupWindowComplete: false, cleanupEvidenceRef: "deploy-log://rotation/jwt", verificationRefs: ["deploy-log://rotation/jwt"] };
  const failures = validateRotationEvidence(invalid, { now: Date.parse("2026-08-10T12:00:00.000Z"), requireCleanup: true });
  assert.match(failures.join("\n"), /machine-verifiable|cleanupWindowComplete/);
});

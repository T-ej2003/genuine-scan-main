import assert from "node:assert/strict";
import test from "node:test";
import {
  validateRotationEvidence,
  validateRotationEvidenceContract,
  validateRotationEvidenceFreshness,
} from "../security/rotation-evidence-contract.mjs";

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
  overlapReadyAt: "2026-08-10T00:00:00.000Z",
  verifiedAt: "2026-08-10T00:10:00.000Z",
  cleanupEligibleAt: "2026-08-10T11:00:00.000Z",
  retirementTimestamp: "2026-08-10T11:05:00.000Z",
  cleanupDeploymentSha: "c".repeat(40),
  cleanupDeploymentObservedAt: "2026-08-10T11:10:00.000Z",
  proofs: {
    previousJwtSlotRetired: true, previousQrPublicSlotRetired: true, jwtPendingRetired: true, qrPrivatePendingRetired: true, qrPublicPendingRetired: true,
    cleanupDeploymentAfterRetirement: true, cleanupRuntimeVerified: true, jwtPreviousRuntimeRejected: true, qrPreviousRuntimeRejected: true,
    jwtCurrentRuntimeVerify: true, qrCurrentRuntimeVerify: true, qrUnknownKeyRejected: true, serviceHealthy: true,
  },
  linkedDeployShas: [sha, "b".repeat(40)],
  verificationRefs: ["https://github.com/example/run/1"],
  families: [
    { name: "jwt_secrets", rotatedAt: "2026-08-10T00:00:00.000Z", operator: "ops@example.com", method: "dual-slot", currentVersionId: "jwt-version-123", previousVersionId: "jwt-version-456", verificationRef: "https://github.com/example/run/1" },
    { name: "qr_signing_keys", rotatedAt: "2026-08-10T00:00:00.000Z", operator: "ops@example.com", method: "dual-slot", currentVersionId: "qr-version-123", previousVersionId: "qr-version-456", currentKeyVersion: "current-v2", previousKeyVersion: "old-v1", verificationRef: "https://github.com/example/run/1" },
  ],
};

test("fresh machine-verifiable evidence passes", () => {
  assert.deepEqual(validateRotationEvidenceContract(fresh, { now: Date.parse("2026-08-10T12:00:00.000Z") }), []);
  assert.deepEqual(validateRotationEvidenceFreshness(fresh, { now: Date.parse("2026-08-10T12:00:00.000Z") }), []);
  assert.deepEqual(validateRotationEvidence(fresh, { now: Date.parse("2026-08-10T12:00:00.000Z") }), []);
});

test("valid stale evidence passes contract validation but fails freshness", () => {
  const stale = {
    ...fresh,
    recordedAt: "2026-04-11T20:00:00.000Z",
    cleanupCompletedAt: "2026-04-12T20:00:00.000Z",
    overlapReadyAt: "2026-04-11T20:00:00.000Z",
    verifiedAt: "2026-04-11T20:10:00.000Z",
    cleanupEligibleAt: "2026-04-12T19:00:00.000Z",
    retirementTimestamp: "2026-04-12T19:05:00.000Z",
    cleanupDeploymentObservedAt: "2026-04-12T19:10:00.000Z",
    families: fresh.families.map((family) => ({ ...family, rotatedAt: "2026-04-11T20:00:00.000Z" })),
  };
  const now = Date.parse("2026-08-10T20:00:00.000Z");
  assert.deepEqual(validateRotationEvidenceContract(stale, { now }), []);
  assert.match(validateRotationEvidenceFreshness(stale, { now }).join("\n"), /stale/);
});

test("pre-rotation source validation accepts stale evidence without implying closure", () => {
  const stale = { ...fresh, cleanupWindowComplete: false };
  const failures = validateRotationEvidenceContract(stale, { now: Date.parse("2026-08-10T20:00:00.000Z") });
  assert.deepEqual(failures, []);
  assert.equal(stale.cleanupWindowComplete, false);
  assert.match(validateRotationEvidenceFreshness(stale, { now: Date.parse("2026-08-10T20:00:00.000Z") }).join("\n"), /cleanupWindowComplete/);
});

test("strict freshness rejects missing final cleanup proof", () => {
  const incomplete = { ...fresh, cleanupWindowComplete: true };
  delete incomplete.cleanupCompletedAt;
  delete incomplete.cleanupDeploymentSha;
  delete incomplete.cleanupDeploymentObservedAt;
  const failures = validateRotationEvidenceFreshness(incomplete, { now: Date.parse("2026-08-10T12:00:00.000Z") });
  assert.match(failures.join("\n"), /cleanupCompletedAt|cleanupDeploymentSha|cleanupDeploymentObservedAt/);
});

test("stale and future evidence fail", () => {
  assert.match(validateRotationEvidence(fresh, { now: Date.parse("2026-12-09T00:00:00.000Z") }).join("\n"), /stale/);
  const future = { ...fresh, recordedAt: "2026-12-10T00:00:00.000Z" };
  assert.match(validateRotationEvidenceContract(future, { now: Date.parse("2026-08-10T00:00:00.000Z") }).join("\n"), /future/);
  assert.match(validateRotationEvidenceFreshness(future, { now: Date.parse("2026-08-10T00:00:00.000Z") }).join("\n"), /future/);
  const futureFamily = { ...fresh, families: fresh.families.map((family) => ({ ...family, rotatedAt: "2026-12-10T00:00:00.000Z" })) };
  assert.match(validateRotationEvidenceContract(futureFamily, { now: Date.parse("2026-08-10T00:00:00.000Z") }).join("\n"), /rotatedAt.*future/);
});

test("placeholder references and incomplete cleanup fail", () => {
  const invalid = { ...fresh, cleanupWindowComplete: false, cleanupEvidenceRef: "deploy-log://rotation/jwt", verificationRefs: ["deploy-log://rotation/jwt"] };
  const failures = validateRotationEvidenceContract(invalid, { now: Date.parse("2026-08-10T12:00:00.000Z"), requireCleanup: true });
  assert.match(failures.join("\n"), /machine-verifiable|cleanupWindowComplete/);
  assert.match(validateRotationEvidenceFreshness(invalid, { now: Date.parse("2026-08-10T12:00:00.000Z") }).join("\n"), /machine-verifiable|cleanupWindowComplete/);
});

test("same version identifiers fail closed", () => {
  const invalid = {
    ...fresh,
    families: fresh.families.map((family) => ({
      ...family,
      previousVersionId: family.currentVersionId,
      ...(family.name === "qr_signing_keys" ? { previousKeyVersion: family.currentKeyVersion } : {}),
    })),
  };
  const failures = validateRotationEvidenceContract(invalid, { now: Date.parse("2026-08-10T12:00:00.000Z") });
  assert.match(failures.join("\n"), /version IDs must be distinct|QR key versions/);
});

import assert from "node:assert/strict";
import test from "node:test";
import { validateOnboardingContract, validateRotationClosedContract } from "../security/production-onboarding-contract.mjs";

const names = ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"];
const acceptance = ["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"];
const overlap = { sourceSha: "a".repeat(40), imageDigest: `sha256:${"b".repeat(64)}`, serviceStable: true, targetTaskDefinitionMatch: true, targetImageDigestMatch: true, health: { serviceHealthy: true, healthReleaseGitSha: "a".repeat(40) }, rotationPhase: "verified", runtime: Object.fromEntries(names.map((name) => [name, true])), acceptance: Object.fromEntries(acceptance.map((name) => [name, true])) };

test("overlap-safe deployment can satisfy onboarding without claiming closure", () => {
  assert.equal(validateOnboardingContract(overlap), true);
  assert.throws(() => validateRotationClosedContract(overlap), /cleanup|grace/i);
});
test("onboarding fails closed for wrong release or missing runtime proof", () => {
  assert.throws(() => validateOnboardingContract({ ...overlap, health: { ...overlap.health, healthReleaseGitSha: "c".repeat(40) } }), /health release/i);
  assert.throws(() => validateOnboardingContract({ ...overlap, runtime: { ...overlap.runtime, artifactHistoricalRuntimeVerify: false } }), /artifactHistoricalRuntimeVerify/);
});
test("rotation closure remains separate and requires cleanup evidence", () => {
  const evidence = { cleanupEligibleAt: new Date(Date.now() - 1000).toISOString(), previousSlotsRetired: true, pendingSlotsRetired: true, cleanupDeploymentAfterRetirement: true, cleanupRuntimeVerified: true, oldJwtRejected: true, oldQrRejected: true, freshFinalRotationEvidence: true };
  assert.equal(validateRotationClosedContract(evidence), true);
  assert.throws(() => validateRotationClosedContract({ ...evidence, cleanupRuntimeVerified: false }), /cleanupRuntimeVerified/);
});

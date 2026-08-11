const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const requiredTrue = (value, name) => { if (value !== true) throw new Error(`${name} is required`); };

export const validateOnboardingContract = (evidence) => {
  if (!evidence || typeof evidence !== "object") throw new Error("onboarding evidence is required");
  if (!SHA.test(evidence.sourceSha)) throw new Error("sourceSha must be a full protected-main SHA");
  if (!DIGEST.test(evidence.imageDigest)) throw new Error("imageDigest must be a full image digest");
  for (const [name, value] of Object.entries({ serviceStable: evidence.serviceStable, targetTaskDefinitionMatch: evidence.targetTaskDefinitionMatch, targetImageDigestMatch: evidence.targetImageDigestMatch, health: evidence.health?.serviceHealthy })) requiredTrue(value, name);
  if (evidence.health.healthReleaseGitSha !== evidence.sourceSha) throw new Error("health release SHA does not match source SHA");
  if (!["overlap-ready", "verified"].includes(evidence.rotationPhase)) throw new Error("onboarding requires an overlap-safe rotation phase");
  for (const name of ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrPreviousRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"]) requiredTrue(evidence.runtime?.[name], `runtime.${name}`);
  for (const name of ["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"]) requiredTrue(evidence.acceptance?.[name], `acceptance.${name}`);
  return true;
};

export const validateRotationClosedContract = (evidence, now = Date.now) => {
  if (!evidence || typeof evidence !== "object") throw new Error("rotation closure evidence is required");
  const eligibleAt = Date.parse(String(evidence.cleanupEligibleAt || ""));
  if (!Number.isFinite(eligibleAt) || now() < eligibleAt) throw new Error("rotation grace window has not elapsed");
  for (const name of ["previousSlotsRetired", "pendingSlotsRetired", "cleanupDeploymentAfterRetirement", "cleanupRuntimeVerified", "oldJwtRejected", "oldQrRejected", "freshFinalRotationEvidence"]) requiredTrue(evidence[name], name);
  return true;
};

const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^sha256:[a-f0-9]{64}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const requiredTrue = (value, name) => { if (value !== true) throw new Error(`${name} is required`); };

// This is the immutable isolationLicensee emitted by
// backend/scripts/production-green-canary-provision.mjs for the reviewed
// production-green-pretraffic-canary-v1 contract.
export const PRODUCTION_GREEN_CANARY_ISOLATION_LICENSEE_ID = "4e5d6a2d-42cd-4b87-ac85-793e2e72b95c";
export const PRODUCTION_ONBOARDING_PATHS = Object.freeze({
  tenantIsolation: `/api/licensees/${PRODUCTION_GREEN_CANARY_ISOLATION_LICENSEE_ID}`,
  rbac: "/api/manufacturer/printer-agent/status",
  auditPath: "/api/audit/logs",
  printerTrust: "/api/manufacturer/printers",
  antiCloning: "/api/verify/:code",
  artifactSigning: "/api/internal/release",
  publicQrVerification: "/api/verify/:code",
});

export const assertOnboardingPaths = (paths = PRODUCTION_ONBOARDING_PATHS) => {
  if (!paths || Object.keys(paths).length !== 7) throw new Error("onboarding path manifest must contain exactly seven probes");
  for (const [name, value] of Object.entries(paths)) {
    if (!Object.hasOwn(PRODUCTION_ONBOARDING_PATHS, name) || typeof value !== "string" || value !== PRODUCTION_ONBOARDING_PATHS[name]) {
      throw new Error(`onboarding path ${name} is invalid`);
    }
  }
  return Object.freeze({ ...paths });
};

export const validateOnboardingContract = (evidence) => {
  if (!evidence || typeof evidence !== "object") throw new Error("onboarding evidence is required");
  if (evidence.valid !== true || typeof evidence.evidenceRef !== "string" || !/^[a-f0-9]{64}$/.test(evidence.evidenceSha256 || "")) throw new Error("onboarding evidence must be hash-bound and valid");
  if (!SHA.test(evidence.sourceSha)) throw new Error("sourceSha must be a full protected-main SHA");
  if (!DIGEST.test(evidence.imageDigest)) throw new Error("imageDigest must be a full image digest");
  if (typeof evidence.taskDefinitionArn !== "string" || typeof evidence.taskArn !== "string" || typeof evidence.rotationId !== "string" || !evidence.taskDefinitionArn || !evidence.taskArn || !evidence.rotationId) throw new Error("onboarding task and rotation identity are required");
  if (!SHA256.test(evidence.rotationStateSha256 || "")) throw new Error("onboarding rotation state SHA-256 is required");
  if (evidence.taskMarker !== true || evidence.ecsExecProof !== true) throw new Error("onboarding requires task marker and ECS Exec proof");
  for (const [name, value] of Object.entries({ serviceStable: evidence.serviceStable, targetTaskDefinitionMatch: evidence.targetTaskDefinitionMatch, targetImageDigestMatch: evidence.targetImageDigestMatch, health: evidence.health?.serviceHealthy })) requiredTrue(value, name);
  if (evidence.health.healthReleaseGitSha !== evidence.sourceSha) throw new Error("health release SHA does not match source SHA");
  if (!["overlap-ready", "verified"].includes(evidence.rotationPhase)) throw new Error("onboarding requires an overlap-safe rotation phase");
  for (const name of ["jwtCurrentRuntimeVerify", "jwtPreviousRuntimeVerify", "jwtInvalidRuntimeRejected", "qrCurrentRuntimeVerify", "qrTamperMatchingKeyTest", "qrUnknownKeyRejected", "cookieCurrentSealOnly", "cookiePreviousOpenDuringOverlap", "artifactCurrentRuntimeVerify", "artifactHistoricalRuntimeVerify"]) requiredTrue(evidence.runtime?.[name], `runtime.${name}`);
  if ((evidence.runtime?.qrPreviousRuntimeVerify === true) === (evidence.runtime?.legacyQrKeypairUnrecoverable === true)) throw new Error("runtime QR historical continuity must be either verified or explicitly unrecoverable");
  for (const name of ["superAdminLogin", "mfa", "authMe", "refresh", "dashboardStats", "qrStats", "tenantIsolation", "rbac", "auditPath", "printerTrust", "antiCloning", "dbReady", "redisReady", "objectStorageReady", "stageANetworkingReady"]) requiredTrue(evidence.acceptance?.[name], `acceptance.${name}`);
  return true;
};

export const validateRotationClosedContract = (evidence, now = Date.now) => {
  if (!evidence || typeof evidence !== "object") throw new Error("rotation closure evidence is required");
  const eligibleAt = Date.parse(String(evidence.cleanupEligibleAt || ""));
  if (!Number.isFinite(eligibleAt) || now() < eligibleAt) throw new Error("rotation grace window has not elapsed");
  for (const name of ["previousSlotsRetired", "pendingSlotsRetired", "cleanupDeploymentAfterRetirement", "cleanupRuntimeVerified", "oldJwtRejected", "freshFinalRotationEvidence"]) requiredTrue(evidence[name], name);
  if (evidence.legacyQrKeypairUnrecoverable === true ? evidence.oldQrRejected !== false || evidence.qrPreviousSlotAbsent !== true : evidence.oldQrRejected !== true) throw new Error("oldQrRejected or explicit unrecoverable legacy QR state is required");
  return true;
};

import { readFileSync } from "node:fs";

const DAY_MS = 24 * 60 * 60 * 1000;
export const ROTATION_EVIDENCE_MAX_AGE_DAYS = 120;
const REQUIRED_FAMILIES = new Set(["jwt_secrets", "qr_signing_keys"]);
const SHA = /^[a-f0-9]{40}$/;
const VERSION_ID = /^[A-Za-z0-9+=/:._-]{7,256}$/;
const ROTATION_ID = /^[A-Za-z0-9._-]{8,128}$/;

const text = (value) => String(value ?? "").trim();
const isIsoDate = (value) => {
  const date = new Date(text(value));
  return !Number.isNaN(date.getTime());
};
const hasRealReference = (value) => {
  const reference = text(value);
  return Boolean(reference) && !reference.startsWith("deploy-log://") && !reference.includes("<") && !reference.includes(">");
};

export const validateRotationEvidenceContract = (evidence, { now = Date.now(), requireCleanup = false } = {}) => {
  const failures = [];
  const required = [
    "evidenceVersion", "rotationId", "recordedAt", "sourceSha", "approvedBy", "approverRole",
    "reason", "ticket", "environment", "cleanupWindowComplete", "cleanupCompletedAt",
    "cleanupVerifiedBy", "linkedDeployShas", "verificationRefs", "families",
  ];
  for (const key of required) if (!(key in (evidence || {}))) failures.push(`rotation evidence missing required field: ${key}`);

  if (evidence?.evidenceVersion !== 2) failures.push("rotation evidence evidenceVersion must be 2");
  if (!ROTATION_ID.test(text(evidence?.rotationId))) failures.push("rotation evidence rotationId is invalid");
  if (!SHA.test(text(evidence?.sourceSha))) failures.push("rotation evidence sourceSha must be a full SHA-1");

  const recordedAt = new Date(text(evidence?.recordedAt));
  if (!isIsoDate(evidence?.recordedAt)) failures.push("rotation evidence recordedAt must be a valid ISO date-time");
  else {
    if (now - recordedAt.getTime() < 0) failures.push("rotation evidence recordedAt must not be in the future");
  }

  if (!Array.isArray(evidence?.linkedDeployShas) || evidence.linkedDeployShas.length < 2 || evidence.linkedDeployShas.some((sha) => !SHA.test(text(sha)))) {
    failures.push("rotation evidence linkedDeployShas must contain at least two full SHAs");
  }
  if (!Array.isArray(evidence?.verificationRefs) || evidence.verificationRefs.length === 0 || evidence.verificationRefs.some((ref) => !hasRealReference(ref))) {
    failures.push("rotation evidence verificationRefs must contain machine-verifiable references");
  }

  const cleanupComplete = evidence?.cleanupWindowComplete === true;
  if (requireCleanup && !cleanupComplete) failures.push("rotation evidence cleanupWindowComplete must be true for production freshness");
  if (cleanupComplete) {
    const timeline = ["overlapReadyAt", "verifiedAt", "cleanupEligibleAt", "retirementTimestamp", "cleanupDeploymentObservedAt", "cleanupCompletedAt"]
      .map((key) => [key, new Date(text(evidence?.[key])).getTime()]);
    for (const [key, value] of timeline) {
      if (!isIsoDate(evidence?.[key])) failures.push(`rotation evidence ${key} must be a valid ISO date-time`);
      else if (value > now) failures.push(`rotation evidence ${key} must not be in the future`);
    }
    for (let index = 1; index < timeline.length; index += 1) {
      if (Number.isFinite(timeline[index - 1][1]) && Number.isFinite(timeline[index][1]) && timeline[index][1] < timeline[index - 1][1]) {
        failures.push(`rotation evidence timeline is not monotonic at ${timeline[index][0]}`);
      }
    }
    if (!SHA.test(text(evidence?.cleanupDeploymentSha))) failures.push("rotation evidence cleanupDeploymentSha must be a full SHA-1");
    if (!isIsoDate(evidence?.cleanupCompletedAt)) failures.push("rotation evidence cleanupCompletedAt must be valid when cleanup is complete");
    else if (new Date(evidence.cleanupCompletedAt).getTime() > now) failures.push("rotation evidence cleanupCompletedAt must not be in the future");
    if (!text(evidence?.cleanupVerifiedBy)) failures.push("rotation evidence cleanupVerifiedBy must be set when cleanup is complete");
    if (!hasRealReference(evidence?.cleanupEvidenceRef)) failures.push("rotation evidence cleanupEvidenceRef must be machine-verifiable");
    const proofNames = [
      "previousJwtSlotRetired", "previousQrPublicSlotRetired", "jwtPendingRetired", "qrPrivatePendingRetired", "qrPublicPendingRetired",
      "cleanupDeploymentAfterRetirement", "cleanupRuntimeVerified", "jwtPreviousRuntimeRejected",
      "jwtCurrentRuntimeVerify", "qrCurrentRuntimeVerify", "qrUnknownKeyRejected", "serviceHealthy",
    ];
    for (const name of proofNames) if (evidence?.proofs?.[name] !== true) failures.push(`rotation evidence cleanup proof ${name} must be true`);
    const legacyQrKeypairUnrecoverable = evidence?.proofs?.historicalContinuity === "LEGACY_QR_KEYPAIR_UNRECOVERABLE" && evidence?.proofs?.legacyQrKeypairUnrecoverable === true;
    if (legacyQrKeypairUnrecoverable ? evidence?.proofs?.qrPreviousRuntimeRejected !== false || evidence?.proofs?.qrPreviousSlotAbsent !== true : evidence?.proofs?.qrPreviousRuntimeRejected !== true) failures.push("rotation evidence QR retirement proof is invalid");
  }

  const families = Array.isArray(evidence?.families) ? evidence.families : [];
  const familyNames = new Set(families.map((family) => text(family?.name)));
  for (const familyName of REQUIRED_FAMILIES) if (!familyNames.has(familyName)) failures.push(`rotation evidence missing required family entry: ${familyName}`);

  for (const family of families) {
    const name = text(family?.name);
    if (!text(family?.operator)) failures.push(`rotation evidence family ${name || "unknown"} missing operator`);
    if (!isIsoDate(family?.rotatedAt)) failures.push(`rotation evidence family ${name || "unknown"} has invalid rotatedAt`);
    else if (new Date(family.rotatedAt).getTime() > now) failures.push(`rotation evidence family ${name || "unknown"} rotatedAt must not be in the future`);
    if (!VERSION_ID.test(text(family?.currentVersionId))) failures.push(`rotation evidence family ${name || "unknown"} currentVersionId is invalid`);
    if (!VERSION_ID.test(text(family?.previousVersionId))) failures.push(`rotation evidence family ${name || "unknown"} previousVersionId is invalid`);
    if (text(family?.currentVersionId) === text(family?.previousVersionId)) failures.push(`rotation evidence family ${name || "unknown"} version IDs must be distinct`);
    if (!hasRealReference(family?.verificationRef)) failures.push(`rotation evidence family ${name || "unknown"} verificationRef is invalid`);
    if (name === "qr_signing_keys") {
      if (!text(family?.currentKeyVersion) || !text(family?.previousKeyVersion) || text(family.currentKeyVersion) === text(family.previousKeyVersion)) {
        failures.push("rotation evidence QR key versions must be present and distinct");
      }
      const unrecoverable = family?.historicalContinuity === "LEGACY_QR_KEYPAIR_UNRECOVERABLE";
      if (unrecoverable ? family?.rollbackCapable !== false : family?.historicalContinuity !== undefined && (family.historicalContinuity !== "VERIFIED_PREVIOUS_QR" || family.rollbackCapable !== true)) failures.push("rotation evidence QR continuity semantics are invalid");
    }
  }

  return failures;
};

export const validateRotationEvidenceFreshness = (evidence, { now = Date.now(), maxAgeDays = ROTATION_EVIDENCE_MAX_AGE_DAYS, requireCleanup = true } = {}) => {
  const failures = validateRotationEvidenceContract(evidence, { now, requireCleanup });
  const recordedAt = new Date(text(evidence?.recordedAt));
  if (isIsoDate(evidence?.recordedAt)) {
    const ageMs = now - recordedAt.getTime();
    if (ageMs > maxAgeDays * DAY_MS) failures.push(`rotation evidence is stale (${Math.floor(ageMs / DAY_MS)} days old; max ${maxAgeDays})`);
  }
  return failures;
};

// Backward-compatible strict API for existing callers and production gates.
export const validateRotationEvidence = validateRotationEvidenceFreshness;

export const readRotationEvidence = (path) => JSON.parse(readFileSync(path, "utf8"));

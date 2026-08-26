export const PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS = 2_592_000;

export function assertProductionRotationGraceSeconds(value, label = "minimumGraceSeconds") {
  if (!Number.isSafeInteger(value) || value < PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS) {
    throw new Error(`${label} must be a safe integer of at least ${PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS} seconds`);
  }
  return value;
}

export function deriveProductionRotationCleanupEligibleAt(observedAt, minimumGraceSeconds) {
  assertProductionRotationGraceSeconds(minimumGraceSeconds);
  if (typeof observedAt !== "string") throw new Error("overlap observedAt must be a canonical ISO timestamp");
  const observedAtMs = Date.parse(observedAt);
  if (!Number.isSafeInteger(observedAtMs) || new Date(observedAtMs).toISOString() !== observedAt) throw new Error("overlap observedAt must be a canonical ISO timestamp");
  const graceMs = minimumGraceSeconds * 1000;
  const cleanupEligibleAtMs = observedAtMs + graceMs;
  if (!Number.isSafeInteger(graceMs) || !Number.isSafeInteger(cleanupEligibleAtMs)) throw new Error("rotation cleanup deadline exceeds the supported timestamp range");
  const cleanupEligibleAt = new Date(cleanupEligibleAtMs).toISOString();
  if (Date.parse(cleanupEligibleAt) !== cleanupEligibleAtMs) throw new Error("rotation cleanup deadline exceeds the supported timestamp range");
  return cleanupEligibleAt;
}

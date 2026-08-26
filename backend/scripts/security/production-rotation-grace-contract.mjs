export const PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS = 2_592_000;
export const PRODUCTION_ROTATION_LEGACY_STATE_VERSION = 3;
export const PRODUCTION_ROTATION_STATE_VERSION = 4;

const PHASES_WITH_GRACE_ANCHOR = new Set([
  "overlap-ready", "verified", "grace-wait", "retirement-started", "retirement-complete",
  "cleanup-deploy-required", "cleanup-runtime-verified", "cleaned",
]);
const PHASES_BEFORE_GRACE_ANCHOR = new Set(["prepared", "overlap-deploy-required"]);
const GRACE_STATE_FIELDS = ["overlapReadyAt", "verifiedAt", "cleanupEligibleAt", "overlapRuntime", "verification"];

const canonicalTimestamp = (value, label) => {
  if (typeof value !== "string") throw new Error(`${label} must be a canonical ISO timestamp`);
  const milliseconds = Date.parse(value);
  if (!Number.isSafeInteger(milliseconds) || new Date(milliseconds).toISOString() !== value) throw new Error(`${label} must be a canonical ISO timestamp`);
  return milliseconds;
};

export function assertProductionRotationGraceSeconds(value, label = "minimumGraceSeconds") {
  if (!Number.isSafeInteger(value) || value < PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS) {
    throw new Error(`${label} must be a safe integer of at least ${PRODUCTION_ROTATION_MINIMUM_GRACE_SECONDS} seconds`);
  }
  return value;
}

export function deriveProductionRotationCleanupEligibleAt(observedAt, minimumGraceSeconds) {
  assertProductionRotationGraceSeconds(minimumGraceSeconds);
  const observedAtMs = canonicalTimestamp(observedAt, "overlap observedAt");
  const graceMs = minimumGraceSeconds * 1000;
  const cleanupEligibleAtMs = observedAtMs + graceMs;
  if (!Number.isSafeInteger(graceMs) || !Number.isSafeInteger(cleanupEligibleAtMs)) throw new Error("rotation cleanup deadline exceeds the supported timestamp range");
  const cleanupEligibleAt = new Date(cleanupEligibleAtMs).toISOString();
  if (Date.parse(cleanupEligibleAt) !== cleanupEligibleAtMs) throw new Error("rotation cleanup deadline exceeds the supported timestamp range");
  return cleanupEligibleAt;
}

function historicalGraceSeconds(state) {
  if (typeof state.overlapReadyAt !== "string" || typeof state.cleanupEligibleAt !== "string") {
    throw new Error("legacy rotation state does not contain an authenticated grace window");
  }
  const overlapReadyAtMs = canonicalTimestamp(state.overlapReadyAt, "legacy overlapReadyAt");
  const cleanupEligibleAtMs = canonicalTimestamp(state.cleanupEligibleAt, "legacy cleanupEligibleAt");
  const graceMs = cleanupEligibleAtMs - overlapReadyAtMs;
  if (!Number.isSafeInteger(graceMs) || graceMs <= 0 || graceMs % 1000 !== 0) {
    throw new Error("legacy rotation grace must be a positive whole number of seconds");
  }
  return assertProductionRotationGraceSeconds(graceMs / 1000, "derived legacy minimumGraceSeconds");
}

function assertPersistedGraceWindow(state, minimumGraceSeconds) {
  const overlapReadyAtMs = canonicalTimestamp(state.overlapReadyAt, "state.overlapReadyAt");
  if (state.cleanupEligibleAt !== deriveProductionRotationCleanupEligibleAt(state.overlapReadyAt, minimumGraceSeconds)) throw new Error("rotation cleanup deadline does not match the persisted grace");
  const proof = state.overlapRuntime;
  if (!proof || typeof proof !== "object" || Array.isArray(proof) || proof.phase !== "overlap"
    || proof.rotationId !== state.rotationId || proof.deploymentSha !== state.overlapDeploymentSha || proof.observedAt !== state.overlapReadyAt) {
    throw new Error("rotation grace anchor does not match the persisted overlap runtime proof");
  }
  if (state.phase !== "overlap-ready" && canonicalTimestamp(state.verifiedAt, "state.verifiedAt") < overlapReadyAtMs) throw new Error("rotation verifiedAt precedes the overlap grace anchor");
}

export function normalizeProductionRotationState(state, { reviewedMinimumGraceSeconds } = {}) {
  if (!state || typeof state !== "object" || Array.isArray(state)) throw new Error("rotation state must be a plain object");
  if (!PHASES_BEFORE_GRACE_ANCHOR.has(state.phase) && !PHASES_WITH_GRACE_ANCHOR.has(state.phase)) throw new Error(`unsupported rotation phase: ${state.phase}`);
  if (reviewedMinimumGraceSeconds !== undefined) assertProductionRotationGraceSeconds(reviewedMinimumGraceSeconds, "reviewed minimumGraceSeconds");

  if (state.stateVersion === PRODUCTION_ROTATION_STATE_VERSION) {
    assertProductionRotationGraceSeconds(state.minimumGraceSeconds, "state.minimumGraceSeconds");
    if (reviewedMinimumGraceSeconds !== undefined && state.minimumGraceSeconds !== reviewedMinimumGraceSeconds) throw new Error("state minimum grace does not match the reviewed config");
    if (PHASES_BEFORE_GRACE_ANCHOR.has(state.phase)) {
      if (GRACE_STATE_FIELDS.some((field) => state[field] !== undefined)) throw new Error("pre-overlap rotation state cannot contain overlap runtime or grace fields");
    } else assertPersistedGraceWindow(state, state.minimumGraceSeconds);
    return Object.freeze({ state, migrated: false });
  }

  if (state.stateVersion !== PRODUCTION_ROTATION_LEGACY_STATE_VERSION) throw new Error(`unsupported rotation stateVersion: ${state.stateVersion}`);
  if (Object.hasOwn(state, "minimumGraceSeconds")) throw new Error("legacy rotation state cannot contain current-schema minimumGraceSeconds");
  let minimumGraceSeconds;
  if (PHASES_BEFORE_GRACE_ANCHOR.has(state.phase)) {
    if (GRACE_STATE_FIELDS.some((field) => state[field] !== undefined)) throw new Error("legacy pre-overlap state cannot contain overlap runtime or grace fields");
    if (reviewedMinimumGraceSeconds === undefined) throw new Error("legacy pre-overlap state requires its authenticated reviewed grace config");
    minimumGraceSeconds = reviewedMinimumGraceSeconds;
  } else {
    minimumGraceSeconds = historicalGraceSeconds(state);
    if (reviewedMinimumGraceSeconds !== undefined && minimumGraceSeconds !== reviewedMinimumGraceSeconds) throw new Error("derived legacy minimum grace does not match the reviewed config");
  }
  const normalized = { ...state, stateVersion: PRODUCTION_ROTATION_STATE_VERSION, minimumGraceSeconds };
  if (PHASES_WITH_GRACE_ANCHOR.has(normalized.phase)) assertPersistedGraceWindow(normalized, normalized.minimumGraceSeconds);
  return Object.freeze({ state: normalized, migrated: true });
}

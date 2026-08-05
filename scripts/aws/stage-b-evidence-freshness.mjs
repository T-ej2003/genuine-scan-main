export const STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS = 3600;
export const STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS = STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS * 1000;
export const STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS = 60 * 1000;
export const STAGE_B_DEPLOYMENT_EVIDENCE_VALIDITY_MODEL = "live-plan-bound-60m";

const strictUtcTimestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export function parseStageBDeploymentEvidenceTimestamp(value, evidenceType = "Stage B deployment evidence") {
  if (typeof value !== "string" || !strictUtcTimestamp.test(value)) throw new Error(`${evidenceType} timestamp is malformed: expected strict UTC ISO-8601 with milliseconds.`);
  const timestampMs = Date.parse(value);
  if (!Number.isFinite(timestampMs) || new Date(timestampMs).toISOString() !== value) throw new Error(`${evidenceType} timestamp is malformed: expected strict UTC ISO-8601 with milliseconds.`);
  return timestampMs;
}

function validationClockMs(now) {
  if (now instanceof Date) {
    const nowMs = now.getTime();
    if (Number.isFinite(nowMs)) return nowMs;
  }
  return parseStageBDeploymentEvidenceTimestamp(now, "Stage B validation clock");
}

export function assertStageBDeploymentEvidenceTimestamp(value, { now = new Date(), evidenceType = "Stage B deployment evidence" } = {}) {
  const timestampMs = parseStageBDeploymentEvidenceTimestamp(value, evidenceType);
  const nowMs = validationClockMs(now);
  const ageMs = nowMs - timestampMs;
  if (ageMs < -STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS) throw new Error(`${evidenceType} timestamp is in the future: timestamp=${value}, ageSeconds=${(ageMs / 1000).toFixed(3)}, allowedClockSkewSeconds=${STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS / 1000}.`);
  return { timestampMs, nowMs, ageMs: Math.max(0, ageMs), ageSeconds: Math.max(0, ageMs / 1000) };
}

export function assertStageBDeploymentEvidenceFreshness(value, { now = new Date(), evidenceType = "Stage B deployment evidence" } = {}) {
  const result = assertStageBDeploymentEvidenceTimestamp(value, { now, evidenceType });
  if (result.ageMs >= STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS) throw new Error(`${evidenceType} stale/expired: timestamp=${value}, ageSeconds=${result.ageSeconds.toFixed(3)}, allowedTtlSeconds=${STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS}.`);
  return { ...result, ttlSeconds: STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS };
}

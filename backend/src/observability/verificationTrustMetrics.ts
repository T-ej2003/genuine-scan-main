import { createHash } from "crypto";

import { logger } from "../utils/logger";

const parseBoolEnv = (value: unknown, fallback: boolean) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const VERIFY_OBSERVABILITY_LOGGING_ENABLED = parseBoolEnv(process.env.VERIFY_OBSERVABILITY_LOGGING_ENABLED, true);
const MAX_METADATA_DEPTH = 4;
const MAX_METADATA_KEYS = 24;

const SENSITIVE_METADATA_KEY = /(email|token|secret|password|cookie|session|proof|user(agent)?|ip|device|customer|actor|decision|licensee|batch|qr|id|ref)$/i;
const SIMPLE_METRIC_STRING = /^[A-Z0-9_:-]{1,64}$/i;

type VerificationTrustMetricPayload = {
  decisionId?: string | null;
  qrCodeId?: string | null;
  licenseeId?: string | null;
  batchId?: string | null;
  proofSource?: string | null;
  proofTier?: string | null;
  classification?: string | null;
  publicOutcome?: string | null;
  riskDisposition?: string | null;
  riskBand?: string | null;
  printTrustState?: string | null;
  issuanceMode?: string | null;
  replayState?: string | null;
  challengeRequired?: boolean;
  challengeCompleted?: boolean;
  challengeCompletedBy?: string | null;
  signingMode?: string | null;
  signingKeyVersion?: string | null;
  signingProvider?: string | null;
  replacementStatus?: string | null;
  breakGlassUsage?: boolean;
  limitedProvenance?: boolean;
  metadata?: Record<string, unknown> | null;
};

const hashRef = (prefix: string, value: unknown) => {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  return `${prefix}_${createHash("sha256").update(normalized).digest("hex").slice(0, 12)}`;
};

const bucketCount = (value: unknown) => {
  const count = Number(value || 0);
  if (!Number.isFinite(count) || count <= 0) return "0";
  if (count === 1) return "1";
  if (count <= 5) return "2_5";
  if (count <= 20) return "6_20";
  if (count <= 100) return "21_100";
  return "101_plus";
};

const sanitizeMetricMetadata = (value: unknown, depth = 0): unknown => {
  if (value == null) return null;
  if (depth >= MAX_METADATA_DEPTH) return "[truncated]";
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "string") {
    const normalized = value.trim();
    if (!normalized) return null;
    if (SIMPLE_METRIC_STRING.test(normalized)) return normalized;
    return hashRef("str", normalized);
  }
  if (Array.isArray(value)) {
    return value.slice(0, 10).map((entry) => sanitizeMetricMetadata(entry, depth + 1));
  }
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, MAX_METADATA_KEYS)) {
      if (SENSITIVE_METADATA_KEY.test(key)) continue;
      out[key] = sanitizeMetricMetadata(entry, depth + 1);
    }
    return out;
  }
  return String(value);
};

export const buildVerificationTrustMetricEvent = (payload: VerificationTrustMetricPayload) => ({
  schemaVersion: 2,
  metric: "verification_trust_state",
  decisionRef: hashRef("decision", payload.decisionId),
  qrRef: hashRef("qr", payload.qrCodeId),
  licenseeRef: hashRef("lic", payload.licenseeId),
  batchRef: hashRef("batch", payload.batchId),
  proofSource: payload.proofSource || null,
  proofTier: payload.proofTier || null,
  classification: payload.classification || null,
  publicOutcome: payload.publicOutcome || null,
  riskDisposition: payload.riskDisposition || null,
  riskBand: payload.riskBand || null,
  printTrustState: payload.printTrustState || null,
  issuanceMode: payload.issuanceMode || null,
  replayState: payload.replayState || null,
  challengeRequired: Boolean(payload.challengeRequired),
  challengeCompleted: Boolean(payload.challengeCompleted),
  challengeCompletedBy: payload.challengeCompletedBy || null,
  signingMode: payload.signingMode || null,
  signingKeyVersion: payload.signingKeyVersion || null,
  signingProvider: payload.signingProvider || null,
  replacementStatus: payload.replacementStatus || null,
  breakGlassUsage: Boolean(payload.breakGlassUsage),
  limitedProvenance: Boolean(payload.limitedProvenance),
  metadata: sanitizeMetricMetadata(payload.metadata || null),
});

export const buildBreakGlassIssuanceMetricEvent = (payload: {
  licenseeId?: string | null;
  quantity?: number | null;
  actorUserId?: string | null;
}) => ({
  schemaVersion: 2,
  metric: "verification_break_glass_generate",
  breakGlassUsage: true,
  licenseeRef: hashRef("lic", payload.licenseeId),
  actorRef: hashRef("actor", payload.actorUserId),
  quantity: Number(payload.quantity || 0),
  quantityBucket: bucketCount(payload.quantity || 0),
});

export const recordVerificationTrustMetric = (payload: VerificationTrustMetricPayload) => {
  if (!VERIFY_OBSERVABILITY_LOGGING_ENABLED) return;

  logger.info("verification_trust_metric", buildVerificationTrustMetricEvent(payload));
};

export const recordBreakGlassIssuanceMetric = (payload: {
  licenseeId?: string | null;
  quantity?: number | null;
  actorUserId?: string | null;
}) => {
  if (!VERIFY_OBSERVABILITY_LOGGING_ENABLED) return;

  logger.warn("verification_trust_metric", buildBreakGlassIssuanceMetricEvent(payload));
};

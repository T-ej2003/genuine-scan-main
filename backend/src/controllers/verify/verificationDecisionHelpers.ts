import { VerificationDegradationMode } from "@prisma/client";

import { createAuditLogSafely } from "../../services/auditService";
import { recordDegradationEvent } from "../../services/degradationEventService";
import {
  attachVerificationPresentationSnapshot,
  issuePublicVerificationSessionStartToken,
  type VerificationDecisionSummary,
} from "../../services/verificationDecisionService";
import { buildPublicVerificationSemantics, type VerificationProofSource } from "./shared";

export const toNum = (value: unknown) => {
  const parsed = parseFloat(String(value));
  return Number.isFinite(parsed) ? parsed : null;
};

export const buildSignedTokenErrorResponse = (message: string, scanOutcome: string) => ({
  success: true,
  data: {
    isAuthentic: false,
    message,
    reasons: [message],
    scanOutcome,
    proofSource: "SIGNED_LABEL" as VerificationProofSource,
  },
});

export const applyPublicSemantics = <T extends Record<string, unknown>>(
  payload: T,
  semantics: ReturnType<typeof buildPublicVerificationSemantics>
) => ({
  ...payload,
  message: semantics.headline,
  publicOutcome: semantics.publicOutcome,
  riskDisposition: semantics.riskDisposition,
  messageKey: semantics.messageKey,
  nextActionKey: semantics.nextActionKey,
});

const withDecisionMetadata = <T extends Record<string, unknown>>(payload: T, decision: VerificationDecisionSummary) => ({
  ...payload,
  decisionVersion: decision.decisionVersion,
  proofTier: decision.proofTier,
  reasonCodes: decision.reasonCodes,
  riskBand: decision.riskBand,
  replacementStatus: decision.replacementStatus,
  degradationMode: decision.degradationMode,
  customerTrustLevel: decision.customerTrustLevel,
  publicOutcome: decision.publicOutcome || payload.publicOutcome || null,
  riskDisposition: decision.riskDisposition || payload.riskDisposition || null,
  messageKey: decision.messageKey || payload.messageKey || null,
  nextActionKey: decision.nextActionKey || payload.nextActionKey || null,
  latestDecisionOutcome: payload.scanOutcome || decision.publicOutcome || null,
});

const toText = (value: unknown) => String(value || "").trim();

const maskPublicCode = (value: unknown) => {
  const code = toText(value);
  if (!code) return null;
  return `${code.slice(0, Math.min(4, code.length))}${code.length > 4 ? `-${code.slice(-4)}` : ""}`;
};

const mapPublicStatus = (payload: Record<string, unknown>) => {
  const outcome = toText(payload.publicOutcome).toUpperCase();
  const classification = toText(payload.classification).toUpperCase();
  const scanOutcome = toText(payload.scanOutcome).toUpperCase();
  const status = toText(payload.status).toUpperCase();

  if (Boolean(payload.isBlocked) || outcome === "BLOCKED" || status === "BLOCKED" || scanOutcome === "BLOCKED") return "blocked";
  if (outcome === "NOT_FOUND" || outcome === "INTEGRITY_ERROR" || classification === "NOT_FOUND" || scanOutcome === "NOT_FOUND") {
    return "not_found";
  }
  if (outcome === "NOT_READY" || classification === "NOT_READY_FOR_CUSTOMER_USE" || payload.isReady === false) {
    return "not_ready";
  }
  if (outcome === "REVIEW_REQUIRED" || outcome === "LIMITED_PROVENANCE" || classification === "SUSPICIOUS_DUPLICATE") {
    return "review_needed";
  }
  return payload.isAuthentic ? "verified" : "review_needed";
};

const mapPublicScanStatus = (payload: Record<string, unknown>) => {
  const count = Number(payload.totalScans ?? payload.scanCount ?? 0);
  if (Boolean(payload.isFirstScan) || toText(payload.classification).toUpperCase() === "FIRST_SCAN") return "first_successful_scan";
  if (count > 1 || payload.latestScanAt || payload.latestVerifiedAt || payload.previousScanAt) return "previously_scanned";
  return "checked";
};

const mapPublicRiskSignalStatus = (publicStatus: string) => {
  if (publicStatus === "verified") return "clear";
  if (publicStatus === "blocked") return "brand_action_required";
  if (publicStatus === "not_found") return "not_assessed";
  if (publicStatus === "not_ready") return "activation_not_complete";
  return "needs_brand_review";
};

const sanitizePublicLicensee = (value: unknown) => {
  const licensee = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  if (!Object.keys(licensee).length) return null;
  return {
    name: toText(licensee.name) || undefined,
    brandName: toText(licensee.brandName) || undefined,
    website: toText(licensee.website) || undefined,
    supportEmail: toText(licensee.supportEmail) || undefined,
    supportPhone: toText(licensee.supportPhone) || undefined,
  };
};

const sanitizePublicBatch = (value: unknown) => {
  const batch = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const manufacturer =
    batch.manufacturer && typeof batch.manufacturer === "object" && !Array.isArray(batch.manufacturer)
      ? (batch.manufacturer as Record<string, unknown>)
      : {};
  if (!Object.keys(batch).length && !Object.keys(manufacturer).length) return null;
  return {
    name: toText(batch.name) || undefined,
    printedAt: toText(batch.printedAt) || undefined,
    manufacturer: Object.keys(manufacturer).length
      ? {
          name: toText(manufacturer.name) || undefined,
          website: toText(manufacturer.website) || undefined,
        }
      : null,
  };
};

const sanitizeOwnershipStatus = (value: unknown) => {
  const status = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  if (!Object.keys(status).length) return null;
  return {
    isClaimed: Boolean(status.isClaimed),
    claimedAt: toText(status.claimedAt) || null,
    isOwnedByRequester: Boolean(status.isOwnedByRequester),
    isClaimedByAnother: Boolean(status.isClaimedByAnother),
    canClaim: Boolean(status.canClaim),
    state: toText(status.state) || undefined,
  };
};

const sanitizeOwnershipTransfer = (value: unknown) => {
  const transfer = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  if (!Object.keys(transfer).length) return null;
  return {
    state: toText(transfer.state) || undefined,
    active: Boolean(transfer.active),
    canCreate: Boolean(transfer.canCreate),
    canCancel: Boolean(transfer.canCancel),
    canAccept: Boolean(transfer.canAccept),
    initiatedByYou: Boolean(transfer.initiatedByYou),
    recipientEmailMasked: toText(transfer.recipientEmailMasked) || null,
    initiatedAt: toText(transfer.initiatedAt) || null,
    expiresAt: toText(transfer.expiresAt) || null,
    acceptedAt: toText(transfer.acceptedAt) || null,
    invalidReason: toText(transfer.invalidReason) || null,
  };
};

const sanitizeVerifyUxPolicy = (value: unknown) => {
  const policy = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  return {
    allowOwnershipClaim: Boolean(policy.allowOwnershipClaim),
    allowFraudReport: policy.allowFraudReport !== false,
    mobileCameraAssist: policy.mobileCameraAssist !== false,
  };
};

const sanitizeChallenge = (value: unknown) => {
  const challenge = value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  if (!Object.keys(challenge).length) return null;
  return {
    required: Boolean(challenge.required),
    completed: Boolean(challenge.completed),
  };
};

const buildPublicVerificationResponseBody = (
  payload: Record<string, unknown>,
  sessionStartToken: string | null
) => {
  const publicStatus = mapPublicStatus(payload);
  const code = toText(payload.code);
  const totalScans = Number(payload.totalScans ?? payload.scanCount ?? 0);

  return {
    isAuthentic: Boolean(payload.isAuthentic),
    publicStatus,
    scanStatus: mapPublicScanStatus(payload),
    riskSignalStatus: mapPublicRiskSignalStatus(publicStatus),
    code: code || undefined,
    maskedCode: maskPublicCode(code),
    message: toText(payload.message) || undefined,
    warningMessage: toText(payload.warningMessage) || undefined,
    status: publicStatus,
    isBlocked: publicStatus === "blocked",
    isReady: publicStatus !== "not_ready",
    isFirstScan: mapPublicScanStatus(payload) === "first_successful_scan",
    totalScans: Number.isFinite(totalScans) ? totalScans : 0,
    firstVerifiedAt: toText(payload.firstVerifiedAt || payload.firstScanAt) || null,
    latestVerifiedAt: toText(payload.latestVerifiedAt || payload.latestScanAt) || null,
    latestScanAt: toText(payload.latestScanAt || payload.latestVerifiedAt) || null,
    licensee: sanitizePublicLicensee(payload.licensee),
    batch: sanitizePublicBatch(payload.batch),
    ownershipStatus: sanitizeOwnershipStatus(payload.ownershipStatus),
    ownershipTransfer: sanitizeOwnershipTransfer(payload.ownershipTransfer),
    verifyUxPolicy: sanitizeVerifyUxPolicy(payload.verifyUxPolicy),
    challenge: sanitizeChallenge(payload.challenge),
    sessionStartToken: sessionStartToken || undefined,
  };
};

export const buildDecisionResponseBody = async <T extends Record<string, unknown>>(payload: T, decision: VerificationDecisionSummary) => {
  const finalPayload = withDecisionMetadata(payload, decision);
  await attachVerificationPresentationSnapshot(decision.decisionId, finalPayload);
  const sessionStartToken = await issuePublicVerificationSessionStartToken(decision.decisionId);
  return buildPublicVerificationResponseBody(finalPayload, sessionStartToken);
};

export const safeCreateAuditLog = async (
  payload: Parameters<typeof createAuditLogSafely>[0],
  context?: Record<string, unknown>
) => {
  const result = await createAuditLogSafely(payload);
  if (result.queued) {
    await recordDegradationEvent({
      dependencyKey: "audit_log",
      mode: VerificationDegradationMode.QUEUE_AND_RETRY,
      code: "AUDIT_LOG_QUEUED",
      message: "Audit log write failed on request path and was queued for retry.",
      context: {
        ...context,
        outboxId: result.outboxId || null,
        errorMessage: result.errorMessage || null,
      },
    });
    return VerificationDegradationMode.QUEUE_AND_RETRY;
  }
  return VerificationDegradationMode.NORMAL;
};

export const resolvePrintTrustState = (
  qrCode: { status?: unknown; issuanceMode?: unknown; printJobId?: unknown; printJob?: unknown } | null | undefined,
  readiness: { isReady?: boolean; governedProofEligible?: boolean } | boolean
) => {
  const readinessState = typeof readiness === "boolean" ? { isReady: readiness, governedProofEligible: false } : readiness;
  const status = String(qrCode?.status || "").trim().toUpperCase();
  const issuanceMode = String(qrCode?.issuanceMode || "LEGACY_UNSPECIFIED").trim().toUpperCase();
  if (issuanceMode === "BREAK_GLASS_DIRECT") return "RESTRICTED_DIRECT_ISSUANCE";
  if (!readinessState.isReady && (status === "ALLOCATED" || status === "ACTIVATED")) {
    return "AWAITING_PRINT_CONFIRMATION";
  }
  if (readinessState.governedProofEligible) return "PRINT_CONFIRMED";
  if (!qrCode?.printJobId && !qrCode?.printJob) return "LEGACY_NO_CONTROLLED_PRINT";
  if (readinessState.isReady) return "LIMITED_PROVENANCE";
  return "AWAITING_PRINT_CONFIRMATION";
};

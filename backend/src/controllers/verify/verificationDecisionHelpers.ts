import { VerificationDegradationMode } from "@prisma/client";

import { createAuditLogSafely } from "../../services/auditService";
import { recordDegradationEvent } from "../../services/degradationEventService";
import { attachVerificationPresentationSnapshot, type VerificationDecisionSummary } from "../../services/verificationDecisionService";
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
  decisionId: decision.decisionId,
  decisionVersion: decision.decisionVersion,
  proofTier: decision.proofTier,
  reasonCodes: decision.reasonCodes,
  riskBand: decision.riskBand,
  replacementStatus: decision.replacementStatus,
  degradationMode: decision.degradationMode,
  customerTrustLevel: decision.customerTrustLevel,
  replacementChainId: decision.replacementChainId || null,
  publicOutcome: decision.publicOutcome || (payload as any).publicOutcome || null,
  riskDisposition: decision.riskDisposition || (payload as any).riskDisposition || null,
  messageKey: decision.messageKey || (payload as any).messageKey || null,
  nextActionKey: decision.nextActionKey || (payload as any).nextActionKey || null,
  latestDecisionOutcome: payload.scanOutcome || decision.publicOutcome || null,
});

export const buildDecisionResponseBody = async <T extends Record<string, unknown>>(payload: T, decision: VerificationDecisionSummary) => {
  const finalPayload = withDecisionMetadata(payload, decision);
  await attachVerificationPresentationSnapshot(decision.decisionId, finalPayload);
  return finalPayload;
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

export const resolvePrintTrustState = (qrCode: any, readiness: { isReady?: boolean; governedProofEligible?: boolean } | boolean) => {
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

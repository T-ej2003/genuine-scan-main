import {
  CustomerTrustLevel,
  VerificationDecisionOutcome,
  VerificationDegradationMode,
  VerificationProofTier,
  VerificationReplacementStatus,
  VerificationRiskBand,
} from "@prisma/client";

import prisma from "../config/database";
import { recordVerificationTrustMetric } from "../observability/verificationTrustMetrics";

const DECISION_VERSION = 1;

const getDecisionStore = () => (prisma as any).verificationDecision;
const getEvidenceStore = () => (prisma as any).verificationEvidenceSnapshot;

const toReasonCode = (value: string) =>
  String(value || "")
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64);

const uniqueReasonCodes = (values: Array<string | null | undefined>) => {
  const codes = values.map((value) => toReasonCode(value || "")).filter(Boolean);
  return Array.from(new Set(codes));
};

const resolveRiskBand = (riskScore?: number | null) => {
  const score = Number(riskScore ?? 0);
  if (score >= 85) return VerificationRiskBand.CRITICAL;
  if (score >= 70) return VerificationRiskBand.HIGH;
  if (score >= 35) return VerificationRiskBand.ELEVATED;
  return VerificationRiskBand.LOW;
};

const resolveProofTier = (params: {
  proofSource?: string | null;
  degradationMode?: VerificationDegradationMode;
}) => {
  if (params.degradationMode && params.degradationMode !== VerificationDegradationMode.NORMAL) {
    return VerificationProofTier.DEGRADED;
  }
  return params.proofSource === "SIGNED_LABEL"
    ? VerificationProofTier.SIGNED_LABEL
    : VerificationProofTier.MANUAL_REGISTRY_LOOKUP;
};

const resolveOutcome = (params: {
  classification?: string | null;
  isAuthentic?: boolean;
  notFound?: boolean;
  errorOutcome?: VerificationDecisionOutcome | null;
}) => {
  if (params.errorOutcome) return params.errorOutcome;
  if (params.notFound) return VerificationDecisionOutcome.NOT_FOUND;

  switch (String(params.classification || "").trim().toUpperCase()) {
    case "BLOCKED_BY_SECURITY":
      return VerificationDecisionOutcome.BLOCKED;
    case "SUSPICIOUS_DUPLICATE":
      return VerificationDecisionOutcome.SUSPICIOUS_DUPLICATE;
    case "NOT_READY_FOR_CUSTOMER_USE":
      return VerificationDecisionOutcome.NOT_READY;
    case "FIRST_SCAN":
    case "LEGIT_REPEAT":
      return VerificationDecisionOutcome.AUTHENTIC;
    default:
      return params.isAuthentic ? VerificationDecisionOutcome.AUTHENTIC : VerificationDecisionOutcome.UNAVAILABLE;
  }
};

export type VerificationDecisionSummary = {
  decisionId: string | null;
  decisionVersion: number;
  proofTier: VerificationProofTier;
  reasonCodes: string[];
  riskBand: VerificationRiskBand;
  replacementStatus: VerificationReplacementStatus;
  degradationMode: VerificationDegradationMode;
  customerTrustLevel: CustomerTrustLevel;
  publicOutcome?: string | null;
  riskDisposition?: string | null;
  messageKey?: string | null;
  nextActionKey?: string | null;
  replacementChainId?: string | null;
};

export const persistVerificationDecision = async (input: {
  qrCodeId?: string | null;
  code?: string | null;
  licenseeId?: string | null;
  batchId?: string | null;
  proofSource?: string | null;
  classification?: string | null;
  reasons?: string[] | null;
  extraReasonCodes?: string[] | null;
  isAuthentic?: boolean;
  scanCount?: number | null;
  riskScore?: number | null;
  notFound?: boolean;
  errorOutcome?: VerificationDecisionOutcome | null;
  degradationMode?: VerificationDegradationMode;
  replacementStatus?: VerificationReplacementStatus;
  customerTrustLevel?: CustomerTrustLevel;
  actorIpHash?: string | null;
  actorDeviceHash?: string | null;
  replacementChainId?: string | null;
  publicOutcome?: string | null;
  riskDisposition?: string | null;
  messageKey?: string | null;
  nextActionKey?: string | null;
  scanSummary?: Record<string, unknown> | null;
  ownershipSnapshot?: Record<string, unknown> | null;
  riskSignals?: Record<string, unknown> | null;
  policySnapshot?: Record<string, unknown> | null;
  lifecycleSnapshot?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
}) : Promise<VerificationDecisionSummary> => {
  const degradationMode = input.degradationMode || VerificationDegradationMode.NORMAL;
  const proofTier = resolveProofTier({
    proofSource: input.proofSource,
    degradationMode,
  });
  const reasonCodes = uniqueReasonCodes([
    input.classification,
    ...(Array.isArray(input.reasons) ? input.reasons : []),
    ...(Array.isArray(input.extraReasonCodes) ? input.extraReasonCodes : []),
    input.proofSource,
    input.replacementStatus,
    degradationMode === VerificationDegradationMode.NORMAL ? null : degradationMode,
  ]);
  const riskBand = resolveRiskBand(input.riskScore);
  const replacementStatus = input.replacementStatus || VerificationReplacementStatus.NONE;
  const customerTrustLevel = input.customerTrustLevel || CustomerTrustLevel.ANONYMOUS;

  const baseSummary: VerificationDecisionSummary = {
    decisionId: null,
    decisionVersion: DECISION_VERSION,
    proofTier,
    reasonCodes,
    riskBand,
    replacementStatus,
    degradationMode,
    customerTrustLevel,
    publicOutcome: input.publicOutcome || null,
    riskDisposition: input.riskDisposition || null,
    messageKey: input.messageKey || null,
    nextActionKey: input.nextActionKey || null,
    replacementChainId: input.replacementChainId || null,
  };

  const decisionStore = getDecisionStore();
  const evidenceStore = getEvidenceStore();
  if (!decisionStore?.create || !evidenceStore?.create) {
    return baseSummary;
  }

  try {
    const decision = await decisionStore.create({
      data: {
        decisionVersion: DECISION_VERSION,
        qrCodeId: input.qrCodeId || undefined,
        code: input.code || undefined,
        licenseeId: input.licenseeId || undefined,
        batchId: input.batchId || undefined,
        proofSource: input.proofSource || undefined,
        proofTier,
        outcome: resolveOutcome({
          classification: input.classification,
          isAuthentic: input.isAuthentic,
          notFound: input.notFound,
          errorOutcome: input.errorOutcome,
        }),
        classification: input.classification || undefined,
        reasonCodes,
        riskBand,
        replacementStatus,
        degradationMode,
        customerTrustLevel,
        isAuthentic: Boolean(input.isAuthentic),
        scanCount: input.scanCount ?? undefined,
        riskScore: input.riskScore ?? undefined,
        actorIpHash: input.actorIpHash || undefined,
        actorDeviceHash: input.actorDeviceHash || undefined,
        metadata: {
          ...(input.metadata || {}),
          publicOutcome: input.publicOutcome || null,
          riskDisposition: input.riskDisposition || null,
          messageKey: input.messageKey || null,
          nextActionKey: input.nextActionKey || null,
          replacementChainId: input.replacementChainId || null,
        },
      },
    });

    await evidenceStore.create({
      data: {
        verificationDecisionId: decision.id,
        scanSummary: input.scanSummary || undefined,
        ownershipSnapshot: input.ownershipSnapshot || undefined,
        riskSignals: input.riskSignals || undefined,
        policySnapshot: input.policySnapshot || undefined,
        lifecycleSnapshot: input.lifecycleSnapshot || undefined,
        metadata: {
          ...(input.metadata || {}),
          publicOutcome: input.publicOutcome || null,
          riskDisposition: input.riskDisposition || null,
          messageKey: input.messageKey || null,
          nextActionKey: input.nextActionKey || null,
        },
      },
    });

    const metadata = (input.metadata || {}) as Record<string, unknown>;
    const lifecycleSnapshot = (input.lifecycleSnapshot || {}) as Record<string, unknown>;
    const replayAssessment = (metadata.replayAssessment || {}) as Record<string, unknown>;
    const signing = (metadata.signing || {}) as Record<string, unknown>;
    recordVerificationTrustMetric({
      decisionId: decision.id,
      qrCodeId: input.qrCodeId || null,
      licenseeId: input.licenseeId || null,
      batchId: input.batchId || null,
      proofSource: input.proofSource || null,
      proofTier,
      classification: input.classification || null,
      publicOutcome: input.publicOutcome || null,
      riskDisposition: input.riskDisposition || null,
      riskBand,
      printTrustState: String(lifecycleSnapshot.printTrustState || "").trim() || null,
      issuanceMode: String(lifecycleSnapshot.issuanceMode || "").trim() || null,
      replayState: String(lifecycleSnapshot.replayState || replayAssessment.replayState || "").trim() || null,
      challengeRequired: Boolean(metadata.stepUpRequired),
      challengeCompleted: Boolean(metadata.stepUpSatisfied),
      challengeCompletedBy: String(metadata.stepUpCompletedBy || "").trim() || null,
      signingMode: String(signing.mode || "").trim() || null,
      signingKeyVersion: String(signing.keyVersion || "").trim() || null,
      signingProvider: String(signing.provider || "").trim() || null,
      replacementStatus,
      breakGlassUsage:
        String(lifecycleSnapshot.issuanceMode || "").trim().toUpperCase() === "BREAK_GLASS_DIRECT" ||
        String(lifecycleSnapshot.printTrustState || "").trim().toUpperCase() === "RESTRICTED_DIRECT_ISSUANCE",
      limitedProvenance:
        String(input.publicOutcome || "").trim().toUpperCase() === "LIMITED_PROVENANCE" ||
        String(lifecycleSnapshot.printTrustState || "").trim().toUpperCase() === "LIMITED_PROVENANCE",
      metadata: {
        sameContextRepeat:
          String(lifecycleSnapshot.replayState || replayAssessment.replayState || "").trim().toUpperCase() === "SAME_CONTEXT_REPEAT",
        changedContextRepeat: ["CHANGED_CONTEXT_REPEAT", "RAPID_CHANGED_CONTEXT_REPEAT"].includes(
          String(lifecycleSnapshot.replayState || replayAssessment.replayState || "").trim().toUpperCase()
        ),
      },
    });

    return {
      ...baseSummary,
      decisionId: decision.id,
    };
  } catch (error) {
    console.warn("verification decision persistence skipped:", error);
    return baseSummary;
  }
};

export const attachVerificationPresentationSnapshot = async (
  decisionId: string | null | undefined,
  presentationSnapshot: Record<string, unknown> | null | undefined
) => {
  const evidenceStore = getEvidenceStore();
  const normalizedDecisionId = String(decisionId || "").trim();
  if (!normalizedDecisionId || !presentationSnapshot || !evidenceStore?.findFirst || !evidenceStore?.update) {
    return false;
  }

  try {
    const existing = await evidenceStore.findFirst({
      where: { verificationDecisionId: normalizedDecisionId },
      orderBy: [{ createdAt: "desc" }],
    });

    if (!existing?.id) return false;

    const metadata =
      existing.metadata && typeof existing.metadata === "object" && !Array.isArray(existing.metadata)
        ? { ...(existing.metadata as Record<string, unknown>) }
        : {};

    metadata.presentationSnapshot = presentationSnapshot;

    await evidenceStore.update({
      where: { id: existing.id },
      data: {
        metadata,
      },
    });

    return true;
  } catch (error) {
    console.warn("verification presentation snapshot skipped:", error);
    return false;
  }
};

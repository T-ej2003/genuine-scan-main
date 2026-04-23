import type { VerificationProofSource, VerifyClassification, OwnershipStatus, ScanSummary } from "./shared";
import {
  buildRiskExplanation,
  buildSecurityContainmentReasons,
  buildVerificationTimeline,
  type OwnershipTransferStatusView,
} from "./shared";

type VerifyUxPolicy = Record<string, unknown> | null;

const emptyOwnershipTransfer = (): OwnershipTransferStatusView => ({
  state: "none",
  active: false,
  canCreate: false,
  canCancel: false,
  canAccept: false,
  initiatedByYou: false,
  recipientEmailMasked: null,
  initiatedAt: null,
  expiresAt: null,
  acceptedAt: null,
  invalidReason: null,
  transferId: null,
  acceptUrl: null,
});

export const buildMissingQrVerificationPayload = (params: {
  normalizedCode?: string | null;
  reasons: string[];
  verifyUxPolicy: VerifyUxPolicy;
  proofSource: VerificationProofSource;
}) => {
  const emptySummary: ScanSummary = {
    totalScans: 0,
    firstVerifiedAt: null,
    latestVerifiedAt: null,
    firstVerifiedLocation: null,
    latestVerifiedLocation: null,
  };
  const emptyOwnership: OwnershipStatus = {
    isClaimed: false,
    claimedAt: null,
    isOwnedByRequester: false,
    isClaimedByAnother: false,
    canClaim: false,
  };

  return {
    isAuthentic: false,
    message: "This QR code is not registered in our system.",
    code: params.normalizedCode || undefined,
    proofSource: params.proofSource,
    classification: "NOT_FOUND" as VerifyClassification,
    reasons: params.reasons,
    scanSummary: emptySummary,
    ownershipStatus: emptyOwnership,
    ownershipTransfer: emptyOwnershipTransfer(),
    verificationTimeline: buildVerificationTimeline({
      scanSummary: emptySummary,
      classification: "NOT_FOUND",
      reasons: params.reasons,
    }),
    riskExplanation: buildRiskExplanation({
      classification: "NOT_FOUND",
      reasons: params.reasons,
      scanSummary: emptySummary,
      ownershipStatus: emptyOwnership,
    }),
    verifyUxPolicy: params.verifyUxPolicy,
    isBlocked: false,
    isReady: false,
    totalScans: 0,
    firstVerifiedAt: null,
    latestVerifiedAt: null,
    riskScore: 70,
    riskSignals: null,
  };
};

export const buildBlockedVerificationPayload = (params: {
  basePayload: Record<string, unknown>;
  containment: ReturnType<typeof import("./shared").buildContainment>;
  scanSummary: ScanSummary;
  ownershipStatus: OwnershipStatus;
  ownershipTransfer: OwnershipTransferStatusView;
  verifyUxPolicy: VerifyUxPolicy;
}) => {
  const reasons = [
    "This QR code has been blocked due to fraud or recall.",
    ...buildSecurityContainmentReasons(params.containment),
  ];
  const verificationTimeline = buildVerificationTimeline({
    scanSummary: params.scanSummary,
    classification: "BLOCKED_BY_SECURITY",
    reasons,
  });
  const riskExplanation = buildRiskExplanation({
    classification: "BLOCKED_BY_SECURITY",
    reasons,
    scanSummary: params.scanSummary,
    ownershipStatus: params.ownershipStatus,
  });

  return {
    ...params.basePayload,
    isAuthentic: false,
    message: "This QR code has been blocked due to fraud or recall.",
    classification: "BLOCKED_BY_SECURITY" as VerifyClassification,
    reasons,
    scanSummary: params.scanSummary,
    ownershipStatus: params.ownershipStatus,
    ownershipTransfer: params.ownershipTransfer,
    verificationTimeline,
    riskExplanation,
    verifyUxPolicy: params.verifyUxPolicy,
    isBlocked: true,
    isReady: false,
    totalScans: params.scanSummary.totalScans,
    firstVerifiedAt: params.scanSummary.firstVerifiedAt,
    latestVerifiedAt: params.scanSummary.latestVerifiedAt,
    riskScore: 100,
    riskSignals: null,
  };
};

export const buildNotReadyVerificationPayload = (params: {
  basePayload: Record<string, unknown>;
  status: string;
  scanSummary: ScanSummary;
  ownershipStatus: OwnershipStatus;
  ownershipTransfer: OwnershipTransferStatusView;
  verifyUxPolicy: VerifyUxPolicy;
  reasons: string[];
  message?: string | null;
}) => {
  const message = params.message || "This QR code is not ready for customer verification.";

  const verificationTimeline = buildVerificationTimeline({
    scanSummary: params.scanSummary,
    classification: "NOT_READY_FOR_CUSTOMER_USE",
    reasons: params.reasons,
  });
  const riskExplanation = buildRiskExplanation({
    classification: "NOT_READY_FOR_CUSTOMER_USE",
    reasons: params.reasons,
    scanSummary: params.scanSummary,
    ownershipStatus: params.ownershipStatus,
  });

  return {
    ...params.basePayload,
    isAuthentic: false,
    message,
    classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
    reasons: params.reasons,
    scanSummary: params.scanSummary,
    ownershipStatus: params.ownershipStatus,
    ownershipTransfer: params.ownershipTransfer,
    verificationTimeline,
    riskExplanation,
    verifyUxPolicy: params.verifyUxPolicy,
    isBlocked: false,
    isReady: false,
    totalScans: params.scanSummary.totalScans,
    firstVerifiedAt: params.scanSummary.firstVerifiedAt,
    latestVerifiedAt: params.scanSummary.latestVerifiedAt,
    riskScore: 70,
    riskSignals: null,
  };
};

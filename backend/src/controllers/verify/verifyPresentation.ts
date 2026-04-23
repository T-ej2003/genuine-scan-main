import { PrintJobStatus, PrintPipelineState, PrintSessionStatus, QRStatus, VerificationReplacementStatus } from "@prisma/client";

import { type VerificationActivitySummary } from "../../services/duplicateRiskService";
import type { OwnershipStatus } from "./verifyOwnership";
import type {
  ReportIncidentType,
  ScanSummary,
  VerificationMessageKey,
  VerificationNextActionKey,
  VerificationProofSource,
  VerificationPublicOutcome,
  VerificationRiskDisposition,
  VerifyClassification,
} from "./verifySchemas";

const parseBoolEnv = (value: unknown, fallback: boolean) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const VERIFY_REQUIRE_GOVERNED_PRINT_PROVENANCE = parseBoolEnv(
  process.env.VERIFY_REQUIRE_GOVERNED_PRINT_PROVENANCE,
  true
);

const normalizeIssuanceMode = (value: unknown) => {
  const normalized = String(value || "LEGACY_UNSPECIFIED").trim().toUpperCase();
  return normalized || "LEGACY_UNSPECIFIED";
};

export const mapLicensee = (licensee: any) =>
  licensee
    ? {
        id: licensee.id,
        name: licensee.name,
        prefix: licensee.prefix,
        brandName: licensee.brandName,
        location: licensee.location,
        website: licensee.website,
        supportEmail: licensee.supportEmail,
        supportPhone: licensee.supportPhone,
      }
    : null;

export const mapBatch = (batch: any) =>
  batch
    ? {
        id: batch.id,
        name: batch.name,
        printedAt: batch.printedAt,
        manufacturer: batch.manufacturer || null,
      }
    : null;

export const normalizeCode = (value: string) => String(value || "").trim().toUpperCase();

export const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const toIso = (value: Date | string | null | undefined) => {
  if (!value) return null;
  const dt = value instanceof Date ? value : new Date(value);
  return Number.isFinite(dt.getTime()) ? dt.toISOString() : null;
};

export const isQrReadyForCustomerUse = (status: QRStatus) => {
  return status === QRStatus.PRINTED || status === QRStatus.REDEEMED || status === QRStatus.SCANNED;
};

export const statusNotReadyReason = (status: QRStatus) => {
  if (status === QRStatus.DORMANT || status === QRStatus.ACTIVE) {
    return "Code exists but has not been assigned to a finished product.";
  }
  if (status === QRStatus.ALLOCATED) {
    return "Code is allocated but the print lifecycle is not complete.";
  }
  if (status === QRStatus.ACTIVATED) {
    return "Code is awaiting print confirmation before customer use.";
  }
  return "Code is not ready for customer verification.";
};

export const statusNotReadyMessage = (status: QRStatus) => {
  if (status === "ALLOCATED") {
    return "This QR code is allocated but not yet printed.";
  }
  if (status === "ACTIVATED") {
    return "This QR code is awaiting confirmed print completion.";
  }
  return "This QR code has not been assigned to a product yet.";
};

const isPrintLifecycleConfirmed = (qrCode: any) => {
  if (!qrCode?.printJobId && !qrCode?.printJob) return true;

  const printJob = qrCode?.printJob;
  if (!printJob) return false;

  if (printJob.confirmedAt) return true;
  if (printJob.status === PrintJobStatus.CONFIRMED) return true;
  if (
    printJob.pipelineState === PrintPipelineState.LOCKED ||
    printJob.pipelineState === PrintPipelineState.PRINT_CONFIRMED
  ) {
    return true;
  }
  if (printJob.printSession?.status === PrintSessionStatus.COMPLETED || printJob.printSession?.completedAt) {
    return true;
  }

  return false;
};

export const resolvePublicVerificationReadiness = (qrCode: any) => {
  const issuanceMode = normalizeIssuanceMode(qrCode?.issuanceMode);
  const customerVerifiableAt = toIso(qrCode?.customerVerifiableAt);
  const hasGovernedPrintProvenance = issuanceMode === "GOVERNED_PRINT";
  const limitedProvenance = issuanceMode !== "GOVERNED_PRINT";

  if (!isQrReadyForCustomerUse(qrCode?.status)) {
    return {
      isReady: false,
      message: statusNotReadyMessage(qrCode?.status),
      reason: statusNotReadyReason(qrCode?.status),
      issuanceMode,
      customerVerifiableAt,
      governedProofEligible: false,
      limitedProvenance,
    };
  }

  if (VERIFY_REQUIRE_GOVERNED_PRINT_PROVENANCE && issuanceMode === "BREAK_GLASS_DIRECT") {
    return {
      isReady: false,
      message: "This label was issued through a restricted emergency path and is not approved for normal customer verification.",
      reason: "Restricted direct issuance bypassed the governed print workflow and cannot receive normal customer-verifiable proof.",
      issuanceMode,
      customerVerifiableAt,
      governedProofEligible: false,
      limitedProvenance: false,
    };
  }

  if (hasGovernedPrintProvenance && !customerVerifiableAt) {
    return {
      isReady: false,
      message: "This QR code is awaiting confirmed print completion.",
      reason: "Governed issuance exists, but customer-verifiable readiness has not been established yet.",
      issuanceMode,
      customerVerifiableAt,
      governedProofEligible: false,
      limitedProvenance: false,
    };
  }

  if (!isPrintLifecycleConfirmed(qrCode)) {
    return {
      isReady: false,
      message: "This QR code is awaiting confirmed print completion.",
      reason: "Code is assigned to a controlled print run, but print confirmation is not complete.",
      issuanceMode,
      customerVerifiableAt,
      governedProofEligible: false,
      limitedProvenance,
    };
  }

  return {
    isReady: true,
    message: null,
    reason: null,
    issuanceMode,
    customerVerifiableAt,
    governedProofEligible: hasGovernedPrintProvenance && Boolean(customerVerifiableAt),
    limitedProvenance,
    provenanceReason:
      limitedProvenance && issuanceMode !== "BREAK_GLASS_DIRECT"
        ? "Governed print provenance is not available for this label."
        : null,
  };
};

export const buildContainment = (qrCode: any) => ({
  qrUnderInvestigation: qrCode.underInvestigationAt
    ? {
        at: toIso(qrCode.underInvestigationAt),
        reason: qrCode.underInvestigationReason || null,
      }
    : null,
  batchSuspended: qrCode.batch?.suspendedAt
    ? {
        at: toIso(qrCode.batch.suspendedAt),
        reason: qrCode.batch.suspendedReason || null,
      }
    : null,
  orgSuspended: qrCode.licensee?.suspendedAt
    ? {
        at: toIso(qrCode.licensee.suspendedAt),
        reason: qrCode.licensee.suspendedReason || null,
      }
    : null,
});

export const buildScanSummary = (params: {
  scanCount: number;
  scannedAt?: Date | null;
  scanInsight?: {
    firstScanAt?: string | null;
    firstScanLocation?: string | null;
    latestScanAt?: string | null;
    latestScanLocation?: string | null;
  } | null;
}): ScanSummary => {
  const firstVerifiedAt =
    params.scanInsight?.firstScanAt ||
    (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);
  const latestVerifiedAt =
    params.scanInsight?.latestScanAt ||
    params.scanInsight?.firstScanAt ||
    (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);

  return {
    totalScans: Number(params.scanCount || 0),
    firstVerifiedAt,
    latestVerifiedAt,
    firstVerifiedLocation: params.scanInsight?.firstScanLocation || null,
    latestVerifiedLocation: params.scanInsight?.latestScanLocation || null,
  };
};

export const buildVerificationTimeline = (params: {
  scanSummary: ScanSummary;
  classification: VerifyClassification;
  reasons: string[];
}) => {
  const firstSeen = params.scanSummary.firstVerifiedAt || null;
  const latestSeen = params.scanSummary.latestVerifiedAt || null;
  const anomalyReason =
    params.classification === "SUSPICIOUS_DUPLICATE" || params.classification === "BLOCKED_BY_SECURITY"
      ? params.reasons[0] || "Anomaly indicators detected."
      : null;

  return {
    firstSeen,
    latestSeen,
    anomalyReason,
    visualSignal:
      params.classification === "FIRST_SCAN" || params.classification === "LEGIT_REPEAT"
        ? "stable"
        : params.classification === "SUSPICIOUS_DUPLICATE"
          ? "warning"
          : "critical",
  };
};

export const buildRiskExplanation = (params: {
  classification: VerifyClassification;
  reasons: string[];
  scanSummary: ScanSummary;
  ownershipStatus: OwnershipStatus;
  activitySummary?: VerificationActivitySummary | null;
}) => {
  if (params.classification === "SUSPICIOUS_DUPLICATE") {
    return {
      level: "elevated",
      title:
        params.activitySummary?.currentActorTrustedOwnerContext && (params.activitySummary?.untrustedScanCount24h || 0) > 0
          ? "External scan activity needs review"
          : "Duplicate risk signals detected",
      details: params.reasons,
      recommendedAction: "Review where the product came from and contact brand support if this result is unexpected.",
    };
  }

  if (params.classification === "BLOCKED_BY_SECURITY") {
    return {
      level: "high",
      title: "Blocked by security controls",
      details: params.reasons,
      recommendedAction: "Do not use this product until support confirms resolution.",
    };
  }

  if (params.classification === "NOT_FOUND") {
    return {
      level: "medium",
      title: "MSCQR could not find this code",
      details: params.reasons,
      recommendedAction: "Check the code carefully and contact brand support if the product should carry an MSCQR label.",
    };
  }

  if (params.ownershipStatus.isClaimedByAnother) {
    return {
      level: "medium",
      title: "Ownership conflict detected",
      details: ["This code is already claimed by another account."],
      recommendedAction: "Treat as potential duplicate and submit a report for investigation.",
    };
  }

  return {
    level: "low",
    title:
      params.activitySummary?.state === "trusted_repeat"
        ? "Repeat checks match the same owner context"
        : params.activitySummary?.state === "mixed_repeat"
          ? "Repeat activity is mixed but not high risk"
          : "No high-risk anomaly detected",
    details: params.reasons,
    recommendedAction:
      params.activitySummary?.state === "trusted_repeat"
        ? "Normal re-checks are fine. Keep purchase proof and monitor future scans."
        : params.scanSummary.totalScans > 1
          ? "Keep purchase proof and monitor future scans."
          : "No action required.",
  };
};

export const describeVerificationProof = (proofSource?: VerificationProofSource | null) => {
  if (proofSource === "SIGNED_LABEL") {
    return {
      title: "Signed label verification",
      detail: "This result is tied to an issued MSCQR label signature and live platform record.",
    };
  }

  return {
    title: "Manual registry lookup",
    detail: "This result confirms the MSCQR registry record and lifecycle state only. It does not confirm physical label binding.",
  };
};

export const buildRepeatWarningMessage = (params: {
  blockedByPolicy: boolean;
  hasContainment: boolean;
  isFirstScan: boolean;
  firstVerifiedAt: string | null;
  classification?: VerifyClassification;
  activitySummary?: VerificationActivitySummary | null;
}) => {
  if (params.blockedByPolicy) {
    return "This code has been auto-blocked by security policy due to anomaly detection.";
  }
  if (params.hasContainment) {
    return "This product is currently under investigation. Please review details and contact support if needed.";
  }
  if (params.classification === "SUSPICIOUS_DUPLICATE") {
    return "MSCQR recorded unusual repeat activity for this code. Review the details before relying on it.";
  }
  if (params.isFirstScan || !params.firstVerifiedAt) {
    return null;
  }

  if (params.activitySummary?.state === "trusted_repeat") {
    return "This code has been checked before, and recent activity matches the same owner or trusted device.";
  }
  if (params.activitySummary?.state === "mixed_repeat") {
    return "This code has been checked before. Some recent activity matches the owner context, but additional external activity was also recorded.";
  }

  return `This code has been checked before. The first customer-facing verification was recorded on ${params.firstVerifiedAt}.`;
};

export const buildPublicVerificationSemantics = (params: {
  classification: VerifyClassification;
  proofSource: VerificationProofSource;
  replacementStatus?: VerificationReplacementStatus | null;
  isFirstScan?: boolean;
  notFound?: boolean;
  integrityError?: boolean;
  printerSetupOnly?: boolean;
  limitedProvenance?: boolean;
  manualSignedHistory?: boolean;
}) => {
  if (params.printerSetupOnly) {
    return {
      publicOutcome: "PRINTER_SETUP_ONLY" as VerificationPublicOutcome,
      riskDisposition: "MONITOR" as VerificationRiskDisposition,
      messageKey: "printer_setup_only" as VerificationMessageKey,
      nextActionKey: "none" as VerificationNextActionKey,
      headline: "MSCQR confirmed this printer setup label.",
    };
  }

  if (params.notFound) {
    return {
      publicOutcome: "NOT_FOUND" as VerificationPublicOutcome,
      riskDisposition: "BLOCKED" as VerificationRiskDisposition,
      messageKey: "not_found" as VerificationMessageKey,
      nextActionKey: "report_concern" as VerificationNextActionKey,
      headline: "MSCQR could not find a live record for this code.",
    };
  }

  if (params.integrityError) {
    return {
      publicOutcome: "INTEGRITY_ERROR" as VerificationPublicOutcome,
      riskDisposition: "BLOCKED" as VerificationRiskDisposition,
      messageKey: "integrity_error" as VerificationMessageKey,
      nextActionKey: "report_concern" as VerificationNextActionKey,
      headline: "MSCQR could not trust this label proof.",
    };
  }

  if (params.classification === "BLOCKED_BY_SECURITY") {
    if (params.replacementStatus === VerificationReplacementStatus.REPLACED_LABEL) {
      return {
        publicOutcome: "BLOCKED" as VerificationPublicOutcome,
        riskDisposition: "BLOCKED" as VerificationRiskDisposition,
        messageKey: "replacement_required" as VerificationMessageKey,
        nextActionKey: "scan_active_replacement" as VerificationNextActionKey,
        headline: "This label has been replaced by a newer controlled issuance.",
      };
    }

    return {
      publicOutcome: "BLOCKED" as VerificationPublicOutcome,
      riskDisposition: "BLOCKED" as VerificationRiskDisposition,
      messageKey: "blocked" as VerificationMessageKey,
      nextActionKey: "contact_support" as VerificationNextActionKey,
      headline: "MSCQR blocked this code for safety review.",
    };
  }

  if (params.classification === "NOT_READY_FOR_CUSTOMER_USE") {
    return {
      publicOutcome: "NOT_READY" as VerificationPublicOutcome,
      riskDisposition: "MONITOR" as VerificationRiskDisposition,
      messageKey: "not_ready" as VerificationMessageKey,
      nextActionKey: "try_again_later" as VerificationNextActionKey,
      headline: "This code is not ready for customer verification yet.",
    };
  }

  if (params.classification === "SUSPICIOUS_DUPLICATE") {
    return {
      publicOutcome: "REVIEW_REQUIRED" as VerificationPublicOutcome,
      riskDisposition: "REVIEW_REQUIRED" as VerificationRiskDisposition,
      messageKey: "review_required" as VerificationMessageKey,
      nextActionKey: "report_concern" as VerificationNextActionKey,
      headline: "This code needs review before it should be trusted.",
    };
  }

  if (params.limitedProvenance && params.proofSource === "SIGNED_LABEL") {
    return {
      publicOutcome: "LIMITED_PROVENANCE" as VerificationPublicOutcome,
      riskDisposition: "MONITOR" as VerificationRiskDisposition,
      messageKey: "limited_provenance" as VerificationMessageKey,
      nextActionKey: "review_details" as VerificationNextActionKey,
      headline: "MSCQR found this label active, but governed print provenance is limited.",
    };
  }

  if (params.proofSource === "MANUAL_CODE_LOOKUP") {
    if (params.manualSignedHistory) {
      return {
        publicOutcome: "MANUAL_RECORD_FOUND" as VerificationPublicOutcome,
        riskDisposition: "MONITOR" as VerificationRiskDisposition,
        messageKey: "manual_record_signed_history" as VerificationMessageKey,
        nextActionKey: "rescan_label" as VerificationNextActionKey,
        headline: "MSCQR found the record for this code, but prior signed-label history exists.",
      };
    }

    return {
      publicOutcome: "MANUAL_RECORD_FOUND" as VerificationPublicOutcome,
      riskDisposition: params.isFirstScan ? ("CLEAR" as VerificationRiskDisposition) : ("MONITOR" as VerificationRiskDisposition),
      messageKey: params.isFirstScan ? ("manual_record_found" as VerificationMessageKey) : ("manual_record_repeat" as VerificationMessageKey),
      nextActionKey: "review_details" as VerificationNextActionKey,
      headline: params.isFirstScan
        ? "MSCQR found a live record for this code."
        : "MSCQR found the same live record for this code again.",
    };
  }

  return {
    publicOutcome: "SIGNED_LABEL_ACTIVE" as VerificationPublicOutcome,
    riskDisposition: params.isFirstScan ? ("CLEAR" as VerificationRiskDisposition) : ("MONITOR" as VerificationRiskDisposition),
    messageKey: params.isFirstScan ? ("signed_label_active" as VerificationMessageKey) : ("signed_label_repeat" as VerificationMessageKey),
    nextActionKey: "review_details" as VerificationNextActionKey,
    headline: params.isFirstScan
      ? "MSCQR confirmed this issued label is active."
      : "MSCQR confirmed this issued label again.",
  };
};

export const buildSecurityContainmentReasons = (containment: ReturnType<typeof buildContainment>) => {
  const reasons: string[] = [];
  if (containment.qrUnderInvestigation?.reason) reasons.push(`QR containment: ${containment.qrUnderInvestigation.reason}`);
  if (containment.batchSuspended?.reason) reasons.push(`Batch containment: ${containment.batchSuspended.reason}`);
  if (containment.orgSuspended?.reason) reasons.push(`Organization containment: ${containment.orgSuspended.reason}`);
  return reasons;
};

export const inferIncidentType = (input: { reason?: string; incidentType?: ReportIncidentType }): ReportIncidentType => {
  if (input.incidentType) return input.incidentType;
  const reason = String(input.reason || "").toLowerCase();
  if (reason.includes("mismatch")) return "wrong_product";
  if (reason.includes("used") || reason.includes("duplicate")) return "duplicate_scan";
  if (reason.includes("seller") || reason.includes("fake") || reason.includes("counterfeit")) return "counterfeit_suspected";
  return "other";
};

export const incidentSummaryText = (incident: any) =>
  [
    `Incident ID: ${incident.id}`,
    `QR Code: ${incident.qrCodeValue}`,
    `Severity: ${incident.severity}`,
    `Status: ${incident.status}`,
    `Description: ${incident.description}`,
  ]
    .filter(Boolean)
    .join("\n");

export const mapUploadedEvidence = (files: Express.Multer.File[]) => {
  return files.map((file) => {
    const fileName = String(file.filename || "").trim();
    return {
      fileUrl: fileName ? `/api/incidents/evidence-files/${encodeURIComponent(fileName)}` : null,
      storageKey: fileName || null,
      fileType: String(file.mimetype || "application/octet-stream"),
    };
  });
};

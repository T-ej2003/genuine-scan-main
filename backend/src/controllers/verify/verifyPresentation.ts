import { QRStatus } from "@prisma/client";

import { type VerificationActivitySummary } from "../../services/duplicateRiskService";
import type { OwnershipStatus } from "./verifyOwnership";
import type { ReportIncidentType, ScanSummary, VerifyClassification } from "./verifySchemas";

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
      recommendedAction: "Review seller source and report suspected counterfeit if this is unexpected.",
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

export const buildRepeatWarningMessage = (params: {
  blockedByPolicy: boolean;
  hasContainment: boolean;
  isFirstScan: boolean;
  firstVerifiedAt: string | null;
  activitySummary?: VerificationActivitySummary | null;
}) => {
  if (params.blockedByPolicy) {
    return "This code has been auto-blocked by security policy due to anomaly detection.";
  }
  if (params.hasContainment) {
    return "This product is currently under investigation. Please review details and contact support if needed.";
  }
  if (params.isFirstScan || !params.firstVerifiedAt) {
    return null;
  }

  if (params.activitySummary?.state === "trusted_repeat") {
    return "Already verified before. Recent checks match the same owner or trusted device.";
  }
  if (params.activitySummary?.state === "mixed_repeat") {
    return "Already verified before. Some recent checks match the owner context, but additional external activity was also recorded.";
  }

  return `Already verified before. First verification was on ${params.firstVerifiedAt}.`;
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

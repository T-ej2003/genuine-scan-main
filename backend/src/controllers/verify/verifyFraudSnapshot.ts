import { QRStatus } from "@prisma/client";

import prisma from "../../config/database";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "../../services/duplicateRiskService";
import { resolveDuplicateRiskProfile } from "../../services/governanceService";
import { getScanInsight } from "../../services/scanInsightService";
import {
  buildOwnershipStatus,
  loadOwnershipByQrCodeId,
  type OwnershipStatus,
} from "./verifyOwnership";
import {
  buildScanSummary,
  isQrReadyForCustomerUse,
  statusNotReadyReason,
} from "./verifyPresentation";
import type { ScanSummary, VerifyClassification } from "./verifySchemas";

export const buildFraudVerificationSnapshot = async (normalizedCode: string) => {
  const qrCode = await prisma.qRCode.findUnique({
    where: { code: normalizedCode },
  });

  if (!qrCode) {
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
      classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
      reasons: ["Code not found in registry."],
      scanSummary: emptySummary,
      ownershipStatus: emptyOwnership,
    };
  }

  const scanInsight = await getScanInsight(qrCode.id, null, {
    licenseeId: qrCode.licenseeId || null,
  });
  const scanSummary = buildScanSummary({
    scanCount: Number(qrCode.scanCount || 0),
    scannedAt: qrCode.scannedAt,
    scanInsight,
  });

  const isBlocked = qrCode.status === QRStatus.BLOCKED;
  const isReady = isQrReadyForCustomerUse(qrCode.status);
  const ownership = await loadOwnershipByQrCodeId(qrCode.id);

  const ownershipStatus = buildOwnershipStatus({
    ownership,
    isReady,
    isBlocked,
  });

  if (isBlocked) {
    return {
      classification: "BLOCKED_BY_SECURITY" as VerifyClassification,
      reasons: ["Code is blocked by security policy or containment controls."],
      scanSummary,
      ownershipStatus,
    };
  }

  if (!isReady) {
    return {
      classification: "NOT_READY_FOR_CUSTOMER_USE" as VerifyClassification,
      reasons: [statusNotReadyReason(qrCode.status)],
      scanSummary,
      ownershipStatus,
    };
  }

  if (scanSummary.totalScans <= 1) {
    return {
      classification: "FIRST_SCAN" as VerifyClassification,
      reasons: ["First successful verification recorded."],
      scanSummary,
      ownershipStatus,
    };
  }

  const riskProfile = await resolveDuplicateRiskProfile(qrCode.licenseeId || null);
  const anomalyModelScore = deriveAnomalyModelScore({ scanSignals: scanInsight.signals });

  const duplicateRisk = assessDuplicateRisk({
    scanCount: scanSummary.totalScans,
    scanSignals: scanInsight.signals,
    ownershipStatus,
    latestScanAt: scanInsight.latestScanAt,
    previousScanAt: scanInsight.previousScanAt,
    anomalyModelScore: Math.round(anomalyModelScore * riskProfile.anomalyWeight),
    tenantRiskLevel: riskProfile.tenantRiskLevel,
    productRiskLevel: riskProfile.productRiskLevel,
  });

  return {
    classification: duplicateRisk.classification as VerifyClassification,
    reasons: duplicateRisk.reasons,
    scanSummary,
    ownershipStatus,
  };
};

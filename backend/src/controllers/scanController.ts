import { Request, Response } from "express";
import prisma from "../config/database";
import { QRStatus } from "@prisma/client";
import { createAuditLog } from "../services/auditService";
import { evaluateScanPolicy } from "../services/scanPolicy";
import { hashToken, verifyQrToken } from "../services/qrTokenService";
import { evaluateScanAndEnforcePolicy } from "../services/policyEngineService";
import { reverseGeocode } from "../services/locationService";
import { getScanInsight } from "../services/scanInsightService";
import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
import { assessDuplicateRisk, deriveAnomalyModelScore } from "../services/duplicateRiskService";
import { deriveRequestDeviceFingerprint } from "../utils/requestFingerprint";
import { resolveDuplicateRiskProfile } from "../services/governanceService";

const deviceFingerprint = (req: Request) => deriveRequestDeviceFingerprint(req);

const isQrReadyForCustomerUse = (status: QRStatus) => {
  return status === QRStatus.PRINTED || status === QRStatus.REDEEMED || status === QRStatus.SCANNED;
};

const buildOwnershipStatus = (params: {
  ownership: { userId: string | null; claimedAt: Date } | null;
  customerUserId?: string | null;
  isReady: boolean;
  isBlocked: boolean;
}) => {
  const ownership = params.ownership;
  const customerUserId = String(params.customerUserId || "").trim();

  if (!ownership) {
    return {
      isClaimed: false,
      claimedAt: null,
      isOwnedByRequester: false,
      isClaimedByAnother: false,
      canClaim: params.isReady && !params.isBlocked,
    };
  }

  const isOwnedByRequester = Boolean(customerUserId) && ownership.userId === customerUserId;
  const isClaimedByAnother = Boolean(customerUserId) && !isOwnedByRequester;

  return {
    isClaimed: true,
    claimedAt: ownership.claimedAt.toISOString(),
    isOwnedByRequester,
    isClaimedByAnother,
    canClaim: false,
  };
};

export const scanToken = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const token = String(req.query.t || "").trim();
    if (!token) {
      return res.status(400).json({ success: false, error: "Missing token" });
    }

    let payload;
    try {
      payload = verifyQrToken(token).payload;
    } catch (e: any) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "Invalid or tampered QR token.",
          scanOutcome: "INVALID_SIGNATURE",
        },
      });
    }

    if (!payload.qr_id || !payload.licensee_id || !payload.nonce) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "Invalid QR token payload.",
          scanOutcome: "INVALID_PAYLOAD",
        },
      });
    }

    if (payload.exp && payload.exp * 1000 < Date.now()) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token expired.",
          scanOutcome: "EXPIRED",
        },
      });
    }

    const qr = await prisma.qRCode.findUnique({
      where: { id: payload.qr_id },
      include: {
        licensee: {
          select: {
            id: true,
            name: true,
            prefix: true,
            brandName: true,
            location: true,
            website: true,
            supportEmail: true,
            supportPhone: true,
            suspendedAt: true,
            suspendedReason: true,
          },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
            suspendedAt: true,
            suspendedReason: true,
            manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
          },
        },
        ownership: {
          select: {
            userId: true,
            claimedAt: true,
          },
        },
      },
    });

    if (!qr) {
      return res.status(404).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR not found.",
          scanOutcome: "NOT_FOUND",
        },
      });
    }

    const tokenHash = hashToken(token);
    if (!qr.tokenHash) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token has not been issued.",
          scanOutcome: "NOT_ISSUED",
        },
      });
    }
    if (qr.tokenHash !== tokenHash) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token revoked or mismatched.",
          scanOutcome: "TOKEN_MISMATCH",
        },
      });
    }

    if (qr.tokenNonce && payload.nonce !== qr.tokenNonce) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token mismatch.",
          scanOutcome: "TOKEN_MISMATCH",
        },
      });
    }

    if (payload.licensee_id !== qr.licenseeId) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token invalid for this licensee.",
          scanOutcome: "TOKEN_MISMATCH",
        },
      });
    }

    const expectedBatchId = qr.batchId ?? null;
    if (payload.batch_id !== expectedBatchId) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token invalid for this batch.",
          scanOutcome: "TOKEN_MISMATCH",
        },
      });
    }

    const expectedManufacturerId = qr.batch?.manufacturer?.id ?? null;
    if (payload.manufacturer_id !== undefined && payload.manufacturer_id !== expectedManufacturerId) {
      return res.status(400).json({
        success: true,
        data: {
          isAuthentic: false,
          message: "QR token invalid for this manufacturer.",
          scanOutcome: "TOKEN_MISMATCH",
        },
      });
    }

    const decision = evaluateScanPolicy(qr.status);
    const now = new Date();
    const fp = deviceFingerprint(req);
    const toNum = (v: any) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };
    const latitude = toNum(req.query.lat);
    const longitude = toNum(req.query.lon);
    const accuracy = toNum(req.query.acc);
    const location = await reverseGeocode(latitude, longitude);

    const updated = await prisma.$transaction(async (tx) => {
      const updatedQr = await tx.qRCode.update({
        where: { id: qr.id },
        data: {
          scanCount: { increment: 1 },
          scannedAt: qr.scannedAt ?? now,
          lastScanIp: req.ip,
          lastScanUserAgent: req.get("user-agent") || null,
          lastScanDevice: fp,
          status: decision.allowRedeem ? QRStatus.REDEEMED : qr.status,
          redeemedAt: decision.allowRedeem ? now : qr.redeemedAt,
          redeemedDeviceFingerprint: decision.allowRedeem ? fp : qr.redeemedDeviceFingerprint,
        },
        include: {
          licensee: true,
          batch: { include: { manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } } } },
        },
      });

      await tx.qrScanLog.create({
        data: {
          code: updatedQr.code,
          qrCodeId: updatedQr.id,
          licenseeId: updatedQr.licenseeId,
          batchId: updatedQr.batchId ?? null,
          status: updatedQr.status,
          isFirstScan: decision.allowRedeem,
          scanCount: updatedQr.scanCount ?? 0,
          ipAddress: req.ip,
          userAgent: req.get("user-agent") || null,
          device: fp,
          latitude,
          longitude,
          accuracy,
          locationName: location?.name || null,
          locationCountry: location?.country || null,
          locationRegion: location?.region || null,
          locationCity: location?.city || null,
        },
      });

      return updatedQr;
    });

    if (decision.allowRedeem) {
      await createAuditLog({
        action: "REDEEMED",
        entityType: "QRCode",
        entityId: updated.id,
        details: {
          qrId: updated.id,
          code: updated.code,
          scanCount: updated.scanCount ?? 0,
        },
        ipAddress: req.ip,
      });
    }

    const policy = await evaluateScanAndEnforcePolicy({
      qrCodeId: updated.id,
      code: updated.code,
      licenseeId: updated.licenseeId,
      batchId: updated.batchId ?? null,
      manufacturerId: updated.batch?.manufacturer?.id || null,
      scanCount: updated.scanCount ?? 0,
      scannedAt: now,
      latitude,
      longitude,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    const finalStatus =
      policy.autoBlockedQr || policy.autoBlockedBatch ? QRStatus.BLOCKED : updated.status;
    const effectiveOutcome = finalStatus === QRStatus.BLOCKED ? "BLOCKED" : decision.outcome;
    const scanInsight = await getScanInsight(updated.id, fp || null, {
      currentIpAddress: req.ip || null,
      licenseeId: updated.licenseeId,
    });
    const customerUserId = req.customer?.userId || null;

    const containment = {
      qrUnderInvestigation: updated.underInvestigationAt
        ? { at: new Date(updated.underInvestigationAt).toISOString(), reason: updated.underInvestigationReason || null }
        : null,
      batchSuspended: updated.batch?.suspendedAt
        ? { at: new Date(updated.batch.suspendedAt).toISOString(), reason: updated.batch.suspendedReason || null }
        : null,
      orgSuspended: updated.licensee?.suspendedAt
        ? { at: new Date(updated.licensee.suspendedAt).toISOString(), reason: updated.licensee.suspendedReason || null }
        : null,
    };

    const hasContainment =
      Boolean(containment.qrUnderInvestigation) ||
      Boolean(containment.batchSuspended) ||
      Boolean(containment.orgSuspended);

    const warningMessage =
      effectiveOutcome === "ALREADY_REDEEMED"
        ? `Already verified before. First verification was at ${scanInsight.firstScanAt || updated.redeemedAt?.toISOString?.() || "unknown time"}.`
      : effectiveOutcome === "SUSPICIOUS"
        ? "This code was generated but not confirmed as printed. Treat with suspicion."
      : effectiveOutcome === "BLOCKED"
        ? policy.autoBlockedQr || policy.autoBlockedBatch
          ? "This code has been auto-blocked by security policy due to anomaly detection."
          : "This code has been blocked due to fraud or recall."
      : hasContainment
        ? "This product is currently under investigation. Please review details and contact support if needed."
      : null;

    const message =
      effectiveOutcome === "VALID"
        ? "Authentic item. First-time verification successful."
      : effectiveOutcome === "ALREADY_REDEEMED"
        ? "Already verified. Please review scan details below."
        : effectiveOutcome === "SUSPICIOUS"
        ? "Not activated for sale. Suspicious scan."
        : effectiveOutcome === "BLOCKED"
        ? "Blocked code."
        : "This code is not active.";

    const isBlocked = finalStatus === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(finalStatus);
    const totalScans = Number(updated.scanCount ?? 0);
    const firstVerifiedAt = scanInsight.firstScanAt || (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);
    const latestVerifiedAt =
      scanInsight.latestScanAt ||
      scanInsight.firstScanAt ||
      (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);

    const ownership = await prisma.ownership.findUnique({
      where: { qrCodeId: updated.id },
      select: {
        userId: true,
        claimedAt: true,
      },
    });

    const ownershipStatus = buildOwnershipStatus({
      ownership,
      customerUserId,
      isReady,
      isBlocked,
    });

    const riskProfile = await resolveDuplicateRiskProfile(updated.licenseeId || null);
    const anomalyModelScore = deriveAnomalyModelScore({
      scanSignals: scanInsight.signals,
      policy,
    });

    const duplicateRisk = assessDuplicateRisk({
      scanCount: totalScans,
      scanSignals: scanInsight.signals,
      policy,
      ownershipStatus,
      customerUserId,
      latestScanAt: scanInsight.latestScanAt,
      previousScanAt: scanInsight.previousScanAt,
      anomalyModelScore: Math.round(anomalyModelScore * riskProfile.anomalyWeight),
      tenantRiskLevel: riskProfile.tenantRiskLevel,
      productRiskLevel: riskProfile.productRiskLevel,
    });

    let classification: "FIRST_SCAN" | "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE" | "BLOCKED_BY_SECURITY" | "NOT_READY_FOR_CUSTOMER_USE";
    let reasons: string[];
    let riskScore = 0;
    let riskSignals = duplicateRisk.signals;

    if (isBlocked) {
      classification = "BLOCKED_BY_SECURITY";
      reasons = ["Code is blocked by security policy or containment controls."];
      riskScore = 100;
    } else if (!isReady) {
      classification = "NOT_READY_FOR_CUSTOMER_USE";
      reasons = ["Code lifecycle is not ready for customer verification."];
      riskScore = 70;
    } else if (decision.allowRedeem) {
      classification = "FIRST_SCAN";
      reasons = ["First successful customer verification recorded."];
      riskScore = 4;
    } else {
      classification = duplicateRisk.classification;
      reasons = duplicateRisk.reasons;
      riskScore = duplicateRisk.riskScore;
    }

    if (ownershipStatus.isClaimedByAnother && customerUserId && !isBlocked) {
      classification = "SUSPICIOUS_DUPLICATE";
      if (!reasons.includes("Ownership is already claimed by another account.")) {
        reasons = ["Ownership is already claimed by another account.", ...reasons];
      }
      riskScore = Math.max(riskScore, 70);
    }

    return res.json({
      success: true,
      data: {
        // Consumers may re-verify the same product; treat repeat scans as authentic unless blocked.
        isAuthentic: effectiveOutcome === "VALID" || effectiveOutcome === "ALREADY_REDEEMED",
        scanOutcome: effectiveOutcome,
        message,
        warningMessage,
        code: updated.code,
        status: finalStatus,
        containment,
        licensee: updated.licensee
          ? {
              id: updated.licensee.id,
              name: updated.licensee.name,
              prefix: updated.licensee.prefix,
              brandName: updated.licensee.brandName,
              location: updated.licensee.location,
              website: updated.licensee.website,
              supportEmail: updated.licensee.supportEmail,
              supportPhone: updated.licensee.supportPhone,
            }
          : null,
        batch: updated.batch
          ? {
              id: updated.batch.id,
              name: updated.batch.name,
              printedAt: updated.batch.printedAt,
              manufacturer: updated.batch.manufacturer || null,
            }
          : null,
        firstScanned: updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null,
        scanCount: updated.scanCount ?? 0,
        isFirstScan: decision.allowRedeem,
        redeemedAt: updated.redeemedAt ? new Date(updated.redeemedAt).toISOString() : null,
        firstScanAt: scanInsight.firstScanAt,
        firstScanLocation: scanInsight.firstScanLocation,
        latestScanAt: scanInsight.latestScanAt,
        latestScanLocation: scanInsight.latestScanLocation,
        previousScanAt: scanInsight.previousScanAt,
        previousScanLocation: scanInsight.previousScanLocation,
        scanSignals: scanInsight.signals,
        classification,
        reasons,
        riskScore,
        riskThreshold: duplicateRisk.threshold,
        riskSignals,
        scanSummary: {
          totalScans,
          firstVerifiedAt,
          latestVerifiedAt,
          firstVerifiedLocation: scanInsight.firstScanLocation || null,
          latestVerifiedLocation: scanInsight.latestScanLocation || null,
        },
        ownershipStatus,
        isBlocked,
        isReady,
        totalScans,
        firstVerifiedAt,
        latestVerifiedAt,
        policy,
      },
    });
  } catch (error) {
    console.error("scanToken error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};

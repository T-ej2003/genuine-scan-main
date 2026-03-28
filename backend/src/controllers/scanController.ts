import { Request, Response } from "express";
import prisma from "../config/database";
import { Prisma, QRStatus } from "@prisma/client";
import { z } from "zod";
import { createAuditLog } from "../services/auditService";
import { evaluateScanPolicy } from "../services/scanPolicy";
import { hashToken, isPrinterTestQrId, verifyQrToken } from "../services/qrTokenService";
import { evaluateScanAndEnforcePolicy } from "../services/policyEngineService";
import { reverseGeocode } from "../services/locationService";
import { getScanInsight } from "../services/scanInsightService";
import { CustomerVerifyRequest } from "../middleware/customerVerifyAuth";
import {
  assessDuplicateRisk,
  deriveAnomalyModelScore,
  type VerificationActivitySummary,
} from "../services/duplicateRiskService";
import { deriveRequestDeviceFingerprint } from "../utils/requestFingerprint";
import { resolveDuplicateRiskProfile } from "../services/governanceService";
import { isPrismaMissingTableError } from "../utils/prismaStorageGuard";
import {
  buildPublicIntegrityErrorBody,
  guardPublicIntegrityFallback,
  isPublicIntegrityDependencyError,
} from "../utils/publicIntegrityGuard";

const deviceFingerprint = (req: Request) => deriveRequestDeviceFingerprint(req);

const scanQuerySchema = z.object({
  t: z.string().trim().min(16).max(4096),
  device: z.string().trim().max(256).optional(),
  lat: z.union([z.string().trim().max(40), z.number()]).optional(),
  lon: z.union([z.string().trim().max(40), z.number()]).optional(),
  acc: z.union([z.string().trim().max(40), z.number()]).optional(),
}).strict();

const isQrReadyForCustomerUse = (status: QRStatus) => {
  return status === QRStatus.PRINTED || status === QRStatus.REDEEMED || status === QRStatus.SCANNED;
};

const buildOwnershipStatus = (params: {
  ownership: { id: string; userId: string | null; claimedAt: Date } | null;
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

const buildRepeatWarningMessage = (params: {
  effectiveOutcome: string;
  blockedByPolicy: boolean;
  hasContainment: boolean;
  firstScanAt: string | null;
  activitySummary?: VerificationActivitySummary | null;
}) => {
  if (params.effectiveOutcome === "SUSPICIOUS") {
    return "This code was generated but not confirmed as printed. Treat with suspicion.";
  }
  if (params.effectiveOutcome === "BLOCKED") {
    return params.blockedByPolicy
      ? "This code has been auto-blocked by security policy due to anomaly detection."
      : "This code has been blocked due to fraud or recall.";
  }
  if (params.hasContainment) {
    return "This product is currently under investigation. Please review details and contact support if needed.";
  }
  if (params.effectiveOutcome !== "ALREADY_REDEEMED") {
    return null;
  }
  if (params.activitySummary?.state === "trusted_repeat") {
    return "Already verified before. Recent checks match the same owner or trusted device.";
  }
  if (params.activitySummary?.state === "mixed_repeat") {
    return "Already verified before. Some recent checks match the owner context, but additional external activity was also recorded.";
  }
  return `Already verified before. First verification was at ${params.firstScanAt || "unknown time"}.`;
};

type ScanOwnershipRecord = {
  id: string;
  userId: string | null;
  claimedAt: Date;
};

const isQrScanActorForeignKeyError = (error: unknown) => {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) return false;
  if (error.code !== "P2003") return false;

  const meta = (error.meta || {}) as Record<string, unknown>;
  const haystack = `${String(meta.field_name || "")} ${String(error.message || "")}`.toLowerCase();
  return haystack.includes("qrscanlog") && (haystack.includes("customeruserid") || haystack.includes("ownershipid"));
};

const loadOwnershipByQrCodeId = async (
  qrCodeId: string,
  options?: { strictStorage?: boolean }
): Promise<ScanOwnershipRecord | null> => {
  try {
    return await prisma.ownership.findUnique({
      where: { qrCodeId },
      select: {
        id: true,
        userId: true,
        claimedAt: true,
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["ownership"])) {
      guardPublicIntegrityFallback({
        strictStorage: options?.strictStorage,
        warningKey: "scan-ownership-storage",
        warningMessage: "[scan] Ownership table is unavailable. Continuing public scan without ownership data.",
        degradedMessage: "Verification is temporarily unavailable because ownership records are not ready.",
        degradedCode: "PUBLIC_OWNERSHIP_UNAVAILABLE",
      });
      return null;
    }
    throw error;
  }
};

const maybeWriteScanLog = async (
  tx: Prisma.TransactionClient,
  input: {
    updatedQr: {
      code: string;
      id: string;
      licenseeId: string;
      batchId: string | null;
      status: QRStatus;
      scanCount: number | null;
    };
    isFirstScan: boolean;
    customerUserId: string | null;
    ownershipId: string | null;
    currentScanTrustedOwnerContext: boolean;
    ipAddress?: string | null;
    userAgent: string | null;
    device: string | null;
    latitude: number | null;
    longitude: number | null;
    accuracy: number | null;
    location: Awaited<ReturnType<typeof reverseGeocode>>;
    strictStorage?: boolean;
  }
) => {
  const baseData = {
    code: input.updatedQr.code,
    qrCodeId: input.updatedQr.id,
    licenseeId: input.updatedQr.licenseeId,
    batchId: input.updatedQr.batchId ?? null,
    status: input.updatedQr.status,
    isFirstScan: input.isFirstScan,
    scanCount: input.updatedQr.scanCount ?? 0,
    customerUserId: input.customerUserId,
    ownershipId: input.currentScanTrustedOwnerContext ? input.ownershipId : null,
    ownershipMatchMethod: input.currentScanTrustedOwnerContext ? "user" : null,
    isTrustedOwnerContext: input.currentScanTrustedOwnerContext,
    ipAddress: input.ipAddress,
    userAgent: input.userAgent,
    device: input.device,
    latitude: input.latitude,
    longitude: input.longitude,
    accuracy: input.accuracy,
    locationName: input.location?.name || null,
    locationCountry: input.location?.country || null,
    locationRegion: input.location?.region || null,
    locationCity: input.location?.city || null,
  };

  try {
    await tx.qrScanLog.create({
      data: baseData,
    });
  } catch (error) {
    if (isQrScanActorForeignKeyError(error)) {
      guardPublicIntegrityFallback({
        strictStorage: input.strictStorage,
        warningKey: "scan-qr-log-actor-fk",
        warningMessage:
          "[scan] QrScanLog customer/ownership foreign key is stale. Retrying public scan log without actor linkage.",
        degradedMessage: "Verification is temporarily unavailable because scan-log integrity checks are stale.",
        degradedCode: "PUBLIC_SCAN_LOG_INTEGRITY_STALE",
      });
      await tx.qrScanLog.create({
        data: {
          ...baseData,
          customerUserId: null,
          ownershipId: null,
          ownershipMatchMethod: null,
          isTrustedOwnerContext: false,
        },
      });
      return;
    }
    if (isPrismaMissingTableError(error, ["qrscanlog"])) {
      guardPublicIntegrityFallback({
        strictStorage: input.strictStorage,
        warningKey: "scan-qr-log-storage",
        warningMessage: "[scan] QrScanLog storage is unavailable. Continuing public scan without scan log persistence.",
        degradedMessage: "Verification is temporarily unavailable because scan-log storage is not ready.",
        degradedCode: "PUBLIC_SCAN_LOG_UNAVAILABLE",
      });
      return;
    }
    throw error;
  }
};

const writePublicScanAuditLog = async (input: {
  qrId: string;
  code: string;
  scanCount: number;
  ipAddress?: string | null;
  strictStorage?: boolean;
}) => {
  try {
    await createAuditLog({
      action: "REDEEMED",
      entityType: "QRCode",
      entityId: input.qrId,
      details: {
        qrId: input.qrId,
        code: input.code,
        scanCount: input.scanCount,
      },
      ipAddress: input.ipAddress || undefined,
    });
  } catch (error) {
    if (
      isPrismaMissingTableError(error, [
        "auditlog",
        "traceevent",
        "forensiceventchain",
        "securityeventoutbox",
      ])
    ) {
      guardPublicIntegrityFallback({
        strictStorage: input.strictStorage,
        warningKey: "scan-audit-storage",
        warningMessage:
          "[scan] Audit/telemetry storage is unavailable. Continuing public verification without audit persistence.",
        degradedMessage: "Verification is temporarily unavailable because audit storage is not ready.",
        degradedCode: "PUBLIC_AUDIT_STORAGE_UNAVAILABLE",
      });
      return;
    }
    console.error("public scan audit log failed:", error);
  }
};

export const scanToken = async (req: CustomerVerifyRequest, res: Response) => {
  try {
    const queryParsed = scanQuerySchema.safeParse(req.query || {});
    if (!queryParsed.success) {
      return res.status(400).json({ success: false, error: queryParsed.error.errors[0]?.message || "Invalid scan request" });
    }
    const requestQuery = queryParsed.data;
    const token = requestQuery.t;

    let payload;
    try {
      payload = verifyQrToken(token).payload;
    } catch {
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

    if (isPrinterTestQrId(payload.qr_id)) {
      return res.json({
        success: true,
        data: {
          isAuthentic: true,
          message: "MSCQR printer setup test label verified. This QR is for printer setup only and does not represent a product.",
          scanOutcome: "PRINTER_SETUP_TEST",
          classification: "LEGIT_REPEAT",
          code: "PRINTER_SETUP_TEST",
          status: "TEST_ONLY",
          warningMessage: "Use this label only to confirm printer setup and print quality.",
          ownershipStatus: {
            isClaimed: false,
            claimedAt: null,
            isOwnedByRequester: false,
            isClaimedByAnother: false,
            canClaim: false,
          },
          verifyUxPolicy: {
            showTimelineCard: false,
            showRiskCards: false,
            allowOwnershipClaim: false,
            allowFraudReport: false,
            mobileCameraAssist: true,
          },
          scanSummary: {
            totalScans: 0,
            firstVerifiedAt: null,
            latestVerifiedAt: null,
          },
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
    const toNum = (v: unknown) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };
    const latitude = toNum(requestQuery.lat);
    const longitude = toNum(requestQuery.lon);
    const accuracy = toNum(requestQuery.acc);
    const location = await reverseGeocode(latitude, longitude);
    const customerUserId = req.customer?.userId || null;
    const ownershipBeforeScan = await loadOwnershipByQrCodeId(qr.id, { strictStorage: true });
    const currentScanTrustedOwnerContext =
      Boolean(customerUserId) && ownershipBeforeScan?.userId === customerUserId;

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

      await maybeWriteScanLog(tx, {
        updatedQr,
        isFirstScan: decision.allowRedeem,
        customerUserId,
        ownershipId: ownershipBeforeScan?.id || null,
        currentScanTrustedOwnerContext,
        ipAddress: req.ip,
        userAgent: req.get("user-agent") || null,
        device: fp,
        latitude,
        longitude,
        accuracy,
        location,
        strictStorage: true,
      });

      return updatedQr;
    });

    if (decision.allowRedeem) {
      await writePublicScanAuditLog({
        qrId: updated.id,
        code: updated.code,
        scanCount: updated.scanCount ?? 0,
        ipAddress: req.ip,
        strictStorage: true,
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
      strictStorage: true,
    });

    const finalStatus =
      policy.autoBlockedQr || policy.autoBlockedBatch ? QRStatus.BLOCKED : updated.status;
    const effectiveOutcome = finalStatus === QRStatus.BLOCKED ? "BLOCKED" : decision.outcome;
    const isBlocked = finalStatus === QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(finalStatus);
    const ownershipStatus = buildOwnershipStatus({
      ownership: ownershipBeforeScan,
      customerUserId,
      isReady,
      isBlocked,
    });
    const scanInsight = await getScanInsight(updated.id, fp || null, {
      currentIpAddress: req.ip || null,
      licenseeId: updated.licenseeId,
      currentCustomerUserId: customerUserId,
      currentOwnershipId: ownershipBeforeScan?.id || null,
      currentActorTrustedOwnerContext: ownershipStatus.isOwnedByRequester,
      strictStorage: true,
    });

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

    const totalScans = Number(updated.scanCount ?? 0);
    const firstVerifiedAt = scanInsight.firstScanAt || (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);
    const latestVerifiedAt =
      scanInsight.latestScanAt ||
      scanInsight.firstScanAt ||
      (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);

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
    const riskSignals = duplicateRisk.signals;
    const activitySummary = decision.allowRedeem ? null : duplicateRisk.activitySummary;

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

    const warningMessage = buildRepeatWarningMessage({
      effectiveOutcome,
      blockedByPolicy: Boolean(policy.autoBlockedQr || policy.autoBlockedBatch),
      hasContainment,
      firstScanAt: scanInsight.firstScanAt || updated.redeemedAt?.toISOString?.() || null,
      activitySummary,
    });

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
        activitySummary,
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
    if (isPublicIntegrityDependencyError(error)) {
      return res.status(error.statusCode).json(buildPublicIntegrityErrorBody(error.message, error.code));
    }
    console.error("scanToken error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};

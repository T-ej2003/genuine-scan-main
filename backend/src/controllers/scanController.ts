import { Request, Response } from "express";
import prisma from "../config/database";
import { QRStatus, ScanRiskClassification } from "@prisma/client";
import { createAuditLog } from "../services/auditService";
import { evaluateScanPolicy } from "../services/scanPolicy";
import { hashToken, verifyQrToken } from "../services/qrTokenService";
import { evaluateScanAndEnforcePolicy } from "../services/policyEngineService";
import { getCustomerIdentityContext } from "../services/customerSessionService";
import { recordClassifiedScan } from "../services/recordClassifiedScanService";
import { buildScanHistorySummary } from "../services/scanHistorySummaryService";

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = Number(process.env.SCAN_RATE_LIMIT_PER_MIN || "60");

const rateLimitState = new Map<string, { count: number; resetAt: number }>();

const hitRateLimit = (key: string) => {
  const now = Date.now();
  const entry = rateLimitState.get(key);
  if (!entry || entry.resetAt <= now) {
    rateLimitState.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
};

export const scanToken = async (req: Request, res: Response) => {
  try {
    const ipKey = String(req.ip || "unknown");
    if (hitRateLimit(ipKey)) {
      return res.status(429).json({
        success: false,
        error: "Rate limit exceeded. Please try again later.",
      });
    }

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
          },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
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
    const identity = getCustomerIdentityContext(req, res);
    const device =
      String((req.query.device as string | undefined) || "").trim() ||
      String(req.get("x-device-fp") || "").trim() ||
      String(req.get("user-agent") || "").trim() ||
      null;
    const toNum = (v: any) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };
    const latitude = toNum(req.query.lat);
    const longitude = toNum(req.query.lon);
    const accuracy = toNum(req.query.acc);
    const { qrCode: updated, classification, ownership } = await recordClassifiedScan({
      qrId: qr.id,
      currentStatus: qr.status,
      allowRedeem: decision.allowRedeem,
      existingScannedAt: qr.scannedAt,
      existingRedeemedAt: qr.redeemedAt,
      ipAddress: req.ip,
      ipHash: identity.ipHash,
      userAgent: req.get("user-agent") || null,
      device,
      latitude,
      longitude,
      accuracy,
      customerUserId: identity.customerUserId,
      anonVisitorId: identity.anonVisitorId,
      visitorFingerprint: identity.visitorFingerprint,
      scannedAt: now,
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
    const summary = await buildScanHistorySummary({
      qrCodeId: updated.id,
      totalScans: updated.scanCount ?? 0,
      customerUserId: identity.customerUserId,
      anonVisitorId: identity.anonVisitorId,
    });

    const effectiveOutcome =
      finalStatus === QRStatus.BLOCKED
        ? "BLOCKED"
        : decision.outcome === "SUSPICIOUS" || decision.outcome === "NOT_PRINTED"
        ? decision.outcome
        : classification.classification === ScanRiskClassification.FIRST_SCAN
        ? "VALID"
        : classification.classification === ScanRiskClassification.LEGIT_REPEAT
        ? "VALID_REPEAT"
        : "SUSPICIOUS_DUPLICATE";

    const warningMessage =
      effectiveOutcome === "VALID_REPEAT"
        ? "You have verified this product before."
        : effectiveOutcome === "SUSPICIOUS_DUPLICATE"
        ? "Possible duplicate: this code is being scanned by different identities/devices."
        : effectiveOutcome === "SUSPICIOUS"
        ? "This code was generated but not confirmed as printed. Treat with caution."
        : effectiveOutcome === "BLOCKED"
        ? policy.autoBlockedQr || policy.autoBlockedBatch
          ? "This code has been auto-blocked by security policy due to anomaly detection."
          : "This code has been blocked due to fraud or recall."
        : null;

    const message =
      effectiveOutcome === "VALID"
        ? "Authentic item. First-time verification successful."
        : effectiveOutcome === "VALID_REPEAT"
        ? "Authentic item verified again."
        : effectiveOutcome === "SUSPICIOUS_DUPLICATE"
        ? "Possible duplicate scan detected."
        : effectiveOutcome === "SUSPICIOUS"
        ? "Not activated for sale. Suspicious scan."
        : effectiveOutcome === "BLOCKED"
        ? "Blocked code."
        : "This code is not active.";

    const isOwnedByYou = Boolean(
      identity.customerUserId &&
        ownership?.customerUserId &&
        ownership.customerUserId === identity.customerUserId
    );

    return res.json({
      success: true,
      data: {
        isAuthentic: effectiveOutcome === "VALID" || effectiveOutcome === "VALID_REPEAT",
        scanOutcome: effectiveOutcome,
        scanClassification:
          finalStatus === QRStatus.BLOCKED ? "SUSPICIOUS_DUPLICATE" : classification.classification,
        reasons:
          finalStatus === QRStatus.BLOCKED
            ? ["Security policy auto-blocked this QR code"]
            : classification.reasons,
        message,
        warningMessage,
        code: updated.code,
        status: finalStatus,
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
        firstScanned: summary.firstScanAt,
        scanCount: updated.scanCount ?? 0,
        isFirstScan: classification.classification === ScanRiskClassification.FIRST_SCAN,
        redeemedAt: updated.redeemedAt ? new Date(updated.redeemedAt).toISOString() : null,
        firstScanAt: summary.firstScanAt,
        firstScanLocation: summary.firstScanLocation,
        latestScanAt: summary.lastScanAt,
        latestScanLocation: summary.lastScanLocation,
        previousScanAt: summary.previousScanAt,
        previousScanLocation: summary.previousScanLocation,
        verifiedByYouCount: summary.verifiedByYouCount,
        topLocations: summary.topLocations,
        ownership: ownership
          ? {
              ownerCustomerId: ownership.customerUserId,
              claimedAt: ownership.claimedAt,
              isOwnedByYou,
            }
          : null,
        claimRecommended: !ownership && !identity.customerUserId,
        anonVisitorId: identity.anonVisitorId,
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

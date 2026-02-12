import { Request, Response } from "express";
import prisma from "../config/database";
import { QRStatus } from "@prisma/client";
import { recordScan } from "../services/qrService";
import { createAuditLog } from "../services/auditService";
import { evaluateScanAndEnforcePolicy } from "../services/policyEngineService";
import { z } from "zod";

const reportFraudSchema = z.object({
  code: z.string().trim().min(2).max(128),
  reason: z.string().trim().min(3).max(120),
  notes: z.string().trim().max(1500).optional(),
  contactEmail: z.string().trim().email().max(160).optional(),
  observedStatus: z.string().trim().max(64).optional(),
  observedOutcome: z.string().trim().max(64).optional(),
  pageUrl: z.string().trim().max(1000).optional(),
});

export const verifyQRCode = async (req: Request, res: Response) => {
  try {
    const { code } = req.params;

    if (!code || code.length < 2) {
      return res.status(400).json({
        success: false,
        error: "Invalid QR code format",
      });
    }

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: code.toUpperCase() },
      include: {
        licensee: {
          select: { id: true, name: true, prefix: true, brandName: true, location: true, website: true, supportEmail: true, supportPhone: true },
        },
        batch: {
          select: {
            id: true,
            name: true,
            printedAt: true,
            manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
          },
        },
        // product batch removed
      },
    });

    if (!qrCode) {
      await createAuditLog({
        action: "VERIFY_FAILED",
        entityType: "QRCode",
        entityId: code,
        details: { reason: "Code not found" },
        ipAddress: req.ip,
      });

      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code is not registered in our system.",
          code,
        },
      });
    }

    // Blocked code
    if (qrCode.status === QRStatus.BLOCKED) {
      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code has been blocked due to fraud or recall.",
          code,
          status: qrCode.status,
          licensee: qrCode.licensee
            ? {
                id: qrCode.licensee.id,
                name: qrCode.licensee.name,
                prefix: qrCode.licensee.prefix,
                brandName: qrCode.licensee.brandName,
                location: qrCode.licensee.location,
                website: qrCode.licensee.website,
                supportEmail: qrCode.licensee.supportEmail,
                supportPhone: qrCode.licensee.supportPhone,
              }
            : null,
          batch: qrCode.batch
            ? {
                id: qrCode.batch.id,
                name: qrCode.batch.name,
                printedAt: qrCode.batch.printedAt,
                manufacturer: qrCode.batch.manufacturer || null,
              }
            : null,
        },
      });
    }

    // If not yet assigned into any batch
    if (qrCode.status === QRStatus.DORMANT || qrCode.status === QRStatus.ACTIVE) {
      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code has not been assigned to a product yet.",
          code,
          status: qrCode.status,
          licensee: qrCode.licensee
            ? {
                id: qrCode.licensee.id,
                name: qrCode.licensee.name,
                prefix: qrCode.licensee.prefix,
                brandName: qrCode.licensee.brandName,
                location: qrCode.licensee.location,
                website: qrCode.licensee.website,
                supportEmail: qrCode.licensee.supportEmail,
                supportPhone: qrCode.licensee.supportPhone,
              }
            : null,
          batch: qrCode.batch
            ? {
                id: qrCode.batch.id,
                name: qrCode.batch.name,
                printedAt: qrCode.batch.printedAt,
                manufacturer: qrCode.batch.manufacturer || null,
              }
            : null,
        },
      });
    }

    // allocated but not printed
    if (qrCode.status === QRStatus.ALLOCATED) {
      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code is allocated but not yet printed.",
          code,
          status: qrCode.status,
          licensee: qrCode.licensee
            ? {
                id: qrCode.licensee.id,
                name: qrCode.licensee.name,
                prefix: qrCode.licensee.prefix,
                brandName: qrCode.licensee.brandName,
                location: qrCode.licensee.location,
                website: qrCode.licensee.website,
                supportEmail: qrCode.licensee.supportEmail,
                supportPhone: qrCode.licensee.supportPhone,
              }
            : null,
          batch: qrCode.batch
            ? {
                id: qrCode.batch.id,
                name: qrCode.batch.name,
                printedAt: qrCode.batch.printedAt,
                manufacturer: qrCode.batch.manufacturer || null,
              }
            : null,
          batchName: qrCode.batch?.name || null,
        },
      });
    }

    // Print job created but not confirmed
    if (qrCode.status === QRStatus.ACTIVATED) {
      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code has not been activated (print not confirmed).",
          code,
          status: qrCode.status,
          licensee: qrCode.licensee
            ? {
                id: qrCode.licensee.id,
                name: qrCode.licensee.name,
                prefix: qrCode.licensee.prefix,
                brandName: qrCode.licensee.brandName,
                location: qrCode.licensee.location,
                website: qrCode.licensee.website,
                supportEmail: qrCode.licensee.supportEmail,
                supportPhone: qrCode.licensee.supportPhone,
              }
            : null,
          batch: qrCode.batch
            ? {
                id: qrCode.batch.id,
                name: qrCode.batch.name,
                printedAt: qrCode.batch.printedAt,
                manufacturer: qrCode.batch.manufacturer || null,
              }
            : null,
          batchName: qrCode.batch?.name || null,
        },
      });
    }

    // Valid printed/redeemed QR - record scan
    const toNum = (v: any) => {
      const n = parseFloat(String(v));
      return Number.isFinite(n) ? n : null;
    };
    const latitude = toNum(req.query.lat);
    const longitude = toNum(req.query.lon);
    const accuracy = toNum(req.query.acc);

    const { isFirstScan, qrCode: updated } = await recordScan(code.toUpperCase(), {
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
      device: (req.query.device as string | undefined) || null,
      latitude,
      longitude,
      accuracy,
    });

    await createAuditLog({
      action: "VERIFY_SUCCESS",
      entityType: "QRCode",
      entityId: qrCode.id,
      details: {
        isFirstScan,
        scanCount: (updated.scanCount ?? 0),
      },
      ipAddress: req.ip,
    });

    const policy = await evaluateScanAndEnforcePolicy({
      qrCodeId: updated.id,
      code: updated.code,
      licenseeId: updated.licenseeId,
      batchId: updated.batchId ?? null,
      manufacturerId: updated.batch?.manufacturer?.id || null,
      scanCount: updated.scanCount ?? 0,
      scannedAt: new Date(),
      latitude,
      longitude,
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
    });

    const blockedByPolicy = policy.autoBlockedQr || policy.autoBlockedBatch;
    const finalStatus = blockedByPolicy ? QRStatus.BLOCKED : updated.status;

    const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;

    const warningMessage = blockedByPolicy
      ? "This code has been auto-blocked by security policy due to anomaly detection."
      : !isFirstScan && firstScanTime
      ? `Already redeemed. First scan was on ${firstScanTime.toISOString()}.`
      : null;

    return res.json({
      success: true,
      data: {
        isAuthentic: isFirstScan && !blockedByPolicy,
        message: blockedByPolicy
          ? "Blocked code."
          : isFirstScan
          ? "This is a genuine product."
          : "Already redeemed. Possible counterfeit or reuse.",
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

        // legacy batch info (if you still use it sometimes)
        batchName: updated.batch?.name || null,
        printedAt: updated.batch?.printedAt || null,

        firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
        scanCount: updated.scanCount ?? 0,
        isFirstScan,

        warningMessage,
        policy,
      },
    });
  } catch (error) {
    console.error("Verify error:", error);
    return res.status(500).json({
      success: false,
      error: "Verification service unavailable",
    });
  }
};

export const reportFraud = async (req: Request, res: Response) => {
  try {
    const parsed = reportFraudSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid report payload",
      });
    }

    const payload = parsed.data;
    const normalizedCode = payload.code.toUpperCase();

    const qrCode = await prisma.qRCode.findUnique({
      where: { code: normalizedCode },
      select: {
        id: true,
        code: true,
        licenseeId: true,
        batchId: true,
        batch: {
          select: {
            manufacturerId: true,
          },
        },
      },
    });

    const log = await createAuditLog({
      action: "CUSTOMER_FRAUD_REPORT",
      entityType: "FraudReport",
      entityId: qrCode?.id || normalizedCode,
      licenseeId: qrCode?.licenseeId || undefined,
      ipAddress: req.ip,
      details: {
        code: normalizedCode,
        reason: payload.reason,
        notes: payload.notes || null,
        contactEmail: payload.contactEmail || null,
        observedStatus: payload.observedStatus || null,
        observedOutcome: payload.observedOutcome || null,
        qrCodeId: qrCode?.id || null,
        batchId: qrCode?.batchId || null,
        manufacturerId: qrCode?.batch?.manufacturerId || null,
        pageUrl: payload.pageUrl || null,
        userAgent: req.get("user-agent") || null,
        reportedAt: new Date().toISOString(),
      },
    });

    return res.status(201).json({
      success: true,
      data: {
        reportId: log.id,
        message: "Fraud report submitted successfully.",
      },
    });
  } catch (error) {
    console.error("reportFraud error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to submit fraud report",
    });
  }
};

import { Request, Response } from "express";
import prisma from "../config/database";
import { QRStatus } from "@prisma/client";
import { recordScan } from "../services/qrService";
import { createAuditLog } from "../services/auditService";

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

    const { isFirstScan, qrCode: updated } = await recordScan(code.toUpperCase(), {
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || null,
      device: (req.query.device as string | undefined) || null,
      latitude: toNum(req.query.lat),
      longitude: toNum(req.query.lon),
      accuracy: toNum(req.query.acc),
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

    const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;

    const warningMessage = !isFirstScan && firstScanTime
      ? `Already redeemed. First scan was on ${firstScanTime.toISOString()}.`
      : null;

    return res.json({
      success: true,
      data: {
        isAuthentic: isFirstScan,
        message: isFirstScan
          ? "This is a genuine product."
          : "Already redeemed. Possible counterfeit or reuse.",
        code: updated.code,

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

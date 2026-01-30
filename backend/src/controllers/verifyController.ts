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
          select: { id: true, name: true, prefix: true },
        },
        batch: {
          select: { id: true, name: true, printedAt: true },
        },
        productBatch: {
          select: {
            id: true,
            productName: true,
            productCode: true,
            description: true,
            serialStart: true,
            serialEnd: true,
            serialFormat: true,
            printedAt: true,
            manufacturer: { select: { id: true, name: true, email: true } },
            parentBatch: { select: { id: true, name: true } },
          },
        },
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

    // If not yet assigned into any batch/productBatch
    if (qrCode.status === QRStatus.DORMANT || qrCode.status === QRStatus.ACTIVE) {
      return res.json({
        success: true,
        data: {
          isAuthentic: false,
          message: "This QR code has not been assigned to a product yet.",
          code,
          status: qrCode.status,
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
          productBatch: qrCode.productBatch
            ? {
                id: qrCode.productBatch.id,
                productName: qrCode.productBatch.productName,
                productCode: qrCode.productBatch.productCode,
                manufacturer: qrCode.productBatch.manufacturer || null,
              }
            : null,
          batchName: qrCode.batch?.name || null,
        },
      });
    }

    // Valid printed/scanned QR - record scan
    const { isFirstScan, qrCode: updated } = await recordScan(code.toUpperCase());

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

    return res.json({
      success: true,
      data: {
        isAuthentic: true,
        message: "This is a genuine product.",
        code: updated.code,

        licensee: updated.licensee?.name,
        licenseePrefix: updated.licensee?.prefix,

        productBatch: updated.productBatch
          ? {
              id: updated.productBatch.id,
              productName: updated.productBatch.productName,
              productCode: updated.productBatch.productCode,
              description: updated.productBatch.description,
              serialStart: updated.productBatch.serialStart,
              serialEnd: updated.productBatch.serialEnd,
              serialFormat: updated.productBatch.serialFormat,
              printedAt: updated.productBatch.printedAt,
              manufacturer: updated.productBatch.manufacturer || null,
              parentBatch: updated.productBatch.parentBatch || null,
            }
          : null,

        // legacy batch info (if you still use it sometimes)
        batchName: updated.batch?.name || null,
        printedAt: updated.batch?.printedAt || updated.productBatch?.printedAt || null,

        firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
        scanCount: updated.scanCount ?? 0,
        isFirstScan,

        warningMessage: !isFirstScan && firstScanTime
          ? `This product has been scanned ${(updated.scanCount ?? 0)} times. First scan was on ${firstScanTime.toISOString()}.`
          : null,
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


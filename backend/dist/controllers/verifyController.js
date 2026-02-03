"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyQRCode = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const qrService_1 = require("../services/qrService");
const auditService_1 = require("../services/auditService");
const verifyQRCode = async (req, res) => {
    try {
        const { code } = req.params;
        if (!code || code.length < 2) {
            return res.status(400).json({
                success: false,
                error: "Invalid QR code format",
            });
        }
        const qrCode = await database_1.default.qRCode.findUnique({
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
                        manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
                        parentBatch: { select: { id: true, name: true } },
                    },
                },
            },
        });
        if (!qrCode) {
            await (0, auditService_1.createAuditLog)({
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
        if (qrCode.status === client_1.QRStatus.DORMANT || qrCode.status === client_1.QRStatus.ACTIVE) {
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
        if (qrCode.status === client_1.QRStatus.ALLOCATED) {
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
                    productBatch: qrCode.productBatch
                        ? {
                            id: qrCode.productBatch.id,
                            productName: qrCode.productBatch.productName,
                            productCode: qrCode.productBatch.productCode,
                            manufacturer: qrCode.productBatch.manufacturer || null,
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
        // Valid printed/scanned QR - record scan
        const toNum = (v) => {
            const n = parseFloat(String(v));
            return Number.isFinite(n) ? n : null;
        };
        const { isFirstScan, qrCode: updated } = await (0, qrService_1.recordScan)(code.toUpperCase(), {
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || null,
            device: req.query.device || null,
            latitude: toNum(req.query.lat),
            longitude: toNum(req.query.lon),
            accuracy: toNum(req.query.acc),
        });
        await (0, auditService_1.createAuditLog)({
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
                printedAt: updated.batch?.printedAt || updated.productBatch?.printedAt || null,
                firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
                scanCount: updated.scanCount ?? 0,
                isFirstScan,
                warningMessage: !isFirstScan && firstScanTime
                    ? `This product has been scanned ${(updated.scanCount ?? 0)} times. First scan was on ${firstScanTime.toISOString()}.`
                    : null,
            },
        });
    }
    catch (error) {
        console.error("Verify error:", error);
        return res.status(500).json({
            success: false,
            error: "Verification service unavailable",
        });
    }
};
exports.verifyQRCode = verifyQRCode;
//# sourceMappingURL=verifyController.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.publicVerify = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const qrService_1 = require("../services/qrService");
const mapStage = (s) => {
    switch (s) {
        case client_1.QRStatus.DORMANT:
            return "DORMANT";
        case client_1.QRStatus.ACTIVE:
            return "ALLOCATED";
        case client_1.QRStatus.ALLOCATED:
            return "ALLOCATED";
        case client_1.QRStatus.PRINTED:
            return "PRINTED";
        case client_1.QRStatus.SCANNED:
            return "SCANNED";
        default:
            return "DORMANT";
    }
};
const publicVerify = async (req, res) => {
    try {
        const raw = String(req.params.code || req.query.code || "")
            .trim()
            .toUpperCase();
        if (!raw) {
            return res.status(400).json({
                status: "INVALID",
                message: "No verification code provided.",
            });
        }
        if (!(0, qrService_1.parseQRCode)(raw)) {
            return res.status(400).json({
                status: "INVALID",
                message: "Invalid QR code format.",
            });
        }
        // Look up QR with safe relations
        const qr = await database_1.default.qRCode.findUnique({
            where: { code: raw },
            include: {
                licensee: { select: { id: true, name: true, prefix: true } },
                batch: {
                    select: {
                        id: true,
                        name: true,
                        printedAt: true,
                        manufacturer: { select: { id: true, name: true, email: true } },
                    },
                },
            },
        });
        if (!qr) {
            return res.status(404).json({
                status: "NOT_FOUND",
                message: "This code does not exist.",
                qrCodeId: raw,
                product: null,
                scan: {
                    verifiedAt: new Date().toISOString(),
                    firstScanAt: null,
                    scanCount: 0,
                },
                stage: "DORMANT",
                confidenceScore: 0,
                theme: { brandName: "Authenticity Check" },
            });
        }
        // Not printed yet => invalid for customers
        if (qr.status !== client_1.QRStatus.PRINTED && qr.status !== client_1.QRStatus.SCANNED) {
            return res.status(200).json({
                status: "INVALID",
                message: "This code exists but the item has not been printed for sale yet.",
                qrCodeId: qr.code,
                product: {
                    name: qr.batch?.name || "Item",
                    brand: qr.licensee?.name || "Brand",
                    category: "",
                    serial: qr.code,
                    batch: qr.batch?.id || "",
                    manufacturedAt: null,
                    manufacturer: qr.batch?.manufacturer?.name || "",
                    licensee: qr.licensee?.name || "",
                    originCountry: "",
                    materials: [],
                },
                scan: {
                    verifiedAt: new Date().toISOString(),
                    firstScanAt: qr.scannedAt ? new Date(qr.scannedAt).toISOString() : null,
                    scanCount: qr.scanCount || 0,
                },
                stage: mapStage(qr.status),
                confidenceScore: 20,
                theme: { brandName: qr.licensee?.name || "Authenticity Check" },
            });
        }
        // Printed or scanned => record scan (increments)
        const result = await (0, qrService_1.recordScan)(raw);
        const updated = result.qrCode;
        const status = result.isFirstScan ? "VALID" : "ALREADY_SCANNED";
        const confidenceScore = result.isFirstScan ? 92 : 78;
        return res.status(200).json({
            status,
            message: result.isFirstScan
                ? "Authentic item. Verification successful."
                : "This item has been scanned before. Re-scans can happen if rechecked or resold.",
            qrCodeId: updated.code,
            product: {
                name: updated.batch?.name || "Item",
                brand: updated.licensee?.name || "Brand",
                category: "",
                serial: updated.code,
                batch: updated.batch?.id || "",
                manufacturedAt: null,
                manufacturer: updated.batch?.manufacturer?.name || "",
                licensee: updated.licensee?.name || "",
                originCountry: "",
                materials: [],
            },
            scan: {
                verifiedAt: new Date().toISOString(),
                firstScanAt: updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null,
                scanCount: updated.scanCount || 0,
            },
            stage: "SCANNED",
            confidenceScore,
            theme: { brandName: updated.licensee?.name || "Authenticity Check" },
        });
    }
    catch (e) {
        console.error("publicVerify error:", e);
        return res.status(500).json({
            status: "SUSPICIOUS",
            message: "Internal server error",
        });
    }
};
exports.publicVerify = publicVerify;
//# sourceMappingURL=publicController.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getQRStats = exports.recordScan = exports.markBatchAsPrinted = exports.allocateQRCodesToBatch = exports.activateQRCodes = exports.generateQRCodesForRange = exports.buildVerifyUrl = exports.makeProductCode = exports.parseQRCode = exports.generateQRCode = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const qrTokenService_1 = require("./qrTokenService");
const generateQRCode = (prefix, number) => {
    return `${prefix}${number.toString().padStart(10, "0")}`;
};
exports.generateQRCode = generateQRCode;
const parseQRCode = (code) => {
    const match = code.match(/^([A-Z0-9]+)(\d{10})$/);
    if (!match)
        return null;
    return { prefix: match[1], number: parseInt(match[2], 10) };
};
exports.parseQRCode = parseQRCode;
const makeProductCode = (input) => {
    const s = String(input || "").trim().toUpperCase();
    const cleaned = s
        .replace(/[^A-Z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .replace(/-+/g, "-");
    return (cleaned || "PRODUCT").slice(0, 24);
};
exports.makeProductCode = makeProductCode;
const buildVerifyUrl = (code) => {
    const base = String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
        String(process.env.CORS_ORIGIN || "").trim() ||
        "http://localhost:8080";
    const normalized = base.replace(/\/+$/, "");
    return `${normalized}/verify/${encodeURIComponent(code)}`;
};
exports.buildVerifyUrl = buildVerifyUrl;
const generateQRCodesForRange = async (licenseeId, prefix, startNumber, endNumber) => {
    const codes = [];
    for (let i = startNumber; i <= endNumber; i++) {
        codes.push({
            code: (0, exports.generateQRCode)(prefix, i),
            licenseeId,
            status: client_1.QRStatus.DORMANT,
            tokenNonce: (0, qrTokenService_1.randomNonce)(),
        });
    }
    const batchSize = 1000;
    let created = 0;
    for (let i = 0; i < codes.length; i += batchSize) {
        const chunk = codes.slice(i, i + batchSize);
        const result = await database_1.default.qRCode.createMany({ data: chunk, skipDuplicates: true });
        created += result.count;
    }
    return created;
};
exports.generateQRCodesForRange = generateQRCodesForRange;
const activateQRCodes = async (licenseeId, codes) => {
    const result = await database_1.default.qRCode.updateMany({
        where: {
            code: { in: codes },
            licenseeId,
            status: client_1.QRStatus.DORMANT,
        },
        data: { status: client_1.QRStatus.ACTIVE },
    });
    return result.count;
};
exports.activateQRCodes = activateQRCodes;
const allocateQRCodesToBatch = async (batchId, licenseeId, startCode, endCode) => {
    const result = await database_1.default.qRCode.updateMany({
        where: {
            licenseeId,
            code: { gte: startCode, lte: endCode },
            status: { in: [client_1.QRStatus.DORMANT, client_1.QRStatus.ACTIVE] },
            batchId: null,
        },
        data: { status: client_1.QRStatus.ALLOCATED, batchId },
    });
    return result.count;
};
exports.allocateQRCodesToBatch = allocateQRCodesToBatch;
const markBatchAsPrinted = async (batchId, manufacturerId) => {
    const batch = await database_1.default.batch.findFirst({ where: { id: batchId, manufacturerId } });
    if (!batch)
        throw new Error("Batch not found or not assigned to this manufacturer");
    if (batch.printedAt)
        throw new Error("Batch has already been marked as printed");
    const now = new Date();
    await database_1.default.batch.update({ where: { id: batchId }, data: { printedAt: now } });
    const result = await database_1.default.qRCode.updateMany({
        where: { batchId, status: client_1.QRStatus.ALLOCATED },
        data: { status: client_1.QRStatus.PRINTED, printedAt: now, printedByUserId: manufacturerId },
    });
    return result.count;
};
exports.markBatchAsPrinted = markBatchAsPrinted;
// product batches removed
const recordScan = async (code, meta) => {
    const existing = await database_1.default.qRCode.findUnique({
        where: { code },
        include: {
            licensee: true,
            batch: { include: { manufacturer: { select: { id: true, name: true, email: true } } } },
        },
    });
    if (!existing)
        throw new Error("QR code not found");
    if (existing.status !== client_1.QRStatus.PRINTED &&
        existing.status !== client_1.QRStatus.REDEEMED &&
        existing.status !== client_1.QRStatus.SCANNED) {
        throw new Error("QR code has not been printed yet");
    }
    const isFirstScan = existing.status === client_1.QRStatus.PRINTED;
    const updated = await database_1.default.$transaction(async (tx) => {
        const qr = await tx.qRCode.update({
            where: { code },
            data: {
                status: isFirstScan ? client_1.QRStatus.REDEEMED : existing.status,
                scannedAt: isFirstScan ? new Date() : existing.scannedAt,
                redeemedAt: isFirstScan ? new Date() : existing.redeemedAt,
                lastScanIp: meta?.ipAddress ?? null,
                lastScanUserAgent: meta?.userAgent ?? null,
                lastScanDevice: meta?.device ?? null,
                scanCount: { increment: 1 },
            },
            include: {
                licensee: true,
                batch: { include: { manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } } } },
            },
        });
        await tx.qrScanLog.create({
            data: {
                code: qr.code,
                qrCodeId: qr.id,
                licenseeId: qr.licenseeId,
                batchId: qr.batchId ?? null,
                status: qr.status,
                isFirstScan,
                scanCount: qr.scanCount ?? 0,
                ipAddress: meta?.ipAddress ?? null,
                userAgent: meta?.userAgent ?? null,
                device: meta?.device ?? null,
                latitude: meta?.latitude ?? null,
                longitude: meta?.longitude ?? null,
                accuracy: meta?.accuracy ?? null,
            },
        });
        return qr;
    });
    return { qrCode: updated, isFirstScan };
};
exports.recordScan = recordScan;
const getQRStats = async (licenseeId) => {
    const where = licenseeId ? { licenseeId } : {};
    const stats = await database_1.default.qRCode.groupBy({
        by: ["status"],
        where,
        _count: true,
    });
    const total = await database_1.default.qRCode.count({ where });
    return {
        total,
        byStatus: stats.reduce((acc, s) => {
            acc[s.status] = s._count;
            return acc;
        }, {}),
    };
};
exports.getQRStats = getQRStats;
//# sourceMappingURL=qrService.js.map
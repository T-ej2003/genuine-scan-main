"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.allocateQrRange = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const qrService_1 = require("./qrService");
const allocateQrRange = async (params) => {
    const { licenseeId, startNumber, endNumber, createdByUserId, source, requestId, createReceivedBatch, tx, } = params;
    const db = tx ?? database_1.default;
    const licensee = await db.licensee.findUnique({
        where: { id: licenseeId },
        select: { id: true, prefix: true },
    });
    if (!licensee)
        throw new Error("Licensee not found");
    const startCode = (0, qrService_1.generateQRCode)(licensee.prefix, startNumber);
    const endCode = (0, qrService_1.generateQRCode)(licensee.prefix, endNumber);
    const totalCodes = endNumber - startNumber + 1;
    // ensure no overlap with existing codes
    const existing = await db.qRCode.count({
        where: { licenseeId, code: { gte: startCode, lte: endCode } },
    });
    if (existing > 0) {
        throw new Error(`Range overlaps existing QR codes (${existing} found in the range).`);
    }
    const range = await db.qRRange.create({
        data: {
            licenseeId,
            startCode,
            endCode,
            totalCodes,
        },
    });
    const codes = [];
    for (let i = startNumber; i <= endNumber; i++) {
        codes.push({
            code: (0, qrService_1.generateQRCode)(licensee.prefix, i),
            licenseeId,
            status: client_1.QRStatus.DORMANT,
        });
    }
    const batchSize = 1000;
    let created = 0;
    for (let i = 0; i < codes.length; i += batchSize) {
        const chunk = codes.slice(i, i + batchSize);
        const result = await db.qRCode.createMany({ data: chunk });
        created += result.count;
    }
    let receivedBatch = null;
    if (createReceivedBatch) {
        const name = `Received ${startCode} → ${endCode}`.slice(0, 120);
        const batch = await db.batch.create({
            data: {
                name,
                licenseeId,
                startCode,
                endCode,
                totalCodes,
            },
            select: { id: true, name: true },
        });
        const updated = await db.qRCode.updateMany({
            where: { licenseeId, code: { gte: startCode, lte: endCode } },
            data: { batchId: batch.id },
        });
        if (updated.count !== totalCodes) {
            throw new Error(`Concurrency issue: assigned ${updated.count}/${totalCodes}. Please retry.`);
        }
        receivedBatch = batch;
    }
    await db.allocationEvent.create({
        data: {
            licenseeId,
            createdByUserId: createdByUserId || null,
            requestId: requestId || null,
            source: source || null,
            startCode,
            endCode,
            totalCodes,
        },
    });
    return { range, createdCount: created, startCode, endCode, totalCodes, receivedBatch };
};
exports.allocateQrRange = allocateQrRange;
//# sourceMappingURL=qrAllocationService.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.recordClassifiedScan = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const locationService_1 = require("./locationService");
const scanRiskService_1 = require("./scanRiskService");
const toCoarseCoord = (value) => {
    if (value == null || !Number.isFinite(value))
        return null;
    return Number(value.toFixed(2));
};
const recordClassifiedScan = async (input) => {
    const now = input.scannedAt || new Date();
    const latitude = toCoarseCoord(input.latitude);
    const longitude = toCoarseCoord(input.longitude);
    const accuracy = input.accuracy != null && Number.isFinite(input.accuracy) ? Number(input.accuracy) : null;
    const location = await (0, locationService_1.reverseGeocode)(latitude, longitude);
    return database_1.default.$transaction(async (tx) => {
        const [history, ownership] = await Promise.all([
            tx.qrScanLog.findMany({
                where: { qrCodeId: input.qrId },
                orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
                take: 60,
                select: {
                    scannedAt: true,
                    customerUserId: true,
                    anonVisitorId: true,
                    locationCountry: true,
                    latitude: true,
                    longitude: true,
                },
            }),
            tx.productOwnership.findUnique({
                where: { qrCodeId: input.qrId },
                select: { customerUserId: true, claimedAt: true },
            }),
        ]);
        const classification = (0, scanRiskService_1.classifyScan)({
            scannedAt: now,
            customerUserId: input.customerUserId || null,
            anonVisitorId: input.anonVisitorId || null,
            ownerCustomerUserId: ownership?.customerUserId || null,
            latitude,
            longitude,
            locationCountry: location?.country || null,
        }, history.map((entry) => ({
            scannedAt: entry.scannedAt,
            customerUserId: entry.customerUserId || null,
            anonVisitorId: entry.anonVisitorId || null,
            locationCountry: entry.locationCountry || null,
            latitude: entry.latitude,
            longitude: entry.longitude,
        })));
        const updatedQr = await tx.qRCode.update({
            where: { id: input.qrId },
            data: {
                scanCount: { increment: 1 },
                scannedAt: input.existingScannedAt || now,
                status: input.allowRedeem ? client_1.QRStatus.REDEEMED : input.currentStatus,
                redeemedAt: input.allowRedeem ? now : input.existingRedeemedAt || null,
                redeemedDeviceFingerprint: input.allowRedeem
                    ? input.visitorFingerprint || input.device || null
                    : undefined,
                lastScanIp: input.ipAddress || null,
                lastScanUserAgent: input.userAgent || null,
                lastScanDevice: input.visitorFingerprint || input.device || null,
            },
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
                        manufacturer: {
                            select: {
                                id: true,
                                name: true,
                                email: true,
                                location: true,
                                website: true,
                            },
                        },
                    },
                },
            },
        });
        await tx.qrScanLog.create({
            data: {
                code: updatedQr.code,
                qrCodeId: updatedQr.id,
                licenseeId: updatedQr.licenseeId,
                batchId: updatedQr.batchId ?? null,
                status: updatedQr.status,
                isFirstScan: input.allowRedeem,
                scanCount: updatedQr.scanCount ?? 0,
                ipAddress: input.ipAddress || null,
                ipHash: input.ipHash || null,
                userAgent: input.userAgent || null,
                device: input.device || null,
                latitude,
                longitude,
                accuracy,
                locationName: location?.name || null,
                locationCountry: location?.country || null,
                locationRegion: location?.region || null,
                locationCity: location?.city || null,
                customerUserId: input.customerUserId || null,
                anonVisitorId: input.anonVisitorId || null,
                visitorFingerprint: input.visitorFingerprint || null,
                riskClassification: classification.classification,
                riskReasons: classification.reasons,
            },
        });
        return {
            qrCode: updatedQr,
            classification,
            ownership,
            location,
        };
    });
};
exports.recordClassifiedScan = recordClassifiedScan;
//# sourceMappingURL=recordClassifiedScanService.js.map
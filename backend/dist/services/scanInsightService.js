"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getScanInsight = void 0;
const database_1 = __importDefault(require("../config/database"));
const locationService_1 = require("./locationService");
const locationLabel = async (row) => {
    if (row.locationName)
        return row.locationName;
    const nameFromParts = [row.locationCity, row.locationRegion, row.locationCountry].filter(Boolean).join(", ");
    if (nameFromParts)
        return nameFromParts;
    const resolved = await (0, locationService_1.reverseGeocode)(row.latitude ?? null, row.longitude ?? null);
    return resolved?.name || null;
};
const getScanInsight = async (qrCodeId, currentDevice) => {
    const now = Date.now();
    const lookback24h = new Date(now - 24 * 60 * 60 * 1000);
    const lookback10m = new Date(now - 10 * 60 * 1000);
    const [first, latestTwo, recent24h, recent10mCount] = await Promise.all([
        database_1.default.qrScanLog.findFirst({
            where: { qrCodeId },
            orderBy: [{ scannedAt: "asc" }, { id: "asc" }],
            select: {
                scannedAt: true,
                locationName: true,
                locationCity: true,
                locationRegion: true,
                locationCountry: true,
                latitude: true,
                longitude: true,
            },
        }),
        database_1.default.qrScanLog.findMany({
            where: { qrCodeId },
            orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
            take: 2,
            select: {
                scannedAt: true,
                locationName: true,
                locationCity: true,
                locationRegion: true,
                locationCountry: true,
                latitude: true,
                longitude: true,
                device: true,
            },
        }),
        database_1.default.qrScanLog.findMany({
            where: {
                qrCodeId,
                scannedAt: { gte: lookback24h },
            },
            select: {
                scannedAt: true,
                device: true,
                locationCountry: true,
            },
        }),
        database_1.default.qrScanLog.count({
            where: {
                qrCodeId,
                scannedAt: { gte: lookback10m },
            },
        }),
    ]);
    const latest = latestTwo[0] || null;
    const previous = latestTwo[1] || null;
    const latestTimestamp = latest?.scannedAt ? new Date(latest.scannedAt).getTime() : null;
    const normalizedCurrentDevice = String(currentDevice || "").trim();
    const distinctDevices = new Set(recent24h
        .map((row) => String(row.device || "").trim())
        .filter(Boolean));
    const distinctCountries = new Set(recent24h
        .map((row) => String(row.locationCountry || "").trim().toUpperCase())
        .filter(Boolean));
    const seenOnCurrentDeviceBefore = Boolean(normalizedCurrentDevice) &&
        recent24h.some((row) => {
            if (!latestTimestamp)
                return false;
            return (String(row.device || "").trim() === normalizedCurrentDevice &&
                new Date(row.scannedAt).getTime() < latestTimestamp);
        });
    const previousScanSameDevice = previous && normalizedCurrentDevice
        ? String(previous.device || "").trim() === normalizedCurrentDevice
        : null;
    return {
        firstScanAt: first?.scannedAt ? new Date(first.scannedAt).toISOString() : null,
        firstScanLocation: first ? await locationLabel(first) : null,
        latestScanAt: latest?.scannedAt ? new Date(latest.scannedAt).toISOString() : null,
        latestScanLocation: latest ? await locationLabel(latest) : null,
        previousScanAt: previous?.scannedAt ? new Date(previous.scannedAt).toISOString() : null,
        previousScanLocation: previous ? await locationLabel(previous) : null,
        signals: {
            distinctDeviceCount24h: distinctDevices.size,
            recentScanCount10m: recent10mCount,
            distinctCountryCount24h: distinctCountries.size,
            seenOnCurrentDeviceBefore,
            previousScanSameDevice,
        },
    };
};
exports.getScanInsight = getScanInsight;
//# sourceMappingURL=scanInsightService.js.map
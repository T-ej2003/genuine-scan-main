"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildScanHistorySummary = void 0;
const database_1 = __importDefault(require("../config/database"));
const scanInsightService_1 = require("./scanInsightService");
const buildScanHistorySummary = async (input) => {
    const [insight, recentLogs, verifiedByYouCount] = await Promise.all([
        (0, scanInsightService_1.getScanInsight)(input.qrCodeId),
        database_1.default.qrScanLog.findMany({
            where: { qrCodeId: input.qrCodeId },
            orderBy: [{ scannedAt: "desc" }, { id: "desc" }],
            take: 50,
            select: {
                locationName: true,
                locationCity: true,
                locationCountry: true,
            },
        }),
        input.customerUserId
            ? database_1.default.qrScanLog.count({
                where: {
                    qrCodeId: input.qrCodeId,
                    customerUserId: input.customerUserId,
                },
            })
            : input.anonVisitorId
                ? database_1.default.qrScanLog.count({
                    where: {
                        qrCodeId: input.qrCodeId,
                        anonVisitorId: input.anonVisitorId,
                    },
                })
                : Promise.resolve(0),
    ]);
    const locationCounts = new Map();
    for (const row of recentLogs) {
        const label = String(row.locationName || "").trim() ||
            [String(row.locationCity || "").trim(), String(row.locationCountry || "").trim()]
                .filter(Boolean)
                .join(", ") ||
            String(row.locationCountry || "").trim() ||
            "Unknown";
        locationCounts.set(label, (locationCounts.get(label) || 0) + 1);
    }
    const topLocations = Array.from(locationCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([label, count]) => ({ label, count }));
    return {
        totalScans: input.totalScans,
        firstScanAt: insight.firstScanAt,
        firstScanLocation: insight.firstScanLocation,
        lastScanAt: insight.latestScanAt,
        lastScanLocation: insight.latestScanLocation,
        previousScanAt: insight.previousScanAt,
        previousScanLocation: insight.previousScanLocation,
        verifiedByYouCount,
        topLocations,
    };
};
exports.buildScanHistorySummary = buildScanHistorySummary;
//# sourceMappingURL=scanHistorySummaryService.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getQrTrackingAnalyticsController = exports.getBatchSummary = exports.getScanLogs = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const locationService_1 = require("../services/locationService");
const qrTrackingAnalyticsService_1 = require("../services/qrTrackingAnalyticsService");
const manufacturerScopeService_1 = require("../services/manufacturerScopeService");
const getScanLogs = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.LICENSEE_ADMIN &&
            req.user.role !== client_1.UserRole.ORG_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER &&
            req.user.role !== client_1.UserRole.MANUFACTURER_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER_USER) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const prismaAny = database_1.default;
        if (!prismaAny.qrScanLog) {
            return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
        }
        const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 1000);
        const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;
        const scope = await (0, manufacturerScopeService_1.resolveScopedLicenseeAccess)(req.user, req.query.licenseeId || null);
        const licenseeId = scope.scopeLicenseeId || undefined;
        const batchId = req.query.batchId || undefined;
        const code = req.query.code?.trim() || undefined;
        const statusRaw = String(req.query.status || "").trim().toUpperCase();
        const validStatuses = new Set(["DORMANT", "ACTIVE", "ALLOCATED", "ACTIVATED", "PRINTED", "REDEEMED", "BLOCKED", "SCANNED"]);
        const status = statusRaw && validStatuses.has(statusRaw) ? statusRaw : undefined;
        const onlyFirstScanRaw = String(req.query.onlyFirstScan || "").trim().toLowerCase();
        const onlyFirstScan = onlyFirstScanRaw === "true" ? true : onlyFirstScanRaw === "false" ? false : undefined;
        const from = req.query.from || undefined;
        const to = req.query.to || undefined;
        const where = {};
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (batchId)
            where.batchId = batchId;
        if (code)
            where.code = { contains: code, mode: "insensitive" };
        if (status)
            where.status = status;
        if (onlyFirstScan != null)
            where.isFirstScan = onlyFirstScan;
        if (from || to) {
            where.scannedAt = {};
            if (from)
                where.scannedAt.gte = new Date(from);
            if (to)
                where.scannedAt.lte = new Date(to);
        }
        if (req.user.role === client_1.UserRole.MANUFACTURER ||
            req.user.role === client_1.UserRole.MANUFACTURER_ADMIN ||
            req.user.role === client_1.UserRole.MANUFACTURER_USER) {
            where.batch = { manufacturerId: req.user.userId };
        }
        const [logs, total] = await Promise.all([
            database_1.default.qrScanLog.findMany({
                where,
                orderBy: { scannedAt: "desc" },
                take: limit,
                skip: offset,
                include: {
                    licensee: { select: { id: true, name: true, prefix: true } },
                    qrCode: { select: { id: true, code: true, status: true } },
                },
            }),
            database_1.default.qrScanLog.count({ where }),
        ]);
        let geocodeBudget = 40;
        const enrichedLogs = await Promise.all(logs.map(async (log) => {
            let fallback = null;
            const hasNamedLocation = Boolean(log.locationName) ||
                Boolean(log.locationCity) ||
                Boolean(log.locationRegion) ||
                Boolean(log.locationCountry);
            if (!hasNamedLocation && geocodeBudget > 0 && log.latitude != null && log.longitude != null) {
                geocodeBudget -= 1;
                fallback = await (0, locationService_1.reverseGeocode)(log.latitude ?? null, log.longitude ?? null);
            }
            return {
                ...log,
                locationName: log.locationName ||
                    [log.locationCity, log.locationRegion, log.locationCountry].filter(Boolean).join(", ") ||
                    fallback?.name ||
                    null,
                deviceLabel: (0, locationService_1.compactDeviceLabel)(log.userAgent || log.device || null),
            };
        }));
        return res.json({ success: true, data: { logs: enrichedLogs, total, limit, offset } });
    }
    catch (e) {
        console.error("getScanLogs error:", e);
        if (e instanceof client_1.Prisma.PrismaClientKnownRequestError && e.code === "P2021") {
            return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
        }
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getScanLogs = getScanLogs;
const getBatchSummary = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.LICENSEE_ADMIN &&
            req.user.role !== client_1.UserRole.ORG_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER &&
            req.user.role !== client_1.UserRole.MANUFACTURER_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER_USER) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const scope = await (0, manufacturerScopeService_1.resolveScopedLicenseeAccess)(req.user, req.query.licenseeId || null);
        const licenseeId = scope.scopeLicenseeId || undefined;
        const manufacturerId = req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN
            ? req.query.manufacturerId || undefined
            : undefined;
        const whereBatch = {};
        if (licenseeId)
            whereBatch.licenseeId = licenseeId;
        if (manufacturerId)
            whereBatch.manufacturerId = manufacturerId;
        if (req.user.role === client_1.UserRole.MANUFACTURER ||
            req.user.role === client_1.UserRole.MANUFACTURER_ADMIN ||
            req.user.role === client_1.UserRole.MANUFACTURER_USER) {
            whereBatch.manufacturerId = req.user.userId;
        }
        const batches = await database_1.default.batch.findMany({
            where: whereBatch,
            orderBy: { createdAt: "desc" },
            select: { id: true, name: true, licenseeId: true, startCode: true, endCode: true, totalCodes: true, createdAt: true },
        });
        if (batches.length === 0) {
            return res.json({ success: true, data: [] });
        }
        const batchIds = batches.map((b) => b.id);
        const grouped = await database_1.default.qRCode.groupBy({
            by: ["batchId", "status"],
            where: { batchId: { in: batchIds } },
            _count: { _all: true },
        });
        const map = new Map();
        for (const g of grouped) {
            if (!g.batchId)
                continue;
            const current = map.get(g.batchId) || {};
            current[g.status] = g._count?._all || 0;
            map.set(g.batchId, current);
        }
        const data = batches.map((b) => ({
            ...b,
            counts: map.get(b.id) || {},
        }));
        return res.json({ success: true, data });
    }
    catch (e) {
        console.error("getBatchSummary error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getBatchSummary = getBatchSummary;
const getQrTrackingAnalyticsController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.LICENSEE_ADMIN &&
            req.user.role !== client_1.UserRole.ORG_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER &&
            req.user.role !== client_1.UserRole.MANUFACTURER_ADMIN &&
            req.user.role !== client_1.UserRole.MANUFACTURER_USER) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parseDate = (value) => {
            const raw = String(value || "").trim();
            if (!raw)
                return undefined;
            const date = new Date(raw);
            return Number.isFinite(date.getTime()) ? date : undefined;
        };
        const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 500);
        const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;
        const scope = await (0, manufacturerScopeService_1.resolveScopedLicenseeAccess)(req.user, req.query.licenseeId || null);
        const licenseeId = scope.scopeLicenseeId || undefined;
        const statusRaw = String(req.query.status || "").trim().toUpperCase();
        const validStatuses = new Set(["DORMANT", "ACTIVE", "ALLOCATED", "ACTIVATED", "PRINTED", "REDEEMED", "BLOCKED", "SCANNED"]);
        const status = validStatuses.has(statusRaw) ? statusRaw : undefined;
        const onlyFirstScanRaw = String(req.query.onlyFirstScan || "").trim().toLowerCase();
        const firstScan = onlyFirstScanRaw === "true" ? true : onlyFirstScanRaw === "false" ? false : undefined;
        const manufacturerId = req.user.role === client_1.UserRole.MANUFACTURER ||
            req.user.role === client_1.UserRole.MANUFACTURER_ADMIN ||
            req.user.role === client_1.UserRole.MANUFACTURER_USER
            ? req.user.userId
            : undefined;
        const data = await (0, qrTrackingAnalyticsService_1.getQrTrackingAnalytics)({
            licenseeId,
            manufacturerId,
            batchQuery: String(req.query.batchQuery || req.query.batchId || req.query.batchName || "").trim() || undefined,
            code: String(req.query.code || "").trim() || undefined,
            status,
            firstScan,
            from: parseDate(req.query.from),
            to: parseDate(req.query.to),
            limit,
            offset,
        });
        return res.json({ success: true, data });
    }
    catch (error) {
        console.error("getQrTrackingAnalyticsController error:", error);
        if (error instanceof client_1.Prisma.PrismaClientKnownRequestError && error.code === "P2021") {
            return res.json({
                success: true,
                data: {
                    scope: {
                        mode: "inventory",
                        title: "Inventory scope",
                        description: "Tracking analytics are unavailable until the scan log tables are ready.",
                        quantities: { distinctCodes: 0, scanEvents: 0, matchedBatches: 0 },
                    },
                    totals: { total: 0, dormant: 0, allocated: 0, printed: 0, redeemed: 0, blocked: 0, created: 0 },
                    trend: [],
                    batches: [],
                    logs: [],
                    pagination: { total: 0, limit: 0, offset: 0 },
                    supportedStatuses: [],
                },
            });
        }
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getQrTrackingAnalyticsController = getQrTrackingAnalyticsController;
//# sourceMappingURL=qrLogController.js.map
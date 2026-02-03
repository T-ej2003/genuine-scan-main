"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getBatchSummary = exports.getScanLogs = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const getScanLogs = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 1000);
        const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;
        const licenseeId = req.query.licenseeId || undefined;
        const batchId = req.query.batchId || undefined;
        const productBatchId = req.query.productBatchId || undefined;
        const code = req.query.code?.trim() || undefined;
        const where = {};
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (batchId)
            where.batchId = batchId;
        if (productBatchId)
            where.productBatchId = productBatchId;
        if (code)
            where.code = { contains: code, mode: "insensitive" };
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
        return res.json({ success: true, data: { logs, total, limit, offset } });
    }
    catch (e) {
        console.error("getScanLogs error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getScanLogs = getScanLogs;
const getBatchSummary = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const licenseeId = req.query.licenseeId || undefined;
        const whereBatch = {};
        if (licenseeId)
            whereBatch.licenseeId = licenseeId;
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
//# sourceMappingURL=qrLogController.js.map
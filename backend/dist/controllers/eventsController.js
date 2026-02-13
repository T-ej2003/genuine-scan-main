"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.dashboardEvents = void 0;
const database_1 = __importDefault(require("../config/database"));
const tenantIsolation_1 = require("../middleware/tenantIsolation");
const auditService_1 = require("../services/auditService");
const client_1 = require("@prisma/client");
function writeSse(res, event, data) {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
}
async function computeDashboard(req) {
    if (!req.user)
        throw new Error("Not authenticated");
    const role = req.user.role;
    const userId = req.user.userId;
    const scopedLicenseeId = (0, tenantIsolation_1.getEffectiveLicenseeId)(req);
    const qrWhere = {};
    const batchWhere = {};
    const manufacturersWhere = {
        role: client_1.UserRole.MANUFACTURER,
        isActive: true,
    };
    if (role === client_1.UserRole.MANUFACTURER) {
        batchWhere.manufacturerId = userId;
        qrWhere.batch = { manufacturerId: userId };
        manufacturersWhere.id = userId;
    }
    else if (scopedLicenseeId) {
        qrWhere.licenseeId = scopedLicenseeId;
        batchWhere.licenseeId = scopedLicenseeId;
        manufacturersWhere.licenseeId = scopedLicenseeId;
    }
    const [totalQRCodes, totalBatches, manufacturers, activeLicensees, qrGrouped, qrTotal] = await Promise.all([
        database_1.default.qRCode.count({ where: qrWhere }),
        database_1.default.batch.count({ where: batchWhere }),
        database_1.default.user.count({ where: manufacturersWhere }),
        role === client_1.UserRole.SUPER_ADMIN
            ? database_1.default.licensee.count({ where: { isActive: true } })
            : scopedLicenseeId
                ? database_1.default.licensee.count({ where: { id: scopedLicenseeId, isActive: true } })
                : 0,
        database_1.default.qRCode.groupBy({
            by: ["status"],
            where: qrWhere,
            _count: true,
        }),
        database_1.default.qRCode.count({ where: qrWhere }),
    ]);
    const byStatus = qrGrouped.reduce((acc, s) => {
        acc[s.status] = s._count;
        return acc;
    }, {});
    return {
        totalQRCodes,
        activeLicensees,
        manufacturers,
        totalBatches,
        qr: { total: qrTotal, byStatus },
    };
}
/**
 * SSE stream for dashboard updates.
 * Use EventSource in frontend:
 *   new EventSource(`${API}/api/events/dashboard?token=${token}`)
 */
const dashboardEvents = async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ success: false, error: "Not authenticated" });
        }
        // SSE headers
        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache, no-transform");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders?.();
        // Send initial payload
        const initial = await computeDashboard(req);
        writeSse(res, "stats", initial);
        const scopedLicenseeId = (0, tenantIsolation_1.getEffectiveLicenseeId)(req);
        const role = req.user.role;
        // Keepalive ping (prevents proxies killing connection)
        const keepAlive = setInterval(() => {
            res.write(": ping\n\n");
        }, 25000);
        // Listen for audit log emits (in-process)
        const off = (0, auditService_1.onAuditLog)(async (log) => {
            try {
                // Tenant filter
                if (role !== client_1.UserRole.SUPER_ADMIN) {
                    if (!scopedLicenseeId)
                        return;
                    if (log.licenseeId !== scopedLicenseeId)
                        return;
                }
                else {
                    // super admin can optionally scope via ?licenseeId= (supported by getEffectiveLicenseeId)
                    if (scopedLicenseeId && log.licenseeId !== scopedLicenseeId)
                        return;
                }
                writeSse(res, "audit", log);
                // also send fresh stats
                const fresh = await computeDashboard(req);
                writeSse(res, "stats", fresh);
            }
            catch (e) {
                // ignore single event errors
            }
        });
        req.on("close", () => {
            clearInterval(keepAlive);
            off();
            res.end();
        });
    }
    catch (err) {
        console.error("dashboardEvents error:", err);
        return res.status(500).end();
    }
};
exports.dashboardEvents = dashboardEvents;
//# sourceMappingURL=eventsController.js.map
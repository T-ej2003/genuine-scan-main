"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.patchIrAlert = exports.listIrAlerts = void 0;
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const notificationService_1 = require("../services/notificationService");
const paginationSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(200).default(50),
    offset: zod_1.z.coerce.number().int().min(0).default(0),
});
const patchAlertSchema = zod_1.z
    .object({
    acknowledged: zod_1.z.boolean().optional(),
    incidentId: zod_1.z.string().uuid().nullable().optional(),
})
    .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });
const listIrAlerts = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const paged = paginationSchema.safeParse(req.query || {});
        if (!paged.success)
            return res.status(400).json({ success: false, error: "Invalid pagination" });
        const licenseeId = String(req.query.licenseeId || "").trim() || undefined;
        const alertTypeRaw = String(req.query.alertType || "").trim().toUpperCase();
        const severityRaw = String(req.query.severity || "").trim().toUpperCase();
        const acknowledgedRaw = String(req.query.acknowledged || "").trim().toLowerCase();
        const policyRuleId = String(req.query.policyRuleId || "").trim() || undefined;
        const qrCodeId = String(req.query.qrCodeId || "").trim() || undefined;
        const batchId = String(req.query.batchId || "").trim() || undefined;
        const manufacturerId = String(req.query.manufacturerId || "").trim() || undefined;
        const where = {};
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (alertTypeRaw && (alertTypeRaw in client_1.PolicyAlertType))
            where.alertType = alertTypeRaw;
        if (severityRaw && (severityRaw in client_1.AlertSeverity))
            where.severity = severityRaw;
        if (policyRuleId)
            where.policyRuleId = policyRuleId;
        if (qrCodeId)
            where.qrCodeId = qrCodeId;
        if (batchId)
            where.batchId = batchId;
        if (manufacturerId)
            where.manufacturerId = manufacturerId;
        if (acknowledgedRaw === "true")
            where.acknowledgedAt = { not: null };
        if (acknowledgedRaw === "false")
            where.acknowledgedAt = null;
        const [alerts, total] = await Promise.all([
            database_1.default.policyAlert.findMany({
                where,
                orderBy: [{ createdAt: "desc" }],
                take: paged.data.limit,
                skip: paged.data.offset,
                include: {
                    licensee: { select: { id: true, name: true, prefix: true } },
                    policyRule: { select: { id: true, name: true, ruleType: true } },
                    qrCode: { select: { id: true, code: true } },
                    batch: { select: { id: true, name: true } },
                    manufacturer: { select: { id: true, name: true, email: true } },
                    acknowledgedByUser: { select: { id: true, name: true, email: true } },
                },
            }),
            database_1.default.policyAlert.count({ where }),
        ]);
        return res.json({ success: true, data: { alerts, total, limit: paged.data.limit, offset: paged.data.offset } });
    }
    catch (e) {
        console.error("listIrAlerts error:", e);
        return res.status(500).json({ success: false, error: "Failed to list alerts" });
    }
};
exports.listIrAlerts = listIrAlerts;
const patchIrAlert = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing alert id" });
        const parsed = patchAlertSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const existing = await database_1.default.policyAlert.findUnique({
            where: { id },
            select: { id: true, licenseeId: true },
        });
        if (!existing)
            return res.status(404).json({ success: false, error: "Alert not found" });
        const data = {};
        if (parsed.data.acknowledged !== undefined) {
            if (parsed.data.acknowledged) {
                data.acknowledgedAt = new Date();
                data.acknowledgedByUserId = req.user.userId;
            }
            else {
                data.acknowledgedAt = null;
                data.acknowledgedByUserId = null;
            }
        }
        if (parsed.data.incidentId !== undefined) {
            data.incidentId = parsed.data.incidentId;
        }
        const updated = await database_1.default.policyAlert.update({
            where: { id },
            data,
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: existing.licenseeId,
            action: "POLICY_ALERT_UPDATED",
            entityType: "PolicyAlert",
            entityId: id,
            details: { changedFields: Object.keys(parsed.data) },
            ipAddress: req.ip,
        });
        await Promise.all([
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.SUPER_ADMIN,
                type: "policy_alert_updated",
                title: "Policy alert updated",
                body: `Alert ${updated.id.slice(0, 8)} metadata was updated.`,
                incidentId: updated.incidentId || null,
                data: {
                    alertId: updated.id,
                    licenseeId: existing.licenseeId,
                    changedFields: Object.keys(parsed.data),
                    targetRoute: "/ir",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.LICENSEE_ADMIN,
                licenseeId: existing.licenseeId,
                type: "policy_alert_updated",
                title: "Policy alert updated",
                body: `Alert ${updated.id.slice(0, 8)} has new acknowledgement/incident linkage.`,
                incidentId: updated.incidentId || null,
                data: {
                    alertId: updated.id,
                    licenseeId: existing.licenseeId,
                    changedFields: Object.keys(parsed.data),
                    targetRoute: "/ir",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
        ]);
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("patchIrAlert error:", e);
        return res.status(500).json({ success: false, error: "Failed to update alert" });
    }
};
exports.patchIrAlert = patchIrAlert;
//# sourceMappingURL=irAlertController.js.map
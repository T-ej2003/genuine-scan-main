"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.exportBatchAuditPackageController = exports.acknowledgePolicyAlertController = exports.getPolicyAlertsController = exports.updatePolicyConfigController = exports.getPolicyConfigController = exports.getRiskAnalyticsController = exports.getBatchSlaAnalyticsController = exports.getTraceTimelineController = void 0;
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const traceEventService_1 = require("../services/traceEventService");
const analyticsService_1 = require("../services/analyticsService");
const policyEngineService_1 = require("../services/policyEngineService");
const auditService_1 = require("../services/auditService");
const immutableAuditExportService_1 = require("../services/immutableAuditExportService");
const policyUpdateSchema = zod_1.z
    .object({
    licenseeId: zod_1.z.string().uuid().optional(),
    autoBlockEnabled: zod_1.z.boolean().optional(),
    autoBlockBatchOnVelocity: zod_1.z.boolean().optional(),
    multiScanThreshold: zod_1.z.number().int().min(2).max(100).optional(),
    geoDriftThresholdKm: zod_1.z.number().min(1).max(20000).optional(),
    velocitySpikeThresholdPerMin: zod_1.z.number().int().min(1).max(10000).optional(),
    stuckBatchHours: zod_1.z.number().int().min(1).max(24 * 365).optional(),
})
    .refine((d) => d.autoBlockEnabled !== undefined ||
    d.autoBlockBatchOnVelocity !== undefined ||
    d.multiScanThreshold !== undefined ||
    d.geoDriftThresholdKm !== undefined ||
    d.velocitySpikeThresholdPerMin !== undefined ||
    d.stuckBatchHours !== undefined, { message: "Provide at least one policy field to update." });
const asInt = (value, fallback, min, max) => {
    const n = Number.parseInt(String(value ?? ""), 10);
    if (!Number.isFinite(n))
        return fallback;
    return Math.min(Math.max(n, min), max);
};
const asOptionalString = (value) => {
    if (typeof value !== "string")
        return undefined;
    const s = value.trim();
    return s || undefined;
};
const asOptionalBool = (value) => {
    if (typeof value === "boolean")
        return value;
    if (typeof value !== "string")
        return undefined;
    const v = value.trim().toLowerCase();
    if (v === "true" || v === "1")
        return true;
    if (v === "false" || v === "0")
        return false;
    return undefined;
};
const resolveScopedLicenseeId = (req) => {
    if (!req.user)
        return undefined;
    if (req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN) {
        return asOptionalString(req.query.licenseeId) || undefined;
    }
    return req.user.licenseeId || undefined;
};
const requirePolicyLicenseeId = (req, bodyLicenseeId) => {
    if (!req.user)
        return null;
    if (req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN) {
        return bodyLicenseeId || asOptionalString(req.query.licenseeId) || undefined;
    }
    return req.user.licenseeId || undefined;
};
const getTraceTimelineController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const limit = asInt(req.query.limit, 50, 1, 200);
        const offset = asInt(req.query.offset, 0, 0, 100000);
        const licenseeId = resolveScopedLicenseeId(req);
        const rawEventType = asOptionalString(req.query.eventType);
        let eventType;
        if (rawEventType) {
            const normalized = rawEventType.toUpperCase();
            if (!(normalized in client_1.TraceEventType)) {
                return res.status(400).json({ success: false, error: "Invalid eventType" });
            }
            eventType = normalized;
        }
        let manufacturerId = asOptionalString(req.query.manufacturerId);
        if (req.user.role === client_1.UserRole.MANUFACTURER ||
            req.user.role === client_1.UserRole.MANUFACTURER_ADMIN ||
            req.user.role === client_1.UserRole.MANUFACTURER_USER) {
            manufacturerId = req.user.userId;
        }
        await (0, traceEventService_1.backfillTraceEventsFromAuditLogs)({
            licenseeId,
            limit: 2500,
        });
        const result = await (0, traceEventService_1.getTraceTimeline)({
            licenseeId,
            eventType,
            batchId: asOptionalString(req.query.batchId),
            manufacturerId,
            qrCodeId: asOptionalString(req.query.qrCodeId),
            limit,
            offset,
        });
        return res.json({
            success: true,
            data: {
                events: result.events,
                total: result.total,
                limit,
                offset,
            },
        });
    }
    catch (e) {
        console.error("getTraceTimelineController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getTraceTimelineController = getTraceTimelineController;
const getBatchSlaAnalyticsController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const licenseeId = resolveScopedLicenseeId(req);
        const limit = asInt(req.query.limit, 200, 1, 2000);
        const stuckBatchHoursRaw = req.query.stuckBatchHours;
        const stuckBatchHours = stuckBatchHoursRaw != null ? asInt(stuckBatchHoursRaw, 24, 1, 24 * 365) : undefined;
        const data = await (0, analyticsService_1.getBatchSlaAnalytics)({ licenseeId, limit, stuckBatchHours });
        return res.json({ success: true, data });
    }
    catch (e) {
        console.error("getBatchSlaAnalyticsController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getBatchSlaAnalyticsController = getBatchSlaAnalyticsController;
const getRiskAnalyticsController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const licenseeId = resolveScopedLicenseeId(req);
        const limit = asInt(req.query.limit, 20, 1, 200);
        const lookbackHours = asInt(req.query.lookbackHours, 24, 1, 24 * 30);
        const data = await (0, analyticsService_1.getRiskAnalytics)({ licenseeId, lookbackHours, limit });
        return res.json({ success: true, data });
    }
    catch (e) {
        console.error("getRiskAnalyticsController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getRiskAnalyticsController = getRiskAnalyticsController;
const getPolicyConfigController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const licenseeId = requirePolicyLicenseeId(req);
        if (!licenseeId) {
            return res.json({
                success: true,
                data: {
                    id: "UNSCOPED_DEFAULT",
                    licenseeId: null,
                    autoBlockEnabled: true,
                    autoBlockBatchOnVelocity: false,
                    multiScanThreshold: 2,
                    geoDriftThresholdKm: 300,
                    velocitySpikeThresholdPerMin: 80,
                    stuckBatchHours: 24,
                    readonly: true,
                },
            });
        }
        const policy = await (0, policyEngineService_1.getOrCreateSecurityPolicy)(licenseeId);
        return res.json({ success: true, data: policy });
    }
    catch (e) {
        console.error("getPolicyConfigController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getPolicyConfigController = getPolicyConfigController;
const updatePolicyConfigController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = policyUpdateSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const licenseeId = requirePolicyLicenseeId(req, parsed.data.licenseeId);
        if (!licenseeId) {
            return res
                .status(400)
                .json({ success: false, error: "licenseeId is required for super admin policy updates" });
        }
        const { licenseeId: _ignore, ...updateFields } = parsed.data;
        const policy = await database_1.default.securityPolicy.upsert({
            where: { licenseeId },
            update: updateFields,
            create: {
                licenseeId,
                ...updateFields,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId,
            action: "UPDATE_SECURITY_POLICY",
            entityType: "SecurityPolicy",
            entityId: policy.id,
            details: {
                updated: updateFields,
            },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: policy });
    }
    catch (e) {
        console.error("updatePolicyConfigController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.updatePolicyConfigController = updatePolicyConfigController;
const getPolicyAlertsController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const licenseeId = resolveScopedLicenseeId(req);
        const limit = asInt(req.query.limit, 50, 1, 500);
        const offset = asInt(req.query.offset, 0, 0, 100000);
        const acknowledged = asOptionalBool(req.query.acknowledged);
        const rawType = asOptionalString(req.query.alertType);
        const rawSeverity = asOptionalString(req.query.severity);
        let alertType;
        if (rawType) {
            const normalized = rawType.toUpperCase();
            if (!(normalized in client_1.PolicyAlertType)) {
                return res.status(400).json({ success: false, error: "Invalid alertType" });
            }
            alertType = normalized;
        }
        let severity;
        if (rawSeverity) {
            const normalized = rawSeverity.toUpperCase();
            if (!(normalized in client_1.AlertSeverity)) {
                return res.status(400).json({ success: false, error: "Invalid severity" });
            }
            severity = normalized;
        }
        const where = {};
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (alertType)
            where.alertType = alertType;
        if (severity)
            where.severity = severity;
        if (acknowledged === true)
            where.acknowledgedAt = { not: null };
        if (acknowledged === false)
            where.acknowledgedAt = null;
        const [alerts, total] = await Promise.all([
            database_1.default.policyAlert.findMany({
                where,
                orderBy: [{ createdAt: "desc" }, { id: "desc" }],
                take: limit,
                skip: offset,
                include: {
                    batch: { select: { id: true, name: true } },
                    manufacturer: { select: { id: true, name: true, email: true } },
                    qrCode: { select: { id: true, code: true } },
                    acknowledgedByUser: { select: { id: true, name: true, email: true } },
                },
            }),
            database_1.default.policyAlert.count({ where }),
        ]);
        return res.json({
            success: true,
            data: {
                alerts,
                total,
                limit,
                offset,
            },
        });
    }
    catch (e) {
        console.error("getPolicyAlertsController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getPolicyAlertsController = getPolicyAlertsController;
const acknowledgePolicyAlertController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Invalid alert id" });
        const licenseeId = resolveScopedLicenseeId(req);
        const existing = await database_1.default.policyAlert.findFirst({
            where: {
                id,
                ...(licenseeId ? { licenseeId } : {}),
            },
            select: { id: true, licenseeId: true, acknowledgedAt: true },
        });
        if (!existing) {
            return res.status(404).json({ success: false, error: "Alert not found" });
        }
        const updated = await database_1.default.policyAlert.update({
            where: { id: existing.id },
            data: {
                acknowledgedAt: existing.acknowledgedAt || new Date(),
                acknowledgedByUserId: req.user.userId,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: updated.licenseeId,
            action: "ACKNOWLEDGE_POLICY_ALERT",
            entityType: "PolicyAlert",
            entityId: updated.id,
            details: {
                alertType: updated.alertType,
                severity: updated.severity,
            },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("acknowledgePolicyAlertController error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.acknowledgePolicyAlertController = acknowledgePolicyAlertController;
const exportBatchAuditPackageController = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const batchId = String(req.params.id || "").trim();
        if (!batchId)
            return res.status(400).json({ success: false, error: "Invalid batch id" });
        const batch = await database_1.default.batch.findUnique({
            where: { id: batchId },
            select: { id: true, licenseeId: true },
        });
        if (!batch)
            return res.status(404).json({ success: false, error: "Batch not found" });
        if (req.user.role !== client_1.UserRole.SUPER_ADMIN &&
            req.user.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN &&
            req.user.licenseeId !== batch.licenseeId) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const pkg = await (0, immutableAuditExportService_1.buildImmutableBatchAuditPackage)(batch.id);
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: batch.licenseeId,
            action: "EXPORT_IMMUTABLE_AUDIT_PACKAGE",
            entityType: "Batch",
            entityId: batch.id,
            details: pkg.metadata,
            ipAddress: req.ip,
        });
        res.setHeader("Content-Type", "application/zip");
        res.setHeader("Content-Disposition", `attachment; filename="${pkg.fileName}"`);
        res.setHeader("X-Audit-Integrity-Hash", String(pkg.metadata.integrityHash || ""));
        return res.status(200).send(pkg.buffer);
    }
    catch (e) {
        console.error("exportBatchAuditPackageController error:", e);
        return res.status(500).json({ success: false, error: e?.message || "Internal server error" });
    }
};
exports.exportBatchAuditPackageController = exportBatchAuditPackageController;
//# sourceMappingURL=tracePolicyController.js.map
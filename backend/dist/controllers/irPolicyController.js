"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.patchIrPolicy = exports.createIrPolicy = exports.listIrPolicies = void 0;
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const paginationSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(200).default(50),
    offset: zod_1.z.coerce.number().int().min(0).default(0),
});
const createPolicyRuleSchema = zod_1.z.object({
    name: zod_1.z.string().trim().min(3).max(120),
    description: zod_1.z.string().trim().max(500).optional(),
    ruleType: zod_1.z.nativeEnum(client_1.PolicyRuleType),
    isActive: zod_1.z.boolean().optional(),
    threshold: zod_1.z.number().int().min(1).max(100000),
    windowMinutes: zod_1.z.number().int().min(1).max(60 * 24 * 30),
    severity: zod_1.z.nativeEnum(client_1.AlertSeverity).optional(),
    autoCreateIncident: zod_1.z.boolean().optional(),
    incidentSeverity: zod_1.z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
    incidentPriority: zod_1.z.enum(["P1", "P2", "P3", "P4"]).optional(),
    licenseeId: zod_1.z.string().uuid().optional(),
    manufacturerId: zod_1.z.string().uuid().optional(),
    actionConfig: zod_1.z.any().optional(),
});
const updatePolicyRuleSchema = createPolicyRuleSchema
    .partial()
    .extend({
    name: zod_1.z.string().trim().min(3).max(120).optional(),
    threshold: zod_1.z.number().int().min(1).max(100000).optional(),
    windowMinutes: zod_1.z.number().int().min(1).max(60 * 24 * 30).optional(),
})
    .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });
const listIrPolicies = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const paged = paginationSchema.safeParse(req.query || {});
        if (!paged.success)
            return res.status(400).json({ success: false, error: "Invalid pagination" });
        const licenseeId = String(req.query.licenseeId || "").trim() || undefined;
        const ruleTypeRaw = String(req.query.ruleType || "").trim().toUpperCase();
        const isActiveRaw = String(req.query.isActive || "").trim().toLowerCase();
        const where = {};
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (ruleTypeRaw && (ruleTypeRaw in client_1.PolicyRuleType))
            where.ruleType = ruleTypeRaw;
        if (isActiveRaw === "true" || isActiveRaw === "false")
            where.isActive = isActiveRaw === "true";
        const [rules, total] = await Promise.all([
            database_1.default.policyRule.findMany({
                where,
                orderBy: [{ updatedAt: "desc" }],
                take: paged.data.limit,
                skip: paged.data.offset,
                include: {
                    organization: { select: { id: true, name: true } },
                    licensee: { select: { id: true, name: true, prefix: true } },
                    createdByUser: { select: { id: true, email: true, name: true } },
                },
            }),
            database_1.default.policyRule.count({ where }),
        ]);
        return res.json({ success: true, data: { rules, total, limit: paged.data.limit, offset: paged.data.offset } });
    }
    catch (e) {
        console.error("listIrPolicies error:", e);
        return res.status(500).json({ success: false, error: "Failed to list policies" });
    }
};
exports.listIrPolicies = listIrPolicies;
const createIrPolicy = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = createPolicyRuleSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        let orgId = null;
        const licenseeId = parsed.data.licenseeId || null;
        if (licenseeId) {
            const licensee = await database_1.default.licensee.findUnique({ where: { id: licenseeId }, select: { orgId: true } });
            if (!licensee)
                return res.status(404).json({ success: false, error: "Licensee not found" });
            orgId = licensee.orgId || null;
        }
        const created = await database_1.default.policyRule.create({
            data: {
                name: parsed.data.name,
                description: parsed.data.description || null,
                ruleType: parsed.data.ruleType,
                isActive: parsed.data.isActive ?? true,
                threshold: parsed.data.threshold,
                windowMinutes: parsed.data.windowMinutes,
                severity: parsed.data.severity || client_1.AlertSeverity.MEDIUM,
                autoCreateIncident: parsed.data.autoCreateIncident ?? false,
                incidentSeverity: parsed.data.incidentSeverity || null,
                incidentPriority: parsed.data.incidentPriority || null,
                licenseeId,
                orgId,
                manufacturerId: parsed.data.manufacturerId || null,
                createdByUserId: req.user.userId,
                actionConfig: parsed.data.actionConfig ?? null,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: licenseeId || undefined,
            action: "POLICY_RULE_CREATED",
            entityType: "PolicyRule",
            entityId: created.id,
            details: {
                name: created.name,
                ruleType: created.ruleType,
                threshold: created.threshold,
                windowMinutes: created.windowMinutes,
                severity: created.severity,
                autoCreateIncident: created.autoCreateIncident,
                manufacturerId: created.manufacturerId,
            },
            ipAddress: req.ip,
        });
        return res.status(201).json({ success: true, data: created });
    }
    catch (e) {
        console.error("createIrPolicy error:", e);
        return res.status(500).json({ success: false, error: "Failed to create policy" });
    }
};
exports.createIrPolicy = createIrPolicy;
const patchIrPolicy = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing policy id" });
        const parsed = updatePolicyRuleSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const existing = await database_1.default.policyRule.findUnique({ where: { id }, select: { id: true, licenseeId: true } });
        if (!existing)
            return res.status(404).json({ success: false, error: "Policy not found" });
        const updated = await database_1.default.policyRule.update({
            where: { id },
            data: {
                ...parsed.data,
                description: parsed.data.description === undefined ? undefined : parsed.data.description || null,
                actionConfig: parsed.data.actionConfig === undefined ? undefined : parsed.data.actionConfig ?? null,
                manufacturerId: parsed.data.manufacturerId === undefined ? undefined : parsed.data.manufacturerId || null,
                licenseeId: parsed.data.licenseeId === undefined ? undefined : parsed.data.licenseeId || null,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: updated.licenseeId || existing.licenseeId || undefined,
            action: "POLICY_RULE_UPDATED",
            entityType: "PolicyRule",
            entityId: updated.id,
            details: { changedFields: Object.keys(parsed.data) },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("patchIrPolicy error:", e);
        return res.status(500).json({ success: false, error: "Failed to update policy" });
    }
};
exports.patchIrPolicy = patchIrPolicy;
//# sourceMappingURL=irPolicyController.js.map
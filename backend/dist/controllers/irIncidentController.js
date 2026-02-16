"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendIrIncidentCommunication = exports.applyIrIncidentAction = exports.addIrIncidentEvent = exports.patchIrIncident = exports.getIrIncident = exports.createIrIncident = exports.listIrIncidents = void 0;
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const incidentService_1 = require("../services/incidentService");
const incidentEmailService_1 = require("../services/incidentEmailService");
const incidentActionsService_1 = require("../services/ir/incidentActionsService");
const paginationSchema = zod_1.z.object({
    limit: zod_1.z.coerce.number().int().min(1).max(200).default(50),
    offset: zod_1.z.coerce.number().int().min(0).default(0),
});
const listIncidentsQuerySchema = zod_1.z.object({
    status: zod_1.z.string().trim().optional(),
    severity: zod_1.z.string().trim().optional(),
    priority: zod_1.z.string().trim().optional(),
    licenseeId: zod_1.z.string().trim().optional(),
    manufacturerId: zod_1.z.string().trim().optional(),
    qr: zod_1.z.string().trim().optional(),
    search: zod_1.z.string().trim().optional(),
    date_from: zod_1.z.string().trim().optional(),
    date_to: zod_1.z.string().trim().optional(),
    assigned_to: zod_1.z.string().trim().optional(),
});
const createIncidentSchema = zod_1.z.object({
    qrCodeValue: zod_1.z.string().trim().min(2).max(128),
    incidentType: zod_1.z.nativeEnum(client_1.IncidentType),
    severity: zod_1.z.nativeEnum(client_1.IncidentSeverity).optional(),
    priority: zod_1.z.nativeEnum(client_1.IncidentPriority).optional(),
    description: zod_1.z.string().trim().min(6).max(2000),
    licenseeId: zod_1.z.string().uuid().optional(),
    tags: zod_1.z.array(zod_1.z.string().trim().min(1).max(40)).max(10).optional(),
});
const patchIncidentSchema = zod_1.z
    .object({
    status: zod_1.z.nativeEnum(client_1.IncidentStatus).optional(),
    severity: zod_1.z.nativeEnum(client_1.IncidentSeverity).optional(),
    priority: zod_1.z.nativeEnum(client_1.IncidentPriority).optional(),
    assignedToUserId: zod_1.z.string().uuid().nullable().optional(),
    internalNotes: zod_1.z.string().trim().max(5000).nullable().optional(),
    tags: zod_1.z.array(zod_1.z.string().trim().min(1).max(40)).max(20).optional(),
    resolutionSummary: zod_1.z.string().trim().max(3000).nullable().optional(),
    resolutionOutcome: zod_1.z.nativeEnum(client_1.IncidentResolutionOutcome).nullable().optional(),
})
    .refine((val) => Object.keys(val).length > 0, { message: "No fields provided" });
const noteSchema = zod_1.z.object({
    note: zod_1.z.string().trim().min(2).max(4000),
});
const actionSchema = zod_1.z.object({
    action: zod_1.z.enum([
        "FLAG_QR_UNDER_INVESTIGATION",
        "UNFLAG_QR_UNDER_INVESTIGATION",
        "SUSPEND_BATCH",
        "REINSTATE_BATCH",
        "SUSPEND_ORG",
        "REINSTATE_ORG",
        "SUSPEND_MANUFACTURER_USERS",
        "REINSTATE_MANUFACTURER_USERS",
    ]),
    reason: zod_1.z.string().trim().min(3).max(600),
    qrCodeId: zod_1.z.string().uuid().optional(),
    batchId: zod_1.z.string().uuid().optional(),
    licenseeId: zod_1.z.string().uuid().optional(),
    manufacturerUserIds: zod_1.z.array(zod_1.z.string().uuid()).optional(),
});
const commSchema = zod_1.z.object({
    recipient: zod_1.z.enum(["reporter", "org_admin"]).optional(),
    toAddress: zod_1.z.string().trim().email().optional(),
    subject: zod_1.z.string().trim().min(3).max(200),
    message: zod_1.z.string().trim().min(1).max(5000),
    template: zod_1.z.string().trim().max(80).optional(),
    senderMode: zod_1.z.enum(["actor", "system"]).optional(),
});
const normalizeCode = (value) => String(value || "").trim().toUpperCase();
const listIrIncidents = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const paged = paginationSchema.safeParse(req.query || {});
        if (!paged.success)
            return res.status(400).json({ success: false, error: "Invalid pagination" });
        const queryParsed = listIncidentsQuerySchema.safeParse(req.query || {});
        if (!queryParsed.success)
            return res.status(400).json({ success: false, error: "Invalid filters" });
        const status = (0, incidentService_1.sanitizeIncidentStatus)(queryParsed.data.status || "") || undefined;
        const severity = (0, incidentService_1.sanitizeIncidentSeverity)(queryParsed.data.severity || "") || undefined;
        const priorityRaw = String(queryParsed.data.priority || "").trim().toUpperCase();
        const priority = priorityRaw && (priorityRaw in client_1.IncidentPriority) ? priorityRaw : undefined;
        const licenseeId = String(queryParsed.data.licenseeId || "").trim() || undefined;
        const manufacturerId = String(queryParsed.data.manufacturerId || "").trim() || undefined;
        const qr = queryParsed.data.qr ? normalizeCode(queryParsed.data.qr) : undefined;
        const search = queryParsed.data.search ? String(queryParsed.data.search).trim() : undefined;
        const assignedTo = String(queryParsed.data.assigned_to || "").trim() || undefined;
        const dateFromRaw = String(queryParsed.data.date_from || "").trim();
        const dateToRaw = String(queryParsed.data.date_to || "").trim();
        const dateFrom = dateFromRaw ? new Date(dateFromRaw) : undefined;
        const dateTo = dateToRaw ? new Date(dateToRaw) : undefined;
        const where = {};
        if (status)
            where.status = status;
        if (severity)
            where.severity = severity;
        if (priority)
            where.priority = priority;
        if (assignedTo)
            where.assignedToUserId = assignedTo;
        if (licenseeId)
            where.licenseeId = licenseeId;
        if (qr)
            where.qrCodeValue = { contains: qr, mode: "insensitive" };
        if (manufacturerId) {
            where.OR = [
                { qrCode: { batch: { manufacturerId } } },
                { scanEvent: { batch: { manufacturerId } } },
            ];
        }
        if (dateFrom || dateTo) {
            where.createdAt = {};
            if (dateFrom && Number.isFinite(dateFrom.getTime()))
                where.createdAt.gte = dateFrom;
            if (dateTo && Number.isFinite(dateTo.getTime()))
                where.createdAt.lte = dateTo;
        }
        if (search) {
            const q = String(search).slice(0, 120);
            where.OR = [
                ...(Array.isArray(where.OR) ? where.OR : []),
                { qrCodeValue: { contains: q, mode: "insensitive" } },
                { description: { contains: q, mode: "insensitive" } },
                { customerEmail: { contains: q, mode: "insensitive" } },
                { customerPhone: { contains: q, mode: "insensitive" } },
                { productBatchNo: { contains: q, mode: "insensitive" } },
            ];
        }
        const [incidents, total] = await Promise.all([
            database_1.default.incident.findMany({
                where,
                orderBy: [{ createdAt: "desc" }],
                take: paged.data.limit,
                skip: paged.data.offset,
                include: {
                    licensee: { select: { id: true, name: true, prefix: true } },
                    assignedToUser: { select: { id: true, name: true, email: true } },
                    qrCode: { select: { id: true, code: true, underInvestigationAt: true } },
                },
            }),
            database_1.default.incident.count({ where }),
        ]);
        return res.json({
            success: true,
            data: {
                incidents,
                total,
                limit: paged.data.limit,
                offset: paged.data.offset,
            },
        });
    }
    catch (e) {
        console.error("listIrIncidents error:", e);
        return res.status(500).json({ success: false, error: "Failed to list incidents" });
    }
};
exports.listIrIncidents = listIrIncidents;
const createIrIncident = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const parsed = createIncidentSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const normalizedCode = normalizeCode(parsed.data.qrCodeValue);
        const qr = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: { id: true, licenseeId: true },
        });
        const licenseeId = parsed.data.licenseeId || qr?.licenseeId || null;
        if (!licenseeId)
            return res.status(400).json({ success: false, error: "licenseeId is required" });
        if (parsed.data.licenseeId && qr?.licenseeId && parsed.data.licenseeId !== qr.licenseeId) {
            return res.status(400).json({ success: false, error: "licenseeId does not match QR code tenant" });
        }
        const severity = parsed.data.severity || client_1.IncidentSeverity.MEDIUM;
        const priority = parsed.data.priority || client_1.IncidentPriority.P3;
        const created = await database_1.default.incident.create({
            data: {
                qrCodeId: qr?.id || null,
                qrCodeValue: normalizedCode,
                licenseeId,
                reportedBy: "ADMIN",
                incidentType: parsed.data.incidentType,
                severity,
                severityOverridden: true,
                priority,
                description: parsed.data.description,
                photos: [],
                tags: parsed.data.tags || [],
                status: client_1.IncidentStatus.NEW,
                slaDueAt: (0, incidentService_1.computeSlaDueAt)(severity),
            },
        });
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: created.id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.CREATED,
            eventPayload: { source: "ir_create" },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId,
            action: "IR_INCIDENT_CREATED",
            entityType: "Incident",
            entityId: created.id,
            details: { qrCodeValue: normalizedCode, incidentType: created.incidentType, severity, priority },
            ipAddress: req.ip,
        });
        return res.status(201).json({ success: true, data: created });
    }
    catch (e) {
        console.error("createIrIncident error:", e);
        return res.status(500).json({ success: false, error: "Failed to create incident" });
    }
};
exports.createIrIncident = createIrIncident;
const getIrIncident = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const incident = await database_1.default.incident.findUnique({
            where: { id },
            include: {
                licensee: { select: { id: true, name: true, prefix: true, supportEmail: true, supportPhone: true } },
                assignedToUser: { select: { id: true, name: true, email: true } },
                qrCode: {
                    select: {
                        id: true,
                        code: true,
                        underInvestigationAt: true,
                        underInvestigationReason: true,
                        batch: { select: { id: true, name: true, suspendedAt: true, suspendedReason: true, manufacturer: { select: { id: true, name: true, email: true } } } },
                    },
                },
                scanEvent: {
                    select: {
                        id: true,
                        scannedAt: true,
                        locationCountry: true,
                        locationCity: true,
                        batch: { select: { id: true, name: true, manufacturer: { select: { id: true, name: true, email: true } } } },
                    },
                },
                events: { orderBy: { createdAt: "asc" }, include: { actorUser: { select: { id: true, name: true, email: true } } } },
                communications: { orderBy: { createdAt: "desc" } },
                evidence: { orderBy: { createdAt: "desc" } },
                policyAlerts: { orderBy: { createdAt: "desc" }, take: 25 },
            },
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        return res.json({ success: true, data: incident });
    }
    catch (e) {
        console.error("getIrIncident error:", e);
        return res.status(500).json({ success: false, error: "Failed to load incident" });
    }
};
exports.getIrIncident = getIrIncident;
const patchIrIncident = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = patchIncidentSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const existing = await database_1.default.incident.findUnique({
            where: { id },
            select: {
                id: true,
                licenseeId: true,
                status: true,
                severity: true,
                priority: true,
                assignedToUserId: true,
                internalNotes: true,
                tags: true,
                resolutionSummary: true,
                resolutionOutcome: true,
            },
        });
        if (!existing)
            return res.status(404).json({ success: false, error: "Incident not found" });
        const updateData = {};
        const changedFields = [];
        if (parsed.data.status && parsed.data.status !== existing.status) {
            updateData.status = parsed.data.status;
            changedFields.push("status");
        }
        if (parsed.data.severity && parsed.data.severity !== existing.severity) {
            updateData.severity = parsed.data.severity;
            updateData.severityOverridden = true;
            updateData.slaDueAt = (0, incidentService_1.computeSlaDueAt)(parsed.data.severity);
            changedFields.push("severity");
        }
        if (parsed.data.priority && parsed.data.priority !== existing.priority) {
            updateData.priority = parsed.data.priority;
            changedFields.push("priority");
        }
        if (parsed.data.assignedToUserId !== undefined && parsed.data.assignedToUserId !== existing.assignedToUserId) {
            updateData.assignedToUserId = parsed.data.assignedToUserId || null;
            changedFields.push("assignedToUserId");
        }
        if (parsed.data.internalNotes !== undefined && parsed.data.internalNotes !== existing.internalNotes) {
            updateData.internalNotes = parsed.data.internalNotes || null;
            changedFields.push("internalNotes");
        }
        if (parsed.data.tags && JSON.stringify(parsed.data.tags) !== JSON.stringify(existing.tags || [])) {
            updateData.tags = parsed.data.tags;
            changedFields.push("tags");
        }
        if (parsed.data.resolutionSummary !== undefined && parsed.data.resolutionSummary !== existing.resolutionSummary) {
            updateData.resolutionSummary = parsed.data.resolutionSummary || null;
            changedFields.push("resolutionSummary");
        }
        if (parsed.data.resolutionOutcome !== undefined) {
            const next = (0, incidentService_1.sanitizeResolutionOutcome)(parsed.data.resolutionOutcome);
            if (next !== existing.resolutionOutcome) {
                updateData.resolutionOutcome = next;
                changedFields.push("resolutionOutcome");
            }
        }
        if (changedFields.length === 0)
            return res.json({ success: true, data: existing });
        const updated = await database_1.default.incident.update({
            where: { id },
            data: updateData,
        });
        if (changedFields.includes("status")) {
            await (0, incidentService_1.recordIncidentEvent)({
                incidentId: id,
                actorType: client_1.IncidentActorType.ADMIN,
                actorUserId: req.user.userId,
                eventType: client_1.IncidentEventType.STATUS_CHANGED,
                eventPayload: { from: existing.status, to: updated.status },
            });
        }
        if (changedFields.includes("assignedToUserId")) {
            await (0, incidentService_1.recordIncidentEvent)({
                incidentId: id,
                actorType: client_1.IncidentActorType.ADMIN,
                actorUserId: req.user.userId,
                eventType: client_1.IncidentEventType.ASSIGNED,
                eventPayload: { from: existing.assignedToUserId, to: updated.assignedToUserId },
            });
        }
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.UPDATED_FIELDS,
            eventPayload: { changedFields },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: existing.licenseeId || undefined,
            action: "IR_INCIDENT_UPDATED",
            entityType: "Incident",
            entityId: id,
            details: { changedFields },
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("patchIrIncident error:", e);
        return res.status(500).json({ success: false, error: "Failed to update incident" });
    }
};
exports.patchIrIncident = patchIrIncident;
const addIrIncidentEvent = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = noteSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid note payload" });
        }
        const incident = await database_1.default.incident.findUnique({ where: { id }, select: { id: true, licenseeId: true } });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        const evt = await (0, incidentService_1.recordIncidentEvent)({
            incidentId: id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.NOTE_ADDED,
            eventPayload: { note: parsed.data.note },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: incident.licenseeId || undefined,
            action: "IR_INCIDENT_NOTE_ADDED",
            entityType: "Incident",
            entityId: id,
            details: { noteLength: parsed.data.note.length },
            ipAddress: req.ip,
        });
        return res.status(201).json({ success: true, data: evt });
    }
    catch (e) {
        console.error("addIrIncidentEvent error:", e);
        return res.status(500).json({ success: false, error: "Failed to add event" });
    }
};
exports.addIrIncidentEvent = addIrIncidentEvent;
const applyIrIncidentAction = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = actionSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const result = await (0, incidentActionsService_1.applyContainmentAction)({
            incidentId: id,
            actorUserId: req.user.userId,
            action: parsed.data.action,
            reason: parsed.data.reason,
            qrCodeId: parsed.data.qrCodeId || null,
            batchId: parsed.data.batchId || null,
            licenseeId: parsed.data.licenseeId || null,
            manufacturerUserIds: parsed.data.manufacturerUserIds,
            ipAddress: req.ip,
        });
        return res.json({ success: true, data: result });
    }
    catch (e) {
        console.error("applyIrIncidentAction error:", e);
        const msg = String(e?.message || "");
        if (msg.includes("MISSING_"))
            return res.status(400).json({ success: false, error: msg });
        if (msg.includes("INCIDENT_NOT_FOUND"))
            return res.status(404).json({ success: false, error: "Incident not found" });
        if (msg.includes("TARGET_NOT_MANUFACTURER"))
            return res.status(400).json({ success: false, error: "Target user must be a manufacturer role" });
        return res.status(500).json({ success: false, error: "Failed to apply action" });
    }
};
exports.applyIrIncidentAction = applyIrIncidentAction;
const resolveOrgAdminEmail = async (licenseeId) => {
    const adminUser = await database_1.default.user.findFirst({
        where: {
            licenseeId,
            role: { in: [client_1.UserRole.LICENSEE_ADMIN, client_1.UserRole.ORG_ADMIN] },
            isActive: true,
            deletedAt: null,
        },
        orderBy: { createdAt: "asc" },
        select: { email: true },
    });
    if (adminUser?.email)
        return String(adminUser.email).trim();
    const licensee = await database_1.default.licensee.findUnique({
        where: { id: licenseeId },
        select: { supportEmail: true },
    });
    return String(licensee?.supportEmail || "").trim() || null;
};
const sendIrIncidentCommunication = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const id = String(req.params.id || "").trim();
        if (!id)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = commSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
        }
        const incident = await database_1.default.incident.findUnique({
            where: { id },
            select: { id: true, licenseeId: true, customerEmail: true },
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        let toAddress = parsed.data.toAddress || "";
        const recipient = parsed.data.recipient || "reporter";
        if (!toAddress) {
            if (recipient === "reporter") {
                toAddress = String(incident.customerEmail || "").trim();
            }
            else if (incident.licenseeId) {
                toAddress = (await resolveOrgAdminEmail(incident.licenseeId)) || "";
            }
        }
        if (!toAddress) {
            return res.status(400).json({ success: false, error: "Recipient email is not available for this incident" });
        }
        const delivery = await (0, incidentEmailService_1.sendIncidentEmail)({
            incidentId: id,
            licenseeId: incident.licenseeId || null,
            toAddress,
            subject: parsed.data.subject,
            text: parsed.data.message,
            actorUser: { id: req.user.userId, role: req.user.role },
            senderMode: parsed.data.senderMode || "system",
            template: parsed.data.template || "ir_manual",
        });
        return res.status(delivery.delivered ? 200 : 502).json({ success: delivery.delivered, data: delivery });
    }
    catch (e) {
        console.error("sendIrIncidentCommunication error:", e);
        return res.status(500).json({ success: false, error: "Failed to send communication" });
    }
};
exports.sendIrIncidentCommunication = sendIrIncidentCommunication;
//# sourceMappingURL=irIncidentController.js.map
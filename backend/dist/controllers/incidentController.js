"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.serveIncidentEvidenceFile = exports.exportIncidentPdfHook = exports.notifyIncidentCustomer = exports.addIncidentEvidence = exports.addIncidentEventNote = exports.patchIncident = exports.getIncident = exports.listIncidents = exports.reportIncident = exports.uploadIncidentEvidence = exports.uploadIncidentReportPhotos = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const captchaService_1 = require("../services/captchaService");
const incidentRateLimitService_1 = require("../services/incidentRateLimitService");
const incidentService_1 = require("../services/incidentService");
const tamperEvidenceService_1 = require("../services/tamperEvidenceService");
const supportWorkflowService_1 = require("../services/supportWorkflowService");
const incidentEmailService_1 = require("../services/incidentEmailService");
const auditService_1 = require("../services/auditService");
const incidentUpload_1 = require("../middleware/incidentUpload");
const publicIncidentSchema = zod_1.z.object({
    qrCodeValue: zod_1.z.string().trim().min(2).max(128),
    incidentType: zod_1.z.enum(["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"]),
    description: zod_1.z.string().trim().min(5).max(2000),
    customerName: zod_1.z.string().trim().max(120).optional(),
    customerEmail: zod_1.z.string().trim().email().max(160).optional(),
    customerPhone: zod_1.z.string().trim().max(40).optional(),
    customerCountry: zod_1.z.string().trim().max(80).optional(),
    preferredContactMethod: zod_1.z.enum(["email", "phone", "whatsapp", "none"]).optional(),
    consentToContact: zod_1.z.boolean().optional().default(false),
    purchasePlace: zod_1.z.string().trim().max(240).optional(),
    purchaseDate: zod_1.z.string().trim().max(32).optional(),
    productBatchNo: zod_1.z.string().trim().max(120).optional(),
    locationLat: zod_1.z.number().min(-90).max(90).optional().nullable(),
    locationLng: zod_1.z.number().min(-180).max(180).optional().nullable(),
    tags: zod_1.z.array(zod_1.z.string().trim().max(40)).optional(),
    photoUrls: zod_1.z.array(zod_1.z.string().trim().url().max(1000)).optional(),
});
const incidentPatchSchema = zod_1.z.object({
    status: zod_1.z
        .enum([
        "NEW",
        "TRIAGED",
        "INVESTIGATING",
        "AWAITING_CUSTOMER",
        "AWAITING_LICENSEE",
        "MITIGATED",
        "RESOLVED",
        "CLOSED",
        "REJECTED_SPAM",
    ])
        .optional(),
    assignedToUserId: zod_1.z.string().trim().uuid().nullable().optional(),
    internalNotes: zod_1.z.string().trim().max(5000).optional(),
    tags: zod_1.z.array(zod_1.z.string().trim().max(40)).optional(),
    severity: zod_1.z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
    resolutionSummary: zod_1.z.string().trim().max(3000).optional(),
    resolutionOutcome: zod_1.z.enum(["CONFIRMED_FRAUD", "NOT_FRAUD", "INCONCLUSIVE"]).nullable().optional(),
});
const incidentNoteSchema = zod_1.z.object({
    note: zod_1.z.string().trim().min(2).max(3000),
});
const notifyCustomerSchema = zod_1.z.object({
    subject: zod_1.z.string().trim().min(3).max(200),
    message: zod_1.z.string().trim().min(3).max(5000),
    senderMode: zod_1.z.enum(["actor", "system"]).optional(),
});
const parseBoolean = (value) => {
    if (typeof value === "boolean")
        return value;
    const normalized = String(value || "").toLowerCase().trim();
    if (normalized === "true" || normalized === "1" || normalized === "yes")
        return true;
    if (normalized === "false" || normalized === "0" || normalized === "no")
        return false;
    return false;
};
const parseNumber = (value) => {
    if (typeof value === "number" && Number.isFinite(value))
        return value;
    const n = Number(String(value ?? ""));
    return Number.isFinite(n) ? n : null;
};
const parseJsonArray = (value) => {
    if (Array.isArray(value)) {
        return value.map((v) => String(v || "").trim()).filter(Boolean);
    }
    const raw = String(value || "").trim();
    if (!raw)
        return [];
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed))
            return parsed.map((v) => String(v || "").trim()).filter(Boolean);
    }
    catch {
        return raw
            .split(",")
            .map((v) => v.trim())
            .filter(Boolean);
    }
    return [];
};
const mapFileToStorageRecord = (file) => {
    const fileName = path_1.default.basename(file.filename || "");
    return {
        fileUrl: `/api/incidents/evidence-files/${encodeURIComponent(fileName)}`,
        storageKey: fileName,
        fileType: String(file.mimetype || "application/octet-stream"),
    };
};
const incidentSummaryText = (incident) => [
    `Incident ID: ${incident.id}`,
    `QR Code: ${incident.qrCodeValue}`,
    `Type: ${(0, incidentService_1.toHumanIncidentType)(incident.incidentType)}`,
    `Severity: ${(0, incidentService_1.toHumanIncidentSeverity)(incident.severity)}`,
    `Status: ${(0, incidentService_1.toHumanIncidentStatus)(incident.status)}`,
    `Description: ${incident.description}`,
    incident.locationName ? `Location: ${incident.locationName}` : null,
    incident.customerEmail ? `Customer Email: ${incident.customerEmail}` : null,
    incident.customerPhone ? `Customer Phone: ${incident.customerPhone}` : null,
    `Open in admin: ${(0, incidentService_1.buildIncidentAdminUrl)(incident.id)}`,
]
    .filter(Boolean)
    .join("\n");
const asIncidentPayload = (req) => {
    return {
        qrCodeValue: String(req.body?.qrCodeValue || req.body?.code || "").trim(),
        incidentType: String(req.body?.incidentType || "other").trim().toLowerCase(),
        description: String(req.body?.description || req.body?.notes || "").trim(),
        customerName: String(req.body?.customerName || "").trim() || undefined,
        customerEmail: String(req.body?.customerEmail || req.body?.contactEmail || "").trim() || undefined,
        customerPhone: String(req.body?.customerPhone || "").trim() || undefined,
        customerCountry: String(req.body?.customerCountry || "").trim() || undefined,
        preferredContactMethod: String(req.body?.preferredContactMethod || "none").trim().toLowerCase() || "none",
        consentToContact: parseBoolean(req.body?.consentToContact),
        purchasePlace: String(req.body?.purchasePlace || "").trim() || undefined,
        purchaseDate: String(req.body?.purchaseDate || "").trim() || undefined,
        productBatchNo: String(req.body?.productBatchNo || "").trim() || undefined,
        locationLat: parseNumber(req.body?.locationLat),
        locationLng: parseNumber(req.body?.locationLng),
        tags: parseJsonArray(req.body?.tags),
        photoUrls: parseJsonArray(req.body?.photoUrls),
    };
};
exports.uploadIncidentReportPhotos = incidentUpload_1.incidentReportUpload.array("photos", 4);
exports.uploadIncidentEvidence = incidentUpload_1.incidentEvidenceUpload.single("file");
const reportIncident = async (req, res) => {
    try {
        const parsed = publicIncidentSchema.safeParse(asIncidentPayload(req));
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid incident payload",
            });
        }
        const captchaToken = String(req.headers["x-captcha-token"] || req.body?.captchaToken || "").trim();
        const captcha = await (0, captchaService_1.verifyCaptchaToken)(captchaToken, req.ip);
        if (!captcha.ok) {
            return res.status(400).json({ success: false, error: captcha.reason || "Captcha verification failed" });
        }
        const deviceFp = String(req.headers["x-device-fp"] || "").trim() ||
            String(req.headers["user-agent"] || "").trim();
        const rate = (0, incidentRateLimitService_1.enforceIncidentRateLimit)({
            ip: req.ip || "",
            qrCode: parsed.data.qrCodeValue,
            deviceFp,
        });
        if (rate.blocked) {
            return res.status(429).json({
                success: false,
                error: "Too many incident reports from this device. Please try again later.",
                retryAfterSec: rate.retryAfterSec,
            });
        }
        const files = (req.files || []);
        const uploadedRecords = files.map(mapFileToStorageRecord);
        const incident = await (0, incidentService_1.createIncidentFromReport)(parsed.data, {
            actorType: client_1.IncidentActorType.CUSTOMER,
            actorUserId: null,
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            deviceFingerprint: String(req.headers["x-device-fp"] || ""),
        }, uploadedRecords);
        const evidenceRows = await database_1.default.incidentEvidence.findMany({
            where: { incidentId: incident.id },
            select: {
                id: true,
                incidentId: true,
                storageKey: true,
                fileType: true,
            },
        });
        const tamperFindings = await (0, tamperEvidenceService_1.runTamperEvidenceChecks)(evidenceRows);
        const tamperSummary = (0, tamperEvidenceService_1.summarizeTamperFindings)(tamperFindings);
        if (tamperSummary.hasWarnings) {
            const nextTags = Array.from(new Set([...(incident.tags || []), "tamper_check_warning"]));
            await database_1.default.incident.update({
                where: { id: incident.id },
                data: { tags: nextTags },
            });
        }
        const supportTicket = await database_1.default.supportTicket.findUnique({
            where: { incidentId: incident.id },
            select: {
                id: true,
                referenceCode: true,
                status: true,
                slaDueAt: true,
            },
        });
        const superadminEmails = await (0, incidentEmailService_1.getSuperadminAlertEmails)();
        const alertSubject = `[Incident][${incident.severity}] New fraud report ${incident.id}`;
        const alertBody = incidentSummaryText(incident);
        for (const email of superadminEmails) {
            await (0, incidentEmailService_1.sendIncidentEmail)({
                incidentId: incident.id,
                licenseeId: incident.licenseeId || null,
                toAddress: email,
                subject: alertSubject,
                text: alertBody,
                senderMode: "system",
                template: "superadmin_alert",
            });
        }
        if (incident.consentToContact && incident.customerEmail) {
            const subject = `We received your report (${incident.id})`;
            const body = `Thanks for contacting AuthenticQR support.\n\n` +
                `Reference ID: ${incident.id}\n` +
                `Support Ticket: ${supportTicket?.referenceCode || "Pending assignment"}\n` +
                `Current status: ${(0, incidentService_1.toHumanIncidentStatus)(incident.status)}\n` +
                `Workflow: intake -> review -> containment -> documentation -> resolution.\n` +
                `What next: Our team will review your report and update you if needed.\n\n` +
                `For your privacy, we only use your contact details for this incident workflow.`;
            await (0, incidentEmailService_1.sendIncidentEmail)({
                incidentId: incident.id,
                licenseeId: incident.licenseeId || null,
                toAddress: incident.customerEmail,
                subject,
                text: body,
                senderMode: "system",
                template: "customer_acknowledgement",
            });
        }
        return res.status(201).json({
            success: true,
            data: {
                incidentId: incident.id,
                reference: incident.id,
                supportTicketRef: supportTicket?.referenceCode || null,
                supportTicketStatus: supportTicket?.status || null,
                supportTicketSla: supportTicket ? (0, supportWorkflowService_1.ticketSlaSnapshot)(supportTicket.slaDueAt) : null,
                status: incident.status,
                severity: incident.severity,
                tamperChecks: {
                    summary: tamperSummary.summary,
                    highestRisk: tamperSummary.highestRisk,
                    hasWarnings: tamperSummary.hasWarnings,
                },
            },
        });
    }
    catch (error) {
        console.error("reportIncident error:", error);
        return res.status(500).json({
            success: false,
            error: "Could not create incident report",
        });
    }
};
exports.reportIncident = reportIncident;
const listIncidents = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 200);
        const offset = Math.max(Number(req.query.offset || 0), 0);
        const status = (0, incidentService_1.sanitizeIncidentStatus)(String(req.query.status || ""));
        const severity = (0, incidentService_1.sanitizeIncidentSeverity)(String(req.query.severity || ""));
        const qr = String(req.query.qr || "").trim() || undefined;
        const search = String(req.query.search || "").trim() || undefined;
        const dateFromRaw = String(req.query.date_from || "").trim();
        const dateToRaw = String(req.query.date_to || "").trim();
        const assignedTo = String(req.query.assigned_to || "").trim() || undefined;
        const licenseeId = req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN
            ? String(req.query.licenseeId || "").trim() || undefined
            : undefined;
        const dateFrom = dateFromRaw ? new Date(dateFromRaw) : undefined;
        const dateTo = dateToRaw ? new Date(dateToRaw) : undefined;
        const result = await (0, incidentService_1.listIncidentsScoped)({
            role: req.user.role,
            actorLicenseeId: req.user.licenseeId,
            filters: {
                status: status || undefined,
                severity: severity || undefined,
                qr,
                search,
                dateFrom: dateFrom && Number.isFinite(dateFrom.getTime()) ? dateFrom : undefined,
                dateTo: dateTo && Number.isFinite(dateTo.getTime()) ? dateTo : undefined,
                assignedTo,
                licenseeId,
                limit,
                offset,
            },
        });
        return res.json({
            success: true,
            data: {
                incidents: result.rows,
                total: result.total,
                limit,
                offset,
            },
        });
    }
    catch (error) {
        console.error("listIncidents error:", error);
        return res.status(500).json({ success: false, error: "Failed to list incidents" });
    }
};
exports.listIncidents = listIncidents;
const getIncident = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        return res.json({ success: true, data: incident });
    }
    catch (error) {
        console.error("getIncident error:", error);
        return res.status(500).json({ success: false, error: "Failed to load incident" });
    }
};
exports.getIncident = getIncident;
const patchIncident = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = incidentPatchSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid update payload",
            });
        }
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        const payload = parsed.data;
        const updateData = {};
        const changedFields = [];
        if (payload.status && payload.status !== incident.status) {
            updateData.status = payload.status;
            changedFields.push("status");
        }
        if (payload.assignedToUserId !== undefined && payload.assignedToUserId !== incident.assignedToUserId) {
            updateData.assignedToUserId = payload.assignedToUserId || null;
            changedFields.push("assignedToUserId");
        }
        if (payload.internalNotes !== undefined && payload.internalNotes !== incident.internalNotes) {
            updateData.internalNotes = payload.internalNotes || null;
            changedFields.push("internalNotes");
        }
        if (payload.tags && JSON.stringify(payload.tags) !== JSON.stringify(incident.tags || [])) {
            updateData.tags = payload.tags;
            changedFields.push("tags");
        }
        if (payload.severity && payload.severity !== incident.severity) {
            updateData.severity = payload.severity;
            updateData.severityOverridden = true;
            updateData.slaDueAt = (0, incidentService_1.computeSlaDueAt)(payload.severity);
            changedFields.push("severity");
        }
        if (payload.resolutionSummary !== undefined && payload.resolutionSummary !== incident.resolutionSummary) {
            updateData.resolutionSummary = payload.resolutionSummary || null;
            changedFields.push("resolutionSummary");
        }
        const nextResolution = (0, incidentService_1.sanitizeResolutionOutcome)(payload.resolutionOutcome || "");
        if (payload.resolutionOutcome !== undefined && nextResolution !== incident.resolutionOutcome) {
            updateData.resolutionOutcome = nextResolution;
            changedFields.push("resolutionOutcome");
        }
        if (changedFields.length === 0) {
            return res.json({ success: true, data: incident });
        }
        const updated = await database_1.default.incident.update({
            where: { id: incident.id },
            data: updateData,
        });
        if (changedFields.includes("status")) {
            await (0, incidentService_1.recordIncidentEvent)({
                incidentId: incident.id,
                actorType: client_1.IncidentActorType.ADMIN,
                actorUserId: req.user.userId,
                eventType: client_1.IncidentEventType.STATUS_CHANGED,
                eventPayload: { from: incident.status, to: updated.status },
            });
        }
        if (changedFields.includes("assignedToUserId")) {
            await (0, incidentService_1.recordIncidentEvent)({
                incidentId: incident.id,
                actorType: client_1.IncidentActorType.ADMIN,
                actorUserId: req.user.userId,
                eventType: client_1.IncidentEventType.ASSIGNED,
                eventPayload: { from: incident.assignedToUserId, to: updated.assignedToUserId },
            });
        }
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.UPDATED_FIELDS,
            eventPayload: { changedFields },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: updated.licenseeId || undefined,
            action: "INCIDENT_UPDATED",
            entityType: "Incident",
            entityId: updated.id,
            ipAddress: req.ip,
            details: {
                changedFields,
                status: updated.status,
                severity: updated.severity,
                assignedToUserId: updated.assignedToUserId,
            },
        });
        await (0, supportWorkflowService_1.ensureIncidentWorkflowArtifacts)({
            incidentId: updated.id,
            actorUserId: req.user.userId,
            actorType: client_1.IncidentActorType.ADMIN,
            emitEvents: false,
        });
        return res.json({ success: true, data: updated });
    }
    catch (error) {
        console.error("patchIncident error:", error);
        return res.status(500).json({ success: false, error: "Failed to update incident" });
    }
};
exports.patchIncident = patchIncident;
const addIncidentEventNote = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = incidentNoteSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid note payload" });
        }
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        const evt = await (0, incidentService_1.recordIncidentEvent)({
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.NOTE_ADDED,
            eventPayload: { note: parsed.data.note },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: incident.licenseeId || undefined,
            action: "INCIDENT_NOTE_ADDED",
            entityType: "Incident",
            entityId: incident.id,
            ipAddress: req.ip,
            details: { noteLength: parsed.data.note.length },
        });
        return res.status(201).json({ success: true, data: evt });
    }
    catch (error) {
        console.error("addIncidentEventNote error:", error);
        return res.status(500).json({ success: false, error: "Failed to add note" });
    }
};
exports.addIncidentEventNote = addIncidentEventNote;
const addIncidentEvidence = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        const file = req.file;
        if (!file)
            return res.status(400).json({ success: false, error: "Missing evidence file" });
        const mapped = mapFileToStorageRecord(file);
        const evidence = await database_1.default.incidentEvidence.create({
            data: {
                incidentId: incident.id,
                fileUrl: mapped.fileUrl,
                storageKey: mapped.storageKey,
                fileType: mapped.fileType,
                uploadedBy: client_1.IncidentActorType.ADMIN,
                uploadedByUserId: req.user.userId,
            },
        });
        const tamperFindings = await (0, tamperEvidenceService_1.runTamperEvidenceChecks)([
            {
                id: evidence.id,
                incidentId: incident.id,
                storageKey: evidence.storageKey,
                fileType: evidence.fileType,
            },
        ]);
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.EVIDENCE_ADDED,
            eventPayload: {
                evidenceId: evidence.id,
                fileType: evidence.fileType,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: incident.licenseeId || undefined,
            action: "INCIDENT_EVIDENCE_ADDED",
            entityType: "Incident",
            entityId: incident.id,
            ipAddress: req.ip,
            details: {
                evidenceId: evidence.id,
                fileType: evidence.fileType,
            },
        });
        return res.status(201).json({
            success: true,
            data: {
                ...evidence,
                tamperChecks: tamperFindings[0] || null,
            },
        });
    }
    catch (error) {
        console.error("addIncidentEvidence error:", error);
        return res.status(500).json({ success: false, error: "Failed to upload evidence" });
    }
};
exports.addIncidentEvidence = addIncidentEvidence;
const notifyIncidentCustomer = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (!(0, incidentService_1.isIncidentAdminRole)(req.user.role)) {
            return res.status(403).json({ success: false, error: "Only admin users can send incident emails" });
        }
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const parsed = notifyCustomerSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid customer notify payload",
            });
        }
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        if (!incident.consentToContact || !incident.customerEmail) {
            return res.status(400).json({
                success: false,
                error: "Customer has not provided consent/email for incident updates",
            });
        }
        const isSuperadminSender = req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN;
        const senderMode = parsed.data.senderMode === "system" && isSuperadminSender ? "system" : "actor";
        const mail = await (0, incidentEmailService_1.sendIncidentEmail)({
            incidentId: incident.id,
            licenseeId: incident.licenseeId || null,
            toAddress: incident.customerEmail,
            subject: parsed.data.subject,
            text: `${parsed.data.message}\n\n` +
                `Reference ID: ${incident.id}\n` +
                `Current status: ${(0, incidentService_1.toHumanIncidentStatus)(incident.status)}\n`,
            actorUser: {
                id: req.user.userId,
                role: req.user.role,
                email: req.user.email,
            },
            senderMode,
            template: "customer_update",
        });
        if (!mail.delivered) {
            return res.status(502).json({
                success: false,
                error: mail.error || "Email delivery failed",
                data: {
                    delivered: false,
                    providerMessageId: mail.providerMessageId || null,
                    attemptedFrom: mail.attemptedFrom || null,
                    usedFrom: mail.usedFrom || null,
                    replyTo: mail.replyTo || null,
                    senderMode,
                },
            });
        }
        return res.json({
            success: true,
            data: {
                delivered: mail.delivered,
                providerMessageId: mail.providerMessageId || null,
                error: mail.error || null,
                attemptedFrom: mail.attemptedFrom || null,
                usedFrom: mail.usedFrom || null,
                replyTo: mail.replyTo || null,
                senderMode,
            },
        });
    }
    catch (error) {
        console.error("notifyIncidentCustomer error:", error);
        return res.status(500).json({ success: false, error: "Failed to notify customer" });
    }
};
exports.notifyIncidentCustomer = notifyIncidentCustomer;
const exportIncidentPdfHook = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const incidentId = String(req.params.id || "").trim();
        if (!incidentId)
            return res.status(400).json({ success: false, error: "Missing incident id" });
        const incident = await (0, incidentService_1.getIncidentByIdScoped)(incidentId, {
            role: req.user.role,
            licenseeId: req.user.licenseeId,
        });
        if (!incident)
            return res.status(404).json({ success: false, error: "Incident not found" });
        await (0, incidentService_1.recordIncidentEvent)({
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.ADMIN,
            actorUserId: req.user.userId,
            eventType: client_1.IncidentEventType.EXPORTED,
            eventPayload: { format: "pdf", status: "not_implemented" },
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: incident.licenseeId || undefined,
            action: "INCIDENT_EXPORT_REQUESTED",
            entityType: "Incident",
            entityId: incident.id,
            details: { format: "pdf", status: "not_implemented" },
        });
        return res.status(501).json({
            success: false,
            error: "Incident PDF export is not implemented yet. Hook is ready for future integration.",
        });
    }
    catch (error) {
        console.error("exportIncidentPdfHook error:", error);
        return res.status(500).json({ success: false, error: "Failed to process export hook" });
    }
};
exports.exportIncidentPdfHook = exportIncidentPdfHook;
const serveIncidentEvidenceFile = async (req, res) => {
    try {
        if (!req.user)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        const fileName = String(req.params.fileName || "").trim();
        if (!fileName)
            return res.status(404).json({ success: false, error: "File not found" });
        const evidence = await database_1.default.incidentEvidence.findFirst({
            where: {
                storageKey: fileName,
                incident: req.user.role === client_1.UserRole.SUPER_ADMIN || req.user.role === client_1.UserRole.PLATFORM_SUPER_ADMIN
                    ? undefined
                    : { licenseeId: req.user.licenseeId || "__none__" },
            },
            select: { id: true },
        });
        if (!evidence)
            return res.status(404).json({ success: false, error: "File not found" });
        const resolved = (0, incidentUpload_1.resolveUploadPath)(fileName);
        if (!resolved.startsWith(path_1.default.resolve(__dirname, "../../uploads/incidents"))) {
            return res.status(400).json({ success: false, error: "Invalid file path" });
        }
        if (!fs_1.default.existsSync(resolved))
            return res.status(404).json({ success: false, error: "File not found" });
        return res.sendFile(resolved);
    }
    catch (error) {
        return res.status(500).json({ success: false, error: "Failed to read file" });
    }
};
exports.serveIncidentEvidenceFile = serveIncidentEvidenceFile;
//# sourceMappingURL=incidentController.js.map
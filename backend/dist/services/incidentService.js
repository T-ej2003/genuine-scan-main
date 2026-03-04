"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildIncidentAdminUrl = exports.toHumanIncidentStatus = exports.toHumanIncidentSeverity = exports.toHumanIncidentType = exports.sanitizeIncidentSeverity = exports.sanitizeIncidentStatus = exports.sanitizeResolutionOutcome = exports.listIncidentsScoped = exports.getIncidentByIdScoped = exports.createIncidentFromReport = exports.recordIncidentEvent = exports.isIncidentAdminRole = exports.normalizeCustomerContact = exports.computeSlaDueAt = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("./auditService");
const securityHashService_1 = require("./securityHashService");
const locationService_1 = require("./locationService");
const policyRuleEngineService_1 = require("./ir/policyRuleEngineService");
const supportWorkflowService_1 = require("./supportWorkflowService");
const notificationService_1 = require("./notificationService");
const MAX_SAFE_TEXT = 3000;
const cleanText = (value, max = MAX_SAFE_TEXT) => {
    const raw = String(value || "").trim();
    if (!raw)
        return "";
    const withoutTags = raw.replace(/<[^>]*>/g, "");
    return withoutTags.replace(/\s+/g, " ").trim().slice(0, max);
};
const normalizeCode = (value) => cleanText(value, 128).toUpperCase();
const incidentTypeMap = {
    counterfeit_suspected: client_1.IncidentType.COUNTERFEIT_SUSPECTED,
    duplicate_scan: client_1.IncidentType.DUPLICATE_SCAN,
    tampered_label: client_1.IncidentType.TAMPERED_LABEL,
    wrong_product: client_1.IncidentType.WRONG_PRODUCT,
    other: client_1.IncidentType.OTHER,
};
const contactMethodMap = {
    email: client_1.IncidentContactMethod.EMAIL,
    phone: client_1.IncidentContactMethod.PHONE,
    whatsapp: client_1.IncidentContactMethod.WHATSAPP,
    none: client_1.IncidentContactMethod.NONE,
};
const sanitizeTags = (tags) => Array.from(new Set((Array.isArray(tags) ? tags : [])
    .map((t) => cleanText(t, 40).toLowerCase())
    .filter(Boolean)
    .slice(0, 10)));
const toDateOrNull = (input) => {
    if (!input)
        return null;
    const dt = new Date(input);
    return Number.isFinite(dt.getTime()) ? dt : null;
};
const severitySlaHours = {
    [client_1.IncidentSeverity.CRITICAL]: 4,
    [client_1.IncidentSeverity.HIGH]: 24,
    [client_1.IncidentSeverity.MEDIUM]: 72,
    [client_1.IncidentSeverity.LOW]: 168,
};
const computeSlaDueAt = (severity) => {
    const hours = severitySlaHours[severity] || 72;
    return new Date(Date.now() + hours * 60 * 60_000);
};
exports.computeSlaDueAt = computeSlaDueAt;
const toPreferredContactMethod = (method) => {
    const key = (method || "none").toLowerCase();
    return contactMethodMap[key] || client_1.IncidentContactMethod.NONE;
};
const normalizeCustomerContact = (input) => {
    const consentToContact = Boolean(input.consentToContact);
    const customerEmail = consentToContact ? cleanText(input.customerEmail, 160).toLowerCase() || null : null;
    const customerPhone = consentToContact ? cleanText(input.customerPhone, 40) || null : null;
    const customerName = consentToContact ? cleanText(input.customerName, 120) || null : null;
    const customerCountry = consentToContact ? cleanText(input.customerCountry, 80) || null : null;
    const preferredContactMethod = consentToContact
        ? toPreferredContactMethod(input.preferredContactMethod)
        : client_1.IncidentContactMethod.NONE;
    return {
        consentToContact,
        customerName,
        customerEmail,
        customerPhone,
        customerCountry,
        preferredContactMethod,
    };
};
exports.normalizeCustomerContact = normalizeCustomerContact;
const isIncidentAdminRole = (role) => role === client_1.UserRole.SUPER_ADMIN ||
    role === client_1.UserRole.PLATFORM_SUPER_ADMIN ||
    role === client_1.UserRole.LICENSEE_ADMIN ||
    role === client_1.UserRole.ORG_ADMIN;
exports.isIncidentAdminRole = isIncidentAdminRole;
const computeSpamSignal = async (input) => {
    const maxPerHour = Number(process.env.INCIDENT_SPAM_MAX_PER_HOUR || "5");
    const since = new Date(Date.now() - 60 * 60_000);
    if (!input.email && !input.phone)
        return false;
    const matches = await database_1.default.incident.count({
        where: {
            createdAt: { gte: since },
            OR: [
                input.email ? { customerEmail: input.email } : undefined,
                input.phone ? { customerPhone: input.phone } : undefined,
            ].filter(Boolean),
        },
    });
    return matches >= maxPerHour;
};
const computeSeverity = async (params) => {
    const { incidentType, qrCodeId, scanCount, locationLat, locationLng } = params;
    if (incidentType === client_1.IncidentType.TAMPERED_LABEL)
        return client_1.IncidentSeverity.CRITICAL;
    let priorIncidentCount = 0;
    if (qrCodeId) {
        priorIncidentCount = await database_1.default.incident.count({
            where: {
                qrCodeId,
                status: { not: client_1.IncidentStatus.REJECTED_SPAM },
            },
        });
    }
    if ((scanCount || 0) >= 5 || priorIncidentCount >= 2) {
        return client_1.IncidentSeverity.CRITICAL;
    }
    if (incidentType === client_1.IncidentType.DUPLICATE_SCAN) {
        const hasLocation = locationLat != null && locationLng != null;
        if ((scanCount || 0) >= 2 || hasLocation)
            return client_1.IncidentSeverity.HIGH;
        return client_1.IncidentSeverity.MEDIUM;
    }
    if (incidentType === client_1.IncidentType.COUNTERFEIT_SUSPECTED)
        return client_1.IncidentSeverity.HIGH;
    if (incidentType === client_1.IncidentType.WRONG_PRODUCT)
        return client_1.IncidentSeverity.MEDIUM;
    return client_1.IncidentSeverity.LOW;
};
const recordIncidentEvent = async (input) => {
    return database_1.default.incidentEvent.create({
        data: {
            incidentId: input.incidentId,
            actorType: input.actorType,
            actorUserId: input.actorUserId || null,
            eventType: input.eventType,
            eventPayload: input.eventPayload ?? null,
        },
    });
};
exports.recordIncidentEvent = recordIncidentEvent;
const createIncidentFromReport = async (payload, actor, uploads) => {
    const qrCodeValue = normalizeCode(payload.qrCodeValue);
    const incidentType = incidentTypeMap[payload.incidentType];
    const description = cleanText(payload.description, 2000);
    const purchasePlace = cleanText(payload.purchasePlace, 240) || null;
    const productBatchNo = cleanText(payload.productBatchNo, 120) || null;
    const locationLat = typeof payload.locationLat === "number" ? payload.locationLat : null;
    const locationLng = typeof payload.locationLng === "number" ? payload.locationLng : null;
    const location = await (0, locationService_1.reverseGeocode)(locationLat, locationLng);
    const qrCode = await database_1.default.qRCode.findUnique({
        where: { code: qrCodeValue },
        select: {
            id: true,
            code: true,
            scanCount: true,
            licenseeId: true,
            scanLogs: {
                orderBy: { scannedAt: "desc" },
                take: 1,
                select: { id: true },
            },
        },
    });
    const normalizedContact = (0, exports.normalizeCustomerContact)({
        consentToContact: payload.consentToContact,
        customerName: payload.customerName,
        customerEmail: payload.customerEmail,
        customerPhone: payload.customerPhone,
        customerCountry: payload.customerCountry,
        preferredContactMethod: payload.preferredContactMethod,
    });
    const consentToContact = normalizedContact.consentToContact;
    const customerEmail = normalizedContact.customerEmail;
    const customerPhone = normalizedContact.customerPhone;
    const customerName = normalizedContact.customerName;
    const customerCountry = normalizedContact.customerCountry;
    const preferredContactMethod = normalizedContact.preferredContactMethod;
    const suspectedSpam = await computeSpamSignal({
        email: customerEmail,
        phone: customerPhone,
    });
    const severity = await computeSeverity({
        incidentType,
        qrCodeId: qrCode?.id || null,
        scanCount: qrCode?.scanCount || 0,
        locationLat,
        locationLng,
    });
    const status = suspectedSpam ? client_1.IncidentStatus.REJECTED_SPAM : client_1.IncidentStatus.NEW;
    const tags = sanitizeTags(payload.tags);
    if (suspectedSpam && !tags.includes("suspected_spam"))
        tags.push("suspected_spam");
    const photoUrls = (Array.isArray(payload.photoUrls) ? payload.photoUrls : [])
        .map((v) => cleanText(v, 1000))
        .filter(Boolean)
        .slice(0, 8);
    const ipHash = (0, securityHashService_1.sha256Hash)(actor.ipAddress);
    const userAgentHash = (0, securityHashService_1.sha256Hash)(actor.userAgent);
    const deviceFingerprintHash = (0, securityHashService_1.deviceFingerprintFromRequest)(actor.ipAddress, actor.userAgent, actor.deviceFingerprint);
    const incident = await database_1.default.$transaction(async (tx) => {
        const created = await tx.incident.create({
            data: {
                qrCodeId: qrCode?.id || null,
                qrCodeValue,
                scanEventId: qrCode?.scanLogs?.[0]?.id || null,
                licenseeId: qrCode?.licenseeId || actor.licenseeId || null,
                reportedBy: actor.actorType === client_1.IncidentActorType.CUSTOMER ? "CUSTOMER" : "ADMIN",
                customerName,
                customerEmail,
                customerPhone,
                customerCountry,
                preferredContactMethod,
                consentToContact,
                incidentType,
                severity,
                description,
                photos: photoUrls,
                purchasePlace,
                purchaseDate: toDateOrNull(payload.purchaseDate),
                productBatchNo,
                locationLat,
                locationLng,
                locationName: location?.name || null,
                locationCountry: location?.country || null,
                locationRegion: location?.region || null,
                locationCity: location?.city || null,
                ipHash,
                userAgentHash,
                deviceFingerprintHash,
                status,
                slaDueAt: (0, exports.computeSlaDueAt)(severity),
                tags,
            },
        });
        await tx.incidentEvent.create({
            data: {
                incidentId: created.id,
                actorType: actor.actorType,
                actorUserId: actor.actorUserId || null,
                eventType: client_1.IncidentEventType.CREATED,
                eventPayload: {
                    incidentType,
                    severity,
                    status,
                    consentToContact,
                    hasUploads: Boolean(uploads && uploads.length > 0),
                    suspectedSpam,
                },
            },
        });
        if (uploads && uploads.length > 0) {
            for (const upload of uploads) {
                await tx.incidentEvidence.create({
                    data: {
                        incidentId: created.id,
                        fileUrl: upload.fileUrl || null,
                        storageKey: upload.storageKey || null,
                        fileType: upload.fileType || null,
                        uploadedBy: actor.actorType,
                        uploadedByUserId: actor.actorUserId || null,
                    },
                });
            }
        }
        return created;
    });
    await (0, auditService_1.createAuditLog)({
        userId: actor.actorUserId || undefined,
        licenseeId: incident.licenseeId || undefined,
        action: "INCIDENT_CREATED",
        entityType: "Incident",
        entityId: incident.id,
        ipAddress: actor.ipAddress || undefined,
        details: {
            qrCodeValue: incident.qrCodeValue,
            incidentType: incident.incidentType,
            severity: incident.severity,
            status: incident.status,
            consentToContact: incident.consentToContact,
            suspectedSpam,
        },
    });
    // IR volume rules - best effort and never block incident creation.
    try {
        await (0, policyRuleEngineService_1.evaluatePolicyRulesForIncidentVolume)({
            incidentId: incident.id,
            licenseeId: incident.licenseeId || null,
        });
    }
    catch (e) {
        console.error("evaluatePolicyRulesForIncidentVolume failed:", e);
    }
    // Workflow artifacts and role-aware notifications are best-effort.
    try {
        await (0, supportWorkflowService_1.ensureIncidentWorkflowArtifacts)({
            incidentId: incident.id,
            actorUserId: actor.actorUserId || null,
            actorType: actor.actorType,
            emitEvents: false,
        });
        await (0, notificationService_1.notifyIncidentLifecycle)({
            incidentId: incident.id,
            licenseeId: incident.licenseeId || null,
            type: "incident_created",
            title: "New incident reported",
            body: `A ${(0, exports.toHumanIncidentType)(incident.incidentType).toLowerCase()} case entered intake (severity ${(0, exports.toHumanIncidentSeverity)(incident.severity)}).`,
            data: {
                severity: incident.severity,
                status: incident.status,
                qrCodeValue: incident.qrCodeValue,
                incidentType: incident.incidentType,
            },
        });
    }
    catch (e) {
        console.error("Incident workflow/notification setup failed:", e);
    }
    return incident;
};
exports.createIncidentFromReport = createIncidentFromReport;
const getIncidentByIdScoped = async (incidentId, actor) => {
    const where = { id: incidentId };
    if (actor.role !== client_1.UserRole.SUPER_ADMIN && actor.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
        where.licenseeId = actor.licenseeId || "__none__";
    }
    return database_1.default.incident.findFirst({
        where,
        include: {
            assignedToUser: { select: { id: true, name: true, email: true } },
            handoff: true,
            supportTicket: {
                include: {
                    messages: {
                        orderBy: { createdAt: "desc" },
                        take: 50,
                        include: {
                            actorUser: { select: { id: true, name: true, email: true } },
                        },
                    },
                },
            },
            events: {
                orderBy: { createdAt: "asc" },
                include: { actorUser: { select: { id: true, name: true, email: true } } },
            },
            communications: { orderBy: { createdAt: "desc" } },
            evidence: { orderBy: { createdAt: "desc" } },
        },
    });
};
exports.getIncidentByIdScoped = getIncidentByIdScoped;
const listIncidentsScoped = async (input) => {
    const where = {};
    if (input.role !== client_1.UserRole.SUPER_ADMIN && input.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
        where.licenseeId = input.actorLicenseeId || "__none__";
    }
    else if (input.filters.licenseeId) {
        where.licenseeId = input.filters.licenseeId;
    }
    if (input.filters.status)
        where.status = input.filters.status;
    if (input.filters.severity)
        where.severity = input.filters.severity;
    if (input.filters.assignedTo)
        where.assignedToUserId = input.filters.assignedTo;
    if (input.filters.qr)
        where.qrCodeValue = { contains: input.filters.qr.toUpperCase(), mode: "insensitive" };
    if (input.filters.dateFrom || input.filters.dateTo) {
        where.createdAt = {};
        if (input.filters.dateFrom)
            where.createdAt.gte = input.filters.dateFrom;
        if (input.filters.dateTo)
            where.createdAt.lte = input.filters.dateTo;
    }
    if (input.filters.search) {
        const q = cleanText(input.filters.search, 120);
        where.OR = [
            { qrCodeValue: { contains: q, mode: "insensitive" } },
            { description: { contains: q, mode: "insensitive" } },
            { customerEmail: { contains: q, mode: "insensitive" } },
            { customerPhone: { contains: q, mode: "insensitive" } },
            { productBatchNo: { contains: q, mode: "insensitive" } },
        ];
    }
    const [rows, total] = await Promise.all([
        database_1.default.incident.findMany({
            where,
            orderBy: [{ createdAt: "desc" }],
            take: input.filters.limit,
            skip: input.filters.offset,
            include: {
                assignedToUser: { select: { id: true, name: true, email: true } },
                handoff: true,
                supportTicket: {
                    select: {
                        id: true,
                        referenceCode: true,
                        status: true,
                        slaDueAt: true,
                    },
                },
                evidence: {
                    orderBy: { createdAt: "desc" },
                    take: 3,
                },
            },
        }),
        database_1.default.incident.count({ where }),
    ]);
    return { rows, total };
};
exports.listIncidentsScoped = listIncidentsScoped;
const sanitizeResolutionOutcome = (value) => {
    const normalized = String(value || "").toUpperCase();
    if (!normalized)
        return null;
    if (normalized === "CONFIRMED_FRAUD")
        return client_1.IncidentResolutionOutcome.CONFIRMED_FRAUD;
    if (normalized === "NOT_FRAUD")
        return client_1.IncidentResolutionOutcome.NOT_FRAUD;
    if (normalized === "INCONCLUSIVE")
        return client_1.IncidentResolutionOutcome.INCONCLUSIVE;
    return null;
};
exports.sanitizeResolutionOutcome = sanitizeResolutionOutcome;
const sanitizeIncidentStatus = (value) => {
    const normalized = String(value || "").toUpperCase();
    if (!normalized)
        return null;
    if (normalized === "NEW")
        return client_1.IncidentStatus.NEW;
    if (normalized === "TRIAGED")
        return client_1.IncidentStatus.TRIAGED;
    if (normalized === "TRIAGE")
        return client_1.IncidentStatus.TRIAGE;
    if (normalized === "INVESTIGATING")
        return client_1.IncidentStatus.INVESTIGATING;
    if (normalized === "CONTAINMENT")
        return client_1.IncidentStatus.CONTAINMENT;
    if (normalized === "ERADICATION")
        return client_1.IncidentStatus.ERADICATION;
    if (normalized === "RECOVERY")
        return client_1.IncidentStatus.RECOVERY;
    if (normalized === "AWAITING_CUSTOMER")
        return client_1.IncidentStatus.AWAITING_CUSTOMER;
    if (normalized === "AWAITING_LICENSEE")
        return client_1.IncidentStatus.AWAITING_LICENSEE;
    if (normalized === "MITIGATED")
        return client_1.IncidentStatus.MITIGATED;
    if (normalized === "RESOLVED")
        return client_1.IncidentStatus.RESOLVED;
    if (normalized === "CLOSED")
        return client_1.IncidentStatus.CLOSED;
    if (normalized === "REOPENED")
        return client_1.IncidentStatus.REOPENED;
    if (normalized === "REJECTED_SPAM")
        return client_1.IncidentStatus.REJECTED_SPAM;
    return null;
};
exports.sanitizeIncidentStatus = sanitizeIncidentStatus;
const sanitizeIncidentSeverity = (value) => {
    const normalized = String(value || "").toUpperCase();
    if (!normalized)
        return null;
    if (normalized === "LOW")
        return client_1.IncidentSeverity.LOW;
    if (normalized === "MEDIUM")
        return client_1.IncidentSeverity.MEDIUM;
    if (normalized === "HIGH")
        return client_1.IncidentSeverity.HIGH;
    if (normalized === "CRITICAL")
        return client_1.IncidentSeverity.CRITICAL;
    return null;
};
exports.sanitizeIncidentSeverity = sanitizeIncidentSeverity;
const toHumanIncidentType = (type) => {
    const map = {
        COUNTERFEIT_SUSPECTED: "Counterfeit suspected",
        DUPLICATE_SCAN: "Duplicate scan",
        TAMPERED_LABEL: "Tampered label",
        WRONG_PRODUCT: "Wrong product",
        OTHER: "Other",
    };
    return map[type] || type;
};
exports.toHumanIncidentType = toHumanIncidentType;
const toHumanIncidentSeverity = (severity) => {
    const map = {
        LOW: "Low",
        MEDIUM: "Medium",
        HIGH: "High",
        CRITICAL: "Critical",
    };
    return map[severity] || severity;
};
exports.toHumanIncidentSeverity = toHumanIncidentSeverity;
const toHumanIncidentStatus = (status) => {
    const map = {
        NEW: "New",
        TRIAGED: "Triaged",
        TRIAGE: "Triage",
        INVESTIGATING: "Investigating",
        CONTAINMENT: "Containment",
        ERADICATION: "Eradication",
        RECOVERY: "Recovery",
        AWAITING_CUSTOMER: "Awaiting customer",
        AWAITING_LICENSEE: "Awaiting licensee",
        MITIGATED: "Mitigated",
        RESOLVED: "Resolved",
        CLOSED: "Closed",
        REOPENED: "Reopened",
        REJECTED_SPAM: "Rejected as spam",
    };
    return map[status] || status;
};
exports.toHumanIncidentStatus = toHumanIncidentStatus;
const buildIncidentAdminUrl = (incidentId) => {
    const base = String(process.env.PUBLIC_ADMIN_WEB_BASE_URL || "").trim() ||
        String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || "").trim() ||
        "http://localhost:8080";
    return `${base.replace(/\/+$/, "")}/incidents?incidentId=${encodeURIComponent(incidentId)}`;
};
exports.buildIncidentAdminUrl = buildIncidentAdminUrl;
//# sourceMappingURL=incidentService.js.map
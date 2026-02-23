"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.submitFraudReport = exports.claimOwnership = void 0;
const path_1 = __importDefault(require("path"));
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const incidentService_1 = require("../services/incidentService");
const incidentEmailService_1 = require("../services/incidentEmailService");
const customerSessionService_1 = require("../services/customerSessionService");
const claimSchema = zod_1.z.object({
    code: zod_1.z.string().trim().min(2).max(128),
});
const fraudReportSchema = zod_1.z.object({
    code: zod_1.z.string().trim().min(2).max(128),
    reason: zod_1.z.string().trim().min(3).max(240),
    notes: zod_1.z.string().trim().max(3000).optional(),
    incidentType: zod_1.z.enum(["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"]).optional(),
    scanClassification: zod_1.z.string().trim().max(64).optional(),
    riskReasons: zod_1.z.array(zod_1.z.string().trim().max(240)).optional(),
    contactEmail: zod_1.z.string().trim().email().max(160).optional(),
    consentToContact: zod_1.z.boolean().optional(),
    purchasePlace: zod_1.z.string().trim().max(240).optional(),
    purchaseDate: zod_1.z.string().trim().max(32).optional(),
    productBatchNo: zod_1.z.string().trim().max(120).optional(),
    locationLat: zod_1.z.number().min(-90).max(90).nullable().optional(),
    locationLng: zod_1.z.number().min(-180).max(180).nullable().optional(),
    historySummary: zod_1.z.record(zod_1.z.any()).optional(),
    pageUrl: zod_1.z.string().trim().max(1200).optional(),
});
const parseBoolean = (value, fallback = false) => {
    if (typeof value === "boolean")
        return value;
    const normalized = String(value || "").trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized))
        return true;
    if (["0", "false", "no", "off"].includes(normalized))
        return false;
    return fallback;
};
const parseNumber = (value) => {
    if (typeof value === "number" && Number.isFinite(value))
        return value;
    const n = Number(String(value ?? "").trim());
    return Number.isFinite(n) ? n : null;
};
const parseJsonObject = (value) => {
    if (value && typeof value === "object" && !Array.isArray(value))
        return value;
    const raw = String(value || "").trim();
    if (!raw)
        return undefined;
    try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
            return parsed;
    }
    catch { }
    return undefined;
};
const parseJsonArray = (value) => {
    if (Array.isArray(value)) {
        return value.map((item) => String(item || "").trim()).filter(Boolean);
    }
    const raw = String(value || "").trim();
    if (!raw)
        return [];
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
            return parsed.map((item) => String(item || "").trim()).filter(Boolean);
        }
    }
    catch { }
    return raw
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean);
};
const mapFileToUploadRecord = (file) => {
    const fileName = path_1.default.basename(file.filename || "");
    return {
        fileUrl: `/api/incidents/evidence-files/${encodeURIComponent(fileName)}`,
        storageKey: fileName,
        fileType: String(file.mimetype || "application/octet-stream"),
    };
};
const inferIncidentType = (input) => {
    const explicit = String(input.explicit || "").trim().toLowerCase();
    if (["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"].includes(explicit)) {
        return explicit;
    }
    const reason = String(input.reason || "").toLowerCase();
    const classification = String(input.scanClassification || "").toUpperCase();
    if (classification === "SUSPICIOUS_DUPLICATE" ||
        reason.includes("duplicate") ||
        reason.includes("copied") ||
        reason.includes("same code")) {
        return "duplicate_scan";
    }
    if (reason.includes("tamper") || reason.includes("sticker"))
        return "tampered_label";
    if (reason.includes("wrong product") || reason.includes("mismatch"))
        return "wrong_product";
    if (reason.includes("counterfeit") || reason.includes("fake"))
        return "counterfeit_suspected";
    return "other";
};
const buildAlertBody = (incident, report) => {
    return [
        `Fraud report: ${report.id}`,
        `Incident: ${incident.id}`,
        `QR code: ${incident.qrCodeValue}`,
        `Type: ${(0, incidentService_1.toHumanIncidentType)(incident.incidentType)}`,
        `Severity: ${(0, incidentService_1.toHumanIncidentSeverity)(incident.severity)}`,
        `Status: ${(0, incidentService_1.toHumanIncidentStatus)(incident.status)}`,
        `Reason: ${report.reason}`,
        report?.details?.scanClassification ? `Classification: ${report.details.scanClassification}` : null,
        Array.isArray(report?.details?.riskReasons) && report.details.riskReasons.length > 0
            ? `Risk reasons: ${report.details.riskReasons.join("; ")}`
            : null,
        incident.locationName ? `Location: ${incident.locationName}` : null,
        incident.customerEmail ? `Customer email: ${incident.customerEmail}` : null,
    ]
        .filter(Boolean)
        .join("\n");
};
const claimOwnership = async (req, res) => {
    try {
        const parsed = claimSchema.safeParse({ code: req.params.code });
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid QR code" });
        }
        const identity = (0, customerSessionService_1.getCustomerIdentityContext)(req, res);
        if (!identity.customerUserId) {
            return res.status(401).json({
                success: false,
                error: "Sign in required to claim ownership",
            });
        }
        const normalizedCode = parsed.data.code.toUpperCase();
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: { id: true, code: true, status: true },
        });
        if (!qrCode) {
            return res.status(404).json({ success: false, error: "QR code not found" });
        }
        const existing = await database_1.default.productOwnership.findUnique({
            where: { qrCodeId: qrCode.id },
            select: { id: true, qrCodeId: true, customerUserId: true, claimedAt: true },
        });
        if (existing && existing.customerUserId !== identity.customerUserId) {
            return res.status(409).json({
                success: false,
                error: "This product has already been claimed by another account",
            });
        }
        const ownership = existing ||
            (await database_1.default.productOwnership.create({
                data: {
                    qrCodeId: qrCode.id,
                    customerUserId: identity.customerUserId,
                },
            }));
        await (0, auditService_1.createAuditLog)({
            action: existing ? "PRODUCT_OWNERSHIP_CONFIRMED" : "PRODUCT_OWNERSHIP_CLAIMED",
            entityType: "QRCode",
            entityId: qrCode.id,
            ipAddress: req.ip,
            details: {
                code: qrCode.code,
                ownershipId: ownership.id,
                customerUserId: identity.customerUserId,
            },
        });
        return res.json({
            success: true,
            data: {
                code: qrCode.code,
                ownership: {
                    id: ownership.id,
                    claimedAt: ownership.claimedAt,
                    ownerCustomerId: ownership.customerUserId,
                    isOwnedByYou: ownership.customerUserId === identity.customerUserId,
                },
            },
        });
    }
    catch (error) {
        console.error("claimOwnership error:", error);
        return res.status(500).json({ success: false, error: "Failed to claim ownership" });
    }
};
exports.claimOwnership = claimOwnership;
const submitFraudReport = async (req, res) => {
    try {
        const identity = (0, customerSessionService_1.getCustomerIdentityContext)(req, res);
        const payload = {
            code: String(req.body?.code || req.body?.qrCodeValue || req.params?.code || "").trim(),
            reason: String(req.body?.reason || req.body?.description || "").trim(),
            notes: String(req.body?.notes || req.body?.description || "").trim() || undefined,
            incidentType: String(req.body?.incidentType || "").trim().toLowerCase() || undefined,
            scanClassification: String(req.body?.scanClassification || "").trim() || undefined,
            riskReasons: parseJsonArray(req.body?.riskReasons),
            contactEmail: String(req.body?.contactEmail || req.body?.customerEmail || "").trim() || undefined,
            consentToContact: parseBoolean(req.body?.consentToContact, true),
            purchasePlace: String(req.body?.purchasePlace || "").trim() || undefined,
            purchaseDate: String(req.body?.purchaseDate || "").trim() || undefined,
            productBatchNo: String(req.body?.productBatchNo || "").trim() || undefined,
            locationLat: parseNumber(req.body?.locationLat),
            locationLng: parseNumber(req.body?.locationLng),
            historySummary: parseJsonObject(req.body?.historySummary),
            pageUrl: String(req.body?.pageUrl || "").trim() || undefined,
        };
        const parsed = fraudReportSchema.safeParse(payload);
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid fraud report payload",
            });
        }
        const data = parsed.data;
        const normalizedCode = data.code.toUpperCase();
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: { id: true, code: true, licenseeId: true },
        });
        const files = (req.files || []);
        const uploads = files.map(mapFileToUploadRecord);
        const customerEmail = String(data.contactEmail || "").trim().toLowerCase() ||
            String(identity.customer?.email || "").trim().toLowerCase() ||
            undefined;
        const incident = await (0, incidentService_1.createIncidentFromReport)({
            qrCodeValue: normalizedCode,
            incidentType: inferIncidentType({
                explicit: data.incidentType || null,
                reason: data.reason,
                scanClassification: data.scanClassification || null,
            }),
            description: data.notes || data.reason,
            consentToContact: Boolean(customerEmail) && Boolean(data.consentToContact),
            customerEmail,
            preferredContactMethod: customerEmail ? "email" : "none",
            purchasePlace: data.purchasePlace,
            purchaseDate: data.purchaseDate,
            productBatchNo: data.productBatchNo,
            locationLat: data.locationLat,
            locationLng: data.locationLng,
            tags: [
                "customer_fraud_report",
                data.scanClassification ? `scan_${String(data.scanClassification).toLowerCase()}` : "scan_unknown",
            ],
        }, {
            actorType: client_1.IncidentActorType.CUSTOMER,
            actorUserId: null,
            ipAddress: req.ip,
            userAgent: req.get("user-agent"),
            deviceFingerprint: identity.visitorFingerprint || null,
        }, uploads);
        const fraudReport = await database_1.default.fraudReport.create({
            data: {
                qrCodeId: qrCode?.id || null,
                qrCodeValue: normalizedCode,
                customerUserId: identity.customerUserId,
                anonVisitorId: identity.anonVisitorId,
                reason: data.reason,
                details: {
                    notes: data.notes || null,
                    scanClassification: data.scanClassification || null,
                    riskReasons: data.riskReasons || [],
                    historySummary: data.historySummary || null,
                    purchasePlace: data.purchasePlace || null,
                    purchaseDate: data.purchaseDate || null,
                    productBatchNo: data.productBatchNo || null,
                    locationLat: data.locationLat ?? null,
                    locationLng: data.locationLng ?? null,
                    pageUrl: data.pageUrl || null,
                    photoCount: uploads.length,
                },
                status: "NEW",
                incidentId: incident.id,
            },
        });
        const alertEmails = await (0, incidentEmailService_1.getSuperadminAlertEmails)();
        const alertSubject = `[Fraud][${incident.severity}] Possible duplicate report ${fraudReport.id}`;
        const alertBody = buildAlertBody(incident, fraudReport);
        for (const email of alertEmails) {
            await (0, incidentEmailService_1.sendIncidentEmail)({
                incidentId: incident.id,
                licenseeId: incident.licenseeId || null,
                toAddress: email,
                subject: alertSubject,
                text: alertBody,
                senderMode: "system",
                template: "fraud_report_alert",
            });
        }
        if (incident.consentToContact && incident.customerEmail) {
            await (0, incidentEmailService_1.sendIncidentEmail)({
                incidentId: incident.id,
                licenseeId: incident.licenseeId || null,
                toAddress: incident.customerEmail,
                subject: `We received your fraud report (${fraudReport.id})`,
                text: `Thanks for reporting this scan.\n\n` +
                    `Report reference: ${fraudReport.id}\n` +
                    `Incident reference: ${incident.id}\n` +
                    `Status: ${(0, incidentService_1.toHumanIncidentStatus)(incident.status)}\n\n` +
                    `Our team will investigate and follow up if we need more information.`,
                senderMode: "system",
                template: "fraud_report_customer_ack",
            });
        }
        return res.status(201).json({
            success: true,
            data: {
                reportId: fraudReport.id,
                incidentId: incident.id,
                status: fraudReport.status,
                message: "Fraud report submitted successfully",
            },
        });
    }
    catch (error) {
        console.error("submitFraudReport error:", error);
        return res.status(500).json({ success: false, error: "Failed to submit fraud report" });
    }
};
exports.submitFraudReport = submitFraudReport;
//# sourceMappingURL=customerSecurityController.js.map
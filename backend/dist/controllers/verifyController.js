"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.submitProductFeedback = exports.reportFraud = exports.verifyQRCode = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const qrService_1 = require("../services/qrService");
const auditService_1 = require("../services/auditService");
const policyEngineService_1 = require("../services/policyEngineService");
const zod_1 = require("zod");
const incidentService_1 = require("../services/incidentService");
const scanInsightService_1 = require("../services/scanInsightService");
const reportFraudSchema = zod_1.z.object({
    code: zod_1.z.string().trim().min(2).max(128),
    reason: zod_1.z.string().trim().min(3).max(120),
    notes: zod_1.z.string().trim().max(1500).optional(),
    contactEmail: zod_1.z.string().trim().email().max(160).optional(),
    observedStatus: zod_1.z.string().trim().max(64).optional(),
    observedOutcome: zod_1.z.string().trim().max(64).optional(),
    pageUrl: zod_1.z.string().trim().max(1000).optional(),
});
const productFeedbackSchema = zod_1.z.object({
    code: zod_1.z.string().trim().min(2).max(128),
    rating: zod_1.z.number().int().min(1).max(5),
    satisfaction: zod_1.z.enum(["very_satisfied", "satisfied", "neutral", "disappointed", "very_disappointed"]),
    notes: zod_1.z.string().trim().max(1000).optional(),
    observedStatus: zod_1.z.string().trim().max(64).optional(),
    observedOutcome: zod_1.z.string().trim().max(64).optional(),
    pageUrl: zod_1.z.string().trim().max(1000).optional(),
});
const verifyQRCode = async (req, res) => {
    try {
        const { code } = req.params;
        if (!code || code.length < 2) {
            return res.status(400).json({
                success: false,
                error: "Invalid QR code format",
            });
        }
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: code.toUpperCase() },
            include: {
                licensee: {
                    select: { id: true, name: true, prefix: true, brandName: true, location: true, website: true, supportEmail: true, supportPhone: true },
                },
                batch: {
                    select: {
                        id: true,
                        name: true,
                        printedAt: true,
                        manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
                    },
                },
                // product batch removed
            },
        });
        if (!qrCode) {
            await (0, auditService_1.createAuditLog)({
                action: "VERIFY_FAILED",
                entityType: "QRCode",
                entityId: code,
                details: { reason: "Code not found" },
                ipAddress: req.ip,
            });
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code is not registered in our system.",
                    code,
                },
            });
        }
        // Blocked code
        if (qrCode.status === client_1.QRStatus.BLOCKED) {
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code has been blocked due to fraud or recall.",
                    code,
                    status: qrCode.status,
                    licensee: qrCode.licensee
                        ? {
                            id: qrCode.licensee.id,
                            name: qrCode.licensee.name,
                            prefix: qrCode.licensee.prefix,
                            brandName: qrCode.licensee.brandName,
                            location: qrCode.licensee.location,
                            website: qrCode.licensee.website,
                            supportEmail: qrCode.licensee.supportEmail,
                            supportPhone: qrCode.licensee.supportPhone,
                        }
                        : null,
                    batch: qrCode.batch
                        ? {
                            id: qrCode.batch.id,
                            name: qrCode.batch.name,
                            printedAt: qrCode.batch.printedAt,
                            manufacturer: qrCode.batch.manufacturer || null,
                        }
                        : null,
                },
            });
        }
        // If not yet assigned into any batch
        if (qrCode.status === client_1.QRStatus.DORMANT || qrCode.status === client_1.QRStatus.ACTIVE) {
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code has not been assigned to a product yet.",
                    code,
                    status: qrCode.status,
                    licensee: qrCode.licensee
                        ? {
                            id: qrCode.licensee.id,
                            name: qrCode.licensee.name,
                            prefix: qrCode.licensee.prefix,
                            brandName: qrCode.licensee.brandName,
                            location: qrCode.licensee.location,
                            website: qrCode.licensee.website,
                            supportEmail: qrCode.licensee.supportEmail,
                            supportPhone: qrCode.licensee.supportPhone,
                        }
                        : null,
                    batch: qrCode.batch
                        ? {
                            id: qrCode.batch.id,
                            name: qrCode.batch.name,
                            printedAt: qrCode.batch.printedAt,
                            manufacturer: qrCode.batch.manufacturer || null,
                        }
                        : null,
                },
            });
        }
        // allocated but not printed
        if (qrCode.status === client_1.QRStatus.ALLOCATED) {
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code is allocated but not yet printed.",
                    code,
                    status: qrCode.status,
                    licensee: qrCode.licensee
                        ? {
                            id: qrCode.licensee.id,
                            name: qrCode.licensee.name,
                            prefix: qrCode.licensee.prefix,
                            brandName: qrCode.licensee.brandName,
                            location: qrCode.licensee.location,
                            website: qrCode.licensee.website,
                            supportEmail: qrCode.licensee.supportEmail,
                            supportPhone: qrCode.licensee.supportPhone,
                        }
                        : null,
                    batch: qrCode.batch
                        ? {
                            id: qrCode.batch.id,
                            name: qrCode.batch.name,
                            printedAt: qrCode.batch.printedAt,
                            manufacturer: qrCode.batch.manufacturer || null,
                        }
                        : null,
                    batchName: qrCode.batch?.name || null,
                },
            });
        }
        // Print job created but not confirmed
        if (qrCode.status === client_1.QRStatus.ACTIVATED) {
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code has not been activated (print not confirmed).",
                    code,
                    status: qrCode.status,
                    licensee: qrCode.licensee
                        ? {
                            id: qrCode.licensee.id,
                            name: qrCode.licensee.name,
                            prefix: qrCode.licensee.prefix,
                            brandName: qrCode.licensee.brandName,
                            location: qrCode.licensee.location,
                            website: qrCode.licensee.website,
                            supportEmail: qrCode.licensee.supportEmail,
                            supportPhone: qrCode.licensee.supportPhone,
                        }
                        : null,
                    batch: qrCode.batch
                        ? {
                            id: qrCode.batch.id,
                            name: qrCode.batch.name,
                            printedAt: qrCode.batch.printedAt,
                            manufacturer: qrCode.batch.manufacturer || null,
                        }
                        : null,
                    batchName: qrCode.batch?.name || null,
                },
            });
        }
        // Valid printed/redeemed QR - record scan
        const toNum = (v) => {
            const n = parseFloat(String(v));
            return Number.isFinite(n) ? n : null;
        };
        const latitude = toNum(req.query.lat);
        const longitude = toNum(req.query.lon);
        const accuracy = toNum(req.query.acc);
        const { isFirstScan, qrCode: updated } = await (0, qrService_1.recordScan)(code.toUpperCase(), {
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || null,
            device: req.query.device || null,
            latitude,
            longitude,
            accuracy,
        });
        await (0, auditService_1.createAuditLog)({
            action: "VERIFY_SUCCESS",
            entityType: "QRCode",
            entityId: qrCode.id,
            details: {
                isFirstScan,
                scanCount: (updated.scanCount ?? 0),
            },
            ipAddress: req.ip,
        });
        const policy = await (0, policyEngineService_1.evaluateScanAndEnforcePolicy)({
            qrCodeId: updated.id,
            code: updated.code,
            licenseeId: updated.licenseeId,
            batchId: updated.batchId ?? null,
            manufacturerId: updated.batch?.manufacturer?.id || null,
            scanCount: updated.scanCount ?? 0,
            scannedAt: new Date(),
            latitude,
            longitude,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || null,
        });
        const blockedByPolicy = policy.autoBlockedQr || policy.autoBlockedBatch;
        const finalStatus = blockedByPolicy ? client_1.QRStatus.BLOCKED : updated.status;
        const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;
        const scanInsight = await (0, scanInsightService_1.getScanInsight)(updated.id);
        const warningMessage = blockedByPolicy
            ? "This code has been auto-blocked by security policy due to anomaly detection."
            : !isFirstScan && firstScanTime
                ? `Already verified before. First verification was on ${scanInsight.firstScanAt || firstScanTime.toISOString()}.`
                : null;
        return res.json({
            success: true,
            data: {
                isAuthentic: isFirstScan && !blockedByPolicy,
                message: blockedByPolicy
                    ? "Blocked code."
                    : isFirstScan
                        ? "This is a genuine product."
                        : "Already verified. Please review scan details below.",
                code: updated.code,
                status: finalStatus,
                licensee: updated.licensee
                    ? {
                        id: updated.licensee.id,
                        name: updated.licensee.name,
                        prefix: updated.licensee.prefix,
                        brandName: updated.licensee.brandName,
                        location: updated.licensee.location,
                        website: updated.licensee.website,
                        supportEmail: updated.licensee.supportEmail,
                        supportPhone: updated.licensee.supportPhone,
                    }
                    : null,
                batch: updated.batch
                    ? {
                        id: updated.batch.id,
                        name: updated.batch.name,
                        printedAt: updated.batch.printedAt,
                        manufacturer: updated.batch.manufacturer || null,
                    }
                    : null,
                // legacy batch info (if you still use it sometimes)
                batchName: updated.batch?.name || null,
                printedAt: updated.batch?.printedAt || null,
                firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
                scanCount: updated.scanCount ?? 0,
                isFirstScan,
                firstScanAt: scanInsight.firstScanAt,
                firstScanLocation: scanInsight.firstScanLocation,
                latestScanAt: scanInsight.latestScanAt,
                latestScanLocation: scanInsight.latestScanLocation,
                previousScanAt: scanInsight.previousScanAt,
                previousScanLocation: scanInsight.previousScanLocation,
                warningMessage,
                policy,
            },
        });
    }
    catch (error) {
        console.error("Verify error:", error);
        return res.status(500).json({
            success: false,
            error: "Verification service unavailable",
        });
    }
};
exports.verifyQRCode = verifyQRCode;
const reportFraud = async (req, res) => {
    try {
        const parsed = reportFraudSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid report payload",
            });
        }
        const payload = parsed.data;
        const normalizedCode = payload.code.toUpperCase();
        const reason = String(payload.reason || "").toLowerCase();
        const mappedType = reason.includes("mismatch")
            ? "wrong_product"
            : reason.includes("used")
                ? "duplicate_scan"
                : reason.includes("seller")
                    ? "counterfeit_suspected"
                    : "other";
        const incident = await (0, incidentService_1.createIncidentFromReport)({
            qrCodeValue: normalizedCode,
            incidentType: mappedType,
            description: payload.notes || payload.reason,
            consentToContact: Boolean(payload.contactEmail),
            customerEmail: payload.contactEmail || undefined,
            preferredContactMethod: payload.contactEmail ? "email" : "none",
            tags: ["legacy_verify_report_fraud"],
        }, {
            actorType: client_1.IncidentActorType.CUSTOMER,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        return res.status(201).json({
            success: true,
            data: {
                reportId: incident.id,
                message: "Fraud report submitted successfully.",
            },
        });
    }
    catch (error) {
        console.error("reportFraud error:", error);
        return res.status(500).json({
            success: false,
            error: "Failed to submit fraud report",
        });
    }
};
exports.reportFraud = reportFraud;
const submitProductFeedback = async (req, res) => {
    try {
        const parsed = productFeedbackSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid feedback payload",
            });
        }
        const payload = parsed.data;
        const normalizedCode = payload.code.toUpperCase();
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: {
                id: true,
                code: true,
                licenseeId: true,
                batchId: true,
                batch: {
                    select: {
                        manufacturerId: true,
                    },
                },
            },
        });
        const feedbackLog = await (0, auditService_1.createAuditLog)({
            action: "CUSTOMER_PRODUCT_FEEDBACK",
            entityType: "CustomerFeedback",
            entityId: qrCode?.id || normalizedCode,
            licenseeId: qrCode?.licenseeId || undefined,
            ipAddress: req.ip,
            details: {
                code: normalizedCode,
                rating: payload.rating,
                satisfaction: payload.satisfaction,
                notes: payload.notes || null,
                observedStatus: payload.observedStatus || null,
                observedOutcome: payload.observedOutcome || null,
                qrCodeId: qrCode?.id || null,
                batchId: qrCode?.batchId || null,
                manufacturerId: qrCode?.batch?.manufacturerId || null,
                pageUrl: payload.pageUrl || null,
                userAgent: req.get("user-agent") || null,
                submittedAt: new Date().toISOString(),
            },
        });
        return res.status(201).json({
            success: true,
            data: {
                feedbackId: feedbackLog.id,
                message: "Feedback submitted successfully.",
            },
        });
    }
    catch (error) {
        console.error("submitProductFeedback error:", error);
        return res.status(500).json({
            success: false,
            error: "Failed to submit product feedback",
        });
    }
};
exports.submitProductFeedback = submitProductFeedback;
//# sourceMappingURL=verifyController.js.map
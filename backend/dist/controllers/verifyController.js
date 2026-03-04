"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.submitProductFeedback = exports.reportFraud = exports.linkDeviceClaimToCustomer = exports.claimProductOwnership = exports.verifyQRCode = exports.verifyCustomerEmailOtp = exports.requestCustomerEmailOtp = void 0;
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const customerVerifyAuthService_1 = require("../services/customerVerifyAuthService");
const authEmailService_1 = require("../services/auth/authEmailService");
const incidentEmailService_1 = require("../services/incidentEmailService");
const incidentService_1 = require("../services/incidentService");
const policyEngineService_1 = require("../services/policyEngineService");
const qrService_1 = require("../services/qrService");
const scanInsightService_1 = require("../services/scanInsightService");
const governanceService_1 = require("../services/governanceService");
const tamperEvidenceService_1 = require("../services/tamperEvidenceService");
const supportWorkflowService_1 = require("../services/supportWorkflowService");
const duplicateRiskService_1 = require("../services/duplicateRiskService");
const captchaService_1 = require("../services/captchaService");
const incidentRateLimitService_1 = require("../services/incidentRateLimitService");
const security_1 = require("../utils/security");
const requestFingerprint_1 = require("../utils/requestFingerprint");
const INCIDENT_TYPES = ["counterfeit_suspected", "duplicate_scan", "tampered_label", "wrong_product", "other"];
const reportFraudSchema = zod_1.z
    .object({
    code: zod_1.z.string().trim().max(128).optional(),
    qrCodeValue: zod_1.z.string().trim().max(128).optional(),
    reason: zod_1.z.string().trim().min(3).max(120).optional(),
    description: zod_1.z.string().trim().max(2000).optional(),
    notes: zod_1.z.string().trim().max(2000).optional(),
    incidentType: zod_1.z.enum(INCIDENT_TYPES).optional(),
    contactEmail: zod_1.z.string().trim().email().max(160).optional(),
    customerEmail: zod_1.z.string().trim().email().max(160).optional(),
    consentToContact: zod_1.z.union([zod_1.z.boolean(), zod_1.z.string()]).optional(),
    preferredContactMethod: zod_1.z.enum(["email", "phone", "whatsapp", "none"]).optional(),
    observedStatus: zod_1.z.string().trim().max(64).optional(),
    observedOutcome: zod_1.z.string().trim().max(64).optional(),
    pageUrl: zod_1.z.string().trim().max(1000).optional(),
    tags: zod_1.z.union([zod_1.z.string(), zod_1.z.array(zod_1.z.string())]).optional(),
})
    .refine((v) => Boolean(String(v.code || v.qrCodeValue || "").trim()), {
    message: "Code is required",
    path: ["code"],
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
const requestOtpSchema = zod_1.z.object({
    email: zod_1.z.string().trim().email().max(160),
});
const verifyOtpSchema = zod_1.z.object({
    challengeToken: zod_1.z.string().trim().min(16),
    otp: zod_1.z.string().trim().min(4).max(12),
});
const DEVICE_CLAIM_COOKIE = "gs_device_claim";
const DEVICE_CLAIM_COOKIE_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 365;
const parseBoolEnv = (value, fallback = false) => {
    const normalized = String(value || "").trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized))
        return true;
    if (["0", "false", "no", "off"].includes(normalized))
        return false;
    return fallback;
};
const deviceClaimCookieOptions = () => ({
    httpOnly: true,
    sameSite: "lax",
    secure: parseBoolEnv(process.env.COOKIE_SECURE, process.env.NODE_ENV === "production"),
    path: "/",
    maxAge: DEVICE_CLAIM_COOKIE_MAX_AGE_MS,
});
const getDeviceClaimTokenFromRequest = (req) => {
    const cookies = req.cookies;
    const raw = String(cookies?.[DEVICE_CLAIM_COOKIE] || "").trim();
    return raw || null;
};
const ensureDeviceClaimToken = (req, res) => {
    const existing = getDeviceClaimTokenFromRequest(req);
    if (existing)
        return existing;
    const next = (0, security_1.randomOpaqueToken)(24);
    res.cookie(DEVICE_CLAIM_COOKIE, next, deviceClaimCookieOptions());
    return next;
};
const mapLicensee = (licensee) => licensee
    ? {
        id: licensee.id,
        name: licensee.name,
        prefix: licensee.prefix,
        brandName: licensee.brandName,
        location: licensee.location,
        website: licensee.website,
        supportEmail: licensee.supportEmail,
        supportPhone: licensee.supportPhone,
    }
    : null;
const mapBatch = (batch) => batch
    ? {
        id: batch.id,
        name: batch.name,
        printedAt: batch.printedAt,
        manufacturer: batch.manufacturer || null,
    }
    : null;
const normalizeCode = (value) => String(value || "").trim().toUpperCase();
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
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
const parseTags = (value) => {
    if (Array.isArray(value)) {
        return value.map((v) => String(v || "").trim()).filter(Boolean);
    }
    const raw = String(value || "").trim();
    if (!raw)
        return [];
    try {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
            return parsed.map((v) => String(v || "").trim()).filter(Boolean);
        }
    }
    catch {
        // fall through
    }
    return raw
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);
};
const toIso = (value) => {
    if (!value)
        return null;
    const dt = value instanceof Date ? value : new Date(value);
    return Number.isFinite(dt.getTime()) ? dt.toISOString() : null;
};
const isQrReadyForCustomerUse = (status) => {
    return status === client_1.QRStatus.PRINTED || status === client_1.QRStatus.REDEEMED || status === client_1.QRStatus.SCANNED;
};
const statusNotReadyReason = (status) => {
    if (status === client_1.QRStatus.DORMANT || status === client_1.QRStatus.ACTIVE) {
        return "Code exists but has not been assigned to a finished product.";
    }
    if (status === client_1.QRStatus.ALLOCATED) {
        return "Code is allocated but the print lifecycle is not complete.";
    }
    if (status === client_1.QRStatus.ACTIVATED) {
        return "Code is awaiting print confirmation before customer use.";
    }
    return "Code is not ready for customer verification.";
};
const buildContainment = (qrCode) => ({
    qrUnderInvestigation: qrCode.underInvestigationAt
        ? {
            at: toIso(qrCode.underInvestigationAt),
            reason: qrCode.underInvestigationReason || null,
        }
        : null,
    batchSuspended: qrCode.batch?.suspendedAt
        ? {
            at: toIso(qrCode.batch.suspendedAt),
            reason: qrCode.batch.suspendedReason || null,
        }
        : null,
    orgSuspended: qrCode.licensee?.suspendedAt
        ? {
            at: toIso(qrCode.licensee.suspendedAt),
            reason: qrCode.licensee.suspendedReason || null,
        }
        : null,
});
const buildScanSummary = (params) => {
    const firstVerifiedAt = params.scanInsight?.firstScanAt ||
        (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);
    const latestVerifiedAt = params.scanInsight?.latestScanAt ||
        params.scanInsight?.firstScanAt ||
        (params.scannedAt && Number.isFinite(params.scannedAt.getTime()) ? params.scannedAt.toISOString() : null);
    return {
        totalScans: Number(params.scanCount || 0),
        firstVerifiedAt,
        latestVerifiedAt,
        firstVerifiedLocation: params.scanInsight?.firstScanLocation || null,
        latestVerifiedLocation: params.scanInsight?.latestScanLocation || null,
    };
};
const buildVerificationTimeline = (params) => {
    const firstSeen = params.scanSummary.firstVerifiedAt || null;
    const latestSeen = params.scanSummary.latestVerifiedAt || null;
    const anomalyReason = params.classification === "SUSPICIOUS_DUPLICATE" || params.classification === "BLOCKED_BY_SECURITY"
        ? params.reasons[0] || "Anomaly indicators detected."
        : null;
    return {
        firstSeen,
        latestSeen,
        anomalyReason,
        visualSignal: params.classification === "FIRST_SCAN" || params.classification === "LEGIT_REPEAT"
            ? "stable"
            : params.classification === "SUSPICIOUS_DUPLICATE"
                ? "warning"
                : "critical",
    };
};
const buildRiskExplanation = (params) => {
    if (params.classification === "SUSPICIOUS_DUPLICATE") {
        return {
            level: "elevated",
            title: "Duplicate risk signals detected",
            details: params.reasons,
            recommendedAction: "Review seller source and report suspected counterfeit if this is unexpected.",
        };
    }
    if (params.classification === "BLOCKED_BY_SECURITY") {
        return {
            level: "high",
            title: "Blocked by security controls",
            details: params.reasons,
            recommendedAction: "Do not use this product until support confirms resolution.",
        };
    }
    if (params.ownershipStatus.isClaimedByAnother) {
        return {
            level: "medium",
            title: "Ownership conflict detected",
            details: ["This code is already claimed by another account."],
            recommendedAction: "Treat as potential duplicate and submit a report for investigation.",
        };
    }
    return {
        level: "low",
        title: "No high-risk anomaly detected",
        details: params.reasons,
        recommendedAction: params.scanSummary.totalScans > 1 ? "Keep purchase proof and monitor future scans." : "No action required.",
    };
};
const buildOwnershipStatus = (params) => {
    const ownership = params.ownership;
    const customerUserId = String(params.customerUserId || "").trim();
    const deviceTokenHash = String(params.deviceTokenHash || "").trim();
    const allowClaim = params.allowClaim !== false;
    const claimUnavailable = !params.isReady || params.isBlocked || !allowClaim;
    if (!ownership) {
        return {
            isClaimed: false,
            claimedAt: null,
            isOwnedByRequester: false,
            isClaimedByAnother: false,
            canClaim: !claimUnavailable,
            state: claimUnavailable ? "claim_not_available" : "unclaimed",
            matchMethod: null,
        };
    }
    let isOwnedByRequester = false;
    let matchMethod = null;
    if (customerUserId && ownership.userId === customerUserId) {
        isOwnedByRequester = true;
        matchMethod = "user";
    }
    else if (deviceTokenHash && ownership.deviceTokenHash && ownership.deviceTokenHash === deviceTokenHash) {
        isOwnedByRequester = true;
        matchMethod = "device_token";
    }
    return {
        isClaimed: true,
        claimedAt: ownership.claimedAt.toISOString(),
        isOwnedByRequester,
        // Avoid false conflicts for anonymous users: only hard-conflict when identity evidence exists.
        isClaimedByAnother: !isOwnedByRequester && (Boolean(customerUserId) || Boolean(deviceTokenHash)),
        canClaim: false,
        state: isOwnedByRequester ? "owned_by_you" : "owned_by_someone_else",
        matchMethod,
    };
};
let ownershipStorageWarningLogged = false;
const isOwnershipStorageMissingError = (error) => {
    if (!(error instanceof client_1.Prisma.PrismaClientKnownRequestError))
        return false;
    if (error.code !== "P2021" && error.code !== "P2022")
        return false;
    const meta = (error.meta || {});
    const metaInfo = `${String(meta.table || "")} ${String(meta.modelName || "")} ${String(meta.column || "")}`.toLowerCase();
    if (metaInfo.includes("ownership"))
        return true;
    return String(error.message || "").toLowerCase().includes("ownership");
};
const loadOwnershipByQrCodeId = async (qrCodeId) => {
    try {
        return await database_1.default.ownership.findUnique({
            where: { qrCodeId },
            select: {
                userId: true,
                claimedAt: true,
                deviceTokenHash: true,
                ipHash: true,
                userAgentHash: true,
                claimSource: true,
                linkedAt: true,
            },
        });
    }
    catch (error) {
        if (isOwnershipStorageMissingError(error)) {
            if (!ownershipStorageWarningLogged) {
                ownershipStorageWarningLogged = true;
                console.warn("[verify] Ownership table is unavailable. Continuing verification without ownership data. Apply ownership migrations.");
            }
            return null;
        }
        throw error;
    }
};
const buildSecurityContainmentReasons = (containment) => {
    const reasons = [];
    if (containment.qrUnderInvestigation?.reason)
        reasons.push(`QR containment: ${containment.qrUnderInvestigation.reason}`);
    if (containment.batchSuspended?.reason)
        reasons.push(`Batch containment: ${containment.batchSuspended.reason}`);
    if (containment.orgSuspended?.reason)
        reasons.push(`Organization containment: ${containment.orgSuspended.reason}`);
    return reasons;
};
const inferIncidentType = (input) => {
    if (input.incidentType)
        return input.incidentType;
    const reason = String(input.reason || "").toLowerCase();
    if (reason.includes("mismatch"))
        return "wrong_product";
    if (reason.includes("used") || reason.includes("duplicate"))
        return "duplicate_scan";
    if (reason.includes("seller") || reason.includes("fake") || reason.includes("counterfeit"))
        return "counterfeit_suspected";
    return "other";
};
const incidentSummaryText = (incident) => [
    `Incident ID: ${incident.id}`,
    `QR Code: ${incident.qrCodeValue}`,
    `Severity: ${incident.severity}`,
    `Status: ${incident.status}`,
    `Description: ${incident.description}`,
]
    .filter(Boolean)
    .join("\n");
const buildFraudVerificationSnapshot = async (normalizedCode) => {
    const qrCode = await database_1.default.qRCode.findUnique({
        where: { code: normalizedCode },
    });
    if (!qrCode) {
        const emptySummary = {
            totalScans: 0,
            firstVerifiedAt: null,
            latestVerifiedAt: null,
            firstVerifiedLocation: null,
            latestVerifiedLocation: null,
        };
        const emptyOwnership = {
            isClaimed: false,
            claimedAt: null,
            isOwnedByRequester: false,
            isClaimedByAnother: false,
            canClaim: false,
        };
        return {
            classification: "NOT_READY_FOR_CUSTOMER_USE",
            reasons: ["Code not found in registry."],
            scanSummary: emptySummary,
            ownershipStatus: emptyOwnership,
        };
    }
    const scanInsight = await (0, scanInsightService_1.getScanInsight)(qrCode.id, null);
    const scanSummary = buildScanSummary({
        scanCount: Number(qrCode.scanCount || 0),
        scannedAt: qrCode.scannedAt,
        scanInsight,
    });
    const isBlocked = qrCode.status === client_1.QRStatus.BLOCKED;
    const isReady = isQrReadyForCustomerUse(qrCode.status);
    const ownership = await loadOwnershipByQrCodeId(qrCode.id);
    const ownershipStatus = buildOwnershipStatus({
        ownership,
        isReady,
        isBlocked,
    });
    if (isBlocked) {
        return {
            classification: "BLOCKED_BY_SECURITY",
            reasons: ["Code is blocked by security policy or containment controls."],
            scanSummary,
            ownershipStatus,
        };
    }
    if (!isReady) {
        return {
            classification: "NOT_READY_FOR_CUSTOMER_USE",
            reasons: [statusNotReadyReason(qrCode.status)],
            scanSummary,
            ownershipStatus,
        };
    }
    if (scanSummary.totalScans <= 1) {
        return {
            classification: "FIRST_SCAN",
            reasons: ["First successful verification recorded."],
            scanSummary,
            ownershipStatus,
        };
    }
    const duplicateRisk = (0, duplicateRiskService_1.assessDuplicateRisk)({
        scanCount: scanSummary.totalScans,
        scanSignals: scanInsight.signals,
        ownershipStatus,
        latestScanAt: scanInsight.latestScanAt,
        previousScanAt: scanInsight.previousScanAt,
    });
    return {
        classification: duplicateRisk.classification,
        reasons: duplicateRisk.reasons,
        scanSummary,
        ownershipStatus,
    };
};
const mapUploadedEvidence = (files) => {
    return files.map((file) => {
        const fileName = String(file.filename || "").trim();
        return {
            fileUrl: fileName ? `/api/incidents/evidence-files/${encodeURIComponent(fileName)}` : null,
            storageKey: fileName || null,
            fileType: String(file.mimetype || "application/octet-stream"),
        };
    });
};
const requestCustomerEmailOtp = async (req, res) => {
    try {
        const parsed = requestOtpSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid email address",
            });
        }
        const challenge = (0, customerVerifyAuthService_1.createCustomerOtpChallenge)(parsed.data.email);
        const subject = "Your AuthenticQR sign-in code";
        const text = `Use this one-time code to continue product protection sign-in: ${challenge.otp}\n\n` +
            `This code expires in 10 minutes. If you did not request this code, you can ignore this message.`;
        const emailResult = await (0, authEmailService_1.sendAuthEmail)({
            toAddress: challenge.email,
            subject,
            text,
            template: "verify_customer_email_otp",
            actorUserId: null,
            ipHash: null,
            userAgent: req.get("user-agent") || undefined,
        });
        if (!emailResult.delivered) {
            return res.status(500).json({
                success: false,
                error: emailResult.error || "Could not send OTP email",
            });
        }
        await (0, auditService_1.createAuditLog)({
            action: "VERIFY_CUSTOMER_OTP_SENT",
            entityType: "CustomerVerifyAuth",
            entityId: challenge.email,
            details: {
                maskedEmail: (0, customerVerifyAuthService_1.maskEmail)(challenge.email),
                expiresAt: challenge.expiresAt,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        return res.json({
            success: true,
            data: {
                challengeToken: challenge.challengeToken,
                expiresAt: challenge.expiresAt,
                maskedEmail: (0, customerVerifyAuthService_1.maskEmail)(challenge.email),
            },
        });
    }
    catch (error) {
        console.error("requestCustomerEmailOtp error:", error);
        return res.status(500).json({
            success: false,
            error: "Could not start email verification",
        });
    }
};
exports.requestCustomerEmailOtp = requestCustomerEmailOtp;
const verifyCustomerEmailOtp = async (req, res) => {
    try {
        const parsed = verifyOtpSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({
                success: false,
                error: parsed.error.errors[0]?.message || "Invalid OTP payload",
            });
        }
        const identity = (0, customerVerifyAuthService_1.verifyCustomerOtpChallenge)({
            challengeToken: parsed.data.challengeToken,
            otp: parsed.data.otp,
        });
        const token = (0, customerVerifyAuthService_1.issueCustomerVerifyToken)(identity);
        await (0, auditService_1.createAuditLog)({
            action: "VERIFY_CUSTOMER_OTP_VERIFIED",
            entityType: "CustomerVerifyAuth",
            entityId: identity.userId,
            details: {
                maskedEmail: (0, customerVerifyAuthService_1.maskEmail)(identity.email),
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        return res.json({
            success: true,
            data: {
                token,
                customer: {
                    userId: identity.userId,
                    email: identity.email,
                    maskedEmail: (0, customerVerifyAuthService_1.maskEmail)(identity.email),
                },
            },
        });
    }
    catch (error) {
        return res.status(400).json({
            success: false,
            error: error?.message || "Invalid OTP code",
        });
    }
};
exports.verifyCustomerEmailOtp = verifyCustomerEmailOtp;
const verifyQRCode = async (req, res) => {
    try {
        const { code } = req.params;
        if (!code || code.length < 2) {
            return res.status(400).json({
                success: false,
                error: "Invalid QR code format",
            });
        }
        const normalizedCode = normalizeCode(code);
        const defaultVerifyUxPolicy = await (0, governanceService_1.resolveVerifyUxPolicy)(null);
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            include: {
                licensee: {
                    select: {
                        id: true,
                        name: true,
                        prefix: true,
                        brandName: true,
                        location: true,
                        website: true,
                        supportEmail: true,
                        supportPhone: true,
                        suspendedAt: true,
                        suspendedReason: true,
                    },
                },
                batch: {
                    select: {
                        id: true,
                        name: true,
                        printedAt: true,
                        suspendedAt: true,
                        suspendedReason: true,
                        manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } },
                    },
                },
            },
        });
        if (!qrCode) {
            await delay(150 + Math.floor(Math.random() * 150));
            const reasons = ["Code not found in registry."];
            const emptySummary = {
                totalScans: 0,
                firstVerifiedAt: null,
                latestVerifiedAt: null,
                firstVerifiedLocation: null,
                latestVerifiedLocation: null,
            };
            const emptyOwnership = {
                isClaimed: false,
                claimedAt: null,
                isOwnedByRequester: false,
                isClaimedByAnother: false,
                canClaim: false,
            };
            await (0, auditService_1.createAuditLog)({
                action: "VERIFY_FAILED",
                entityType: "QRCode",
                entityId: normalizedCode,
                details: { reason: "Code not found" },
                ipAddress: req.ip,
            });
            return res.json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "This QR code is not registered in our system.",
                    code: normalizedCode,
                    classification: "NOT_READY_FOR_CUSTOMER_USE",
                    reasons,
                    scanSummary: emptySummary,
                    ownershipStatus: emptyOwnership,
                    verificationTimeline: buildVerificationTimeline({
                        scanSummary: emptySummary,
                        classification: "NOT_READY_FOR_CUSTOMER_USE",
                        reasons,
                    }),
                    riskExplanation: buildRiskExplanation({
                        classification: "NOT_READY_FOR_CUSTOMER_USE",
                        reasons,
                        scanSummary: emptySummary,
                        ownershipStatus: emptyOwnership,
                    }),
                    verifyUxPolicy: defaultVerifyUxPolicy,
                    isBlocked: false,
                    isReady: false,
                    totalScans: 0,
                    firstVerifiedAt: null,
                    latestVerifiedAt: null,
                    riskScore: 70,
                    riskSignals: null,
                },
            });
        }
        const verifyUxPolicy = await (0, governanceService_1.resolveVerifyUxPolicy)(qrCode.licenseeId || null);
        const customerUserId = req.customer?.userId || null;
        const requestDeviceFingerprint = (0, requestFingerprint_1.deriveRequestDeviceFingerprint)(req);
        const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
        const deviceTokenHash = deviceClaimToken ? (0, security_1.hashToken)(deviceClaimToken) : null;
        const requesterIpHash = (0, security_1.hashIp)(req.ip);
        const containment = buildContainment(qrCode);
        const scanInsight = await (0, scanInsightService_1.getScanInsight)(qrCode.id, requestDeviceFingerprint);
        const baseScanSummary = buildScanSummary({
            scanCount: Number(qrCode.scanCount || 0),
            scannedAt: qrCode.scannedAt,
            scanInsight,
        });
        const qrBlocked = qrCode.status === client_1.QRStatus.BLOCKED;
        const qrReady = isQrReadyForCustomerUse(qrCode.status);
        const baseOwnership = await loadOwnershipByQrCodeId(qrCode.id);
        const baseOwnershipStatus = buildOwnershipStatus({
            ownership: baseOwnership,
            customerUserId,
            deviceTokenHash,
            ipHash: requesterIpHash,
            isReady: qrReady,
            isBlocked: qrBlocked,
            allowClaim: verifyUxPolicy.allowOwnershipClaim,
        });
        const basePayload = {
            code: qrCode.code,
            status: qrCode.status,
            containment,
            licensee: mapLicensee(qrCode.licensee),
            batch: mapBatch(qrCode.batch),
            batchName: qrCode.batch?.name || null,
            printedAt: qrCode.batch?.printedAt || null,
            scanCount: baseScanSummary.totalScans,
            firstScanAt: scanInsight.firstScanAt,
            firstScanLocation: scanInsight.firstScanLocation,
            latestScanAt: scanInsight.latestScanAt,
            latestScanLocation: scanInsight.latestScanLocation,
            previousScanAt: scanInsight.previousScanAt,
            previousScanLocation: scanInsight.previousScanLocation,
            scanSignals: scanInsight.signals,
        };
        if (qrCode.status === client_1.QRStatus.BLOCKED) {
            const reasons = [
                "This QR code has been blocked due to fraud or recall.",
                ...buildSecurityContainmentReasons(containment),
            ];
            const verificationTimeline = buildVerificationTimeline({
                scanSummary: baseScanSummary,
                classification: "BLOCKED_BY_SECURITY",
                reasons,
            });
            const riskExplanation = buildRiskExplanation({
                classification: "BLOCKED_BY_SECURITY",
                reasons,
                scanSummary: baseScanSummary,
                ownershipStatus: baseOwnershipStatus,
            });
            return res.json({
                success: true,
                data: {
                    ...basePayload,
                    isAuthentic: false,
                    message: "This QR code has been blocked due to fraud or recall.",
                    classification: "BLOCKED_BY_SECURITY",
                    reasons,
                    scanSummary: baseScanSummary,
                    ownershipStatus: baseOwnershipStatus,
                    verificationTimeline,
                    riskExplanation,
                    verifyUxPolicy,
                    isBlocked: true,
                    isReady: false,
                    totalScans: baseScanSummary.totalScans,
                    firstVerifiedAt: baseScanSummary.firstVerifiedAt,
                    latestVerifiedAt: baseScanSummary.latestVerifiedAt,
                    riskScore: 100,
                    riskSignals: null,
                },
            });
        }
        if (qrCode.status === client_1.QRStatus.DORMANT || qrCode.status === client_1.QRStatus.ACTIVE || qrCode.status === client_1.QRStatus.ALLOCATED || qrCode.status === client_1.QRStatus.ACTIVATED) {
            const message = qrCode.status === client_1.QRStatus.ALLOCATED
                ? "This QR code is allocated but not yet printed."
                : qrCode.status === client_1.QRStatus.ACTIVATED
                    ? "This QR code has not been activated (print not confirmed)."
                    : "This QR code has not been assigned to a product yet.";
            const reasons = [statusNotReadyReason(qrCode.status)];
            const verificationTimeline = buildVerificationTimeline({
                scanSummary: baseScanSummary,
                classification: "NOT_READY_FOR_CUSTOMER_USE",
                reasons,
            });
            const riskExplanation = buildRiskExplanation({
                classification: "NOT_READY_FOR_CUSTOMER_USE",
                reasons,
                scanSummary: baseScanSummary,
                ownershipStatus: baseOwnershipStatus,
            });
            return res.json({
                success: true,
                data: {
                    ...basePayload,
                    isAuthentic: false,
                    message,
                    classification: "NOT_READY_FOR_CUSTOMER_USE",
                    reasons,
                    scanSummary: baseScanSummary,
                    ownershipStatus: baseOwnershipStatus,
                    verificationTimeline,
                    riskExplanation,
                    verifyUxPolicy,
                    isBlocked: false,
                    isReady: false,
                    totalScans: baseScanSummary.totalScans,
                    firstVerifiedAt: baseScanSummary.firstVerifiedAt,
                    latestVerifiedAt: baseScanSummary.latestVerifiedAt,
                    riskScore: 70,
                    riskSignals: null,
                },
            });
        }
        const toNum = (v) => {
            const n = parseFloat(String(v));
            return Number.isFinite(n) ? n : null;
        };
        const latitude = toNum(req.query.lat);
        const longitude = toNum(req.query.lon);
        const accuracy = toNum(req.query.acc);
        const { isFirstScan, qrCode: updated } = await (0, qrService_1.recordScan)(normalizedCode, {
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || null,
            device: requestDeviceFingerprint,
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
                scanCount: updated.scanCount ?? 0,
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
        const blockedByPolicy = Boolean(policy.autoBlockedQr || policy.autoBlockedBatch);
        const finalStatus = blockedByPolicy ? client_1.QRStatus.BLOCKED : updated.status;
        const isBlocked = blockedByPolicy || finalStatus === client_1.QRStatus.BLOCKED;
        const isReady = isQrReadyForCustomerUse(finalStatus);
        const firstScanTime = updated.scannedAt ? new Date(updated.scannedAt) : null;
        const postScanInsight = await (0, scanInsightService_1.getScanInsight)(updated.id, requestDeviceFingerprint);
        const postScanSummary = buildScanSummary({
            scanCount: Number(updated.scanCount || 0),
            scannedAt: firstScanTime,
            scanInsight: postScanInsight,
        });
        const runtimeContainment = buildContainment(updated);
        const hasContainment = Boolean(runtimeContainment.qrUnderInvestigation) ||
            Boolean(runtimeContainment.batchSuspended) ||
            Boolean(runtimeContainment.orgSuspended);
        const warningMessage = blockedByPolicy
            ? "This code has been auto-blocked by security policy due to anomaly detection."
            : hasContainment
                ? "This product is currently under investigation. Please review details and contact support if needed."
                : !isFirstScan && postScanSummary.firstVerifiedAt
                    ? `Already verified before. First verification was on ${postScanSummary.firstVerifiedAt}.`
                    : null;
        const ownership = await loadOwnershipByQrCodeId(updated.id);
        const ownershipStatus = buildOwnershipStatus({
            ownership,
            customerUserId,
            deviceTokenHash,
            ipHash: requesterIpHash,
            isReady,
            isBlocked,
            allowClaim: verifyUxPolicy.allowOwnershipClaim,
        });
        const duplicateRisk = (0, duplicateRiskService_1.assessDuplicateRisk)({
            scanCount: postScanSummary.totalScans,
            scanSignals: postScanInsight.signals,
            policy,
            ownershipStatus,
            customerUserId,
            latestScanAt: postScanInsight.latestScanAt,
            previousScanAt: postScanInsight.previousScanAt,
        });
        let classification;
        let reasons;
        let riskScore = duplicateRisk.riskScore;
        let riskSignals = duplicateRisk.signals;
        if (isBlocked) {
            classification = "BLOCKED_BY_SECURITY";
            reasons = [
                blockedByPolicy
                    ? "Security policy auto-blocked this code after anomaly detection."
                    : "This code is blocked by security controls.",
                ...buildSecurityContainmentReasons(runtimeContainment),
            ];
            riskScore = 100;
            riskSignals = null;
        }
        else if (isFirstScan) {
            classification = "FIRST_SCAN";
            reasons = ["First successful customer verification recorded."];
            riskScore = 4;
            riskSignals = null;
        }
        else {
            classification = duplicateRisk.classification;
            reasons = duplicateRisk.reasons;
        }
        if (ownershipStatus.isClaimedByAnother && !isBlocked) {
            classification = "SUSPICIOUS_DUPLICATE";
            if (!reasons.includes("Ownership is already claimed by another account.")) {
                reasons.unshift("Ownership is already claimed by another account.");
            }
            riskScore = Math.max(riskScore, 70);
        }
        const verificationTimeline = buildVerificationTimeline({
            scanSummary: postScanSummary,
            classification,
            reasons,
        });
        const riskExplanation = buildRiskExplanation({
            classification,
            reasons,
            scanSummary: postScanSummary,
            ownershipStatus,
        });
        return res.json({
            success: true,
            data: {
                isAuthentic: !isBlocked,
                message: isBlocked
                    ? "Blocked code."
                    : isFirstScan
                        ? "This is a genuine product."
                        : "Already verified. Please review scan details below.",
                code: updated.code,
                status: finalStatus,
                containment: runtimeContainment,
                licensee: mapLicensee(updated.licensee),
                batch: mapBatch(updated.batch),
                batchName: updated.batch?.name || null,
                printedAt: updated.batch?.printedAt || null,
                firstScanned: firstScanTime ? firstScanTime.toISOString() : null,
                scanCount: updated.scanCount ?? 0,
                isFirstScan,
                firstScanAt: postScanInsight.firstScanAt,
                firstScanLocation: postScanInsight.firstScanLocation,
                latestScanAt: postScanInsight.latestScanAt,
                latestScanLocation: postScanInsight.latestScanLocation,
                previousScanAt: postScanInsight.previousScanAt,
                previousScanLocation: postScanInsight.previousScanLocation,
                scanSignals: postScanInsight.signals,
                classification,
                reasons,
                scanSummary: postScanSummary,
                ownershipStatus,
                verificationTimeline,
                riskExplanation,
                verifyUxPolicy,
                isBlocked,
                isReady,
                totalScans: postScanSummary.totalScans,
                firstVerifiedAt: postScanSummary.firstVerifiedAt,
                latestVerifiedAt: postScanSummary.latestVerifiedAt,
                riskScore,
                riskSignals,
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
const claimProductOwnership = async (req, res) => {
    try {
        const normalizedCode = normalizeCode(req.params.code || "");
        if (!normalizedCode || normalizedCode.length < 2) {
            return res.status(400).json({
                success: false,
                error: "Invalid QR code format",
            });
        }
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: {
                id: true,
                code: true,
                status: true,
                licenseeId: true,
            },
        });
        if (!qrCode) {
            return res.status(404).json({
                success: false,
                error: "QR code not found",
            });
        }
        const verifyUxPolicy = await (0, governanceService_1.resolveVerifyUxPolicy)(qrCode.licenseeId || null);
        const isBlocked = qrCode.status === client_1.QRStatus.BLOCKED;
        const isReady = isQrReadyForCustomerUse(qrCode.status);
        const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
        const customerUserId = req.customer?.userId || null;
        const deviceClaimToken = ensureDeviceClaimToken(req, res);
        const deviceTokenHash = deviceClaimToken ? (0, security_1.hashToken)(deviceClaimToken) : null;
        const requesterIpHash = (0, security_1.hashIp)(req.ip);
        const normalizedUa = (0, security_1.normalizeUserAgent)(req.get("user-agent") || null);
        const requesterUserAgentHash = normalizedUa ? (0, security_1.hashToken)(`ua:${normalizedUa}`) : null;
        const buildClaimResponse = (ownership) => {
            const ownershipStatus = buildOwnershipStatus({
                ownership,
                customerUserId,
                deviceTokenHash,
                ipHash: requesterIpHash,
                isReady,
                isBlocked,
                allowClaim,
            });
            return {
                ownershipStatus,
                claimTimestamp: ownership?.claimedAt?.toISOString?.() || null,
            };
        };
        if (isBlocked || !isReady || !allowClaim) {
            return res.status(409).json({
                success: false,
                error: isBlocked
                    ? "Claim not allowed for blocked products"
                    : !isReady
                        ? "Claim is available only after product activation"
                        : "Claiming is currently disabled by policy",
            });
        }
        const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
        if (existingOwnership) {
            const currentStatus = buildClaimResponse(existingOwnership).ownershipStatus;
            if (currentStatus.isOwnedByRequester) {
                if (customerUserId && !existingOwnership.userId) {
                    const linked = await database_1.default.ownership.update({
                        where: { qrCodeId: qrCode.id },
                        data: {
                            userId: customerUserId,
                            linkedAt: new Date(),
                            claimSource: "DEVICE_AND_USER",
                        },
                        select: {
                            userId: true,
                            claimedAt: true,
                            deviceTokenHash: true,
                            ipHash: true,
                            userAgentHash: true,
                            claimSource: true,
                            linkedAt: true,
                        },
                    });
                    await (0, auditService_1.createAuditLog)({
                        action: "VERIFY_CLAIM_LINKED_TO_USER",
                        entityType: "Ownership",
                        entityId: qrCode.id,
                        licenseeId: qrCode.licenseeId || undefined,
                        ipAddress: req.ip,
                        userAgent: req.get("user-agent") || undefined,
                        details: {
                            qrCodeId: qrCode.id,
                            customerUserId,
                        },
                    });
                    return res.json({
                        success: true,
                        data: {
                            claimResult: "LINKED_TO_SIGNED_IN_ACCOUNT",
                            message: "Device claim linked to your signed-in account.",
                            ...buildClaimResponse(linked),
                        },
                    });
                }
                return res.json({
                    success: true,
                    data: {
                        claimResult: "ALREADY_OWNED_BY_YOU",
                        message: "This product is already owned by you on this device/account.",
                        ...buildClaimResponse(existingOwnership),
                    },
                });
            }
            await (0, auditService_1.createAuditLog)({
                action: "VERIFY_CLAIM_CONFLICT",
                entityType: "Ownership",
                entityId: qrCode.id,
                licenseeId: qrCode.licenseeId || undefined,
                ipAddress: req.ip,
                userAgent: req.get("user-agent") || undefined,
                details: {
                    qrCodeId: qrCode.id,
                    requesterUserId: customerUserId,
                    hasDeviceToken: Boolean(deviceTokenHash),
                    existingOwnership: true,
                },
            });
            return res.json({
                success: true,
                data: {
                    claimResult: "OWNED_BY_ANOTHER_USER",
                    conflict: true,
                    classification: "SUSPICIOUS_DUPLICATE",
                    reasons: [
                        "Ownership is already claimed by another account or device.",
                        "If this is unexpected, report suspected counterfeit immediately.",
                    ],
                    warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
                    ...buildClaimResponse(existingOwnership),
                },
            });
        }
        let createdOwnership = null;
        try {
            createdOwnership = await database_1.default.ownership.create({
                data: {
                    qrCodeId: qrCode.id,
                    userId: customerUserId || null,
                    deviceTokenHash,
                    ipHash: requesterIpHash,
                    userAgentHash: requesterUserAgentHash,
                    claimSource: customerUserId ? "USER" : "DEVICE",
                },
                select: {
                    userId: true,
                    claimedAt: true,
                    deviceTokenHash: true,
                    ipHash: true,
                    userAgentHash: true,
                    claimSource: true,
                    linkedAt: true,
                },
            });
        }
        catch (error) {
            if (isOwnershipStorageMissingError(error)) {
                return res.status(503).json({
                    success: false,
                    error: "Ownership feature is temporarily unavailable. Please retry after maintenance.",
                });
            }
            if (error instanceof client_1.Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
                const existing = await loadOwnershipByQrCodeId(qrCode.id);
                if (existing) {
                    return res.json({
                        success: true,
                        data: {
                            claimResult: "OWNED_BY_ANOTHER_USER",
                            conflict: true,
                            classification: "SUSPICIOUS_DUPLICATE",
                            reasons: [
                                "Ownership is already claimed by another account or device.",
                                "If this is unexpected, report suspected counterfeit immediately.",
                            ],
                            warningMessage: "Ownership conflict detected. Treat this product as potential duplicate until reviewed.",
                            ...buildClaimResponse(existing),
                        },
                    });
                }
            }
            throw error;
        }
        await (0, auditService_1.createAuditLog)({
            action: "VERIFY_CLAIM_SUCCESS",
            entityType: "Ownership",
            entityId: qrCode.id,
            licenseeId: qrCode.licenseeId || undefined,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
            details: {
                qrCodeId: qrCode.id,
                customerUserId,
                claimSource: customerUserId ? "USER" : "DEVICE",
            },
        });
        return res.status(201).json({
            success: true,
            data: {
                claimResult: customerUserId ? "CLAIMED_USER" : "CLAIMED_DEVICE",
                message: customerUserId
                    ? "Product ownership claimed and linked to your account."
                    : "Product ownership claimed on this device.",
                ...buildClaimResponse(createdOwnership),
            },
        });
    }
    catch (error) {
        console.error("claimProductOwnership error:", error);
        return res.status(500).json({
            success: false,
            error: "Failed to claim ownership",
        });
    }
};
exports.claimProductOwnership = claimProductOwnership;
const linkDeviceClaimToCustomer = async (req, res) => {
    try {
        const customer = req.customer;
        if (!customer) {
            return res.status(401).json({
                success: false,
                error: "Customer authentication required",
            });
        }
        const normalizedCode = normalizeCode(req.params.code || "");
        if (!normalizedCode || normalizedCode.length < 2) {
            return res.status(400).json({
                success: false,
                error: "Invalid QR code format",
            });
        }
        const qrCode = await database_1.default.qRCode.findUnique({
            where: { code: normalizedCode },
            select: {
                id: true,
                status: true,
                licenseeId: true,
            },
        });
        if (!qrCode) {
            return res.status(404).json({
                success: false,
                error: "QR code not found",
            });
        }
        const verifyUxPolicy = await (0, governanceService_1.resolveVerifyUxPolicy)(qrCode.licenseeId || null);
        const allowClaim = verifyUxPolicy.allowOwnershipClaim !== false;
        const isBlocked = qrCode.status === client_1.QRStatus.BLOCKED;
        const isReady = isQrReadyForCustomerUse(qrCode.status);
        if (!allowClaim || isBlocked || !isReady) {
            return res.status(409).json({
                success: false,
                error: "Ownership linking is not available for this product state.",
            });
        }
        const deviceClaimToken = getDeviceClaimTokenFromRequest(req);
        const deviceTokenHash = deviceClaimToken ? (0, security_1.hashToken)(deviceClaimToken) : null;
        const requesterIpHash = (0, security_1.hashIp)(req.ip);
        const existingOwnership = await loadOwnershipByQrCodeId(qrCode.id);
        if (!existingOwnership) {
            return res.status(404).json({
                success: false,
                error: "No device claim exists for this product yet.",
            });
        }
        if (existingOwnership.userId && existingOwnership.userId === customer.userId) {
            return res.json({
                success: true,
                data: {
                    linkResult: "ALREADY_LINKED",
                    message: "Ownership is already linked to your account.",
                    ownershipStatus: buildOwnershipStatus({
                        ownership: existingOwnership,
                        customerUserId: customer.userId,
                        deviceTokenHash,
                        ipHash: requesterIpHash,
                        isReady,
                        isBlocked,
                        allowClaim,
                    }),
                },
            });
        }
        if (existingOwnership.userId && existingOwnership.userId !== customer.userId) {
            return res.status(409).json({
                success: false,
                error: "Ownership is already linked to another account.",
            });
        }
        const ownershipStatus = buildOwnershipStatus({
            ownership: existingOwnership,
            customerUserId: null,
            deviceTokenHash,
            ipHash: requesterIpHash,
            isReady,
            isBlocked,
            allowClaim,
        });
        if (!ownershipStatus.isOwnedByRequester) {
            return res.status(409).json({
                success: false,
                error: "Current device could not prove ownership for linking.",
            });
        }
        const linked = await database_1.default.ownership.update({
            where: { qrCodeId: qrCode.id },
            data: {
                userId: customer.userId,
                linkedAt: new Date(),
                claimSource: "DEVICE_AND_USER",
            },
            select: {
                userId: true,
                claimedAt: true,
                deviceTokenHash: true,
                ipHash: true,
                userAgentHash: true,
                claimSource: true,
                linkedAt: true,
            },
        });
        await (0, auditService_1.createAuditLog)({
            action: "VERIFY_CLAIM_LINKED_TO_USER",
            entityType: "Ownership",
            entityId: qrCode.id,
            licenseeId: qrCode.licenseeId || undefined,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
            details: {
                qrCodeId: qrCode.id,
                customerUserId: customer.userId,
            },
        });
        return res.json({
            success: true,
            data: {
                linkResult: "LINKED",
                message: "Device claim linked to your account.",
                ownershipStatus: buildOwnershipStatus({
                    ownership: linked,
                    customerUserId: customer.userId,
                    deviceTokenHash,
                    ipHash: requesterIpHash,
                    isReady,
                    isBlocked,
                    allowClaim,
                }),
            },
        });
    }
    catch (error) {
        console.error("linkDeviceClaimToCustomer error:", error);
        return res.status(500).json({
            success: false,
            error: "Failed to link claim",
        });
    }
};
exports.linkDeviceClaimToCustomer = linkDeviceClaimToCustomer;
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
        const normalizedCode = normalizeCode(payload.code || payload.qrCodeValue || "");
        const fingerprint = (0, requestFingerprint_1.deriveRequestDeviceFingerprint)(req, { allowClientHint: false });
        const rateLimit = (0, incidentRateLimitService_1.enforceIncidentRateLimit)({
            ip: req.ip,
            qrCode: normalizedCode,
            deviceFp: fingerprint,
        });
        if (rateLimit.blocked) {
            res.setHeader("Retry-After", String(rateLimit.retryAfterSec));
            return res.status(429).json({
                success: false,
                error: "Too many reports submitted. Please try again later.",
            });
        }
        const captchaToken = String(req.headers["x-captcha-token"] || req.body?.captchaToken || "").trim();
        const captcha = await (0, captchaService_1.verifyCaptchaToken)(captchaToken, req.ip);
        if (!captcha.ok) {
            return res.status(400).json({
                success: false,
                error: captcha.reason || "Captcha verification failed",
            });
        }
        const incidentType = inferIncidentType({
            reason: payload.reason,
            incidentType: payload.incidentType,
        });
        const snapshot = await buildFraudVerificationSnapshot(normalizedCode);
        const metadataLines = [
            `Classification: ${snapshot.classification}`,
            `Reasons: ${snapshot.reasons.join(" | ") || "n/a"}`,
            `Scan summary: total=${snapshot.scanSummary.totalScans}, first=${snapshot.scanSummary.firstVerifiedAt || "n/a"}, latest=${snapshot.scanSummary.latestVerifiedAt || "n/a"}`,
            `Ownership: claimed=${String(snapshot.ownershipStatus.isClaimed)}, ownedByRequester=${String(snapshot.ownershipStatus.isOwnedByRequester)}`,
        ];
        const userDescription = String(payload.description || "").trim() ||
            String(payload.notes || "").trim() ||
            String(payload.reason || "").trim() ||
            "Suspected counterfeit report from verify page.";
        const finalDescription = `${userDescription}\n\n--- Verification metadata ---\n${metadataLines.join("\n")}`.slice(0, 2000);
        const uploadedFiles = Array.isArray(req.files) ? req.files : [];
        const uploadRecords = mapUploadedEvidence(uploadedFiles);
        const tags = [
            ...parseTags(payload.tags),
            "verify_fraud_report",
            `classification_${snapshot.classification.toLowerCase()}`,
            snapshot.ownershipStatus.isClaimed ? "ownership_claimed" : "ownership_unclaimed",
        ].slice(0, 10);
        const customerEmail = String(payload.contactEmail || payload.customerEmail || "").trim() || undefined;
        const incident = await (0, incidentService_1.createIncidentFromReport)({
            qrCodeValue: normalizedCode,
            incidentType,
            description: finalDescription,
            consentToContact: parseBoolean(payload.consentToContact, Boolean(customerEmail)),
            customerEmail,
            preferredContactMethod: customerEmail ? "email" : payload.preferredContactMethod || "none",
            tags,
        }, {
            actorType: client_1.IncidentActorType.CUSTOMER,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        }, uploadRecords);
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
        return res.status(201).json({
            success: true,
            data: {
                reportId: incident.id,
                supportTicketRef: supportTicket?.referenceCode || null,
                supportTicketStatus: supportTicket?.status || null,
                supportTicketSla: supportTicket ? (0, supportWorkflowService_1.ticketSlaSnapshot)(supportTicket.slaDueAt) : null,
                message: "Fraud report submitted successfully.",
                classification: snapshot.classification,
                reasons: snapshot.reasons,
                scanSummary: snapshot.scanSummary,
                ownershipStatus: snapshot.ownershipStatus,
                tamperChecks: {
                    summary: tamperSummary.summary,
                    highestRisk: tamperSummary.highestRisk,
                    hasWarnings: tamperSummary.hasWarnings,
                },
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
        const feedbackRate = (0, incidentRateLimitService_1.enforceIncidentRateLimit)({
            ip: req.ip,
            qrCode: normalizedCode,
            deviceFp: (0, requestFingerprint_1.deriveRequestDeviceFingerprint)(req, { allowClientHint: false }),
        });
        if (feedbackRate.blocked) {
            res.setHeader("Retry-After", String(feedbackRate.retryAfterSec));
            return res.status(429).json({
                success: false,
                error: "Too many feedback attempts. Please try again later.",
            });
        }
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
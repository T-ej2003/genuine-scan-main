"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanToken = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const auditService_1 = require("../services/auditService");
const scanPolicy_1 = require("../services/scanPolicy");
const qrTokenService_1 = require("../services/qrTokenService");
const policyEngineService_1 = require("../services/policyEngineService");
const crypto_1 = require("crypto");
const locationService_1 = require("../services/locationService");
const scanInsightService_1 = require("../services/scanInsightService");
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = Number(process.env.SCAN_RATE_LIMIT_PER_MIN || "60");
const rateLimitState = new Map();
const hitRateLimit = (key) => {
    const now = Date.now();
    const entry = rateLimitState.get(key);
    if (!entry || entry.resetAt <= now) {
        rateLimitState.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
        return false;
    }
    entry.count += 1;
    return entry.count > RATE_LIMIT_MAX;
};
const deviceFingerprint = (req) => {
    const raw = String(req.get("x-device-fp") || "") +
        "|" +
        String(req.get("user-agent") || "") +
        "|" +
        String(req.ip || "");
    return (0, crypto_1.createHash)("sha256").update(raw).digest("hex");
};
const isQrReadyForCustomerUse = (status) => {
    return status === client_1.QRStatus.PRINTED || status === client_1.QRStatus.REDEEMED || status === client_1.QRStatus.SCANNED;
};
const buildOwnershipStatus = (params) => {
    const ownership = params.ownership;
    const customerUserId = String(params.customerUserId || "").trim();
    if (!ownership) {
        return {
            isClaimed: false,
            claimedAt: null,
            isOwnedByRequester: false,
            isClaimedByAnother: false,
            canClaim: params.isReady && !params.isBlocked,
        };
    }
    const isOwnedByRequester = Boolean(customerUserId) && ownership.userId === customerUserId;
    return {
        isClaimed: true,
        claimedAt: ownership.claimedAt.toISOString(),
        isOwnedByRequester,
        isClaimedByAnother: !isOwnedByRequester,
        canClaim: false,
    };
};
const deriveDuplicateReasons = (params) => {
    const reasons = [];
    const scanSignals = params.scanSignals || null;
    const policy = params.policy || null;
    const triggered = policy?.triggered || {};
    const alerts = Array.isArray(policy?.alerts) ? policy.alerts : [];
    if (Number(scanSignals?.distinctDeviceCount24h ?? 0) > 1)
        reasons.push("Multiple devices scanned this code recently.");
    if (Number(scanSignals?.recentScanCount10m ?? 0) >= 3)
        reasons.push("A short burst of scans was detected.");
    if (Number(scanSignals?.distinctCountryCount24h ?? 0) > 1)
        reasons.push("Recent scans came from different countries.");
    if (params.scanCount >= 4 || triggered.multiScan)
        reasons.push("High repeat-scan volume was detected.");
    if (triggered.geoDrift)
        reasons.push("Scan geography drift exceeded policy threshold.");
    if (triggered.velocitySpike)
        reasons.push("Scan velocity exceeded policy threshold.");
    for (const alert of alerts) {
        const message = String(alert?.message || "").trim();
        if (!message)
            continue;
        if (!reasons.includes(message))
            reasons.push(message);
    }
    return reasons.slice(0, 6);
};
const scanToken = async (req, res) => {
    try {
        const ipKey = String(req.ip || "unknown");
        if (hitRateLimit(ipKey)) {
            return res.status(429).json({
                success: false,
                error: "Rate limit exceeded. Please try again later.",
            });
        }
        const token = String(req.query.t || "").trim();
        if (!token) {
            return res.status(400).json({ success: false, error: "Missing token" });
        }
        let payload;
        try {
            payload = (0, qrTokenService_1.verifyQrToken)(token).payload;
        }
        catch (e) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "Invalid or tampered QR token.",
                    scanOutcome: "INVALID_SIGNATURE",
                },
            });
        }
        if (!payload.qr_id || !payload.licensee_id || !payload.nonce) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "Invalid QR token payload.",
                    scanOutcome: "INVALID_PAYLOAD",
                },
            });
        }
        if (payload.exp && payload.exp * 1000 < Date.now()) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token expired.",
                    scanOutcome: "EXPIRED",
                },
            });
        }
        const qr = await database_1.default.qRCode.findUnique({
            where: { id: payload.qr_id },
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
                ownership: {
                    select: {
                        userId: true,
                        claimedAt: true,
                    },
                },
            },
        });
        if (!qr) {
            return res.status(404).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR not found.",
                    scanOutcome: "NOT_FOUND",
                },
            });
        }
        const tokenHash = (0, qrTokenService_1.hashToken)(token);
        if (!qr.tokenHash) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token has not been issued.",
                    scanOutcome: "NOT_ISSUED",
                },
            });
        }
        if (qr.tokenHash !== tokenHash) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token revoked or mismatched.",
                    scanOutcome: "TOKEN_MISMATCH",
                },
            });
        }
        if (qr.tokenNonce && payload.nonce !== qr.tokenNonce) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token mismatch.",
                    scanOutcome: "TOKEN_MISMATCH",
                },
            });
        }
        if (payload.licensee_id !== qr.licenseeId) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token invalid for this licensee.",
                    scanOutcome: "TOKEN_MISMATCH",
                },
            });
        }
        const expectedBatchId = qr.batchId ?? null;
        if (payload.batch_id !== expectedBatchId) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token invalid for this batch.",
                    scanOutcome: "TOKEN_MISMATCH",
                },
            });
        }
        const expectedManufacturerId = qr.batch?.manufacturer?.id ?? null;
        if (payload.manufacturer_id !== undefined && payload.manufacturer_id !== expectedManufacturerId) {
            return res.status(400).json({
                success: true,
                data: {
                    isAuthentic: false,
                    message: "QR token invalid for this manufacturer.",
                    scanOutcome: "TOKEN_MISMATCH",
                },
            });
        }
        const decision = (0, scanPolicy_1.evaluateScanPolicy)(qr.status);
        const now = new Date();
        const fp = deviceFingerprint(req);
        const toNum = (v) => {
            const n = parseFloat(String(v));
            return Number.isFinite(n) ? n : null;
        };
        const latitude = toNum(req.query.lat);
        const longitude = toNum(req.query.lon);
        const accuracy = toNum(req.query.acc);
        const location = await (0, locationService_1.reverseGeocode)(latitude, longitude);
        const updated = await database_1.default.$transaction(async (tx) => {
            const updatedQr = await tx.qRCode.update({
                where: { id: qr.id },
                data: {
                    scanCount: { increment: 1 },
                    scannedAt: qr.scannedAt ?? now,
                    lastScanIp: req.ip,
                    lastScanUserAgent: req.get("user-agent") || null,
                    lastScanDevice: fp,
                    status: decision.allowRedeem ? client_1.QRStatus.REDEEMED : qr.status,
                    redeemedAt: decision.allowRedeem ? now : qr.redeemedAt,
                    redeemedDeviceFingerprint: decision.allowRedeem ? fp : qr.redeemedDeviceFingerprint,
                },
                include: {
                    licensee: true,
                    batch: { include: { manufacturer: { select: { id: true, name: true, email: true, location: true, website: true } } } },
                },
            });
            await tx.qrScanLog.create({
                data: {
                    code: updatedQr.code,
                    qrCodeId: updatedQr.id,
                    licenseeId: updatedQr.licenseeId,
                    batchId: updatedQr.batchId ?? null,
                    status: updatedQr.status,
                    isFirstScan: decision.allowRedeem,
                    scanCount: updatedQr.scanCount ?? 0,
                    ipAddress: req.ip,
                    userAgent: req.get("user-agent") || null,
                    device: fp,
                    latitude,
                    longitude,
                    accuracy,
                    locationName: location?.name || null,
                    locationCountry: location?.country || null,
                    locationRegion: location?.region || null,
                    locationCity: location?.city || null,
                },
            });
            return updatedQr;
        });
        if (decision.allowRedeem) {
            await (0, auditService_1.createAuditLog)({
                action: "REDEEMED",
                entityType: "QRCode",
                entityId: updated.id,
                details: {
                    qrId: updated.id,
                    code: updated.code,
                    scanCount: updated.scanCount ?? 0,
                },
                ipAddress: req.ip,
            });
        }
        const policy = await (0, policyEngineService_1.evaluateScanAndEnforcePolicy)({
            qrCodeId: updated.id,
            code: updated.code,
            licenseeId: updated.licenseeId,
            batchId: updated.batchId ?? null,
            manufacturerId: updated.batch?.manufacturer?.id || null,
            scanCount: updated.scanCount ?? 0,
            scannedAt: now,
            latitude,
            longitude,
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || null,
        });
        const finalStatus = policy.autoBlockedQr || policy.autoBlockedBatch ? client_1.QRStatus.BLOCKED : updated.status;
        const effectiveOutcome = finalStatus === client_1.QRStatus.BLOCKED ? "BLOCKED" : decision.outcome;
        const scanInsight = await (0, scanInsightService_1.getScanInsight)(updated.id, fp || null);
        const customerUserId = req.customer?.userId || null;
        const containment = {
            qrUnderInvestigation: updated.underInvestigationAt
                ? { at: new Date(updated.underInvestigationAt).toISOString(), reason: updated.underInvestigationReason || null }
                : null,
            batchSuspended: updated.batch?.suspendedAt
                ? { at: new Date(updated.batch.suspendedAt).toISOString(), reason: updated.batch.suspendedReason || null }
                : null,
            orgSuspended: updated.licensee?.suspendedAt
                ? { at: new Date(updated.licensee.suspendedAt).toISOString(), reason: updated.licensee.suspendedReason || null }
                : null,
        };
        const hasContainment = Boolean(containment.qrUnderInvestigation) ||
            Boolean(containment.batchSuspended) ||
            Boolean(containment.orgSuspended);
        const warningMessage = effectiveOutcome === "ALREADY_REDEEMED"
            ? `Already verified before. First verification was at ${scanInsight.firstScanAt || updated.redeemedAt?.toISOString?.() || "unknown time"}.`
            : effectiveOutcome === "SUSPICIOUS"
                ? "This code was generated but not confirmed as printed. Treat with suspicion."
                : effectiveOutcome === "BLOCKED"
                    ? policy.autoBlockedQr || policy.autoBlockedBatch
                        ? "This code has been auto-blocked by security policy due to anomaly detection."
                        : "This code has been blocked due to fraud or recall."
                    : hasContainment
                        ? "This product is currently under investigation. Please review details and contact support if needed."
                        : null;
        const message = effectiveOutcome === "VALID"
            ? "Authentic item. First-time verification successful."
            : effectiveOutcome === "ALREADY_REDEEMED"
                ? "Already verified. Please review scan details below."
                : effectiveOutcome === "SUSPICIOUS"
                    ? "Not activated for sale. Suspicious scan."
                    : effectiveOutcome === "BLOCKED"
                        ? "Blocked code."
                        : "This code is not active.";
        const isBlocked = finalStatus === client_1.QRStatus.BLOCKED;
        const isReady = isQrReadyForCustomerUse(finalStatus);
        const totalScans = Number(updated.scanCount ?? 0);
        const firstVerifiedAt = scanInsight.firstScanAt || (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);
        const latestVerifiedAt = scanInsight.latestScanAt ||
            scanInsight.firstScanAt ||
            (updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null);
        const ownership = await database_1.default.ownership.findUnique({
            where: { qrCodeId: updated.id },
            select: {
                userId: true,
                claimedAt: true,
            },
        });
        const ownershipStatus = buildOwnershipStatus({
            ownership,
            customerUserId,
            isReady,
            isBlocked,
        });
        const duplicateReasons = deriveDuplicateReasons({
            scanCount: totalScans,
            scanSignals: scanInsight.signals,
            policy,
        });
        let classification;
        let reasons;
        if (isBlocked) {
            classification = "BLOCKED_BY_SECURITY";
            reasons = ["Code is blocked by security policy or containment controls."];
        }
        else if (!isReady) {
            classification = "NOT_READY_FOR_CUSTOMER_USE";
            reasons = ["Code lifecycle is not ready for customer verification."];
        }
        else if (decision.allowRedeem) {
            classification = "FIRST_SCAN";
            reasons = ["First successful customer verification recorded."];
        }
        else if (duplicateReasons.length) {
            classification = "SUSPICIOUS_DUPLICATE";
            reasons = duplicateReasons;
        }
        else {
            classification = "LEGIT_REPEAT";
            reasons = ["Repeat verification pattern matches normal customer behavior."];
        }
        if (ownershipStatus.isClaimedByAnother && customerUserId && !isBlocked) {
            classification = "SUSPICIOUS_DUPLICATE";
            if (!reasons.includes("Ownership is already claimed by another account.")) {
                reasons = ["Ownership is already claimed by another account.", ...reasons];
            }
        }
        return res.json({
            success: true,
            data: {
                // Consumers may re-verify the same product; treat repeat scans as authentic unless blocked.
                isAuthentic: effectiveOutcome === "VALID" || effectiveOutcome === "ALREADY_REDEEMED",
                scanOutcome: effectiveOutcome,
                message,
                warningMessage,
                code: updated.code,
                status: finalStatus,
                containment,
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
                firstScanned: updated.scannedAt ? new Date(updated.scannedAt).toISOString() : null,
                scanCount: updated.scanCount ?? 0,
                isFirstScan: decision.allowRedeem,
                redeemedAt: updated.redeemedAt ? new Date(updated.redeemedAt).toISOString() : null,
                firstScanAt: scanInsight.firstScanAt,
                firstScanLocation: scanInsight.firstScanLocation,
                latestScanAt: scanInsight.latestScanAt,
                latestScanLocation: scanInsight.latestScanLocation,
                previousScanAt: scanInsight.previousScanAt,
                previousScanLocation: scanInsight.previousScanLocation,
                scanSignals: scanInsight.signals,
                classification,
                reasons,
                scanSummary: {
                    totalScans,
                    firstVerifiedAt,
                    latestVerifiedAt,
                    firstVerifiedLocation: scanInsight.firstScanLocation || null,
                    latestVerifiedLocation: scanInsight.latestScanLocation || null,
                },
                ownershipStatus,
                isBlocked,
                isReady,
                totalScans,
                firstVerifiedAt,
                latestVerifiedAt,
                policy,
            },
        });
    }
    catch (error) {
        console.error("scanToken error:", error);
        return res.status(500).json({
            success: false,
            error: "Verification service unavailable",
        });
    }
};
exports.scanToken = scanToken;
//# sourceMappingURL=scanController.js.map
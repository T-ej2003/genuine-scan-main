"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.sendAuthEmail = void 0;
const nodemailer_1 = __importDefault(require("nodemailer"));
const database_1 = __importDefault(require("../../config/database"));
const auditService_1 = require("../auditService");
const client_1 = require("@prisma/client");
const email_1 = require("../../utils/email");
const parseBool = (value, fallback = false) => {
    const normalized = String(value ?? "").trim().toLowerCase();
    if (["1", "true", "yes", "on"].includes(normalized))
        return true;
    if (["0", "false", "no", "off"].includes(normalized))
        return false;
    return fallback;
};
const normalizeEmail = (value) => {
    const email = String(value || "").trim().toLowerCase();
    return email || null;
};
const getFirstEnv = (...keys) => {
    for (const key of keys) {
        const value = String(process.env[key] || "").trim();
        if (value)
            return value;
    }
    return "";
};
const getMailFromDisplayName = () => String(getFirstEnv("MAIL_FROM_NAME", "EMAIL_FROM_NAME", "APP_NAME") || "MSCQR").trim() || "MSCQR";
const getPreferredSuperadminEmailFromEnv = () => (0, email_1.normalizeEmailAddress)(getFirstEnv("SUPER_ADMIN_EMAIL", "PLATFORM_SUPERADMIN_EMAIL", "SUPERADMIN_FROM_EMAIL", "EMAIL_FROM", "MAIL_FROM"));
const getAuthFromEmailFromEnv = () => (0, email_1.normalizeEmailAddress)(getFirstEnv("AUTH_EMAIL_FROM", "EMAIL_FROM", "MAIL_FROM"));
const inferHostFromUserEmail = (userEmail) => {
    const domain = String(userEmail.split("@")[1] || "").toLowerCase().trim();
    if (!domain)
        return null;
    if (domain === "gmail.com" || domain === "googlemail.com") {
        return { host: "smtp.gmail.com", port: 465, secure: true };
    }
    if (["outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com"].includes(domain)) {
        return { host: "smtp.office365.com", port: 587, secure: false };
    }
    if (domain.includes("yahoo.")) {
        return { host: "smtp.mail.yahoo.com", port: 465, secure: true };
    }
    if (["icloud.com", "me.com", "mac.com"].includes(domain)) {
        return { host: "smtp.mail.me.com", port: 587, secure: false };
    }
    if (domain === "zoho.com" || domain.endsWith(".zoho.com")) {
        return { host: "smtp.zoho.com", port: 465, secure: true };
    }
    return null;
};
const resolveSmtpConfig = () => {
    const user = getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER");
    const pass = getFirstEnv("SMTP_PASS", "SMTP_PASSWORD", "EMAIL_PASS", "MAIL_PASS", "MAIL_PASSWORD");
    const explicitHost = getFirstEnv("SMTP_HOST", "EMAIL_HOST", "MAIL_HOST");
    if (!user || !pass) {
        return {
            config: null,
            error: "SMTP transport is not configured (missing SMTP_USER/SMTP_PASS)",
        };
    }
    const inferred = explicitHost ? null : inferHostFromUserEmail(user);
    const host = explicitHost || inferred?.host || "";
    if (!host) {
        return {
            config: null,
            error: "SMTP transport is not configured (missing SMTP_HOST and could not infer provider from SMTP_USER)",
        };
    }
    const defaultPort = inferred?.port || 587;
    const parsedPort = Number(getFirstEnv("SMTP_PORT", "EMAIL_PORT", "MAIL_PORT") || defaultPort);
    const port = Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : defaultPort;
    const secure = parseBool(getFirstEnv("SMTP_SECURE", "EMAIL_SECURE", "MAIL_SECURE"), inferred ? inferred.secure : port === 465);
    return { config: { host, user, pass, port, secure } };
};
let transporter = null;
let transporterKey = null;
const getTransporter = () => {
    if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
        transporterKey = "jsonTransport";
        transporter = nodemailer_1.default.createTransport({ jsonTransport: true });
        return { transporter, smtpUser: normalizeEmail(getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER")), configError: null };
    }
    const { config, error } = resolveSmtpConfig();
    if (!config)
        return { transporter: null, smtpUser: null, configError: error || "SMTP transport is not configured" };
    const nextKey = `${config.host}|${config.port}|${config.secure}|${config.user}`;
    if (transporter && transporterKey === nextKey) {
        return { transporter, smtpUser: normalizeEmail(config.user), configError: null };
    }
    transporterKey = nextKey;
    transporter = nodemailer_1.default.createTransport({
        host: config.host,
        port: config.port,
        secure: config.secure,
        auth: { user: config.user, pass: config.pass },
    });
    return { transporter, smtpUser: normalizeEmail(config.user), configError: null };
};
const formatFromAddress = (email) => `"${getMailFromDisplayName()}" <${email}>`;
const summarizeMailError = (error) => {
    const message = String(error?.message || "Email delivery failed").trim();
    const code = String(error?.code || "").trim();
    const responseCode = Number(error?.responseCode || 0);
    const response = String(error?.response || "").trim();
    const parts = [message];
    if (code)
        parts.push(`code=${code}`);
    if (responseCode)
        parts.push(`smtp=${responseCode}`);
    if (response)
        parts.push(`response=${response}`);
    return parts.join(" | ");
};
const isFromRejectedError = (error) => {
    const message = String(error?.message || "").toLowerCase();
    const response = String(error?.response || "").toLowerCase();
    const code = String(error?.code || "").toUpperCase();
    const responseCode = Number(error?.responseCode || 0);
    const haystack = `${message} ${response}`;
    if (["EENVELOPE", "EADDRESS", "EAUTH"].includes(code)) {
        if (haystack.includes("sender") || haystack.includes("from") || haystack.includes("not allowed") || haystack.includes("unauthorized")) {
            return true;
        }
    }
    if ([550, 552, 553, 554].includes(responseCode)) {
        if (haystack.includes("sender") || haystack.includes("from") || haystack.includes("not allowed") || haystack.includes("unauthorized") || haystack.includes("rejected") || haystack.includes("not owned")) {
            return true;
        }
    }
    return (haystack.includes("sender address rejected") ||
        haystack.includes("sender rejected") ||
        haystack.includes("from address") ||
        haystack.includes("from header") ||
        haystack.includes("not permitted") ||
        haystack.includes("not owned") ||
        haystack.includes("unauthorized"));
};
const getPrimarySuperadminEmail = async () => {
    const fromEnv = getPreferredSuperadminEmailFromEnv();
    if (fromEnv)
        return fromEnv;
    const primary = await database_1.default.user.findFirst({
        where: {
            // accept both legacy and new role names
            role: { in: [client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN] },
            isActive: true,
            deletedAt: null,
        },
        orderBy: { createdAt: "asc" },
        select: { email: true },
    });
    return normalizeEmail(primary?.email);
};
const sendAuthEmail = async (input) => {
    const trState = getTransporter();
    const tr = trState.transporter;
    const smtpUser = trState.smtpUser;
    const toAddress = (0, email_1.normalizeEmailAddress)(input.toAddress);
    const primarySuperadminEmail = await getPrimarySuperadminEmail();
    const configuredFrom = getAuthFromEmailFromEnv();
    const smtpUserEmail = (0, email_1.normalizeEmailAddress)(smtpUser);
    const attemptedFrom = primarySuperadminEmail || configuredFrom || smtpUserEmail;
    const usedFrom = smtpUserEmail || configuredFrom || attemptedFrom;
    const replyTo = primarySuperadminEmail || configuredFrom || null;
    let delivered = false;
    let providerMessageId = null;
    let providerResponse = null;
    let acceptedRecipients = [];
    let rejectedRecipients = [];
    let errorMessage = null;
    let fallbackUsed = false;
    try {
        if (!toAddress)
            throw new Error("Missing recipient address");
        if (!tr)
            throw new Error(trState.configError || "SMTP transport is not configured");
        if (!usedFrom)
            throw new Error("SMTP sender account is not configured");
        const firstOpts = {
            from: formatFromAddress(usedFrom),
            to: toAddress,
            subject: input.subject,
            text: input.text,
            html: input.html,
        };
        if (replyTo)
            firstOpts.replyTo = replyTo;
        const info = await tr.sendMail(firstOpts);
        providerMessageId = info?.messageId ? String(info.messageId) : null;
        providerResponse = info?.response ? String(info.response) : null;
        acceptedRecipients = Array.isArray(info?.accepted)
            ? info.accepted.map((v) => String(v || "").trim()).filter(Boolean)
            : [];
        rejectedRecipients = Array.isArray(info?.rejected)
            ? info.rejected.map((v) => String(v || "").trim()).filter(Boolean)
            : [];
        delivered = acceptedRecipients.length > 0 || rejectedRecipients.length === 0;
        if (!delivered) {
            errorMessage = "SMTP provider rejected recipient";
        }
    }
    catch (error) {
        // If the superadmin email was used as From somewhere, retry with smtpUser.
        const shouldRetryWithSmtpSender = Boolean(smtpUserEmail) &&
            Boolean(usedFrom) &&
            normalizeEmail(usedFrom) !== smtpUserEmail &&
            isFromRejectedError(error);
        if (shouldRetryWithSmtpSender) {
            fallbackUsed = true;
            try {
                const retryOpts = {
                    from: formatFromAddress(smtpUserEmail),
                    to: toAddress || String(input.toAddress || "").trim(),
                    subject: input.subject,
                    text: input.text,
                    html: input.html,
                };
                if (replyTo)
                    retryOpts.replyTo = replyTo;
                const info = await tr.sendMail(retryOpts);
                providerMessageId = info?.messageId ? String(info.messageId) : null;
                providerResponse = info?.response ? String(info.response) : null;
                acceptedRecipients = Array.isArray(info?.accepted)
                    ? info.accepted.map((v) => String(v || "").trim()).filter(Boolean)
                    : [];
                rejectedRecipients = Array.isArray(info?.rejected)
                    ? info.rejected.map((v) => String(v || "").trim()).filter(Boolean)
                    : [];
                delivered = acceptedRecipients.length > 0 || rejectedRecipients.length === 0;
                if (!delivered) {
                    errorMessage = "SMTP provider rejected recipient";
                }
            }
            catch (retryError) {
                errorMessage = summarizeMailError(retryError || error);
            }
        }
        else {
            errorMessage = summarizeMailError(error);
        }
    }
    if (delivered) {
        console.info("AUTH_EMAIL delivered", {
            template: input.template,
            toAddress,
            usedFrom,
            replyTo,
            providerMessageId,
            providerResponse,
            acceptedRecipients,
            rejectedRecipients,
            fallbackUsed,
        });
    }
    else {
        console.error("AUTH_EMAIL failed", {
            template: input.template,
            toAddress: toAddress || String(input.toAddress || "").trim(),
            usedFrom,
            replyTo,
            providerMessageId,
            providerResponse,
            acceptedRecipients,
            rejectedRecipients,
            error: errorMessage,
            fallbackUsed,
        });
    }
    try {
        await (0, auditService_1.createAuditLog)({
            userId: input.actorUserId || undefined,
            licenseeId: input.licenseeId || undefined,
            orgId: input.orgId || undefined,
            action: delivered ? "AUTH_EMAIL_SENT" : "AUTH_EMAIL_FAILED",
            entityType: "AuthEmail",
            entityId: null,
            details: {
                template: input.template,
                toAddress: toAddress || String(input.toAddress || "").trim(),
                subject: input.subject,
                attemptedFrom,
                usedFrom,
                replyTo,
                delivered,
                providerMessageId,
                providerResponse,
                acceptedRecipients,
                rejectedRecipients,
                error: errorMessage,
                fallbackUsed,
            },
            ipHash: input.ipHash || undefined,
            userAgent: input.userAgent || undefined,
        });
    }
    catch (e) {
        // Don't fail auth flows because audit email logging failed.
        console.error("AUTH_EMAIL audit log failed:", e);
    }
    return {
        delivered,
        error: errorMessage,
        attemptedFrom,
        usedFrom,
        replyTo,
        providerMessageId,
        providerResponse,
        acceptedRecipients,
        rejectedRecipients,
    };
};
exports.sendAuthEmail = sendAuthEmail;
//# sourceMappingURL=authEmailService.js.map
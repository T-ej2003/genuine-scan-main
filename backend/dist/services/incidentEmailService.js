"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.__resetIncidentEmailTransporterForTests = exports.getSuperadminAlertEmails = exports.sendIncidentEmail = void 0;
const nodemailer_1 = __importDefault(require("nodemailer"));
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("./auditService");
let transporter = null;
let transporterKey = null;
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
const getPreferredSuperadminEmailFromEnv = () => normalizeEmail(getFirstEnv("SUPER_ADMIN_EMAIL", "PLATFORM_SUPERADMIN_EMAIL", "SUPERADMIN_FROM_EMAIL", "EMAIL_FROM", "MAIL_FROM"));
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
    return {
        config: {
            host,
            user,
            pass,
            port,
            secure,
            source: explicitHost ? "env" : "inferred",
        },
    };
};
const getTransporter = () => {
    const { config, error } = resolveSmtpConfig();
    if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
        transporterKey = "jsonTransport";
        transporter = nodemailer_1.default.createTransport({ jsonTransport: true });
        return {
            transporter,
            configError: null,
            configSource: "json",
            smtpUser: normalizeEmail(getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER")),
        };
    }
    if (!config) {
        return {
            transporter: null,
            configError: error || "SMTP transport is not configured",
            configSource: null,
            smtpUser: null,
        };
    }
    const nextKey = `${config.host}|${config.port}|${config.secure}|${config.user}`;
    if (transporter && transporterKey === nextKey) {
        return {
            transporter,
            configError: null,
            configSource: config.source,
            smtpUser: normalizeEmail(config.user),
        };
    }
    transporterKey = nextKey;
    transporter = nodemailer_1.default.createTransport({
        host: config.host,
        port: config.port,
        secure: config.secure,
        auth: {
            user: config.user,
            pass: config.pass,
        },
    });
    return {
        transporter,
        configError: null,
        configSource: config.source,
        smtpUser: normalizeEmail(config.user),
    };
};
const preview = (body) => body.slice(0, 500);
const formatFromAddress = (email) => `"${getMailFromDisplayName()}" <${email}>`;
const isAdminRole = (role) => {
    const normalized = String(role || "").toUpperCase();
    return (normalized === client_1.UserRole.SUPER_ADMIN ||
        normalized === client_1.UserRole.PLATFORM_SUPER_ADMIN ||
        normalized === client_1.UserRole.LICENSEE_ADMIN ||
        normalized === client_1.UserRole.ORG_ADMIN);
};
const isFromRejectedError = (error) => {
    const message = String(error?.message || "").toLowerCase();
    const response = String(error?.response || "").toLowerCase();
    const code = String(error?.code || "").toUpperCase();
    const responseCode = Number(error?.responseCode || 0);
    const haystack = `${message} ${response}`;
    if (["EENVELOPE", "EADDRESS", "EAUTH"].includes(code)) {
        if (haystack.includes("sender") ||
            haystack.includes("from") ||
            haystack.includes("not allowed") ||
            haystack.includes("unauthorized")) {
            return true;
        }
    }
    if ([550, 552, 553, 554].includes(responseCode)) {
        if (haystack.includes("sender") ||
            haystack.includes("from") ||
            haystack.includes("not allowed") ||
            haystack.includes("unauthorized") ||
            haystack.includes("rejected") ||
            haystack.includes("not owned")) {
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
const resolveActorUser = async (actorUser) => {
    if (!actorUser)
        return null;
    const actorUserId = String(actorUser.id || "").trim();
    if (!actorUserId) {
        const email = normalizeEmail(actorUser.email);
        return {
            id: null,
            email,
            name: String(actorUser.name || "").trim() || null,
            role: actorUser.role || null,
        };
    }
    const dbUser = await database_1.default.user.findUnique({
        where: { id: actorUserId },
        select: {
            id: true,
            email: true,
            name: true,
            role: true,
            isActive: true,
            deletedAt: true,
        },
    });
    if (!dbUser || dbUser.deletedAt || dbUser.isActive === false) {
        return {
            id: actorUserId,
            email: normalizeEmail(actorUser.email),
            name: String(actorUser.name || "").trim() || null,
            role: actorUser.role || null,
        };
    }
    return {
        id: dbUser.id,
        email: normalizeEmail(dbUser.email),
        name: String(dbUser.name || "").trim() || null,
        role: dbUser.role,
    };
};
const getPrimarySuperadminEmail = async () => {
    const fromEnv = getPreferredSuperadminEmailFromEnv();
    if (fromEnv)
        return fromEnv;
    const primary = await database_1.default.user.findFirst({
        where: {
            role: { in: [client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN] },
            isActive: true,
            deletedAt: null,
        },
        orderBy: {
            createdAt: "asc",
        },
        select: { email: true },
    });
    return normalizeEmail(primary?.email);
};
const withSenderSignature = (text, senderEmail, senderName) => {
    const cleanText = String(text || "");
    if (!senderEmail)
        return cleanText;
    if (cleanText.toLowerCase().includes("sender:"))
        return cleanText;
    const name = String(senderName || "Incident response").trim() || "Incident response";
    return `${cleanText}\n\n---\nSender: ${name} <${senderEmail}>`;
};
const buildMailOptions = (input) => {
    const options = {
        from: formatFromAddress(input.usedFrom),
        to: input.toAddress,
        subject: input.subject,
        text: input.text,
        html: input.html,
    };
    if (input.replyTo)
        options.replyTo = input.replyTo;
    return options;
};
const sendIncidentEmail = async (input) => {
    const trState = getTransporter();
    const tr = trState.transporter;
    const smtpConfigSource = trState.configSource;
    const smtpUser = trState.smtpUser;
    const toAddress = normalizeEmail(input.toAddress);
    const actorUser = await resolveActorUser(input.actorUser);
    const senderMode = input.senderMode || (actorUser?.email ? "actor" : "system");
    let attemptedFrom = null;
    let usedFrom = null;
    let replyTo = null;
    let status = client_1.IncidentCommStatus.QUEUED;
    let providerMessageId = null;
    let errMessage = null;
    let fallbackUsed = false;
    if (senderMode === "actor") {
        if (actorUser?.role && !isAdminRole(actorUser.role)) {
            errMessage = "Only admin/superadmin can send incident emails";
        }
        else {
            attemptedFrom = actorUser?.email || null;
            usedFrom = attemptedFrom;
            replyTo = attemptedFrom;
        }
    }
    else {
        const primarySuperadminEmail = await getPrimarySuperadminEmail();
        attemptedFrom = actorUser?.email || primarySuperadminEmail || smtpUser;
        usedFrom = smtpUser || attemptedFrom;
        replyTo = actorUser?.email || primarySuperadminEmail || null;
    }
    const sendTextBase = String(input.text || "").trim();
    try {
        if (errMessage)
            throw new Error(errMessage);
        if (!toAddress)
            throw new Error("Missing recipient address");
        if (!tr)
            throw new Error(trState.configError || "SMTP transport is not configured");
        if (!usedFrom)
            throw new Error("SMTP sender account is not configured");
        if (senderMode === "actor" && !attemptedFrom) {
            throw new Error("Sender profile email is required in Account Settings");
        }
        const textForFirstAttempt = withSenderSignature(sendTextBase, replyTo && replyTo !== usedFrom ? replyTo : null, actorUser?.name || null);
        const firstInfo = await tr.sendMail(buildMailOptions({
            toAddress,
            subject: input.subject,
            text: textForFirstAttempt,
            html: input.html,
            usedFrom,
            replyTo,
        }));
        status = client_1.IncidentCommStatus.SENT;
        providerMessageId = firstInfo?.messageId ? String(firstInfo.messageId) : null;
    }
    catch (error) {
        const shouldRetryWithSmtpSender = Boolean(smtpUser) &&
            Boolean(usedFrom) &&
            normalizeEmail(usedFrom) !== smtpUser &&
            isFromRejectedError(error);
        if (shouldRetryWithSmtpSender) {
            fallbackUsed = true;
            usedFrom = smtpUser;
            replyTo = attemptedFrom || replyTo;
            try {
                const textForRetry = withSenderSignature(sendTextBase, replyTo, actorUser?.name || null);
                const retryInfo = await tr.sendMail(buildMailOptions({
                    toAddress: toAddress,
                    subject: input.subject,
                    text: textForRetry,
                    html: input.html,
                    usedFrom: usedFrom,
                    replyTo,
                }));
                status = client_1.IncidentCommStatus.SENT;
                providerMessageId = retryInfo?.messageId ? String(retryInfo.messageId) : null;
            }
            catch (retryError) {
                status = client_1.IncidentCommStatus.FAILED;
                errMessage = retryError?.message || error?.message || "Email delivery failed";
            }
        }
        else {
            status = client_1.IncidentCommStatus.FAILED;
            errMessage = error?.message || "Email delivery failed";
        }
    }
    await database_1.default.incidentCommunication.create({
        data: {
            incidentId: input.incidentId,
            direction: client_1.IncidentCommDirection.OUTBOUND,
            channel: client_1.IncidentCommChannel.EMAIL,
            toAddress: toAddress || String(input.toAddress || "").trim(),
            subject: input.subject,
            bodyPreview: preview(sendTextBase),
            attemptedFrom,
            usedFrom,
            replyTo,
            providerMessageId,
            errorMessage: errMessage,
            status,
        },
    });
    const actorType = actorUser?.id ? client_1.IncidentActorType.ADMIN : client_1.IncidentActorType.SYSTEM;
    await database_1.default.incidentEvent.create({
        data: {
            incidentId: input.incidentId,
            actorType,
            actorUserId: actorType === client_1.IncidentActorType.ADMIN ? actorUser?.id || null : null,
            eventType: client_1.IncidentEventType.EMAIL_SENT,
            eventPayload: {
                template: input.template || null,
                to_address: toAddress || String(input.toAddress || "").trim(),
                subject: input.subject,
                attempted_from: attemptedFrom,
                used_from: usedFrom,
                reply_to: replyTo,
                delivered: status === client_1.IncidentCommStatus.SENT,
                provider_message_id: providerMessageId,
                error: errMessage,
                fallback_used: fallbackUsed,
                sender_mode: senderMode,
                smtp_config_source: smtpConfigSource,
            },
        },
    });
    await (0, auditService_1.createAuditLog)({
        userId: actorUser?.id || undefined,
        licenseeId: input.licenseeId || undefined,
        action: "INCIDENT_EMAIL_SENT",
        entityType: "Incident",
        entityId: input.incidentId,
        details: {
            template: input.template || null,
            toAddress: toAddress || String(input.toAddress || "").trim(),
            subject: input.subject,
            attemptedFrom,
            usedFrom,
            replyTo,
            status,
            delivered: status === client_1.IncidentCommStatus.SENT,
            providerMessageId,
            error: errMessage,
            fallbackUsed,
            senderMode,
            smtpConfigSource,
        },
    });
    return {
        delivered: status === client_1.IncidentCommStatus.SENT,
        providerMessageId,
        error: errMessage,
        attemptedFrom,
        usedFrom,
        replyTo,
    };
};
exports.sendIncidentEmail = sendIncidentEmail;
const getSuperadminAlertEmails = async () => {
    const fromEnv = String(process.env.SUPERADMIN_ALERT_EMAILS || "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);
    const explicitPrimary = getPreferredSuperadminEmailFromEnv();
    if (fromEnv.length > 0) {
        return Array.from(new Set([...(explicitPrimary ? [explicitPrimary] : []), ...fromEnv]));
    }
    if (explicitPrimary)
        return [explicitPrimary];
    const users = await database_1.default.user.findMany({
        where: {
            role: { in: [client_1.UserRole.SUPER_ADMIN, client_1.UserRole.PLATFORM_SUPER_ADMIN] },
            isActive: true,
            deletedAt: null,
        },
        select: { email: true },
    });
    return Array.from(new Set(users.map((u) => normalizeEmail(u.email)).filter(Boolean)));
};
exports.getSuperadminAlertEmails = getSuperadminAlertEmails;
const __resetIncidentEmailTransporterForTests = () => {
    transporter = null;
    transporterKey = null;
};
exports.__resetIncidentEmailTransporterForTests = __resetIncidentEmailTransporterForTests;
//# sourceMappingURL=incidentEmailService.js.map
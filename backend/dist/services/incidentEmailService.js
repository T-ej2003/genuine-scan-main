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
const smtpPort = Number(process.env.SMTP_PORT || "587");
const getTransporter = () => {
    if (transporter)
        return transporter;
    if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
        transporter = nodemailer_1.default.createTransport({ jsonTransport: true });
        return transporter;
    }
    const host = String(process.env.SMTP_HOST || "").trim();
    const user = String(process.env.SMTP_USER || "").trim();
    const pass = String(process.env.SMTP_PASS || "").trim();
    const secure = parseBool(process.env.SMTP_SECURE, smtpPort === 465);
    if (!host || !user || !pass)
        return null;
    transporter = nodemailer_1.default.createTransport({
        host,
        port: smtpPort,
        secure,
        auth: {
            user,
            pass,
        },
    });
    return transporter;
};
const preview = (body) => body.slice(0, 500);
const formatFromAddress = (email) => `"AuthenticQR" <${email}>`;
const isAdminRole = (role) => {
    const normalized = String(role || "").toUpperCase();
    return normalized === client_1.UserRole.SUPER_ADMIN || normalized === client_1.UserRole.LICENSEE_ADMIN;
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
    const primary = await database_1.default.user.findFirst({
        where: {
            role: client_1.UserRole.SUPER_ADMIN,
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
    const tr = getTransporter();
    const smtpUser = normalizeEmail(process.env.SMTP_USER);
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
            throw new Error("SMTP transport is not configured");
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
    if (fromEnv.length > 0)
        return Array.from(new Set(fromEnv));
    const users = await database_1.default.user.findMany({
        where: {
            role: client_1.UserRole.SUPER_ADMIN,
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
};
exports.__resetIncidentEmailTransporterForTests = __resetIncidentEmailTransporterForTests;
//# sourceMappingURL=incidentEmailService.js.map
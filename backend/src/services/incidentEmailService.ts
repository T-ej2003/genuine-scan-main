import nodemailer, { SendMailOptions, Transporter } from "nodemailer";
import {
  IncidentActorType,
  IncidentCommChannel,
  IncidentCommDirection,
  IncidentCommStatus,
  IncidentEventType,
  UserRole,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";

type IncidentEmailActorUser = {
  id?: string | null;
  role?: UserRole | string | null;
  email?: string | null;
  name?: string | null;
};

type SendIncidentEmailInput = {
  incidentId: string;
  licenseeId?: string | null;
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  actorUser?: IncidentEmailActorUser | null;
  senderMode?: "actor" | "system";
  template?: string;
};

type SendIncidentEmailResult = {
  delivered: boolean;
  providerMessageId?: string | null;
  error?: string | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
};

let transporter: Transporter | null = null;
let transporterKey: string | null = null;

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const normalizeEmail = (value: unknown) => {
  const email = String(value || "").trim().toLowerCase();
  return email || null;
};

const getFirstEnv = (...keys: string[]) => {
  for (const key of keys) {
    const value = String(process.env[key] || "").trim();
    if (value) return value;
  }
  return "";
};

type ResolvedSmtpConfig = {
  host: string;
  user: string;
  pass: string;
  port: number;
  secure: boolean;
  source: "env" | "inferred";
};

const inferHostFromUserEmail = (userEmail: string) => {
  const domain = String(userEmail.split("@")[1] || "").toLowerCase().trim();
  if (!domain) return null;

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

const resolveSmtpConfig = (): { config: ResolvedSmtpConfig | null; error?: string } => {
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
      error:
        "SMTP transport is not configured (missing SMTP_HOST and could not infer provider from SMTP_USER)",
    };
  }

  const defaultPort = inferred?.port || 587;
  const parsedPort = Number(getFirstEnv("SMTP_PORT", "EMAIL_PORT", "MAIL_PORT") || defaultPort);
  const port = Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : defaultPort;
  const secure = parseBool(
    getFirstEnv("SMTP_SECURE", "EMAIL_SECURE", "MAIL_SECURE"),
    inferred ? inferred.secure : port === 465
  );

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
    transporter = nodemailer.createTransport({ jsonTransport: true });
    return {
      transporter,
      configError: null as string | null,
      configSource: "json" as const,
      smtpUser: normalizeEmail(getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER")),
    };
  }

  if (!config) {
    return {
      transporter: null,
      configError: error || "SMTP transport is not configured",
      configSource: null as string | null,
      smtpUser: null as string | null,
    };
  }

  const nextKey = `${config.host}|${config.port}|${config.secure}|${config.user}`;
  if (transporter && transporterKey === nextKey) {
    return {
      transporter,
      configError: null as string | null,
      configSource: config.source,
      smtpUser: normalizeEmail(config.user),
    };
  }

  transporterKey = nextKey;
  transporter = nodemailer.createTransport({
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
    configError: null as string | null,
    configSource: config.source,
    smtpUser: normalizeEmail(config.user),
  };
};

const preview = (body: string) => body.slice(0, 500);

const formatFromAddress = (email: string) => `"AuthenticQR" <${email}>`;

const isAdminRole = (role?: UserRole | string | null) => {
  const normalized = String(role || "").toUpperCase();
  return (
    normalized === UserRole.SUPER_ADMIN ||
    normalized === UserRole.PLATFORM_SUPER_ADMIN ||
    normalized === UserRole.LICENSEE_ADMIN ||
    normalized === UserRole.ORG_ADMIN
  );
};

const isFromRejectedError = (error: any) => {
  const message = String(error?.message || "").toLowerCase();
  const response = String(error?.response || "").toLowerCase();
  const code = String(error?.code || "").toUpperCase();
  const responseCode = Number(error?.responseCode || 0);

  const haystack = `${message} ${response}`;

  if (["EENVELOPE", "EADDRESS", "EAUTH"].includes(code)) {
    if (
      haystack.includes("sender") ||
      haystack.includes("from") ||
      haystack.includes("not allowed") ||
      haystack.includes("unauthorized")
    ) {
      return true;
    }
  }

  if ([550, 552, 553, 554].includes(responseCode)) {
    if (
      haystack.includes("sender") ||
      haystack.includes("from") ||
      haystack.includes("not allowed") ||
      haystack.includes("unauthorized") ||
      haystack.includes("rejected") ||
      haystack.includes("not owned")
    ) {
      return true;
    }
  }

  return (
    haystack.includes("sender address rejected") ||
    haystack.includes("sender rejected") ||
    haystack.includes("from address") ||
    haystack.includes("from header") ||
    haystack.includes("not permitted") ||
    haystack.includes("not owned") ||
    haystack.includes("unauthorized")
  );
};

const resolveActorUser = async (actorUser?: IncidentEmailActorUser | null) => {
  if (!actorUser) return null;

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

  const dbUser = await prisma.user.findUnique({
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
  const primary = await prisma.user.findFirst({
    where: {
      role: { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] },
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

const withSenderSignature = (text: string, senderEmail?: string | null, senderName?: string | null) => {
  const cleanText = String(text || "");
  if (!senderEmail) return cleanText;
  if (cleanText.toLowerCase().includes("sender:")) return cleanText;
  const name = String(senderName || "Incident response").trim() || "Incident response";
  return `${cleanText}\n\n---\nSender: ${name} <${senderEmail}>`;
};

const buildMailOptions = (input: {
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  usedFrom: string;
  replyTo?: string | null;
}) => {
  const options: SendMailOptions = {
    from: formatFromAddress(input.usedFrom),
    to: input.toAddress,
    subject: input.subject,
    text: input.text,
    html: input.html,
  };
  if (input.replyTo) options.replyTo = input.replyTo;
  return options;
};

export const sendIncidentEmail = async (input: SendIncidentEmailInput): Promise<SendIncidentEmailResult> => {
  const trState = getTransporter();
  const tr = trState.transporter;
  const smtpConfigSource = trState.configSource;
  const smtpUser = trState.smtpUser;
  const toAddress = normalizeEmail(input.toAddress);
  const actorUser = await resolveActorUser(input.actorUser);
  const senderMode = input.senderMode || (actorUser?.email ? "actor" : "system");

  let attemptedFrom: string | null = null;
  let usedFrom: string | null = null;
  let replyTo: string | null = null;
  let status: IncidentCommStatus = IncidentCommStatus.QUEUED;
  let providerMessageId: string | null = null;
  let errMessage: string | null = null;
  let fallbackUsed = false;

  if (senderMode === "actor") {
    if (actorUser?.role && !isAdminRole(actorUser.role)) {
      errMessage = "Only admin/superadmin can send incident emails";
    } else {
      attemptedFrom = actorUser?.email || null;
      usedFrom = attemptedFrom;
      replyTo = attemptedFrom;
    }
  } else {
    const primarySuperadminEmail = await getPrimarySuperadminEmail();
    attemptedFrom = actorUser?.email || primarySuperadminEmail || smtpUser;
    usedFrom = smtpUser || attemptedFrom;
    replyTo = actorUser?.email || primarySuperadminEmail || null;
  }

  const sendTextBase = String(input.text || "").trim();

  try {
    if (errMessage) throw new Error(errMessage);
    if (!toAddress) throw new Error("Missing recipient address");
    if (!tr) throw new Error(trState.configError || "SMTP transport is not configured");
    if (!usedFrom) throw new Error("SMTP sender account is not configured");

    if (senderMode === "actor" && !attemptedFrom) {
      throw new Error("Sender profile email is required in Account Settings");
    }

    const textForFirstAttempt = withSenderSignature(
      sendTextBase,
      replyTo && replyTo !== usedFrom ? replyTo : null,
      actorUser?.name || null
    );

    const firstInfo = await tr.sendMail(
      buildMailOptions({
        toAddress,
        subject: input.subject,
        text: textForFirstAttempt,
        html: input.html,
        usedFrom,
        replyTo,
      })
    );

    status = IncidentCommStatus.SENT;
    providerMessageId = firstInfo?.messageId ? String(firstInfo.messageId) : null;
  } catch (error: any) {
    const shouldRetryWithSmtpSender =
      Boolean(smtpUser) &&
      Boolean(usedFrom) &&
      normalizeEmail(usedFrom) !== smtpUser &&
      isFromRejectedError(error);

    if (shouldRetryWithSmtpSender) {
      fallbackUsed = true;
      usedFrom = smtpUser;
      replyTo = attemptedFrom || replyTo;
      try {
        const textForRetry = withSenderSignature(sendTextBase, replyTo, actorUser?.name || null);
        const retryInfo = await tr!.sendMail(
          buildMailOptions({
            toAddress: toAddress!,
            subject: input.subject,
            text: textForRetry,
            html: input.html,
            usedFrom: usedFrom as string,
            replyTo,
          })
        );
        status = IncidentCommStatus.SENT;
        providerMessageId = retryInfo?.messageId ? String(retryInfo.messageId) : null;
      } catch (retryError: any) {
        status = IncidentCommStatus.FAILED;
        errMessage = retryError?.message || error?.message || "Email delivery failed";
      }
    } else {
      status = IncidentCommStatus.FAILED;
      errMessage = error?.message || "Email delivery failed";
    }
  }

  await prisma.incidentCommunication.create({
    data: {
      incidentId: input.incidentId,
      direction: IncidentCommDirection.OUTBOUND,
      channel: IncidentCommChannel.EMAIL,
      toAddress: toAddress || String(input.toAddress || "").trim(),
      subject: input.subject,
      bodyPreview: preview(sendTextBase),
      attemptedFrom,
      usedFrom,
      replyTo,
      providerMessageId,
      errorMessage: errMessage,
      status,
    } as any,
  });

  const actorType = actorUser?.id ? IncidentActorType.ADMIN : IncidentActorType.SYSTEM;

  await prisma.incidentEvent.create({
    data: {
      incidentId: input.incidentId,
      actorType,
      actorUserId: actorType === IncidentActorType.ADMIN ? actorUser?.id || null : null,
      eventType: IncidentEventType.EMAIL_SENT,
      eventPayload: {
        template: input.template || null,
        to_address: toAddress || String(input.toAddress || "").trim(),
        subject: input.subject,
        attempted_from: attemptedFrom,
        used_from: usedFrom,
        reply_to: replyTo,
        delivered: status === IncidentCommStatus.SENT,
        provider_message_id: providerMessageId,
        error: errMessage,
        fallback_used: fallbackUsed,
        sender_mode: senderMode,
        smtp_config_source: smtpConfigSource,
      },
    },
  });

  await createAuditLog({
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
      delivered: status === IncidentCommStatus.SENT,
      providerMessageId,
      error: errMessage,
      fallbackUsed,
      senderMode,
      smtpConfigSource,
    },
  });

  return {
    delivered: status === IncidentCommStatus.SENT,
    providerMessageId,
    error: errMessage,
    attemptedFrom,
    usedFrom,
    replyTo,
  };
};

export const getSuperadminAlertEmails = async (): Promise<string[]> => {
  const fromEnv = String(process.env.SUPERADMIN_ALERT_EMAILS || "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  if (fromEnv.length > 0) return Array.from(new Set(fromEnv));

  const users = await prisma.user.findMany({
    where: {
      role: { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] },
      isActive: true,
      deletedAt: null,
    },
    select: { email: true },
  });

  return Array.from(new Set(users.map((u) => normalizeEmail(u.email)).filter(Boolean) as string[]));
};

export const __resetIncidentEmailTransporterForTests = () => {
  transporter = null;
  transporterKey = null;
};

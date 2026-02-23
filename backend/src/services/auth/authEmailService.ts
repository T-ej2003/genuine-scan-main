import nodemailer, { type SendMailOptions, type Transporter } from "nodemailer";
import prisma from "../../config/database";
import { createAuditLog } from "../auditService";
import { UserRole } from "@prisma/client";

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

const getMailFromDisplayName = () =>
  String(getFirstEnv("MAIL_FROM_NAME", "EMAIL_FROM_NAME", "APP_NAME") || "MSCQR").trim() || "MSCQR";

const getPreferredSuperadminEmailFromEnv = () =>
  normalizeEmail(
    getFirstEnv(
      "SUPER_ADMIN_EMAIL",
      "PLATFORM_SUPERADMIN_EMAIL",
      "SUPERADMIN_FROM_EMAIL",
      "EMAIL_FROM",
      "MAIL_FROM"
    )
  );

type ResolvedSmtpConfig = {
  host: string;
  user: string;
  pass: string;
  port: number;
  secure: boolean;
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
  const secure = parseBool(getFirstEnv("SMTP_SECURE", "EMAIL_SECURE", "MAIL_SECURE"), inferred ? inferred.secure : port === 465);

  return { config: { host, user, pass, port, secure } };
};

let transporter: Transporter | null = null;
let transporterKey: string | null = null;

const getTransporter = () => {
  if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
    transporterKey = "jsonTransport";
    transporter = nodemailer.createTransport({ jsonTransport: true });
    return { transporter, smtpUser: normalizeEmail(getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER")), configError: null as string | null };
  }

  const { config, error } = resolveSmtpConfig();
  if (!config) return { transporter: null, smtpUser: null as string | null, configError: error || "SMTP transport is not configured" };

  const nextKey = `${config.host}|${config.port}|${config.secure}|${config.user}`;
  if (transporter && transporterKey === nextKey) {
    return { transporter, smtpUser: normalizeEmail(config.user), configError: null as string | null };
  }

  transporterKey = nextKey;
  transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: { user: config.user, pass: config.pass },
  });

  return { transporter, smtpUser: normalizeEmail(config.user), configError: null as string | null };
};

const formatFromAddress = (email: string) => `"${getMailFromDisplayName()}" <${email}>`;

const isFromRejectedError = (error: any) => {
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

const getPrimarySuperadminEmail = async () => {
  const fromEnv = getPreferredSuperadminEmailFromEnv();
  if (fromEnv) return fromEnv;

  const primary = await prisma.user.findFirst({
    where: {
      // accept both legacy and new role names
      role: { in: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN] },
      isActive: true,
      deletedAt: null,
    },
    orderBy: { createdAt: "asc" },
    select: { email: true },
  });
  return normalizeEmail(primary?.email);
};

export const sendAuthEmail = async (input: {
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  template: string;
  orgId?: string | null;
  licenseeId?: string | null;
  actorUserId?: string | null;
  ipHash?: string | null;
  userAgent?: string | null;
}): Promise<{ delivered: boolean; error?: string | null; attemptedFrom?: string | null; usedFrom?: string | null; replyTo?: string | null; providerMessageId?: string | null }> => {
  const trState = getTransporter();
  const tr = trState.transporter;
  const smtpUser = trState.smtpUser;
  const toAddress = normalizeEmail(input.toAddress);

  const primarySuperadminEmail = await getPrimarySuperadminEmail();
  const attemptedFrom = primarySuperadminEmail || smtpUser;
  const usedFrom = smtpUser || attemptedFrom;
  const replyTo = primarySuperadminEmail || null;

  let delivered = false;
  let providerMessageId: string | null = null;
  let errorMessage: string | null = null;
  let fallbackUsed = false;

  try {
    if (!toAddress) throw new Error("Missing recipient address");
    if (!tr) throw new Error(trState.configError || "SMTP transport is not configured");
    if (!usedFrom) throw new Error("SMTP sender account is not configured");

    const firstOpts: SendMailOptions = {
      from: formatFromAddress(usedFrom),
      to: toAddress,
      subject: input.subject,
      text: input.text,
      html: input.html,
    };
    if (replyTo) firstOpts.replyTo = replyTo;

    const info = await tr.sendMail(firstOpts);
    delivered = true;
    providerMessageId = info?.messageId ? String(info.messageId) : null;
  } catch (error: any) {
    // If the superadmin email was used as From somewhere, retry with smtpUser.
    const shouldRetryWithSmtpSender =
      Boolean(smtpUser) && Boolean(usedFrom) && normalizeEmail(usedFrom) !== smtpUser && isFromRejectedError(error);

    if (shouldRetryWithSmtpSender) {
      fallbackUsed = true;
      try {
        const retryOpts: SendMailOptions = {
          from: formatFromAddress(smtpUser as string),
          to: toAddress || String(input.toAddress || "").trim(),
          subject: input.subject,
          text: input.text,
          html: input.html,
        };
        if (replyTo) retryOpts.replyTo = replyTo;
        const info = await tr!.sendMail(retryOpts);
        delivered = true;
        providerMessageId = info?.messageId ? String(info.messageId) : null;
      } catch (retryError: any) {
        errorMessage = retryError?.message || error?.message || "Email delivery failed";
      }
    } else {
      errorMessage = error?.message || "Email delivery failed";
    }
  }

  try {
    await createAuditLog({
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
        error: errorMessage,
        fallbackUsed,
      },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
  } catch (e) {
    // Don't fail auth flows because audit email logging failed.
    console.error("AUTH_EMAIL audit log failed:", e);
  }

  return { delivered, error: errorMessage, attemptedFrom, usedFrom, replyTo, providerMessageId };
};

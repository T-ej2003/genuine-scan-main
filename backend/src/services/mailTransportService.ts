import nodemailer, { type SendMailOptions, type Transporter } from "nodemailer";
import { normalizeEmailAddress } from "../utils/email";

export type EmailErrorCode =
  | "SMTP_CONFIG_MISSING"
  | "SMTP_AUTH_FAILED"
  | "SMTP_CONNECTION_FAILED"
  | "SMTP_TIMEOUT"
  | "SMTP_SEND_FAILED"
  | "EMAIL_DISABLED"
  | "UNKNOWN_EMAIL_ERROR";

export type MailDeliveryResult = {
  delivered: boolean;
  errorCode?: EmailErrorCode | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  providerMessageId?: string | null;
  acceptedRecipients?: string[];
  rejectedRecipients?: string[];
  fallbackUsed?: boolean;
};

type ResolvedSmtpConfig = {
  host: string;
  user: string;
  pass: string;
  port: number;
  secure: boolean;
  source: "env" | "inferred";
};

type TransportState = {
  transporter: Transporter | null;
  smtpUser: string | null;
  configErrorCode: EmailErrorCode | null;
  configSource: "env" | "inferred" | "json" | null;
};

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parsePositiveInt = (value: unknown, fallback: number) => {
  const parsed = Number(String(value ?? "").trim());
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
};

const getFirstEnv = (...keys: string[]) => {
  for (const key of keys) {
    const value = String(process.env[key] || "").trim();
    if (value) return value;
  }
  return "";
};

const normalizeEmail = (value: unknown) => normalizeEmailAddress(value);

export const maskEmailForLog = (value: unknown) => {
  const email = normalizeEmail(value);
  if (!email) return null;
  const [local, domain] = email.split("@");
  if (!local || !domain) return "[REDACTED]";
  const visible = local.length <= 2 ? `${local[0] || ""}*` : `${local.slice(0, 2)}***`;
  return `${visible}@${domain}`;
};

export const getMailFromDisplayName = () =>
  String(getFirstEnv("MAIL_FROM_NAME", "EMAIL_FROM_NAME", "APP_NAME") || "MSCQR").trim() || "MSCQR";

export const getConfiguredMailFrom = () =>
  normalizeEmail(getFirstEnv("SMTP_FROM", "AUTH_EMAIL_FROM", "EMAIL_FROM", "MAIL_FROM", "SUPERADMIN_FROM_EMAIL"));

export const getPreferredSuperadminEmailFromEnv = () =>
  normalizeEmail(
    getFirstEnv(
      "SUPER_ADMIN_EMAIL",
      "PLATFORM_SUPERADMIN_EMAIL",
      "SUPERADMIN_FROM_EMAIL",
      "EMAIL_FROM",
      "MAIL_FROM"
    )
  );

const inferHostFromUserEmail = (userEmail: string) => {
  const domain = String(userEmail.split("@")[1] || "").toLowerCase().trim();
  if (!domain) return null;

  if (domain === "gmail.com" || domain === "googlemail.com") return { host: "smtp.gmail.com", port: 465, secure: true };
  if (["outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com"].includes(domain)) {
    return { host: "smtp.office365.com", port: 587, secure: false };
  }
  if (domain.includes("yahoo.")) return { host: "smtp.mail.yahoo.com", port: 465, secure: true };
  if (["icloud.com", "me.com", "mac.com"].includes(domain)) return { host: "smtp.mail.me.com", port: 587, secure: false };
  if (domain === "zoho.com" || domain.endsWith(".zoho.com")) return { host: "smtp.zoho.com", port: 465, secure: true };

  return null;
};

const resolveSmtpConfig = (): { config: ResolvedSmtpConfig | null; errorCode?: EmailErrorCode } => {
  const user = getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER");
  const pass = getFirstEnv("SMTP_PASS", "SMTP_PASSWORD", "EMAIL_PASS", "MAIL_PASS", "MAIL_PASSWORD");
  const explicitHost = getFirstEnv("SMTP_HOST", "EMAIL_HOST", "MAIL_HOST");

  if (!user || !pass) return { config: null, errorCode: "SMTP_CONFIG_MISSING" };

  const inferred = explicitHost ? null : inferHostFromUserEmail(user);
  const host = explicitHost || inferred?.host || "";
  if (!host) return { config: null, errorCode: "SMTP_CONFIG_MISSING" };

  const defaultPort = inferred?.port || 587;
  const port = parsePositiveInt(getFirstEnv("SMTP_PORT", "EMAIL_PORT", "MAIL_PORT"), defaultPort);
  const secure = parseBool(getFirstEnv("SMTP_SECURE", "EMAIL_SECURE", "MAIL_SECURE"), inferred ? inferred.secure : port === 465);

  return { config: { host, user, pass, port, secure, source: explicitHost ? "env" : "inferred" } };
};

let transporter: Transporter | null = null;
let transporterKey: string | null = null;

export const getMailTransportState = (): TransportState => {
  if (parseBool(process.env.EMAIL_DISABLED || process.env.MAIL_DISABLED, false)) {
    return { transporter: null, smtpUser: null, configErrorCode: "EMAIL_DISABLED", configSource: null };
  }

  if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
    transporterKey = "jsonTransport";
    transporter = nodemailer.createTransport({ jsonTransport: true });
    return {
      transporter,
      smtpUser: normalizeEmail(getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER")),
      configErrorCode: null,
      configSource: "json",
    };
  }

  const { config, errorCode } = resolveSmtpConfig();
  if (!config) return { transporter: null, smtpUser: null, configErrorCode: errorCode || "SMTP_CONFIG_MISSING", configSource: null };

  const nextKey = `${config.host}|${config.port}|${config.secure}|${config.user}`;
  if (transporter && transporterKey === nextKey) {
    return { transporter, smtpUser: normalizeEmail(config.user), configErrorCode: null, configSource: config.source };
  }

  transporterKey = nextKey;
  transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: { user: config.user, pass: config.pass },
    connectionTimeout: parsePositiveInt(process.env.SMTP_CONNECTION_TIMEOUT_MS, 8_000),
    greetingTimeout: parsePositiveInt(process.env.SMTP_GREETING_TIMEOUT_MS, 8_000),
    socketTimeout: parsePositiveInt(process.env.SMTP_SOCKET_TIMEOUT_MS, 10_000),
  });

  return { transporter, smtpUser: normalizeEmail(config.user), configErrorCode: null, configSource: config.source };
};

export const formatFromAddress = (email: string) => `"${getMailFromDisplayName()}" <${email}>`;

const classifyMailError = (error: any): EmailErrorCode => {
  if (error?.name === "EmailTimeoutError") return "SMTP_TIMEOUT";
  const code = String(error?.code || "").toUpperCase();
  const responseCode = Number(error?.responseCode || 0);
  const message = String(error?.message || "").toLowerCase();
  const response = String(error?.response || "").toLowerCase();
  const haystack = `${message} ${response}`;

  if (code === "EAUTH" || responseCode === 535 || haystack.includes("authentication")) return "SMTP_AUTH_FAILED";
  if (["ECONNECTION", "ECONNREFUSED", "ETIMEDOUT", "ESOCKET", "EDNS"].includes(code)) return "SMTP_CONNECTION_FAILED";
  if (code === "ETIMEDOUT" || haystack.includes("timeout") || haystack.includes("timed out")) return "SMTP_TIMEOUT";
  if (code || responseCode) return "SMTP_SEND_FAILED";
  return "UNKNOWN_EMAIL_ERROR";
};

export const isFromRejectedMailError = (error: any) => {
  const message = String(error?.message || "").toLowerCase();
  const response = String(error?.response || "").toLowerCase();
  const code = String(error?.code || "").toUpperCase();
  const responseCode = Number(error?.responseCode || 0);
  const haystack = `${message} ${response}`;

  if (["EENVELOPE", "EADDRESS", "EAUTH"].includes(code)) {
    if (haystack.includes("sender") || haystack.includes("from") || haystack.includes("not allowed") || haystack.includes("unauthorized")) return true;
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

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number): Promise<T> => {
  let timer: NodeJS.Timeout | null = null;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      const error = new Error("Email send timed out");
      error.name = "EmailTimeoutError";
      reject(error);
    }, timeoutMs);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const summarizeInfo = (info: any) => {
  const acceptedRecipients = Array.isArray(info?.accepted)
    ? info.accepted.map((value: any) => String(value || "").trim()).filter(Boolean)
    : [];
  const rejectedRecipients = Array.isArray(info?.rejected)
    ? info.rejected.map((value: any) => String(value || "").trim()).filter(Boolean)
    : [];
  const delivered = acceptedRecipients.length > 0 || rejectedRecipients.length === 0;
  return {
    delivered,
    providerMessageId: info?.messageId ? String(info.messageId) : null,
    acceptedRecipients,
    rejectedRecipients,
  };
};

export const sendMailSafely = async (input: {
  toAddress: string;
  subject: string;
  text: string;
  html?: string;
  fromAddress?: string | null;
  fallbackFromAddress?: string | null;
  replyTo?: string | null;
  template?: string | null;
}): Promise<MailDeliveryResult> => {
  const transportState = getMailTransportState();
  const toAddress = normalizeEmail(input.toAddress);
  const fromAddress = normalizeEmail(input.fromAddress) || transportState.smtpUser || getConfiguredMailFrom();
  const fallbackFromAddress = normalizeEmail(input.fallbackFromAddress) || transportState.smtpUser || null;
  const replyTo = normalizeEmail(input.replyTo);
  const timeoutMs = parsePositiveInt(process.env.EMAIL_SEND_TIMEOUT_MS || process.env.SMTP_SEND_TIMEOUT_MS, 10_000);

  const baseResult = {
    attemptedFrom: fromAddress,
    usedFrom: fromAddress,
    replyTo,
    providerMessageId: null,
    acceptedRecipients: [] as string[],
    rejectedRecipients: [] as string[],
    fallbackUsed: false,
  };

  const logMeta = (result: MailDeliveryResult) => ({
    template: input.template || null,
    toAddress: maskEmailForLog(toAddress),
    attemptedFrom: maskEmailForLog(result.attemptedFrom),
    usedFrom: maskEmailForLog(result.usedFrom),
    replyTo: maskEmailForLog(result.replyTo),
    providerMessageId: result.providerMessageId || null,
    acceptedRecipients: (result.acceptedRecipients || []).map(maskEmailForLog).filter(Boolean),
    rejectedRecipients: (result.rejectedRecipients || []).map(maskEmailForLog).filter(Boolean),
    emailErrorCode: result.errorCode || null,
    fallbackUsed: Boolean(result.fallbackUsed),
  });

  try {
    if (!toAddress) throw Object.assign(new Error("Missing recipient address"), { code: "EADDRESS" });
    if (!transportState.transporter) {
      const result: MailDeliveryResult = {
        ...baseResult,
        delivered: false,
        errorCode: transportState.configErrorCode || "SMTP_CONFIG_MISSING",
      };
      console.error("MAIL delivery skipped", logMeta(result));
      return result;
    }
    if (!fromAddress) {
      const result: MailDeliveryResult = { ...baseResult, delivered: false, errorCode: "SMTP_CONFIG_MISSING" };
      console.error("MAIL delivery skipped", logMeta(result));
      return result;
    }

    const options: SendMailOptions = {
      from: formatFromAddress(fromAddress),
      to: toAddress,
      subject: input.subject,
      text: input.text,
      html: input.html,
    };
    if (replyTo) options.replyTo = replyTo;

    const info = await withTimeout(transportState.transporter.sendMail(options), timeoutMs);
    const summary = summarizeInfo(info);
    const result: MailDeliveryResult = {
      ...baseResult,
      delivered: summary.delivered,
      errorCode: summary.delivered ? null : "SMTP_SEND_FAILED",
      providerMessageId: summary.providerMessageId,
      acceptedRecipients: summary.acceptedRecipients,
      rejectedRecipients: summary.rejectedRecipients,
    };
    console[summary.delivered ? "info" : "error"]("MAIL delivery completed", logMeta(result));
    return result;
  } catch (error: any) {
    if (fallbackFromAddress && fromAddress && fallbackFromAddress !== fromAddress && isFromRejectedMailError(error)) {
      try {
        const retryOptions: SendMailOptions = {
          from: formatFromAddress(fallbackFromAddress),
          to: toAddress || String(input.toAddress || "").trim(),
          subject: input.subject,
          text: input.text,
          html: input.html,
        };
        if (replyTo) retryOptions.replyTo = replyTo;
        const retryInfo = await withTimeout(transportState.transporter!.sendMail(retryOptions), timeoutMs);
        const summary = summarizeInfo(retryInfo);
        const result: MailDeliveryResult = {
          ...baseResult,
          delivered: summary.delivered,
          errorCode: summary.delivered ? null : "SMTP_SEND_FAILED",
          usedFrom: fallbackFromAddress,
          providerMessageId: summary.providerMessageId,
          acceptedRecipients: summary.acceptedRecipients,
          rejectedRecipients: summary.rejectedRecipients,
          fallbackUsed: true,
        };
        console[summary.delivered ? "info" : "error"]("MAIL delivery completed", logMeta(result));
        return result;
      } catch (retryError: any) {
        const result: MailDeliveryResult = {
          ...baseResult,
          delivered: false,
          errorCode: classifyMailError(retryError || error),
          usedFrom: fallbackFromAddress,
          fallbackUsed: true,
        };
        console.error("MAIL delivery failed", logMeta(result));
        return result;
      }
    }

    const result: MailDeliveryResult = {
      ...baseResult,
      delivered: false,
      errorCode: classifyMailError(error),
    };
    console.error("MAIL delivery failed", logMeta(result));
    return result;
  }
};

export const __resetMailTransporterForTests = () => {
  transporter = null;
  transporterKey = null;
};

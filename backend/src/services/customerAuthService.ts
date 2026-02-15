import { createHash, randomInt } from "crypto";
import nodemailer, { type Transporter } from "nodemailer";
import { CustomerAuthProvider } from "@prisma/client";

import prisma from "../config/database";

const OTP_TTL_MINUTES = Number(process.env.CUSTOMER_OTP_TTL_MINUTES || "10");
const OTP_MAX_ATTEMPTS = Number(process.env.CUSTOMER_OTP_MAX_ATTEMPTS || "5");
const OTP_RATE_WINDOW_MINUTES = Number(process.env.CUSTOMER_OTP_RATE_WINDOW_MINUTES || "10");
const OTP_RATE_MAX_PER_WINDOW = Number(process.env.CUSTOMER_OTP_RATE_MAX_PER_WINDOW || "5");

let transport: Transporter | null = null;
let transportKey: string | null = null;

const normalizeEmail = (value: unknown) => String(value || "").trim().toLowerCase();

const getAuthSalt = () =>
  String(process.env.CUSTOMER_OTP_SALT || process.env.SESSION_SECRET || process.env.JWT_SECRET || "customer-otp-salt");

const hashOtp = (email: string, otp: string) =>
  createHash("sha256")
    .update(`${getAuthSalt()}:${normalizeEmail(email)}:${String(otp || "").trim()}`)
    .digest("hex");

const getFirstEnv = (...keys: string[]) => {
  for (const key of keys) {
    const value = String(process.env[key] || "").trim();
    if (value) return value;
  }
  return "";
};

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
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
  return null;
};

const resolveTransport = () => {
  if (parseBool(process.env.EMAIL_USE_JSON_TRANSPORT, false)) {
    if (!transport || transportKey !== "json") {
      transport = nodemailer.createTransport({ jsonTransport: true });
      transportKey = "json";
    }
    return { transporter: transport, fromEmail: getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER") || null };
  }

  const user = getFirstEnv("SMTP_USER", "SMTP_USERNAME", "EMAIL_USER", "MAIL_USER");
  const pass = getFirstEnv("SMTP_PASS", "SMTP_PASSWORD", "EMAIL_PASS", "MAIL_PASS", "MAIL_PASSWORD");
  const explicitHost = getFirstEnv("SMTP_HOST", "EMAIL_HOST", "MAIL_HOST");
  const inferred = explicitHost ? null : inferHostFromUserEmail(user);
  const host = explicitHost || inferred?.host || "";

  if (!user || !pass || !host) {
    return { transporter: null as Transporter | null, fromEmail: user || null };
  }

  const defaultPort = inferred?.port || 587;
  const parsedPort = Number(getFirstEnv("SMTP_PORT", "EMAIL_PORT", "MAIL_PORT") || defaultPort);
  const port = Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : defaultPort;
  const secure = parseBool(getFirstEnv("SMTP_SECURE", "EMAIL_SECURE", "MAIL_SECURE"), inferred ? inferred.secure : port === 465);

  const key = `${host}|${port}|${secure}|${user}`;
  if (!transport || transportKey !== key) {
    transport = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: { user, pass },
    });
    transportKey = key;
  }

  return { transporter: transport, fromEmail: user };
};

const sendOtpEmail = async (email: string, otp: string) => {
  const { transporter, fromEmail } = resolveTransport();
  if (!transporter || !fromEmail) {
    if (String(process.env.NODE_ENV || "").toLowerCase() !== "production") {
      console.warn(`[customer-otp] SMTP not configured. OTP for ${email}: ${otp}`);
      return { delivered: false, previewOnly: true };
    }
    throw new Error("SMTP is not configured for OTP delivery");
  }

  await transporter.sendMail({
    from: `"AuthenticQR" <${fromEmail}>`,
    to: email,
    subject: "Your AuthenticQR verification code",
    text:
      `Use this one-time code to continue: ${otp}\n\n` +
      `It expires in ${OTP_TTL_MINUTES} minutes.\n` +
      `If you did not request this, you can ignore this email.`,
  });

  return { delivered: true, previewOnly: false };
};

const upsertCustomerUser = async (input: {
  email: string;
  name?: string | null;
  provider: CustomerAuthProvider;
  providerId?: string | null;
}) => {
  const email = normalizeEmail(input.email);
  const name = String(input.name || "").trim() || null;
  const providerId = String(input.providerId || "").trim() || null;

  const existing = await prisma.customerUser.findUnique({ where: { email } });
  if (existing) {
    const nextName = name || existing.name || null;
    const shouldAttachProviderId =
      input.provider === CustomerAuthProvider.GOOGLE &&
      providerId &&
      (!existing.providerId || existing.providerId === providerId);

    return prisma.customerUser.update({
      where: { id: existing.id },
      data: {
        name: nextName,
        provider: shouldAttachProviderId ? CustomerAuthProvider.GOOGLE : existing.provider,
        providerId: shouldAttachProviderId ? providerId : existing.providerId,
      },
    });
  }

  return prisma.customerUser.create({
    data: {
      email,
      name,
      provider: input.provider,
      providerId,
    },
  });
};

export const requestEmailOtp = async (input: { email: string; name?: string | null }) => {
  const email = normalizeEmail(input.email);
  if (!email) throw new Error("Email is required");

  const windowStart = new Date(Date.now() - OTP_RATE_WINDOW_MINUTES * 60_000);
  const sentInWindow = await prisma.customerOtpCode.count({
    where: {
      email,
      createdAt: { gte: windowStart },
    },
  });

  if (sentInWindow >= OTP_RATE_MAX_PER_WINDOW) {
    throw new Error("Too many OTP requests. Please try again shortly.");
  }

  const otp = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const codeHash = hashOtp(email, otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60_000);

  const existing = await prisma.customerUser.findUnique({ where: { email } });

  await prisma.customerOtpCode.create({
    data: {
      email,
      codeHash,
      expiresAt,
      customerUserId: existing?.id || null,
    },
  });

  const delivery = await sendOtpEmail(email, otp);

  return {
    delivered: delivery.delivered,
    expiresAt: expiresAt.toISOString(),
  };
};

export const verifyEmailOtp = async (input: { email: string; otp: string; name?: string | null }) => {
  const email = normalizeEmail(input.email);
  const otp = String(input.otp || "").trim();
  if (!email || otp.length < 4) throw new Error("Invalid OTP request");

  const otpRecord = await prisma.customerOtpCode.findFirst({
    where: {
      email,
      consumedAt: null,
    },
    orderBy: [{ createdAt: "desc" }],
  });

  if (!otpRecord) throw new Error("No OTP found. Please request a new code.");
  if (otpRecord.expiresAt.getTime() < Date.now()) throw new Error("OTP expired. Please request a new code.");
  if ((otpRecord.attempts || 0) >= OTP_MAX_ATTEMPTS) throw new Error("Too many incorrect attempts. Request a new code.");

  const expected = hashOtp(email, otp);
  if (expected !== otpRecord.codeHash) {
    await prisma.customerOtpCode.update({
      where: { id: otpRecord.id },
      data: { attempts: { increment: 1 } },
    });
    throw new Error("Incorrect OTP");
  }

  await prisma.customerOtpCode.update({
    where: { id: otpRecord.id },
    data: { consumedAt: new Date() },
  });

  return upsertCustomerUser({
    email,
    name: input.name,
    provider: CustomerAuthProvider.EMAIL_OTP,
    providerId: null,
  });
};

const verifyGoogleIdToken = async (idToken: string) => {
  const token = String(idToken || "").trim();
  if (!token) throw new Error("Missing Google ID token");

  const response = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(token)}`);
  if (!response.ok) {
    throw new Error("Google authentication failed");
  }

  const payload = (await response.json().catch(() => null)) as
    | {
        aud?: string;
        email?: string;
        email_verified?: string;
        name?: string;
        sub?: string;
      }
    | null;

  if (!payload) throw new Error("Google authentication failed");

  const expectedClientId = String(process.env.GOOGLE_CLIENT_ID || "").trim();
  if (expectedClientId && payload.aud !== expectedClientId) {
    throw new Error("Google token audience mismatch");
  }

  if (String(payload.email_verified || "").toLowerCase() !== "true") {
    throw new Error("Google account email is not verified");
  }

  const email = normalizeEmail(payload.email || "");
  const sub = String(payload.sub || "").trim();
  const name = String(payload.name || "").trim() || null;
  if (!email || !sub) throw new Error("Google profile is incomplete");

  return { email, name, providerId: sub };
};

export const authenticateWithGoogle = async (input: { idToken: string }) => {
  const profile = await verifyGoogleIdToken(input.idToken);
  return upsertCustomerUser({
    email: profile.email,
    name: profile.name,
    provider: CustomerAuthProvider.GOOGLE,
    providerId: profile.providerId,
  });
};

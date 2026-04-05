import { createHmac, timingSafeEqual } from "crypto";
import jwt from "jsonwebtoken";

import { getJwtSecret, randomOpaqueToken } from "../utils/security";

export type CustomerVerifyIdentity = {
  userId: string;
  email: string;
  authStrength?: "EMAIL_OTP" | "PASSKEY";
  webauthnVerifiedAt?: string | null;
};

type OtpChallengeJwtPayload = {
  type: "customer_verify_otp_challenge";
  email: string;
  nonce: string;
  expAt: number;
  otpMac: string;
};

type CustomerAuthJwtPayload = {
  type: "customer_verify_access";
  userId: string;
  email: string;
  authStrength?: "EMAIL_OTP" | "PASSKEY";
  webauthnVerifiedAt?: string | null;
};

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? Math.floor(parsed) : fallback;
};

const getOtpTtlMinutes = () => parseIntEnv("CUSTOMER_VERIFY_OTP_TTL_MINUTES", 10);
const getCustomerTokenTtlHours = () => parseIntEnv("CUSTOMER_VERIFY_TOKEN_TTL_HOURS", 24 * 30);

const getOtpSecret = () => {
  const explicit = String(process.env.CUSTOMER_VERIFY_OTP_SECRET || "").trim();
  return explicit || getJwtSecret();
};

const getCustomerTokenSecret = () => {
  const explicit = String(process.env.CUSTOMER_VERIFY_TOKEN_SECRET || "").trim();
  return explicit || getJwtSecret();
};

export const normalizeCustomerVerifyEmail = (input: string) => String(input || "").trim().toLowerCase();

export const deriveCustomerVerifyUserId = (email: string) => {
  const digest = createHmac("sha256", getCustomerTokenSecret()).update(email).digest("hex").slice(0, 32);
  return `cust_${digest}`;
};

const buildOtpMac = (input: { email: string; otp: string; nonce: string; expAt: number }) => {
  const payload = `${input.email}|${input.otp}|${input.nonce}|${String(input.expAt)}`;
  return createHmac("sha256", getOtpSecret()).update(payload).digest("hex");
};

const secureEqualHex = (left: string, right: string) => {
  const a = Buffer.from(left, "hex");
  const b = Buffer.from(right, "hex");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
};

const sanitizeOtp = (otp: string) => String(otp || "").replace(/[^0-9]/g, "").slice(0, 6);

const randomOtp = () => String(Math.floor(Math.random() * 1_000_000)).padStart(6, "0");

export const maskEmail = (email: string) => {
  const normalized = normalizeCustomerVerifyEmail(email);
  const [name, domain] = normalized.split("@");
  if (!name || !domain) return "***";
  if (name.length <= 2) return `${name[0] || "*"}***@${domain}`;
  return `${name.slice(0, 2)}***@${domain}`;
};

export const createCustomerOtpChallenge = (emailInput: string) => {
  const email = normalizeCustomerVerifyEmail(emailInput);
  if (!email) {
    throw new Error("Email is required");
  }

  const otp = randomOtp();
  const nonce = randomOpaqueToken(16);
  const expAt = Date.now() + getOtpTtlMinutes() * 60_000;
  const otpMac = buildOtpMac({ email, otp, nonce, expAt });

  const challengeToken = jwt.sign(
    {
      type: "customer_verify_otp_challenge",
      email,
      nonce,
      expAt,
      otpMac,
    } satisfies OtpChallengeJwtPayload,
    getOtpSecret(),
    { expiresIn: `${getOtpTtlMinutes()}m` }
  );

  return {
    email,
    otp,
    challengeToken,
    expiresAt: new Date(expAt).toISOString(),
  };
};

export const verifyCustomerOtpChallenge = (input: { challengeToken: string; otp: string }): CustomerVerifyIdentity => {
  const token = String(input.challengeToken || "").trim();
  const otp = sanitizeOtp(input.otp);

  if (!token) {
    throw new Error("Missing OTP challenge token");
  }

  if (!/^\d{6}$/.test(otp)) {
    throw new Error("Invalid OTP format");
  }

  let decoded: OtpChallengeJwtPayload;
  try {
    decoded = jwt.verify(token, getOtpSecret()) as OtpChallengeJwtPayload;
  } catch {
    throw new Error("OTP challenge expired or invalid");
  }

  if (!decoded || decoded.type !== "customer_verify_otp_challenge") {
    throw new Error("Invalid OTP challenge payload");
  }

  const email = normalizeCustomerVerifyEmail(decoded.email || "");
  const nonce = String(decoded.nonce || "").trim();
  const expAt = Number(decoded.expAt || 0);
  const otpMac = String(decoded.otpMac || "").trim();

  if (!email || !nonce || !Number.isFinite(expAt) || expAt <= Date.now()) {
    throw new Error("OTP challenge expired or invalid");
  }

  const expectedMac = buildOtpMac({ email, otp, nonce, expAt });
  if (!otpMac || !secureEqualHex(expectedMac, otpMac)) {
    throw new Error("Invalid OTP code");
  }

  return {
    userId: deriveCustomerVerifyUserId(email),
    email,
  };
};

export const issueCustomerVerifyToken = (
  identity: CustomerVerifyIdentity,
  options?: {
    authStrength?: "EMAIL_OTP" | "PASSKEY";
    webauthnVerifiedAt?: string | Date | null;
  }
) => {
  const authStrength = options?.authStrength || identity.authStrength || "EMAIL_OTP";
  const webauthnVerifiedAt =
    options?.webauthnVerifiedAt instanceof Date
      ? options.webauthnVerifiedAt.toISOString()
      : options?.webauthnVerifiedAt || identity.webauthnVerifiedAt || null;
  const payload: CustomerAuthJwtPayload = {
    type: "customer_verify_access",
    userId: identity.userId,
    email: normalizeCustomerVerifyEmail(identity.email),
    authStrength,
    webauthnVerifiedAt,
  };
  return jwt.sign(payload, getCustomerTokenSecret(), {
    expiresIn: `${getCustomerTokenTtlHours()}h`,
  });
};

export const verifyCustomerVerifyToken = (rawToken: string): CustomerVerifyIdentity => {
  const token = String(rawToken || "").trim();
  if (!token) throw new Error("Missing token");

  let decoded: CustomerAuthJwtPayload;
  try {
    decoded = jwt.verify(token, getCustomerTokenSecret()) as CustomerAuthJwtPayload;
  } catch {
    throw new Error("Invalid or expired customer token");
  }

  if (!decoded || decoded.type !== "customer_verify_access") {
    throw new Error("Invalid customer token payload");
  }

  const email = normalizeCustomerVerifyEmail(decoded.email || "");
  const userId = String(decoded.userId || "").trim();
  if (!email || !userId) {
    throw new Error("Invalid customer token payload");
  }

  if (deriveCustomerVerifyUserId(email) !== userId) {
    throw new Error("Customer token signature mismatch");
  }

  return {
    userId,
    email,
    authStrength: decoded.authStrength === "PASSKEY" ? "PASSKEY" : "EMAIL_OTP",
    webauthnVerifiedAt: decoded.webauthnVerifiedAt || null,
  };
};

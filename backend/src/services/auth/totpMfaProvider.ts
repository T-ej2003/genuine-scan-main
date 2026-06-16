import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import { generateSecret, generateURI, verify } from "otplib";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

const issuer = () => String(process.env.MFA_TOTP_ISSUER || process.env.APP_NAME || "MSCQR").trim() || "MSCQR";

const encryptionKey = () => {
  const explicit = String(process.env.AUTH_MFA_ENCRYPTION_KEY || "").trim();
  if (explicit) return createHash("sha256").update(explicit).digest();

  if (process.env.NODE_ENV === "production") {
    throw new Error("Missing AUTH_MFA_ENCRYPTION_KEY");
  }

  const legacy = String(process.env.JWT_SECRET || "").trim();
  if (!legacy) throw new Error("Missing AUTH_MFA_ENCRYPTION_KEY or JWT_SECRET");
  return createHash("sha256").update(legacy).digest();
};

export type EncryptedTotpSecret = {
  secretCiphertext: string;
  secretIv: string;
  secretTag: string;
};

export const getTotpWindow = () => Math.max(0, Math.min(4, parseIntEnv("AUTH_MFA_TOTP_WINDOW", 1)));

export const createTotpSecret = () => {
  const secret = generateSecret();
  return secret;
};

export const encryptTotpSecret = (plaintext: string): EncryptedTotpSecret => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return {
    secretCiphertext: ciphertext.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
};

export const decryptTotpSecret = (payload: EncryptedTotpSecret) => {
  const decipher = createDecipheriv("aes-256-gcm", encryptionKey(), Buffer.from(payload.secretIv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.secretTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(payload.secretCiphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
};

export const buildTotpUri = (params: { email: string; secret: string }) =>
  generateURI({
    issuer: issuer(),
    label: params.email,
    secret: params.secret,
  });

export const verifyTotpToken = async (params: { secret: string; token: string }) => {
  const token = String(params.token || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(token)) return false;
  const result = await verify({
    secret: params.secret,
    token,
    window: getTotpWindow(),
  } as any);
  return Boolean(result?.valid);
};

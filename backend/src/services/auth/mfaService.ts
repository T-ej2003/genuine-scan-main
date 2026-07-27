import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { AuthRiskLevel, Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { logger } from "../../utils/logger";
import { buildAdminMfaChallengeExpiry, buildAdminMfaChallengeTtlAuditDetails } from "./authDurationConfig";
import { revokeAllUserRefreshTokens } from "./refreshTokenService";
import {
  beginTotpMfaEnrollment,
  completeStableMfaLoginChallenge,
  confirmTotpMfaEnrollment,
  createStableMfaLoginChallenge,
  getAdminMfaAdapterStatus,
  lockMfaState,
  MfaAdapterError,
  rotateMfaBackupCodesWithAdapter,
  verifyMfaCodeWithAdapter,
  type MfaEnrollmentMode,
} from "./mfaAdapter";
import {
  createAdminMfaChallengeBoundary,
  disableAdminMfaBoundary,
} from "../../rls-waves/session-b/b01/adminMfaRepository";

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const DEFAULT_TOTP_WINDOW = 1;
type LoginMfaDbClient = NonNullable<Parameters<typeof getAdminMfaAdapterStatus>[1]>
  & Pick<Prisma.TransactionClient, "authMfaChallenge">;

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

const getTotpWindow = () => {
  const configured = parseIntEnv("AUTH_MFA_TOTP_WINDOW", DEFAULT_TOTP_WINDOW);
  return Math.max(0, Math.min(4, configured));
};

const getMaxChallengeAttempts = () => Math.max(1, Math.min(10, parseIntEnv("AUTH_MFA_CHALLENGE_MAX_ATTEMPTS", 5)));
const getBackupCodeCount = () => Math.max(1, Math.min(20, parseIntEnv("AUTH_MFA_BACKUP_CODE_COUNT", 8)));

const issuer = () => String(process.env.MFA_TOTP_ISSUER || process.env.APP_NAME || "MSCQR").trim();

const encryptionKey = () => {
  const explicit = String(process.env.AUTH_MFA_ENCRYPTION_KEY || "").trim();
  if (explicit) {
    return createHash("sha256").update(explicit).digest();
  }

  if (process.env.NODE_ENV === "production") {
    throw new Error("Missing AUTH_MFA_ENCRYPTION_KEY");
  }

  const legacy = String(process.env.JWT_SECRET || "").trim();
  if (!legacy) throw new Error("Missing AUTH_MFA_ENCRYPTION_KEY or JWT_SECRET");
  console.warn("[auth] MFA encryption is using JWT_SECRET fallback outside production. Set AUTH_MFA_ENCRYPTION_KEY.");
  const seed = legacy;
  return createHash("sha256").update(seed).digest();
};

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

const base32Encode = (input: Buffer) => {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of input) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += base32Alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += base32Alphabet[(value << (5 - bits)) & 31];
  }

  return output;
};

const base32Decode = (input: string) => {
  const normalized = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const ch of normalized) {
    const idx = base32Alphabet.indexOf(ch);
    if (idx < 0) continue;

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
};

const hotp = (secret: Buffer, counter: number) => {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);

  const digest = createHmac("sha1", secret).update(counterBuf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const code = (binCode % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
  return code;
};

const verifyTotp = (secretBase32: string, code: string, atMs = Date.now()) => {
  const normalizedCode = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalizedCode)) return false;

  const secret = base32Decode(secretBase32);
  if (!secret.length) return false;

  const counter = Math.floor(atMs / (TOTP_STEP_SECONDS * 1000));
  const windowSize = getTotpWindow();
  for (let i = -windowSize; i <= windowSize; i += 1) {
    const expected = hotp(secret, counter + i);
    const exp = Buffer.from(expected);
    const got = Buffer.from(normalizedCode);
    if (exp.length === got.length && timingSafeEqual(exp, got)) {
      return true;
    }
  }
  return false;
};

const encryptSecret = (plaintext: string) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encryptionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    secretCiphertext: ciphertext.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: tag.toString("base64"),
  };
};

const decryptSecret = (payload: { secretCiphertext: string; secretIv: string; secretTag: string }) => {
  const decipher = createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(payload.secretIv, "base64")
  );
  decipher.setAuthTag(Buffer.from(payload.secretTag, "base64"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(payload.secretCiphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
  return plaintext;
};

const generateBackupCodes = (count = 8) => {
  const out: string[] = [];
  for (let i = 0; i < count; i += 1) {
    const raw = randomBytes(5).toString("hex").toUpperCase();
    out.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return out;
};

const backupHash = (code: string) => hashToken(String(code || "").trim().toUpperCase());

const sessionBindingValue = (sessionId: string) => `admin-mfa-session:${String(sessionId || "").trim()}`;
const sessionBindingHash = (sessionId?: string | null) => {
  const normalized = String(sessionId || "").trim();
  return normalized ? hashToken(sessionBindingValue(normalized)) : null;
};
const sessionBindingCandidates = (sessionId?: string | null) => {
  const normalized = String(sessionId || "").trim();
  return normalized ? buildTokenHashCandidates(sessionBindingValue(normalized)) : [];
};

const mfaAuditOutboxRecord = (input: {
    userId?: string | null;
    action: string;
    entityId?: string | null;
    details?: Record<string, unknown>;
    ipHash?: string | null;
    userAgent?: string | null;
  }) => ({
  data: {
    payload: {
      ...(input.userId ? { userId: input.userId } : {}),
      action: input.action,
      entityType: "AuthMfaChallenge",
      ...(input.entityId ? { entityId: input.entityId } : {}),
      details: (input.details || {}) as Prisma.InputJsonObject,
      ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    } as Prisma.InputJsonObject,
  },
});

const normalizeRiskLevel = (level?: AuthRiskLevel | string | null): AuthRiskLevel => {
  const value = String(level || "").toUpperCase();
  if (value === "CRITICAL") return AuthRiskLevel.CRITICAL;
  if (value === "HIGH") return AuthRiskLevel.HIGH;
  if (value === "MEDIUM") return AuthRiskLevel.MEDIUM;
  return AuthRiskLevel.LOW;
};

export const getAdminMfaStatus = async (userId: string, db: LoginMfaDbClient = prisma) => {
  return getAdminMfaAdapterStatus(userId, db);
};

export const beginAdminMfaSetup = async (params: {
  userId: string;
  email: string;
  mode: MfaEnrollmentMode;
}, db?: Prisma.TransactionClient) => {
  return beginTotpMfaEnrollment(params, db);
};

export const confirmAdminMfaSetup = async (params: {
  userId: string;
  code: string;
  mode: MfaEnrollmentMode;
  audit?: { ipHash: string | null; userAgent: string | null };
}, db?: Prisma.TransactionClient) => {
  return confirmTotpMfaEnrollment(params, db);
};

export const disableAdminMfa = async (
  userId: string,
  db?: Prisma.TransactionClient,
  audit?: { ipHash: string | null; userAgent: string | null }
): Promise<{ enabled: false }> => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  return disableAdminMfaBoundary(db, {
    disabledAt: new Date(),
    ipHash: audit?.ipHash || null,
    userAgent: audit?.userAgent || null,
  });
};

export const createAdminMfaChallenge = async (params: {
  userId: string;
  sessionId?: string | null;
  purpose?: string | null;
  riskScore: number;
  riskLevel?: AuthRiskLevel | string | null;
  reasons?: string[];
  ipHash?: string | null;
  userAgent?: string | null;
  supersedeOpen?: boolean;
  maxAttempts?: number;
}, db: LoginMfaDbClient = prisma) => {
  if (String(params.purpose || "admin_login").trim() === "admin_login") {
    return createStableMfaLoginChallenge(params, db);
  }

  const rawTicket = randomOpaqueToken(36);
  const ticketHash = hashToken(rawTicket);
  const now = new Date();
  const { expiresAt, config: ttlConfig } = buildAdminMfaChallengeExpiry(now);
  const bindingHash = sessionBindingHash(params.sessionId);
  const purpose = String(params.purpose || "admin_login").trim() || "admin_login";
  const maxAttempts = Math.max(1, Math.min(10, params.maxAttempts || getMaxChallengeAttempts()));
  if (!bindingHash) throw new Error("MFA_CHALLENGE_SESSION_REQUIRED");
  const riskScore = Math.max(0, Math.min(100, Math.round(params.riskScore || 0)));
  const riskLevel = normalizeRiskLevel(params.riskLevel);
  const challenge = await createAdminMfaChallengeBoundary(db, {
    kind: "SESSION",
    ticketHash,
    sessionBindingHash: bindingHash,
    purpose,
    riskScore,
    riskLevel,
    reasons: Array.isArray(params.reasons) ? params.reasons.slice(0, 12) : [],
    ipHash: params.ipHash || null,
    userAgentHash: params.userAgent ? hashToken(params.userAgent) : null,
    maxAttempts,
    createdAt: now,
    expiresAt,
  });
  const ttlDetails = buildAdminMfaChallengeTtlAuditDetails(ttlConfig, now, expiresAt);

  logger.info("auth_mfa_challenge_issued", {
    challengeId: challenge.challengeId,
    purpose,
    ...ttlDetails,
  });

  return {
    ticket: rawTicket,
    expiresAt,
  };
};

export const verifyAdminMfaCode = async (
  params: { userId: string; code: string },
  db?: Prisma.TransactionClient
) => {
  return verifyMfaCodeWithAdapter(params, db);
};

export const rotateAdminMfaBackupCodes = async (
  params: { userId: string; code: string },
  db?: Prisma.TransactionClient
) => {
  return rotateMfaBackupCodesWithAdapter(params, db);
};

export const completeAdminMfaChallenge = async (params: {
  userId: string;
  sessionId?: string | null;
  ticket: string;
  method?: "totp" | "backup_code" | null;
  code: string;
  ipHash?: string | null;
  userAgent?: string | null;
}, db?: Prisma.TransactionClient): Promise<{
  userId: string;
  riskScore: number;
  riskLevel: AuthRiskLevel;
  reasons: string[];
  method: "TOTP" | "BACKUP_CODE";
}> => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  return completeStableMfaLoginChallenge(params, db);
};

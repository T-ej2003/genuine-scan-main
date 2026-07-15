import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { AuthRiskLevel } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, matchesHashedToken, randomOpaqueToken } from "../../utils/security";
import { logger } from "../../utils/logger";
import { createAuditLogSafely, type AuditLogInput } from "../auditService";
import { buildAdminMfaChallengeExpiry, buildAdminMfaChallengeTtlAuditDetails } from "./authDurationConfig";
import {
  beginTotpMfaEnrollment,
  completeStableMfaLoginChallenge,
  confirmTotpMfaEnrollment,
  createStableMfaLoginChallenge,
  getAdminMfaAdapterStatus,
  rotateMfaBackupCodesWithAdapter,
  verifyMfaCodeWithAdapter,
} from "./mfaAdapter";

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const DEFAULT_TOTP_WINDOW = 1;
type LoginMfaDbClient = NonNullable<Parameters<typeof getAdminMfaAdapterStatus>[1]>;

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

const auditMfaEvent = async (input: {
  userId?: string | null;
  action: string;
  entityId?: string | null;
  details?: Record<string, unknown>;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const event: AuditLogInput = {
    userId: input.userId || undefined,
    action: input.action,
    entityType: "AuthMfaChallenge",
    entityId: input.entityId || undefined,
    details: input.details || {},
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  };
  await createAuditLogSafely(event).catch(() => undefined);
};

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

export const beginAdminMfaSetup = async (params: { userId: string; email: string }) => {
  return beginTotpMfaEnrollment(params);
};

export const confirmAdminMfaSetup = async (params: { userId: string; code: string }) => {
  return confirmTotpMfaEnrollment(params);
};

export const disableAdminMfa = async (userId: string) => {
  await prisma.adminMfaCredential.updateMany({
    where: { userId },
    data: {
      isEnabled: false,
      verifiedAt: null,
      lastUsedAt: null,
    },
  });

  return { enabled: false };
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

  if (params.supersedeOpen !== false) {
    await prisma.authMfaChallenge.updateMany({
      where: {
        userId: params.userId,
        purpose,
        ...(bindingHash ? { sessionBindingHash: bindingHash } : {}),
        consumedAt: null,
        supersededAt: null,
        expiresAt: { gt: now },
      },
      data: { supersededAt: now },
    });
  }

  const challenge = await prisma.authMfaChallenge.create({
    data: {
      userId: params.userId,
      ticketHash,
      sessionBindingHash: bindingHash,
      purpose,
      riskScore: Math.max(0, Math.min(100, Math.round(params.riskScore || 0))),
      riskLevel: normalizeRiskLevel(params.riskLevel),
      reasons: Array.isArray(params.reasons) ? params.reasons.slice(0, 12) : [],
      createdIpHash: params.ipHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(params.userAgent) : null,
      attempts: 0,
      maxAttempts,
      expiresAt,
    },
  });
  const ttlDetails = buildAdminMfaChallengeTtlAuditDetails(ttlConfig, now, expiresAt);

  logger.info("auth_mfa_challenge_issued", {
    challengeId: challenge.id,
    purpose,
    ...ttlDetails,
  });

  await auditMfaEvent({
    userId: params.userId,
    action: "AUTH_MFA_CHALLENGE_ISSUED",
    entityId: challenge.id,
    details: {
      purpose,
      riskScore: challenge.riskScore,
      riskLevel: challenge.riskLevel,
      ...ttlDetails,
      sessionBound: Boolean(bindingHash),
    },
    ipHash: params.ipHash,
    userAgent: params.userAgent,
  });

  return {
    ticket: rawTicket,
    expiresAt,
  };
};

const consumeBackupCode = async (userId: string, codesHash: string[], provided: string) => {
  const index = codesHash.findIndex((entry) => {
    return matchesHashedToken(String(provided || "").trim().toUpperCase(), entry);
  });
  if (index < 0) return false;

  const updated = [...codesHash];
  updated.splice(index, 1);
  await prisma.adminMfaCredential.update({
    where: { userId },
    data: {
      backupCodesHash: updated,
      lastUsedAt: new Date(),
    },
  });
  return true;
};

export const verifyAdminMfaCode = async (params: { userId: string; code: string }) => {
  return verifyMfaCodeWithAdapter(params);
};

export const rotateAdminMfaBackupCodes = async (params: { userId: string; code: string }) => {
  return rotateMfaBackupCodesWithAdapter(params);
};

export const completeAdminMfaChallenge = async (params: {
  userId: string;
  sessionId?: string | null;
  ticket: string;
  method?: "totp" | "backup_code" | null;
  code: string;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  try {
    return await completeStableMfaLoginChallenge(params);
  } catch (error) {
    if (error instanceof Error && error.message !== "MFA_CHALLENGE_NOT_FOUND") throw error;
  }

  const ticketHashCandidates = buildTokenHashCandidates(String(params.ticket || "").trim());
  const now = new Date();

  const challenge = await prisma.authMfaChallenge.findFirst({
    where: {
      ticketHash: { in: ticketHashCandidates },
    },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          role: true,
          licenseeId: true,
          orgId: true,
          isActive: true,
          status: true,
          deletedAt: true,
          disabledAt: true,
        },
      },
    },
  });

  if (!challenge) throw new Error("MFA_CHALLENGE_NOT_FOUND");
  if (challenge.userId !== params.userId) throw new Error("MFA_CHALLENGE_FORBIDDEN");

  if (challenge.sessionBindingHash) {
    const bindingCandidates = sessionBindingCandidates(params.sessionId);
    if (!bindingCandidates.length || !bindingCandidates.includes(challenge.sessionBindingHash)) {
      throw new Error("MFA_CHALLENGE_NOT_FOUND");
    }
  } else if (challenge.purpose === "admin_login") {
    throw new Error("MFA_CHALLENGE_NOT_FOUND");
  }

  if (challenge.supersededAt || challenge.consumedAt) {
    throw new Error("MFA_CHALLENGE_NOT_FOUND");
  }

  if (challenge.expiresAt.getTime() <= now.getTime()) {
    await auditMfaEvent({
      userId: challenge.userId,
      action: "AUTH_MFA_CHALLENGE_EXPIRED",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, expiresAt: challenge.expiresAt.toISOString() },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    });
    throw new Error("MFA_CHALLENGE_NOT_FOUND");
  }

  if (challenge.attempts >= challenge.maxAttempts) {
    await auditMfaEvent({
      userId: challenge.userId,
      action: "AUTH_MFA_TOO_MANY_ATTEMPTS",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, attempts: challenge.attempts, maxAttempts: challenge.maxAttempts },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    });
    throw new Error("MFA_TOO_MANY_ATTEMPTS");
  }

  const normalizedCode = String(params.code || "").trim();
  const requestedMethod = params.method || null;
  const totpShapeOk = /^\d{6}$/.test(normalizedCode.replace(/\s+/g, ""));
  const backupShapeOk = /^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(normalizedCode);
  const codeShapeOk =
    requestedMethod === "totp"
      ? totpShapeOk
      : requestedMethod === "backup_code"
        ? backupShapeOk
        : totpShapeOk || backupShapeOk;
  if (!codeShapeOk) {
    const nextAttempts = challenge.attempts + 1;
    await prisma.authMfaChallenge.updateMany({
      where: { id: challenge.id, consumedAt: null, supersededAt: null },
      data: { attempts: { increment: 1 } },
    });
    await auditMfaEvent({
      userId: challenge.userId,
      action: nextAttempts >= challenge.maxAttempts ? "AUTH_MFA_TOO_MANY_ATTEMPTS" : "AUTH_MFA_FAILURE",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, reason: "INVALID_CODE_SHAPE", attempts: nextAttempts, maxAttempts: challenge.maxAttempts },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    });
    throw new Error(nextAttempts >= challenge.maxAttempts ? "MFA_TOO_MANY_ATTEMPTS" : "INVALID_MFA_CODE");
  }

  let verification: Awaited<ReturnType<typeof verifyAdminMfaCode>>;
  try {
    verification = await verifyAdminMfaCode({
      userId: challenge.userId,
      code: normalizedCode,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error || "");
    if (message === "INVALID_MFA_CODE") {
      const nextAttempts = challenge.attempts + 1;
      await prisma.authMfaChallenge.updateMany({
        where: { id: challenge.id, consumedAt: null, supersededAt: null },
        data: { attempts: { increment: 1 } },
      });
      await auditMfaEvent({
        userId: challenge.userId,
        action: nextAttempts >= challenge.maxAttempts ? "AUTH_MFA_TOO_MANY_ATTEMPTS" : "AUTH_MFA_FAILURE",
        entityId: challenge.id,
        details: { purpose: challenge.purpose, attempts: nextAttempts, maxAttempts: challenge.maxAttempts },
        ipHash: params.ipHash,
        userAgent: params.userAgent,
      });
      throw new Error(nextAttempts >= challenge.maxAttempts ? "MFA_TOO_MANY_ATTEMPTS" : "INVALID_MFA_CODE");
    }
    throw error;
  }

  const consumed = await prisma.authMfaChallenge.updateMany({
    where: {
      id: challenge.id,
      consumedAt: null,
      supersededAt: null,
      expiresAt: { gt: now },
    },
    data: {
      consumedAt: now,
      createdIpHash: params.ipHash || challenge.createdIpHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(params.userAgent) : challenge.createdUserAgentHash,
    },
  });

  if (consumed.count !== 1) {
    throw new Error("MFA_CHALLENGE_NOT_FOUND");
  }

  await auditMfaEvent({
    userId: challenge.userId,
    action: verification.method === "BACKUP_CODE" ? "AUTH_MFA_BACKUP_CODE_USED" : "AUTH_MFA_SUCCESS",
    entityId: challenge.id,
    details: {
      purpose: challenge.purpose,
      method: verification.method,
      riskScore: challenge.riskScore,
      riskLevel: challenge.riskLevel,
    },
    ipHash: params.ipHash,
    userAgent: params.userAgent,
  });

  return {
    userId: challenge.userId,
    riskScore: challenge.riskScore,
    riskLevel: challenge.riskLevel,
    reasons: challenge.reasons,
    method: verification.method,
  };
};

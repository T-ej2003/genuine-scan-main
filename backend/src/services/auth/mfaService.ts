import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "crypto";
import { AuthRiskLevel } from "@prisma/client";

import prisma from "../../config/database";
import { hashToken, randomOpaqueToken } from "../../utils/security";

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1;

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

const issuer = () => String(process.env.MFA_TOTP_ISSUER || process.env.APP_NAME || "MSCQR").trim();

const encryptionKey = () => {
  const seed = String(process.env.AUTH_MFA_ENCRYPTION_KEY || process.env.JWT_SECRET || "").trim();
  if (!seed) throw new Error("Missing AUTH_MFA_ENCRYPTION_KEY or JWT_SECRET");
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
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i += 1) {
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

const normalizeRiskLevel = (level?: AuthRiskLevel | string | null): AuthRiskLevel => {
  const value = String(level || "").toUpperCase();
  if (value === "CRITICAL") return AuthRiskLevel.CRITICAL;
  if (value === "HIGH") return AuthRiskLevel.HIGH;
  if (value === "MEDIUM") return AuthRiskLevel.MEDIUM;
  return AuthRiskLevel.LOW;
};

export const getAdminMfaStatus = async (userId: string) => {
  const row = await prisma.adminMfaCredential.findUnique({
    where: { userId },
    select: {
      id: true,
      isEnabled: true,
      verifiedAt: true,
      lastUsedAt: true,
      backupCodesHash: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return {
    enrolled: Boolean(row),
    enabled: Boolean(row?.isEnabled),
    verifiedAt: row?.verifiedAt || null,
    lastUsedAt: row?.lastUsedAt || null,
    backupCodesRemaining: Array.isArray(row?.backupCodesHash) ? row.backupCodesHash.length : 0,
    createdAt: row?.createdAt || null,
    updatedAt: row?.updatedAt || null,
  };
};

export const beginAdminMfaSetup = async (params: { userId: string; email: string }) => {
  const secret = base32Encode(randomBytes(20));
  const encrypted = encryptSecret(secret);
  const backupCodes = generateBackupCodes(parseIntEnv("AUTH_MFA_BACKUP_CODE_COUNT", 8));

  const backupCodesHash = backupCodes.map((code) => backupHash(code));

  await prisma.adminMfaCredential.upsert({
    where: { userId: params.userId },
    update: {
      ...encrypted,
      backupCodesHash,
      isEnabled: false,
      verifiedAt: null,
      lastUsedAt: null,
    },
    create: {
      userId: params.userId,
      ...encrypted,
      backupCodesHash,
      isEnabled: false,
      verifiedAt: null,
      lastUsedAt: null,
    },
  });

  const account = encodeURIComponent(`${issuer()}:${params.email}`);
  const query = new URLSearchParams({
    secret,
    issuer: issuer(),
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_STEP_SECONDS),
  });

  return {
    secret,
    otpauthUri: `otpauth://totp/${account}?${query.toString()}`,
    backupCodes,
  };
};

export const confirmAdminMfaSetup = async (params: { userId: string; code: string }) => {
  const row = await prisma.adminMfaCredential.findUnique({
    where: { userId: params.userId },
    select: {
      id: true,
      userId: true,
      secretCiphertext: true,
      secretIv: true,
      secretTag: true,
    },
  });

  if (!row) throw new Error("MFA_SETUP_NOT_STARTED");

  const secret = decryptSecret(row);
  const valid = verifyTotp(secret, params.code);
  if (!valid) throw new Error("INVALID_MFA_CODE");

  await prisma.adminMfaCredential.update({
    where: { userId: params.userId },
    data: {
      isEnabled: true,
      verifiedAt: new Date(),
      lastUsedAt: new Date(),
    },
  });

  return { enabled: true };
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
  riskScore: number;
  riskLevel?: AuthRiskLevel | string | null;
  reasons?: string[];
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const rawTicket = randomOpaqueToken(36);
  const ticketHash = hashToken(rawTicket);
  const expiresAt = new Date(Date.now() + parseIntEnv("AUTH_MFA_CHALLENGE_TTL_MINUTES", 5) * 60_000);

  await prisma.authMfaChallenge.create({
    data: {
      userId: params.userId,
      ticketHash,
      riskScore: Math.max(0, Math.min(100, Math.round(params.riskScore || 0))),
      riskLevel: normalizeRiskLevel(params.riskLevel),
      reasons: Array.isArray(params.reasons) ? params.reasons.slice(0, 12) : [],
      createdIpHash: params.ipHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(params.userAgent) : null,
      expiresAt,
    },
  });

  return {
    ticket: rawTicket,
    expiresAt,
  };
};

const consumeBackupCode = async (userId: string, codesHash: string[], provided: string) => {
  const wanted = backupHash(provided);
  const index = codesHash.findIndex((entry) => {
    const left = Buffer.from(entry);
    const right = Buffer.from(wanted);
    return left.length === right.length && timingSafeEqual(left, right);
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

export const completeAdminMfaChallenge = async (params: {
  ticket: string;
  code: string;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const ticketHash = hashToken(String(params.ticket || "").trim());
  const now = new Date();

  const challenge = await prisma.authMfaChallenge.findFirst({
    where: {
      ticketHash,
      consumedAt: null,
      expiresAt: { gt: now },
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

  const credential = await prisma.adminMfaCredential.findUnique({
    where: { userId: challenge.userId },
    select: {
      userId: true,
      isEnabled: true,
      secretCiphertext: true,
      secretIv: true,
      secretTag: true,
      backupCodesHash: true,
    },
  });

  if (!credential?.isEnabled) throw new Error("MFA_NOT_ENABLED");

  const normalizedCode = String(params.code || "").trim();
  let verified = false;

  if (/^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(normalizedCode) && credential.backupCodesHash.length > 0) {
    verified = await consumeBackupCode(challenge.userId, credential.backupCodesHash, normalizedCode);
  }

  if (!verified) {
    const secret = decryptSecret(credential);
    verified = verifyTotp(secret, normalizedCode);
    if (verified) {
      await prisma.adminMfaCredential.update({
        where: { userId: challenge.userId },
        data: { lastUsedAt: new Date() },
      });
    }
  }

  if (!verified) throw new Error("INVALID_MFA_CODE");

  await prisma.authMfaChallenge.update({
    where: { id: challenge.id },
    data: {
      consumedAt: now,
      createdIpHash: params.ipHash || challenge.createdIpHash || null,
      createdUserAgentHash: params.userAgent ? hashToken(params.userAgent) : challenge.createdUserAgentHash,
    },
  });

  return {
    userId: challenge.userId,
    riskScore: challenge.riskScore,
    riskLevel: challenge.riskLevel,
    reasons: challenge.reasons,
  };
};

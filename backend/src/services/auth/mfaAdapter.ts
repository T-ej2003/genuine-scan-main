import { AuthRiskLevel } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { logger } from "../../utils/logger";
import { createAuditLogSafely, type AuditLogInput } from "../auditService";
import { buildAdminMfaChallengeExpiry, buildAdminMfaChallengeTtlAuditDetails } from "./authDurationConfig";
import {
  consumeLegacyBackupCode,
  consumeUserBackupCode,
  generateBackupCodes,
  hashBackupCode,
  replaceUserBackupCodes,
} from "./backupCodeMfaProvider";
import {
  buildTotpUri,
  createTotpSecret,
  decryptTotpSecret,
  encryptTotpSecret,
  verifyTotpToken,
  type EncryptedTotpSecret,
} from "./totpMfaProvider";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  return Number.isFinite(raw) ? Math.floor(raw) : fallback;
};

const getMaxChallengeAttempts = () => Math.max(1, Math.min(10, parseIntEnv("AUTH_MFA_CHALLENGE_MAX_ATTEMPTS", 5)));

const normalizeRiskLevel = (level?: AuthRiskLevel | string | null): AuthRiskLevel => {
  const value = String(level || "").toUpperCase();
  if (value === "CRITICAL") return AuthRiskLevel.CRITICAL;
  if (value === "HIGH") return AuthRiskLevel.HIGH;
  if (value === "MEDIUM") return AuthRiskLevel.MEDIUM;
  return AuthRiskLevel.LOW;
};

export class MfaAdapterError extends Error {
  status: number;
  retryAfterSeconds?: number;

  constructor(message: string, options?: { status?: number; retryAfterSeconds?: number }) {
    super(message);
    this.status = options?.status || 400;
    this.retryAfterSeconds = options?.retryAfterSeconds;
  }
}

const auditMfaEvent = async (input: {
  userId?: string | null;
  action: string;
  entityType?: string;
  entityId?: string | null;
  details?: Record<string, unknown>;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const event: AuditLogInput = {
    userId: input.userId || undefined,
    action: input.action,
    entityType: input.entityType || "MfaLoginChallenge",
    entityId: input.entityId || undefined,
    details: input.details || {},
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  };
  await createAuditLogSafely(event).catch(() => undefined);
};

export const getAdminMfaAdapterStatus = async (userId: string) => {
  const [legacyTotp, legacyWebAuthn, factors, backupCodesRemaining] = await Promise.all([
    prisma.adminMfaCredential.findUnique({
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
    }),
    prisma.adminWebAuthnCredential.findMany({
      where: { userId },
      orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
      select: { id: true, label: true, transports: true, lastUsedAt: true, createdAt: true, updatedAt: true },
    }),
    prisma.userMfaFactor.findMany({
      where: { userId, disabledAt: null },
      orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
      select: {
        id: true,
        type: true,
        label: true,
        transports: true,
        lastUsedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    }),
    prisma.userBackupCode.count({ where: { userId, usedAt: null } }),
  ]);

  const hasTotp = factors.some((factor) => factor.type === "TOTP") || Boolean(legacyTotp?.isEnabled);
  const newWebAuthnFactors = factors.filter((factor) => factor.type === "WEBAUTHN");
  const hasWebAuthn = newWebAuthnFactors.length > 0 || legacyWebAuthn.length > 0;
  const methods = [
    ...(hasWebAuthn ? (["WEBAUTHN"] as const) : []),
    ...(hasTotp ? (["TOTP"] as const) : []),
    ...((backupCodesRemaining > 0 || (legacyTotp?.backupCodesHash?.length || 0) > 0) ? (["BACKUP_CODE"] as const) : []),
  ];
  const lastUsedAtCandidates = [
    legacyTotp?.lastUsedAt || null,
    ...legacyWebAuthn.map((entry) => entry.lastUsedAt || null),
    ...factors.map((entry) => entry.lastUsedAt || null),
  ]
    .filter((value): value is Date => Boolean(value))
    .sort((a, b) => b.getTime() - a.getTime());

  return {
    enrolled: Boolean(legacyTotp) || legacyWebAuthn.length > 0 || factors.length > 0,
    enabled: hasTotp || hasWebAuthn,
    totpEnabled: hasTotp,
    hasWebAuthn,
    methods,
    preferredMethod: hasWebAuthn ? "WEBAUTHN" : hasTotp ? "TOTP" : null,
    verifiedAt: legacyTotp?.verifiedAt || null,
    lastUsedAt: lastUsedAtCandidates[0] || null,
    backupCodesRemaining: backupCodesRemaining || legacyTotp?.backupCodesHash?.length || 0,
    createdAt: legacyTotp?.createdAt || factors[0]?.createdAt || null,
    updatedAt: legacyTotp?.updatedAt || factors[0]?.updatedAt || null,
    webauthnCredentials: [
      ...newWebAuthnFactors.map((entry) => ({
        id: entry.id,
        label: entry.label || "Passkey",
        transports: entry.transports,
        lastUsedAt: entry.lastUsedAt || null,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      })),
      ...legacyWebAuthn.map((entry) => ({
        id: entry.id,
        label: entry.label || "Security key",
        transports: entry.transports,
        lastUsedAt: entry.lastUsedAt || null,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt,
      })),
    ],
  };
};

export const beginTotpMfaEnrollment = async (params: { userId: string; email: string }) => {
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret);
  const backupCodes = generateBackupCodes();
  const backupCodesHash = backupCodes.map((code) => hashBackupCode(code));

  await prisma.$transaction([
    prisma.adminMfaCredential.upsert({
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
    }),
    prisma.userMfaFactor.deleteMany({
      where: { userId: params.userId, type: "TOTP", disabledAt: null },
    }),
    prisma.userMfaFactor.create({
      data: {
        userId: params.userId,
        type: "TOTP",
        label: "Authenticator app",
        ...encrypted,
      },
    }),
    prisma.userBackupCode.deleteMany({
      where: { userId: params.userId, usedAt: null },
    }),
    prisma.userBackupCode.createMany({
      data: backupCodes.map((code) => ({
        userId: params.userId,
        codeHash: hashBackupCode(code),
      })),
    }),
  ]);

  return {
    secret,
    otpauthUri: buildTotpUri({ email: params.email, secret }),
    backupCodes,
  };
};

export const confirmTotpMfaEnrollment = async (params: { userId: string; code: string }) => {
  const factor = await prisma.userMfaFactor.findFirst({
    where: { userId: params.userId, type: "TOTP", disabledAt: null, secretCiphertext: { not: null } },
    orderBy: { createdAt: "desc" },
    select: { id: true, secretCiphertext: true, secretIv: true, secretTag: true },
  });
  const secretPayload = factor
    ? {
        secretCiphertext: factor.secretCiphertext,
        secretIv: factor.secretIv,
        secretTag: factor.secretTag,
      } as EncryptedTotpSecret
    : null;

  if (!secretPayload) throw new Error("MFA_SETUP_NOT_STARTED");
  const valid = await verifyTotpToken({ secret: decryptTotpSecret(secretPayload), token: params.code });
  if (!valid) throw new Error("INVALID_MFA_CODE");

  const now = new Date();
  await prisma.$transaction([
    prisma.userMfaFactor.update({ where: { id: factor!.id }, data: { lastUsedAt: now, disabledAt: null } }),
    prisma.adminMfaCredential.updateMany({
      where: { userId: params.userId },
      data: { isEnabled: true, verifiedAt: now, lastUsedAt: now },
    }),
  ]);

  return { enabled: true };
};

const verifyTotpAgainstNewFactor = async (params: { userId: string; code: string }) => {
  const factors = await prisma.userMfaFactor.findMany({
    where: { userId: params.userId, type: "TOTP", disabledAt: null, secretCiphertext: { not: null } },
    orderBy: { createdAt: "desc" },
    select: { id: true, secretCiphertext: true, secretIv: true, secretTag: true },
  });

  for (const factor of factors) {
    if (!factor.secretCiphertext || !factor.secretIv || !factor.secretTag) continue;
    const verified = await verifyTotpToken({
      secret: decryptTotpSecret(factor as EncryptedTotpSecret),
      token: params.code,
    });
    if (verified) {
      await prisma.userMfaFactor.update({ where: { id: factor.id }, data: { lastUsedAt: new Date() } });
      return true;
    }
  }
  return false;
};

const verifyTotpAgainstLegacyCredential = async (params: { userId: string; code: string }) => {
  const legacy = await prisma.adminMfaCredential.findUnique({
    where: { userId: params.userId },
    select: {
      userId: true,
      isEnabled: true,
      secretCiphertext: true,
      secretIv: true,
      secretTag: true,
    },
  });
  if (!legacy?.isEnabled) return false;

  const verified = await verifyTotpToken({ secret: decryptTotpSecret(legacy), token: params.code });
  if (!verified) return false;
  await prisma.$transaction([
    prisma.adminMfaCredential.update({ where: { userId: params.userId }, data: { lastUsedAt: new Date() } }),
    prisma.userMfaFactor.upsert({
      where: { id: `legacy-totp-${params.userId}` },
      update: {
        type: "TOTP",
        label: "Authenticator app",
        secretCiphertext: legacy.secretCiphertext,
        secretIv: legacy.secretIv,
        secretTag: legacy.secretTag,
        legacySource: "AdminMfaCredential",
        legacyCredentialId: params.userId,
        disabledAt: null,
        lastUsedAt: new Date(),
      },
      create: {
        id: `legacy-totp-${params.userId}`,
        userId: params.userId,
        type: "TOTP",
        label: "Authenticator app",
        secretCiphertext: legacy.secretCiphertext,
        secretIv: legacy.secretIv,
        secretTag: legacy.secretTag,
        legacySource: "AdminMfaCredential",
        legacyCredentialId: params.userId,
        lastUsedAt: new Date(),
      },
    }),
  ]);
  return true;
};

export const verifyMfaCodeWithAdapter = async (params: { userId: string; code: string }) => {
  const normalizedCode = String(params.code || "").trim();
  if (!normalizedCode) throw new Error("INVALID_MFA_CODE");

  if (/^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(normalizedCode)) {
    const [newBackupCodeCount, consumed] = await Promise.all([
      prisma.userBackupCode.count({ where: { userId: params.userId } }),
      consumeUserBackupCode({ userId: params.userId, code: normalizedCode }),
    ]);
    if (consumed) return { ok: true as const, method: "BACKUP_CODE" as const };
    if (newBackupCodeCount > 0) throw new Error("INVALID_MFA_CODE");

    const legacy = await prisma.adminMfaCredential.findUnique({
      where: { userId: params.userId },
      select: { backupCodesHash: true },
    });
    if (legacy?.backupCodesHash?.length) {
      const legacyConsumed = await consumeLegacyBackupCode({
        userId: params.userId,
        code: normalizedCode,
        codesHash: legacy.backupCodesHash,
      });
      if (legacyConsumed) return { ok: true as const, method: "BACKUP_CODE" as const };
    }
  }

  const totpVerified = await verifyTotpAgainstNewFactor({ userId: params.userId, code: normalizedCode }) ||
    await verifyTotpAgainstLegacyCredential({ userId: params.userId, code: normalizedCode });
  if (!totpVerified) throw new Error("INVALID_MFA_CODE");
  return { ok: true as const, method: "TOTP" as const };
};

export const rotateMfaBackupCodesWithAdapter = async (params: { userId: string; code: string }) => {
  await verifyMfaCodeWithAdapter({ userId: params.userId, code: params.code });
  const backupCodes = generateBackupCodes();
  await Promise.all([
    replaceUserBackupCodes({ userId: params.userId, codes: backupCodes }),
    prisma.adminMfaCredential.updateMany({
      where: { userId: params.userId },
      data: {
        backupCodesHash: backupCodes.map((code) => hashBackupCode(code)),
        lastUsedAt: new Date(),
      },
    }),
  ]);
  return { backupCodes };
};

export const createStableMfaLoginChallenge = async (params: {
  userId: string;
  purpose?: string | null;
  riskScore: number;
  riskLevel?: AuthRiskLevel | string | null;
  reasons?: string[];
  ipHash?: string | null;
  userAgent?: string | null;
  maxAttempts?: number;
}) => {
  const ticket = randomOpaqueToken(36);
  const now = new Date();
  const { expiresAt, config: ttlConfig } = buildAdminMfaChallengeExpiry(now);
  const purpose = String(params.purpose || "admin_login").trim() || "admin_login";
  const maxAttempts = Math.max(1, Math.min(10, params.maxAttempts || getMaxChallengeAttempts()));

  const challenge = await prisma.mfaLoginChallenge.create({
    data: {
      userId: params.userId,
      ticketHash: hashToken(ticket),
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
    details: { purpose, riskScore: challenge.riskScore, riskLevel: challenge.riskLevel, ...ttlDetails },
    ipHash: params.ipHash,
    userAgent: params.userAgent,
  });

  return { ticket, expiresAt };
};

export const completeStableMfaLoginChallenge = async (params: {
  userId: string;
  ticket: string;
  method?: "totp" | "backup_code" | null;
  code: string;
  ipHash?: string | null;
  userAgent?: string | null;
}) => {
  const now = new Date();
  const challenge = await prisma.mfaLoginChallenge.findFirst({
    where: { ticketHash: { in: buildTokenHashCandidates(String(params.ticket || "").trim()) } },
  });
  if (!challenge) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (challenge.userId !== params.userId) throw new MfaAdapterError("MFA_CHALLENGE_FORBIDDEN", { status: 403 });
  if (challenge.consumedAt) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (challenge.expiresAt.getTime() <= now.getTime()) {
    await auditMfaEvent({
      userId: challenge.userId,
      action: "AUTH_MFA_CHALLENGE_EXPIRED",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, expiresAt: challenge.expiresAt.toISOString() },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    });
    throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  }
  if (challenge.attempts >= challenge.maxAttempts) {
    const retryAfterSeconds = challenge.retryAfterSeconds || 60;
    throw new MfaAdapterError("MFA_TOO_MANY_ATTEMPTS", { status: 429, retryAfterSeconds });
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

  const recordFailure = async (reason?: string) => {
    const nextAttempts = challenge.attempts + 1;
    const retryAfterSeconds = nextAttempts >= challenge.maxAttempts ? 60 : null;
    await prisma.mfaLoginChallenge.updateMany({
      where: { id: challenge.id, consumedAt: null },
      data: {
        attempts: { increment: 1 },
        retryAfterSeconds,
      },
    });
    await auditMfaEvent({
      userId: challenge.userId,
      action: nextAttempts >= challenge.maxAttempts ? "AUTH_MFA_TOO_MANY_ATTEMPTS" : "AUTH_MFA_FAILURE",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, attempts: nextAttempts, maxAttempts: challenge.maxAttempts, ...(reason ? { reason } : {}) },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    });
    throw new MfaAdapterError(nextAttempts >= challenge.maxAttempts ? "MFA_TOO_MANY_ATTEMPTS" : "INVALID_MFA_CODE", {
      status: nextAttempts >= challenge.maxAttempts ? 429 : 400,
      retryAfterSeconds: retryAfterSeconds || undefined,
    });
  };

  if (!codeShapeOk) await recordFailure("INVALID_CODE_SHAPE");

  let verification: Awaited<ReturnType<typeof verifyMfaCodeWithAdapter>>;
  try {
    verification = await verifyMfaCodeWithAdapter({ userId: challenge.userId, code: normalizedCode });
  } catch (error) {
    if (error instanceof Error && error.message === "INVALID_MFA_CODE") await recordFailure();
    throw error;
  }

  const consumed = await prisma.mfaLoginChallenge.updateMany({
    where: { id: challenge.id, consumedAt: null, expiresAt: { gt: now } },
    data: { consumedAt: now },
  });
  if (consumed.count !== 1) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });

  await auditMfaEvent({
    userId: challenge.userId,
    action: verification.method === "BACKUP_CODE" ? "AUTH_MFA_BACKUP_CODE_USED" : "AUTH_MFA_SUCCESS",
    entityId: challenge.id,
    details: { purpose: challenge.purpose, method: verification.method, riskScore: challenge.riskScore, riskLevel: challenge.riskLevel },
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

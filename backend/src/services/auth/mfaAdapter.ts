import { AuthRiskLevel, Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { logger } from "../../utils/logger";
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
import { getMfaBootstrapTtlMinutes } from "./tokenService";

export type MfaEnrollmentMode = "FIRST_ENROLLMENT" | "REPLACEMENT";

const MFA_ENROLLMENT_PENDING_SOURCE = "MFA_ENROLLMENT_PENDING";

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
  commitFailure: boolean;

  constructor(message: string, options?: { status?: number; retryAfterSeconds?: number; commitFailure?: boolean }) {
    super(message);
    this.status = options?.status || 400;
    this.retryAfterSeconds = options?.retryAfterSeconds;
    this.commitFailure = options?.commitFailure === true;
  }
}

type LoginMfaDbClient = Pick<
  Prisma.TransactionClient,
  "$executeRaw" | "adminMfaCredential" | "adminWebAuthnCredential" | "userMfaFactor" | "userBackupCode" | "mfaLoginChallenge" | "auditLogOutbox"
>;

const safeMfaErrorCategory = (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error || "");
  if (/AUTH_MFA_ENCRYPTION_KEY|JWT_SECRET|secret/i.test(message)) return "TOTP_SECRET_DECRYPT_FAILED";
  if (/decrypt|Unsupported state|authenticate|bad decrypt|auth tag/i.test(message)) return "TOTP_SECRET_DECRYPT_FAILED";
  if (/database|prisma|transaction|constraint|unique/i.test(message)) return "MFA_FACTOR_STORE_FAILED";
  return "MFA_VERIFIER_INTERNAL_ERROR";
};

const logTotpPathFailure = (params: {
  level?: "warn" | "error";
  userId: string;
  factorPath: "new_factor" | "legacy_credential";
  factorId?: string | null;
  error: unknown;
}) => {
  const error = params.error instanceof Error ? params.error : null;
  logger[params.level || "warn"]("auth_mfa_totp_factor_verification_failed", {
    userId: params.userId,
    factorPath: params.factorPath,
    factorId: params.factorId || null,
    errorCategory: safeMfaErrorCategory(params.error),
    errorName: error?.name || typeof params.error,
  });
};

type TotpVerificationPathResult = {
  verified: boolean;
  attempted: number;
  operationalFailures: number;
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
      entityType: "MfaLoginChallenge",
      ...(input.entityId ? { entityId: input.entityId } : {}),
      details: (input.details || {}) as Prisma.InputJsonObject,
      ...(input.ipHash ? { ipHash: input.ipHash } : {}),
      ...(input.userAgent ? { userAgent: input.userAgent } : {}),
    } as Prisma.InputJsonObject,
  },
});

const runMfaCompletionTransaction = async <T>(callback: (tx: Prisma.TransactionClient) => Promise<T>) => {
  const outcome = await prisma.$transaction(async (tx) => {
    try {
      return { ok: true as const, value: await callback(tx) };
    } catch (error) {
      if (error instanceof MfaAdapterError && error.commitFailure) {
        return { ok: false as const, error };
      }
      throw error;
    }
  });
  if (!outcome.ok) throw outcome.error;
  return outcome.value;
};

const isVerifiedTotpFactor = (factor: { type: string; legacySource: string | null; lastUsedAt: Date | null }) =>
  factor.type === "TOTP" &&
  factor.legacySource !== MFA_ENROLLMENT_PENDING_SOURCE &&
  Boolean(factor.lastUsedAt || factor.legacySource === "AdminMfaCredential");

export const getAdminMfaAdapterStatus = async (userId: string, db: LoginMfaDbClient = prisma) => {
  const [legacyTotp, legacyWebAuthn, factors, backupCodesRemaining] = await Promise.all([
    db.adminMfaCredential.findUnique({
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
    db.adminWebAuthnCredential.findMany({
      where: { userId },
      orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
      select: { id: true, label: true, transports: true, lastUsedAt: true, createdAt: true, updatedAt: true },
    }),
    db.userMfaFactor.findMany({
      where: { userId, disabledAt: null },
      orderBy: [{ lastUsedAt: "desc" }, { createdAt: "desc" }],
      select: {
        id: true,
        type: true,
        label: true,
        legacySource: true,
        transports: true,
        lastUsedAt: true,
        createdAt: true,
        updatedAt: true,
      },
    }),
    db.userBackupCode.count({ where: { userId, usedAt: null } }),
  ]);

  const enrolledFactors = factors.filter((factor) => factor.legacySource !== MFA_ENROLLMENT_PENDING_SOURCE);
  const hasTotp = enrolledFactors.some(isVerifiedTotpFactor) || Boolean(legacyTotp?.isEnabled);
  const newWebAuthnFactors = enrolledFactors.filter((factor) => factor.type === "WEBAUTHN");
  const hasWebAuthn = newWebAuthnFactors.length > 0 || legacyWebAuthn.length > 0;
  const methods = [
    ...(hasWebAuthn ? (["WEBAUTHN"] as const) : []),
    ...(hasTotp ? (["TOTP"] as const) : []),
    ...(hasTotp && (backupCodesRemaining > 0 || (legacyTotp?.isEnabled && (legacyTotp.backupCodesHash?.length || 0) > 0))
      ? (["BACKUP_CODE"] as const)
      : []),
  ];
  const lastUsedAtCandidates = [
    legacyTotp?.lastUsedAt || null,
    ...legacyWebAuthn.map((entry) => entry.lastUsedAt || null),
    ...enrolledFactors.map((entry) => entry.lastUsedAt || null),
  ]
    .filter((value): value is Date => Boolean(value))
    .sort((a, b) => b.getTime() - a.getTime());

  return {
    enrolled: hasTotp || hasWebAuthn,
    enabled: hasTotp || hasWebAuthn,
    totpEnabled: hasTotp,
    hasWebAuthn,
    methods,
    preferredMethod: hasWebAuthn ? "WEBAUTHN" : hasTotp ? "TOTP" : null,
    verifiedAt: legacyTotp?.verifiedAt || null,
    lastUsedAt: lastUsedAtCandidates[0] || null,
    backupCodesRemaining: backupCodesRemaining || (legacyTotp?.isEnabled ? legacyTotp.backupCodesHash?.length || 0 : 0),
    createdAt: legacyTotp?.isEnabled ? legacyTotp.createdAt : enrolledFactors[0]?.createdAt || null,
    updatedAt: legacyTotp?.isEnabled ? legacyTotp.updatedAt : enrolledFactors[0]?.updatedAt || null,
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

export const lockMfaState = (tx: LoginMfaDbClient, userId: string) =>
  tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`mfa_state:${userId}`}, 0))`;

const pendingEnrollmentCutoff = () =>
  new Date(Date.now() - getMfaBootstrapTtlMinutes() * 60_000);

const assertEnrollmentMode = (mode: MfaEnrollmentMode, enrolled: boolean) => {
  if (mode === "FIRST_ENROLLMENT" && enrolled) throw new MfaAdapterError("MFA_ALREADY_ENROLLED", { status: 409 });
  if (mode === "REPLACEMENT" && !enrolled) {
    throw new MfaAdapterError("MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR", { status: 409 });
  }
};

export const beginTotpMfaEnrollment = async (params: {
  userId: string;
  email: string;
  mode: MfaEnrollmentMode;
}, db?: Prisma.TransactionClient): Promise<{ secret: string; otpauthUri: string; backupCodes: string[] }> => {
  if (!db) return prisma.$transaction((tx) => beginTotpMfaEnrollment(params, tx));
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret);
  const backupCodes = generateBackupCodes();
  const backupCodesHash = backupCodes.map((code) => hashBackupCode(code));
  const mode = params.mode;

  const tx = db;
    await lockMfaState(tx, params.userId);
    const [legacyTotp, legacyWebAuthnCount, factors] = await Promise.all([
      tx.adminMfaCredential.findUnique({
        where: { userId: params.userId },
        select: {
          id: true,
          userId: true,
          secretCiphertext: true,
          secretIv: true,
          secretTag: true,
          backupCodesHash: true,
          isEnabled: true,
          verifiedAt: true,
          lastUsedAt: true,
        },
      }),
      tx.adminWebAuthnCredential.count({ where: { userId: params.userId } }),
      tx.userMfaFactor.findMany({
        where: { userId: params.userId, disabledAt: null, type: { in: ["TOTP", "WEBAUTHN"] } },
        select: {
          id: true,
          type: true,
          secretCiphertext: true,
          secretIv: true,
          secretTag: true,
          legacySource: true,
          legacyCredentialId: true,
          credentialId: true,
          publicKey: true,
          createdAt: true,
          lastUsedAt: true,
        },
      }),
    ]);
    const enrolled = Boolean(legacyTotp?.isEnabled || legacyTotp?.verifiedAt || legacyWebAuthnCount) ||
      factors.some((factor) =>
        factor.legacySource !== MFA_ENROLLMENT_PENDING_SOURCE &&
        (factor.type === "WEBAUTHN" || isVerifiedTotpFactor(factor))
      );
    assertEnrollmentMode(mode, enrolled);

    const pending = factors.filter(
      (factor) => factor.type === "TOTP" && factor.legacySource === MFA_ENROLLMENT_PENDING_SOURCE
    );
    const cutoff = pendingEnrollmentCutoff();
    if (pending.some((factor) => factor.createdAt.getTime() > cutoff.getTime())) {
      throw new MfaAdapterError("MFA_SETUP_ALREADY_STARTED", { status: 409 });
    }
    if (pending.length) {
      await tx.userMfaFactor.deleteMany({ where: { id: { in: pending.map((factor) => factor.id) } } });
    }

    const enrolledTotpFactors = factors.filter(
      (factor) => factor.type === "TOTP" && factor.legacySource !== MFA_ENROLLMENT_PENDING_SOURCE
    );
    if (mode === "REPLACEMENT" && legacyTotp?.isEnabled && !enrolledTotpFactors.length) {
      await tx.userMfaFactor.upsert({
        where: { id: `legacy-totp-${params.userId}` },
        update: {
          type: "TOTP",
          label: "Authenticator app",
          secretCiphertext: legacyTotp.secretCiphertext,
          secretIv: legacyTotp.secretIv,
          secretTag: legacyTotp.secretTag,
          legacySource: "AdminMfaCredential",
          legacyCredentialId: params.userId,
          disabledAt: null,
          lastUsedAt: legacyTotp.lastUsedAt || legacyTotp.verifiedAt,
        },
        create: {
          id: `legacy-totp-${params.userId}`,
          userId: params.userId,
          type: "TOTP",
          label: "Authenticator app",
          secretCiphertext: legacyTotp.secretCiphertext,
          secretIv: legacyTotp.secretIv,
          secretTag: legacyTotp.secretTag,
          legacySource: "AdminMfaCredential",
          legacyCredentialId: params.userId,
          lastUsedAt: legacyTotp.lastUsedAt || legacyTotp.verifiedAt,
        },
      });
    }
    if (mode === "REPLACEMENT" && legacyTotp?.isEnabled && legacyTotp.backupCodesHash.length) {
      await tx.userBackupCode.createMany({
        data: legacyTotp.backupCodesHash.map((codeHash) => ({ userId: params.userId, codeHash })),
        skipDuplicates: true,
      });
    }

    await tx.adminMfaCredential.upsert({
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
    await tx.userMfaFactor.create({
      data: {
        userId: params.userId,
        type: "TOTP",
        label: "Authenticator app",
        ...encrypted,
        legacySource: MFA_ENROLLMENT_PENDING_SOURCE,
        legacyCredentialId: params.userId,
      },
    });
  return {
    secret,
    otpauthUri: buildTotpUri({ email: params.email, secret }),
    backupCodes,
  };
};

export const confirmTotpMfaEnrollment = async (params: {
  userId: string;
  code: string;
  mode: MfaEnrollmentMode;
  audit?: { ipHash: string | null; userAgent: string | null };
}, db?: Prisma.TransactionClient): Promise<{ enabled: true }> => {
  if (!db) return prisma.$transaction((tx) => confirmTotpMfaEnrollment(params, tx));
  const tx = db;
    await lockMfaState(tx, params.userId);
    const [legacyTotp, legacyWebAuthnCount, factors] = await Promise.all([
      tx.adminMfaCredential.findUnique({
        where: { userId: params.userId },
        select: {
          id: true,
          userId: true,
          secretCiphertext: true,
          secretIv: true,
          secretTag: true,
          backupCodesHash: true,
          isEnabled: true,
          verifiedAt: true,
          lastUsedAt: true,
        },
      }),
      tx.adminWebAuthnCredential.count({ where: { userId: params.userId } }),
      tx.userMfaFactor.findMany({
        where: { userId: params.userId, disabledAt: null, type: { in: ["TOTP", "WEBAUTHN"] } },
        select: {
          id: true,
          type: true,
          secretCiphertext: true,
          secretIv: true,
          secretTag: true,
          legacySource: true,
          legacyCredentialId: true,
          credentialId: true,
          publicKey: true,
          createdAt: true,
          lastUsedAt: true,
        },
      }),
    ]);
    const enrolled = Boolean(legacyTotp?.isEnabled || legacyTotp?.verifiedAt || legacyWebAuthnCount) ||
      factors.some((factor) =>
        factor.legacySource !== MFA_ENROLLMENT_PENDING_SOURCE &&
        (factor.type === "WEBAUTHN" || isVerifiedTotpFactor(factor))
      );
    const mode = params.mode;
    assertEnrollmentMode(mode, enrolled);

    const pending = factors.filter(
      (factor) =>
        factor.type === "TOTP" &&
        factor.legacySource === MFA_ENROLLMENT_PENDING_SOURCE &&
        factor.createdAt.getTime() > pendingEnrollmentCutoff().getTime()
    );
    if (pending.length !== 1 || !legacyTotp || legacyTotp.isEnabled || legacyTotp.verifiedAt) {
      throw new MfaAdapterError("MFA_SETUP_NOT_STARTED", { status: 409 });
    }
    const factor = pending[0];
    const secretPayload = factor.secretCiphertext && factor.secretIv && factor.secretTag
      ? {
          secretCiphertext: factor.secretCiphertext,
          secretIv: factor.secretIv,
          secretTag: factor.secretTag,
        } as EncryptedTotpSecret
      : null;
    if (
      !secretPayload ||
      secretPayload.secretCiphertext !== legacyTotp.secretCiphertext ||
      secretPayload.secretIv !== legacyTotp.secretIv ||
      secretPayload.secretTag !== legacyTotp.secretTag
    ) {
      throw new MfaAdapterError("MFA_SETUP_NOT_STARTED", { status: 409 });
    }

    const valid = await verifyTotpToken({ secret: decryptTotpSecret(secretPayload), token: params.code });
    if (!valid) throw new MfaAdapterError("INVALID_MFA_CODE", { status: 400 });

    const now = new Date();
    await tx.userMfaFactor.updateMany({
      where: { userId: params.userId, type: "TOTP", disabledAt: null, id: { not: factor.id } },
      data: { disabledAt: now },
    });
    await tx.userMfaFactor.update({
      where: { id: factor.id },
      data: {
        legacySource: null,
        legacyCredentialId: null,
        lastUsedAt: now,
        disabledAt: null,
      },
    });
    const enabled = await tx.adminMfaCredential.updateMany({
      where: { userId: params.userId, isEnabled: false, verifiedAt: null },
      data: { isEnabled: true, verifiedAt: now, lastUsedAt: now },
    });
    if (enabled.count !== 1) throw new MfaAdapterError("MFA_SETUP_NOT_STARTED", { status: 409 });

    await tx.userBackupCode.deleteMany({ where: { userId: params.userId, usedAt: null } });
    await tx.userBackupCode.createMany({
      data: legacyTotp.backupCodesHash.map((codeHash) => ({ userId: params.userId, codeHash })),
    });
    if (params.audit) {
      const replacement = mode === "REPLACEMENT";
      await tx.auditLogOutbox.create({
        data: {
          payload: {
            userId: params.userId,
            action: replacement ? "AUTH_MFA_REPLACED" : "AUTH_MFA_ENROLLED",
            entityType: "User",
            entityId: params.userId,
            details: { source: replacement ? "ACTIVE_SESSION" : "LOGIN_BOOTSTRAP" },
            ...params.audit,
          },
        },
      });
    }
  return { enabled: true };
};

const verifyTotpAgainstNewFactor = async (
  params: { userId: string; code: string },
  db: LoginMfaDbClient
): Promise<TotpVerificationPathResult> => {
  const factors = (await db.userMfaFactor.findMany({
    where: { userId: params.userId, type: "TOTP", disabledAt: null, secretCiphertext: { not: null } },
    orderBy: { createdAt: "desc" },
    select: {
      id: true,
      type: true,
      secretCiphertext: true,
      secretIv: true,
      secretTag: true,
      legacySource: true,
      lastUsedAt: true,
    },
  })).filter(isVerifiedTotpFactor);

  let attempted = 0;
  let operationalFailures = 0;
  for (const factor of factors) {
    if (!factor.secretCiphertext || !factor.secretIv || !factor.secretTag) continue;
    let verified = false;
    try {
      attempted += 1;
      verified = await verifyTotpToken({
        secret: decryptTotpSecret(factor as EncryptedTotpSecret),
        token: params.code,
      });
    } catch (error) {
      operationalFailures += 1;
      logTotpPathFailure({ userId: params.userId, factorPath: "new_factor", factorId: factor.id, error });
      continue;
    }
    if (verified) {
      await db.userMfaFactor.update({ where: { id: factor.id }, data: { lastUsedAt: new Date() } });
      return { verified: true, attempted, operationalFailures };
    }
  }
  return { verified: false, attempted, operationalFailures };
};

const verifyTotpAgainstLegacyCredential = async (
  params: { userId: string; code: string },
  db: LoginMfaDbClient
): Promise<TotpVerificationPathResult> => {
  const legacy = await db.adminMfaCredential.findUnique({
    where: { userId: params.userId },
    select: {
      userId: true,
      isEnabled: true,
      secretCiphertext: true,
      secretIv: true,
      secretTag: true,
    },
  });
  if (!legacy?.isEnabled) return { verified: false, attempted: 0, operationalFailures: 0 };

  let verified = false;
  try {
    verified = await verifyTotpToken({ secret: decryptTotpSecret(legacy), token: params.code });
  } catch (error) {
    logTotpPathFailure({ userId: params.userId, factorPath: "legacy_credential", factorId: params.userId, error });
    return { verified: false, attempted: 1, operationalFailures: 1 };
  }
  if (!verified) return { verified: false, attempted: 1, operationalFailures: 0 };

  const usedAt = new Date();
  try {
    await db.adminMfaCredential.update({ where: { userId: params.userId }, data: { lastUsedAt: usedAt } });
    await db.userMfaFactor.upsert({
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
        lastUsedAt: usedAt,
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
        lastUsedAt: usedAt,
      },
    });
  } catch (error) {
    logTotpPathFailure({ level: "error", userId: params.userId, factorPath: "legacy_credential", factorId: params.userId, error });
    throw new MfaAdapterError("MFA_VERIFICATION_UNAVAILABLE", { status: 409 });
  }
  return { verified: true, attempted: 1, operationalFailures: 0 };
};

const verifyMfaCodeWithClient = async (
  params: { userId: string; code: string },
  db: LoginMfaDbClient
) => {
  const normalizedCode = String(params.code || "").trim();
  if (!normalizedCode) throw new Error("INVALID_MFA_CODE");

  if (/^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(normalizedCode)) {
    const newBackupCodeCount = await db.userBackupCode.count({ where: { userId: params.userId } });
    const consumed = await consumeUserBackupCode({ userId: params.userId, code: normalizedCode }, db);
    if (consumed) return { ok: true as const, method: "BACKUP_CODE" as const };
    if (newBackupCodeCount > 0) throw new Error("INVALID_MFA_CODE");

    let legacy = await db.adminMfaCredential.findUnique({
      where: { userId: params.userId },
      select: { isEnabled: true, backupCodesHash: true },
    });
    for (let attempt = 0; attempt < 2 && legacy?.isEnabled && legacy.backupCodesHash.length; attempt += 1) {
      if (await consumeLegacyBackupCode({
          userId: params.userId,
          code: normalizedCode,
          codesHash: legacy.backupCodesHash,
        }, db)) {
        return { ok: true as const, method: "BACKUP_CODE" as const };
      }
      if (await consumeUserBackupCode({ userId: params.userId, code: normalizedCode }, db)) {
        return { ok: true as const, method: "BACKUP_CODE" as const };
      }
      legacy = await db.adminMfaCredential.findUnique({
        where: { userId: params.userId },
        select: { isEnabled: true, backupCodesHash: true },
      });
    }
  }

  const newFactorResult = await verifyTotpAgainstNewFactor({ userId: params.userId, code: normalizedCode }, db);
  if (newFactorResult.verified) return { ok: true as const, method: "TOTP" as const };

  const legacyResult = await verifyTotpAgainstLegacyCredential({ userId: params.userId, code: normalizedCode }, db);
  if (legacyResult.verified) return { ok: true as const, method: "TOTP" as const };

  const attempted = newFactorResult.attempted + legacyResult.attempted;
  const operationalFailures = newFactorResult.operationalFailures + legacyResult.operationalFailures;
  if (attempted > 0 && attempted === operationalFailures) {
    logger.error("auth_mfa_totp_verification_unavailable", {
      userId: params.userId,
      factorPathsAttempted: [
        ...(newFactorResult.attempted > 0 ? ["new_factor"] : []),
        ...(legacyResult.attempted > 0 ? ["legacy_credential"] : []),
      ],
      errorCategory: "MFA_VERIFICATION_UNAVAILABLE",
    });
    throw new MfaAdapterError("MFA_VERIFICATION_UNAVAILABLE", { status: 409 });
  }

  if (operationalFailures > 0) {
    logger.warn("auth_mfa_totp_verification_completed_with_factor_errors", {
      userId: params.userId,
      factorPathsAttempted: [
        ...(newFactorResult.attempted > 0 ? ["new_factor"] : []),
        ...(legacyResult.attempted > 0 ? ["legacy_credential"] : []),
      ],
      operationalFailures,
    });
  }

  throw new Error("INVALID_MFA_CODE");
};

export const verifyMfaCodeWithAdapter = async (
  params: { userId: string; code: string },
  db?: Prisma.TransactionClient
) => {
  const verify = async (tx: Prisma.TransactionClient) => {
    await lockMfaState(tx, params.userId);
    return verifyMfaCodeWithClient(params, tx);
  };
  return db ? verify(db) : prisma.$transaction(verify);
};

export const rotateMfaBackupCodesWithAdapter = async (
  params: { userId: string; code: string },
  db?: Prisma.TransactionClient
) => {
  const rotate = async (tx: Prisma.TransactionClient) => {
    await verifyMfaCodeWithAdapter({ userId: params.userId, code: params.code }, tx);
    const backupCodes = generateBackupCodes();
    await replaceUserBackupCodes({ userId: params.userId, codes: backupCodes }, tx);
    await tx.adminMfaCredential.updateMany({
      where: { userId: params.userId },
      data: {
        backupCodesHash: backupCodes.map((code) => hashBackupCode(code)),
        lastUsedAt: new Date(),
      },
    });
    return { backupCodes };
  };
  return db ? rotate(db) : prisma.$transaction(rotate);
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
}, db: LoginMfaDbClient = prisma) => {
  const ticket = randomOpaqueToken(36);
  const now = new Date();
  const { expiresAt, config: ttlConfig } = buildAdminMfaChallengeExpiry(now);
  const purpose = String(params.purpose || "admin_login").trim() || "admin_login";
  const maxAttempts = Math.max(1, Math.min(10, params.maxAttempts || getMaxChallengeAttempts()));

  const challenge = await db.mfaLoginChallenge.create({
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

  await db.auditLogOutbox.create(mfaAuditOutboxRecord({
    userId: params.userId,
    action: "AUTH_MFA_CHALLENGE_ISSUED",
    entityId: challenge.id,
    details: { purpose, riskScore: challenge.riskScore, riskLevel: challenge.riskLevel, ...ttlDetails },
    ipHash: params.ipHash,
    userAgent: params.userAgent,
  }));

  return { ticket, expiresAt };
};

export const completeStableMfaLoginChallenge = async (params: {
  userId: string;
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
  if (!db) return runMfaCompletionTransaction((tx) => completeStableMfaLoginChallenge(params, tx));

  await lockMfaState(db, params.userId);
  const now = new Date();
  const challenge = await db.mfaLoginChallenge.findFirst({
    where: { ticketHash: { in: buildTokenHashCandidates(String(params.ticket || "").trim()) } },
  });
  if (!challenge) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (challenge.userId !== params.userId) throw new MfaAdapterError("MFA_CHALLENGE_FORBIDDEN", { status: 403 });
  if (challenge.consumedAt) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (challenge.expiresAt.getTime() <= now.getTime()) {
    await db.auditLogOutbox.create(mfaAuditOutboxRecord({
      userId: challenge.userId,
      action: "AUTH_MFA_CHALLENGE_EXPIRED",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, expiresAt: challenge.expiresAt.toISOString() },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    }));
    throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410, commitFailure: true });
  }
  if (challenge.attempts >= challenge.maxAttempts) {
    const retryAfterSeconds = challenge.retryAfterSeconds || 60;
    await db.auditLogOutbox.create(mfaAuditOutboxRecord({
      userId: challenge.userId,
      action: "AUTH_MFA_TOO_MANY_ATTEMPTS",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, attempts: challenge.attempts, maxAttempts: challenge.maxAttempts },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    }));
    throw new MfaAdapterError("MFA_TOO_MANY_ATTEMPTS", {
      status: 429,
      retryAfterSeconds,
      commitFailure: true,
    });
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

  let failureReason: "INVALID_CODE_SHAPE" | "INVALID_MFA_CODE" | null = codeShapeOk ? null : "INVALID_CODE_SHAPE";
  let verification!: Awaited<ReturnType<typeof verifyMfaCodeWithAdapter>>;
  if (!failureReason) {
    try {
      verification = await verifyMfaCodeWithAdapter({ userId: challenge.userId, code: normalizedCode }, db);
    } catch (error) {
      if (error instanceof Error && error.message === "INVALID_MFA_CODE") {
        failureReason = "INVALID_MFA_CODE";
      } else {
        logger.warn("auth_mfa_challenge_verifier_error", {
          userId: challenge.userId,
          challengeId: challenge.id,
          purpose: challenge.purpose,
          requestedMethod,
          errorCategory: error instanceof MfaAdapterError ? error.message : safeMfaErrorCategory(error),
          errorName: error instanceof Error ? error.name : typeof error,
        });
        throw error;
      }
    }
  }

  if (failureReason) {
    const nextAttempts = challenge.attempts + 1;
    const retryAfterSeconds = nextAttempts >= challenge.maxAttempts ? 60 : null;
    const updated = await db.mfaLoginChallenge.updateMany({
      where: { id: challenge.id, consumedAt: null },
      data: {
        attempts: { increment: 1 },
        retryAfterSeconds,
      },
    });
    if (updated.count !== 1) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
    await db.auditLogOutbox.create(mfaAuditOutboxRecord({
      userId: challenge.userId,
      action: nextAttempts >= challenge.maxAttempts ? "AUTH_MFA_TOO_MANY_ATTEMPTS" : "AUTH_MFA_FAILURE",
      entityId: challenge.id,
      details: { purpose: challenge.purpose, attempts: nextAttempts, maxAttempts: challenge.maxAttempts, ...(failureReason === "INVALID_CODE_SHAPE" ? { reason: failureReason } : {}) },
      ipHash: params.ipHash,
      userAgent: params.userAgent,
    }));
    throw new MfaAdapterError(nextAttempts >= challenge.maxAttempts ? "MFA_TOO_MANY_ATTEMPTS" : "INVALID_MFA_CODE", {
      status: nextAttempts >= challenge.maxAttempts ? 429 : 400,
      retryAfterSeconds: retryAfterSeconds || undefined,
      commitFailure: true,
    });
  }

  const consumed = await db.mfaLoginChallenge.updateMany({
    where: { id: challenge.id, consumedAt: null, expiresAt: { gt: now } },
    data: { consumedAt: now },
  });
  if (consumed.count !== 1) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });

  await db.auditLogOutbox.create(mfaAuditOutboxRecord({
    userId: challenge.userId,
    action: verification.method === "BACKUP_CODE" ? "AUTH_MFA_BACKUP_CODE_USED" : "AUTH_MFA_SUCCESS",
    entityId: challenge.id,
    details: { purpose: challenge.purpose, method: verification.method, riskScore: challenge.riskScore, riskLevel: challenge.riskLevel },
    ipHash: params.ipHash,
    userAgent: params.userAgent,
  }));

  return {
    userId: challenge.userId,
    riskScore: challenge.riskScore,
    riskLevel: challenge.riskLevel,
    reasons: challenge.reasons,
    method: verification.method,
  };
};

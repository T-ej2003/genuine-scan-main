import { AuthRiskLevel, Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { buildTokenHashCandidates, hashToken, randomOpaqueToken } from "../../utils/security";
import { logger } from "../../utils/logger";
import { buildAdminMfaChallengeExpiry, buildAdminMfaChallengeTtlAuditDetails } from "./authDurationConfig";
import {
  generateBackupCodes,
  hashBackupCode,
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
import {
  beginAdminTotpEnrollment,
  completeAdminTotpEnrollment,
  consumeAdminMfaVerifier,
  loadAdminMfaState,
  loadAdminMfaVerifiers,
  loadAdminTotpEnrollment,
  replaceAdminBackupCodes,
  createAdminMfaChallengeBoundary,
  loadAdminMfaChallengeBoundary,
  recordAdminMfaChallengeFailure,
  completeAdminMfaChallengeBoundary,
} from "../../rls-waves/session-b/b01/adminMfaRepository";
import { buildBackupCodeHashCandidates, matchesBackupCodeHash } from "./backupCodeHashService";

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
  "$executeRaw" | "$queryRaw" | "mfaLoginChallenge" | "auditLogOutbox"
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
  if (!db?.$queryRaw) throw new Error("B01 MFA capability transaction is required");
  const state = await loadAdminMfaState(db);
  const legacyTotp = (state.legacyTotp || null) as any;
  const legacyWebAuthn = Array.isArray(state.legacyWebAuthn) ? state.legacyWebAuthn as any[] : [];
  const factors = Array.isArray(state.factors) ? state.factors as any[] : [];
  const backupCodesRemaining = Number(state.backupCodesRemaining || 0);
  const asDate = (value: unknown) => value ? new Date(String(value)) : null;

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
    asDate(legacyTotp?.lastUsedAt),
    ...legacyWebAuthn.map((entry) => asDate(entry.lastUsedAt)),
    ...enrolledFactors.map((entry) => asDate(entry.lastUsedAt)),
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
    verifiedAt: asDate(legacyTotp?.verifiedAt),
    lastUsedAt: lastUsedAtCandidates[0] || null,
    backupCodesRemaining: backupCodesRemaining || (legacyTotp?.isEnabled ? legacyTotp.backupCodesHash?.length || 0 : 0),
    createdAt: asDate(legacyTotp?.isEnabled ? legacyTotp.createdAt : enrolledFactors[0]?.createdAt),
    updatedAt: asDate(legacyTotp?.isEnabled ? legacyTotp.updatedAt : enrolledFactors[0]?.updatedAt),
    webauthnCredentials: [
      ...newWebAuthnFactors.map((entry) => ({
        id: entry.id,
        label: entry.label || "Passkey",
        transports: entry.transports,
        lastUsedAt: asDate(entry.lastUsedAt),
        createdAt: asDate(entry.createdAt),
        updatedAt: asDate(entry.updatedAt),
      })),
      ...legacyWebAuthn.map((entry) => ({
        id: entry.id,
        label: entry.label || "Security key",
        transports: entry.transports,
        lastUsedAt: asDate(entry.lastUsedAt),
        createdAt: asDate(entry.createdAt),
        updatedAt: asDate(entry.updatedAt),
      })),
    ],
  };
};

export const lockMfaState = (tx: LoginMfaDbClient, userId: string) =>
  tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${`mfa_state:${userId}`}, 0))`;

const pendingEnrollmentCutoff = () =>
  new Date(Date.now() - getMfaBootstrapTtlMinutes() * 60_000);

const sessionBindingCandidates = (sessionId?: string | null) => {
  const normalized = String(sessionId || "").trim();
  return normalized ? buildTokenHashCandidates(`admin-mfa-session:${normalized}`) : [];
};

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
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const secret = createTotpSecret();
  const encrypted = encryptTotpSecret(secret);
  const backupCodes = generateBackupCodes();
  const backupCodesHash = backupCodes.map((code) => hashBackupCode(code));
  await beginAdminTotpEnrollment(db, {
    mode: params.mode,
    ...encrypted,
    backupHashes: backupCodesHash,
    pendingCutoff: pendingEnrollmentCutoff(),
    createdAt: new Date(),
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
  if (!db) throw new Error("B01 MFA capability transaction is required");
  const state = await loadAdminTotpEnrollment(db, { mode: params.mode, pendingCutoff: pendingEnrollmentCutoff() }) as any;
  const pending = Array.isArray(state.pending) ? state.pending : [];
  const legacyTotp = state.credential;
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
  await completeAdminTotpEnrollment(db, {
    mode: params.mode,
    factorId: factor.id,
    ...secretPayload,
    completedAt: new Date(),
    ipHash: params.audit?.ipHash || null,
    userAgent: params.audit?.userAgent || null,
  });
  return { enabled: true };
};

const verifyMfaCodeWithClient = async (
  params: { userId: string; code: string },
  db: LoginMfaDbClient
) => {
  const normalizedCode = String(params.code || "").trim();
  if (!normalizedCode) throw new Error("INVALID_MFA_CODE");
  const state = await loadAdminMfaVerifiers(db) as any;
  if (/^[A-Za-z0-9]{4,8}-[A-Za-z0-9]{4,8}$/.test(normalizedCode)) {
    const backupCodes = Array.isArray(state.backupCodes) ? state.backupCodes as Array<{ id: string; codeHash: string }> : [];
    const candidates = buildBackupCodeHashCandidates(normalizedCode);
    const row = backupCodes.find((entry) => candidates.includes(entry.codeHash));
    if (row) {
      const result = await consumeAdminMfaVerifier(db, { method: "BACKUP_CODE", recordId: row.id, usedAt: new Date() });
      if (result.consumed) return { ok: true as const, method: "BACKUP_CODE" as const };
    }
    if (backupCodes.length) throw new Error("INVALID_MFA_CODE");
    const hashes = Array.isArray(state.legacy?.backupCodesHash) ? state.legacy.backupCodesHash as string[] : [];
    const index = hashes.findIndex((entry) => matchesBackupCodeHash(normalizedCode, entry));
    if (state.legacy?.isEnabled && index >= 0) {
      const next = [...hashes];
      next.splice(index, 1);
      const result = await consumeAdminMfaVerifier(db, {
        method: "BACKUP_LEGACY", expectedLegacyHashes: hashes, nextLegacyHashes: next, usedAt: new Date(),
      });
      if (result.consumed) return { ok: true as const, method: "BACKUP_CODE" as const };
    }
  }

  let attempted = 0;
  let operationalFailures = 0;
  const factors = Array.isArray(state.factors) ? state.factors as any[] : [];
  for (const factor of factors.filter(isVerifiedTotpFactor)) {
    if (!factor.secretCiphertext || !factor.secretIv || !factor.secretTag) continue;
    try {
      attempted += 1;
      if (await verifyTotpToken({ secret: decryptTotpSecret(factor), token: normalizedCode })) {
        const result = await consumeAdminMfaVerifier(db, { method: "TOTP_FACTOR", recordId: factor.id, usedAt: new Date() });
        if (result.consumed) return { ok: true as const, method: "TOTP" as const };
      }
    } catch (error) {
      operationalFailures += 1;
      logTotpPathFailure({ userId: params.userId, factorPath: "new_factor", factorId: factor.id, error });
    }
  }
  const legacy = state.legacy;
  if (legacy?.isEnabled && legacy.secretCiphertext && legacy.secretIv && legacy.secretTag) {
    try {
      attempted += 1;
      if (await verifyTotpToken({ secret: decryptTotpSecret(legacy), token: normalizedCode })) {
        const result = await consumeAdminMfaVerifier(db, { method: "TOTP_LEGACY", usedAt: new Date() });
        if (result.consumed) return { ok: true as const, method: "TOTP" as const };
      }
    } catch (error) {
      operationalFailures += 1;
      logTotpPathFailure({ userId: params.userId, factorPath: "legacy_credential", factorId: params.userId, error });
    }
  }
  if (attempted > 0 && attempted === operationalFailures) {
    logger.error("auth_mfa_totp_verification_unavailable", {
      userId: params.userId,
      factorPathsAttempted: [
        ...(factors.length ? ["new_factor"] : []),
        ...(legacy?.isEnabled ? ["legacy_credential"] : []),
      ],
      errorCategory: "MFA_VERIFICATION_UNAVAILABLE",
    });
    throw new MfaAdapterError("MFA_VERIFICATION_UNAVAILABLE", { status: 409 });
  }

  if (operationalFailures > 0) {
    logger.warn("auth_mfa_totp_verification_completed_with_factor_errors", {
      userId: params.userId,
      factorPathsAttempted: [
        ...(factors.length ? ["new_factor"] : []),
        ...(legacy?.isEnabled ? ["legacy_credential"] : []),
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
  if (!db) throw new Error("B01 MFA capability transaction is required");
  return verifyMfaCodeWithClient(params, db as LoginMfaDbClient);
};

export const rotateMfaBackupCodesWithAdapter = async (
  params: { userId: string; code: string },
  db?: Prisma.TransactionClient
) => {
  if (!db) throw new Error("B01 MFA capability transaction is required");
  await verifyMfaCodeWithAdapter({ userId: params.userId, code: params.code }, db);
  const backupCodes = generateBackupCodes();
  await replaceAdminBackupCodes(db, backupCodes.map(hashBackupCode), new Date());
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
}, db: LoginMfaDbClient = prisma) => {
  if (!db?.$queryRaw) throw new Error("B01 MFA capability transaction is required");
  const ticket = randomOpaqueToken(36);
  const now = new Date();
  const { expiresAt, config: ttlConfig } = buildAdminMfaChallengeExpiry(now);
  const purpose = String(params.purpose || "admin_login").trim() || "admin_login";
  const maxAttempts = Math.max(1, Math.min(10, params.maxAttempts || getMaxChallengeAttempts()));

  const riskScore = Math.max(0, Math.min(100, Math.round(params.riskScore || 0)));
  const riskLevel = normalizeRiskLevel(params.riskLevel);
  const challenge = await createAdminMfaChallengeBoundary(db, {
    kind: "LOGIN",
    ticketHash: hashToken(ticket),
    sessionBindingHash: null,
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

  return { ticket, expiresAt };
};

export const completeStableMfaLoginChallenge = async (params: {
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
  const now = new Date();
  const challenge = await loadAdminMfaChallengeBoundary(db, {
    ticketHashes: buildTokenHashCandidates(String(params.ticket || "").trim()),
    sessionBindingHashes: sessionBindingCandidates(params.sessionId),
    checkedAt: now,
  });
  if (!challenge) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (challenge.userId !== params.userId) throw new MfaAdapterError("MFA_CHALLENGE_FORBIDDEN", { status: 403 });
  if (challenge.consumedAt) throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410 });
  if (new Date(challenge.expiresAt).getTime() <= now.getTime()) {
    await recordAdminMfaChallengeFailure(db, {
      kind: challenge.kind,
      challengeId: challenge.id,
      action: "AUTH_MFA_CHALLENGE_EXPIRED",
      attempts: challenge.attempts,
      failedAt: now,
      ipHash: params.ipHash || null,
      userAgent: params.userAgent || null,
    });
    throw new MfaAdapterError("MFA_CHALLENGE_NOT_FOUND", { status: 410, commitFailure: true });
  }
  if (challenge.attempts >= challenge.maxAttempts) {
    const retryAfterSeconds = 60;
    await recordAdminMfaChallengeFailure(db, {
      kind: challenge.kind,
      challengeId: challenge.id,
      action: "AUTH_MFA_TOO_MANY_ATTEMPTS",
      attempts: challenge.attempts,
      failedAt: now,
      ipHash: params.ipHash || null,
      userAgent: params.userAgent || null,
    });
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
    await recordAdminMfaChallengeFailure(db, {
      kind: challenge.kind,
      challengeId: challenge.id,
      action: nextAttempts >= challenge.maxAttempts ? "AUTH_MFA_TOO_MANY_ATTEMPTS" : "AUTH_MFA_FAILURE",
      attempts: nextAttempts,
      failedAt: now,
      ipHash: params.ipHash || null,
      userAgent: params.userAgent || null,
    });
    throw new MfaAdapterError(nextAttempts >= challenge.maxAttempts ? "MFA_TOO_MANY_ATTEMPTS" : "INVALID_MFA_CODE", {
      status: nextAttempts >= challenge.maxAttempts ? 429 : 400,
      retryAfterSeconds: retryAfterSeconds || undefined,
      commitFailure: true,
    });
  }

  await completeAdminMfaChallengeBoundary(db, {
    kind: challenge.kind,
    challengeId: challenge.id,
    method: verification.method,
    completedAt: now,
    ipHash: params.ipHash || null,
    userAgent: params.userAgent || null,
  });

  return {
    userId: challenge.userId,
    riskScore: challenge.riskScore,
    riskLevel: challenge.riskLevel as AuthRiskLevel,
    reasons: challenge.reasons,
    method: verification.method,
  };
};

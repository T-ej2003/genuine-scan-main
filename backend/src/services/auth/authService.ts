import prisma from "../../config/database";
import { Prisma, UserRole, UserStatus } from "@prisma/client";
import { verifyPassword, hashPassword, shouldRehashPassword } from "./passwordService";
import {
  signAccessToken,
  newRefreshToken,
  signMfaBootstrapToken,
  getMfaBootstrapTtlMinutes,
} from "./tokenService";
import {
  createRefreshToken,
  rotateRefreshToken,
  revokeAllUserRefreshTokens,
  revokeRefreshTokenByRaw,
} from "./refreshTokenService";
import { createAuditLog } from "../auditService";
import { assessAuthSessionRisk } from "./sessionRiskService";
import { resolveManufacturerSessionScope } from "../manufacturerScopeService";
import { isVerifiedAccount } from "./emailVerificationService";
import { createAdminMfaChallenge, getAdminMfaStatus } from "./mfaService";
import { randomOpaqueToken } from "../../utils/security";
import type { AuthAssuranceLevel, AuthSessionStage, StepUpMethod } from "../../types";
// rls-prototype-approved-import: reviewed auth bootstrap context boundary.
import { withRlsPrototypeTransaction } from "../../lib/rlsTransactionContextPrototype";
import { lookupPasswordBootstrapUser, recordPasswordLoginFailure } from "./authBootstrapRepository";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const getMaxLoginAttempts = () => parseIntEnv("AUTH_MAX_LOGIN_ATTEMPTS", 10);
const getLockoutMinutes = () => parseIntEnv("AUTH_LOCKOUT_MINUTES", 15);
export const getAdminStepUpWindowMinutes = () => parseIntEnv("ADMIN_STEP_UP_WINDOW_MINUTES", 30);
export const getPasswordReauthWindowMinutes = () => parseIntEnv("AUTH_PASSWORD_STEP_UP_WINDOW_MINUTES", 30);
export const getAdminLoginMfaCycleDays = () => parseIntEnv("ADMIN_LOGIN_MFA_CYCLE_DAYS", 28);

const addMinutes = (d: Date, minutes: number) => new Date(d.getTime() + minutes * 60 * 1000);
const addDays = (d: Date, days: number) => new Date(d.getTime() + days * 24 * 60 * 60 * 1000);
const DISABLED_STATUS = (UserStatus as unknown as { DISABLED?: string } | undefined)?.DISABLED || "DISABLED";

const isDisabledUser = (u: {
  deletedAt: Date | null;
  isActive: boolean;
  status: string | null;
  disabledAt?: Date | null;
}) =>
  Boolean(u.deletedAt) ||
  u.isActive === false ||
  Boolean(u.disabledAt) ||
  String(u.status || "").toUpperCase() === DISABLED_STATUS;

export const isPlatformSuperAdminRole = (role: UserRole) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const isOrgAdminRole = (role: UserRole) =>
  role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN;

export const isAdminMfaRequiredRole = (role: UserRole) =>
  isPlatformSuperAdminRole(role) || isOrgAdminRole(role) || isManufacturerRole(role);

export const isManufacturerRole = (role: UserRole) =>
  role === UserRole.MANUFACTURER || role === UserRole.MANUFACTURER_ADMIN || role === UserRole.MANUFACTURER_USER;

export const getSensitiveActionStepUpMethod = (role: UserRole): StepUpMethod =>
  isAdminMfaRequiredRole(role) ? "ADMIN_MFA" : "PASSWORD_REAUTH";

export const buildJwtPayloadForUser = (u: {
  id: string;
  email: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  scopeVersion?: string | null;
  linkedLicenseeIds?: string[] | null;
  authAssurance: AuthAssuranceLevel;
  authenticatedAt?: Date | null;
  mfaVerifiedAt?: Date | null;
}) => ({
  userId: u.id,
  email: u.email,
  role: u.role,
  licenseeId: u.licenseeId,
  orgId: u.orgId,
  scopeVersion: u.scopeVersion || null,
  linkedLicenseeIds: u.linkedLicenseeIds || null,
  sessionStage: "ACTIVE" as const,
  authAssurance: u.authAssurance,
  authenticatedAt: u.authenticatedAt?.toISOString?.() || null,
  mfaVerifiedAt: u.mfaVerifiedAt?.toISOString?.() || null,
});

type AuthDbClient = Prisma.TransactionClient;

export const authSessionUserSelect = Prisma.validator<Prisma.UserSelect>()({
  id: true,
  email: true,
  name: true,
  role: true,
  licenseeId: true,
  orgId: true,
  emailVerifiedAt: true,
  deletedAt: true,
  disabledAt: true,
  isActive: true,
  status: true,
  licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } },
});

type AuthSessionUser = Prisma.UserGetPayload<{ select: typeof authSessionUserSelect }>;
type SessionScopeInput = {
  requestedLicenseeId?: string | null;
  requestedOrgId?: string | null;
  requestedScopeVersion?: string | null;
  requestId?: string | null;
  purpose?: "manufacturer-bootstrap" | "manufacturer-scope-switch";
};

const mapLinkedLicenseesForSession = async (
  user: Pick<AuthSessionUser, "id" | "licenseeId" | "orgId">,
  input: SessionScopeInput,
  assurance: "password-verified" | "mfa-verified",
  db: AuthDbClient
) => resolveManufacturerSessionScope({
  manufacturerId: user.id,
  legacyLicenseeId: user.licenseeId,
  legacyOrgId: user.orgId,
  requestedLicenseeId: input.requestedLicenseeId,
  requestedOrgId: input.requestedOrgId,
  requestedScopeVersion: input.requestedScopeVersion,
  audit: input.requestId && input.purpose
    ? { requestId: input.requestId, purpose: input.purpose, assurance }
    : undefined,
}, db);

const loadActiveSessionState = async (
  input: { userId: string; authAssurance: AuthAssuranceLevel } & SessionScopeInput,
  db: AuthDbClient
) => {
  const user = await db.user.findUnique({ where: { id: input.userId }, select: authSessionUserSelect });
  if (!user) throw new Error("User not found");
  if (isDisabledUser(user)) throw new Error("Account is disabled");

  const mfaRequired = isAdminMfaRequiredRole(user.role);
  const mfaStatus = mfaRequired ? await getAdminMfaStatus(user.id, db) : null;
  if (input.authAssurance === "ADMIN_MFA" && mfaRequired && !mfaStatus?.enabled) {
    throw new Error("MFA_CURRENT_STATE_REQUIRED");
  }

  const linkedScope = isManufacturerRole(user.role)
    ? await mapLinkedLicenseesForSession(
        user,
        input,
        input.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
        db
      )
    : { selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] as string[] };
  if (isManufacturerRole(user.role) && !linkedScope.selectedLicensee) {
    throw new Error("SCOPE_SELECTION_REQUIRED");
  }

  const primaryLicensee = isManufacturerRole(user.role) ? linkedScope.selectedLicensee : user.licensee;
  return {
    user,
    linkedScope,
    mfaRequired,
    mfaStatus,
    primaryLicensee,
    sessionLicenseeId: primaryLicensee?.id || (isManufacturerRole(user.role) ? null : user.licenseeId),
    sessionOrgId: primaryLicensee?.orgId || (isManufacturerRole(user.role) ? null : user.orgId),
    scopeVersion: isManufacturerRole(user.role) ? linkedScope.selectedLicensee?.scopeVersion ?? null : null,
  };
};

type ActiveSessionState = Awaited<ReturnType<typeof loadActiveSessionState>>;

const buildActiveSessionResponse = (
  state: ActiveSessionState,
  input: {
    authAssurance: AuthAssuranceLevel;
    authenticatedAt: Date;
    mfaVerifiedAt: Date | null;
  },
  refresh: { rawToken: string; id: string; expiresAt: Date }
) => {
  const { user, linkedScope, mfaRequired, mfaStatus, primaryLicensee, sessionLicenseeId, sessionOrgId, scopeVersion } = state;
  const accessToken = signAccessToken(buildJwtPayloadForUser({
    id: user.id,
    email: user.email,
    role: user.role,
    licenseeId: sessionLicenseeId,
    orgId: sessionOrgId,
    scopeVersion,
    linkedLicenseeIds: linkedScope.linkedLicenseeIds,
    authAssurance: input.authAssurance,
    authenticatedAt: input.authenticatedAt,
    mfaVerifiedAt: input.mfaVerifiedAt,
  }));

  return {
    sessionStage: "ACTIVE" as AuthSessionStage,
    accessToken,
    refreshToken: refresh.rawToken,
    refreshTokenExpiresAt: refresh.expiresAt,
    sessionId: refresh.id,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      licenseeId: sessionLicenseeId,
      orgId: sessionOrgId,
      scopeVersion,
      licensee: primaryLicensee
        ? {
            id: primaryLicensee.id,
            name: primaryLicensee.name,
            prefix: primaryLicensee.prefix,
            brandName: "brandName" in primaryLicensee ? primaryLicensee.brandName ?? null : null,
            ...(scopeVersion ? { scopeVersion } : {}),
          }
        : null,
      linkedLicensees: linkedScope.linkedLicensees,
      emailVerifiedAt: user.emailVerifiedAt,
    },
    auth: {
      sessionStage: "ACTIVE" as const,
      authAssurance: input.authAssurance,
      mfaRequired,
      mfaEnrolled: mfaRequired ? Boolean(mfaStatus?.enabled || mfaStatus?.enrolled) : input.authAssurance === "ADMIN_MFA",
      availableMfaMethods: mfaRequired ? mfaStatus?.methods || [] : [],
      preferredMfaMethod: mfaRequired ? mfaStatus?.preferredMethod || null : null,
      authenticatedAt: input.authenticatedAt.toISOString(),
      mfaVerifiedAt: input.mfaVerifiedAt?.toISOString?.() || null,
      stepUpRequired: false,
      stepUpMethod: getSensitiveActionStepUpMethod(user.role),
      sessionId: refresh.id,
      sessionExpiresAt: refresh.expiresAt.toISOString(),
    },
  };
};

export const issueSessionForUser = async (input: {
  userId: string;
  ipHash: string | null;
  userAgent: string | null;
  authAssurance?: AuthAssuranceLevel;
  authenticatedAt?: Date | null;
  mfaVerifiedAt?: Date | null;
  now?: Date;
} & SessionScopeInput, db: AuthDbClient = prisma) => {
  const now = input.now || new Date();
  const authAssurance = input.authAssurance || "PASSWORD";
  const authenticatedAt = input.authenticatedAt || now;
  const mfaVerifiedAt = input.mfaVerifiedAt || null;
  const state = await loadActiveSessionState({ ...input, authAssurance }, db);
  const refreshToken = newRefreshToken();
  const created = await createRefreshToken({
    userId: state.user.id,
    orgId: state.sessionOrgId,
    rawToken: refreshToken,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    authenticatedAt,
    mfaVerifiedAt,
    now,
  }, db);
  return buildActiveSessionResponse(state, { authAssurance, authenticatedAt, mfaVerifiedAt }, {
    rawToken: refreshToken,
    id: created.row.id,
    expiresAt: created.expiresAt,
  });
};

type SessionIssueResult = Awaited<ReturnType<typeof issueSessionForUser>>;

type BootstrapSessionResult = {
  sessionStage: "MFA_BOOTSTRAP";
  accessToken: string;
  refreshToken: null;
  refreshTokenExpiresAt: null;
  user: SessionIssueResult["user"];
  auth: {
    sessionStage: "MFA_BOOTSTRAP";
    authAssurance: "PASSWORD";
    mfaRequired: true;
    mfaEnrolled: boolean;
    authenticatedAt: string;
    mfaVerifiedAt: null;
    stepUpRequired: boolean;
    stepUpMethod: "ADMIN_MFA";
    sessionId: string;
    sessionExpiresAt: string;
    mfaChallenge?: {
      ticket: string;
      expiresAt: string;
    } | null;
  };
};

export type PasswordLoginResult = SessionIssueResult | BootstrapSessionResult;
type RefreshSessionResult =
  | { ok: false; reason: "INVALID" | "EXPIRED" | "REVOKED" | "REUSE_DETECTED" }
  | ({ ok: true } & (SessionIssueResult | BootstrapSessionResult));

const buildBootstrapSessionForUser = async (input: {
  user: {
    id: string;
    email: string;
    name: string;
    role: UserRole;
    licenseeId: string | null;
    orgId: string | null;
    emailVerifiedAt: Date | null;
    licensee?: { id: string; name: string; prefix: string; brandName?: string | null; orgId?: string | null } | null;
  };
  ipHash: string | null;
  userAgent: string | null;
  now: Date;
  mfaEnrolled: boolean;
  riskScore?: number;
  riskLevel?: string | null;
  reasons?: string[];
  requestId?: string | null;
  requestedLicenseeId?: string | null;
  requestedScopeVersion?: string | null;
}, db: AuthDbClient = prisma) => {
  const linkedScope = isManufacturerRole(input.user.role)
    ? await mapLinkedLicenseesForSession(input.user, {
        requestedLicenseeId: input.requestedLicenseeId,
        requestedScopeVersion: input.requestedScopeVersion,
        requestId: input.requestId,
        purpose: "manufacturer-bootstrap",
      }, "password-verified", db)
    : { selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] as string[] };
  const mfaStatus = await getAdminMfaStatus(input.user.id, db);
  const primaryLicensee = isManufacturerRole(input.user.role)
    ? linkedScope.selectedLicensee
    : input.user.licensee || null;
  const sessionLicenseeId = primaryLicensee?.id || (isManufacturerRole(input.user.role) ? null : input.user.licenseeId);
  const sessionOrgId = primaryLicensee?.orgId || (isManufacturerRole(input.user.role) ? null : input.user.orgId);
  const scopeVersion = isManufacturerRole(input.user.role)
    ? linkedScope.selectedLicensee?.scopeVersion ?? null
    : null;

  const bootstrapSessionId = randomOpaqueToken(24);
  const accessToken = signMfaBootstrapToken({
    userId: input.user.id,
    email: input.user.email,
    role: input.user.role,
    licenseeId: sessionLicenseeId,
    orgId: sessionOrgId,
    scopeVersion,
    linkedLicenseeIds: linkedScope.linkedLicenseeIds,
    sessionId: bootstrapSessionId,
  });
  const mfaChallenge = input.mfaEnrolled
    ? await createAdminMfaChallenge({
        userId: input.user.id,
        sessionId: bootstrapSessionId,
        purpose: "admin_login",
        riskScore: input.riskScore || 0,
        riskLevel: input.riskLevel || "LOW",
        reasons: input.reasons?.length ? input.reasons : ["Admin login requires MFA confirmation."],
        ipHash: input.ipHash,
        userAgent: input.userAgent,
        supersedeOpen: true,
      }, db)
    : null;

  return {
    sessionStage: "MFA_BOOTSTRAP" as const,
    accessToken,
    refreshToken: null,
    refreshTokenExpiresAt: null,
    user: {
      id: input.user.id,
      email: input.user.email,
      name: input.user.name,
      role: input.user.role,
      licenseeId: sessionLicenseeId,
      orgId: sessionOrgId,
      scopeVersion,
      licensee: primaryLicensee
        ? {
            id: primaryLicensee.id,
            name: primaryLicensee.name,
            prefix: primaryLicensee.prefix,
            brandName: "brandName" in primaryLicensee ? primaryLicensee.brandName ?? null : null,
            ...(scopeVersion ? { scopeVersion } : {}),
          }
        : null,
      linkedLicensees: linkedScope.linkedLicensees,
      emailVerifiedAt: input.user.emailVerifiedAt,
    },
    auth: {
      sessionStage: "MFA_BOOTSTRAP" as const,
      authAssurance: "PASSWORD" as const,
      mfaRequired: true as const,
      mfaEnrolled: input.mfaEnrolled,
      availableMfaMethods: mfaStatus?.methods || [],
      preferredMfaMethod: mfaStatus?.preferredMethod || null,
      authenticatedAt: input.now.toISOString(),
      mfaVerifiedAt: null,
      stepUpRequired: true,
      scopeSelectionRequired: isManufacturerRole(input.user.role) && !primaryLicensee,
      stepUpMethod: "ADMIN_MFA" as const,
      sessionId: bootstrapSessionId,
      sessionExpiresAt: new Date(input.now.getTime() + getMfaBootstrapTtlMinutes() * 60 * 1000).toISOString(),
      mfaChallenge: mfaChallenge
        ? {
            ticket: mfaChallenge.ticket,
            expiresAt: mfaChallenge.expiresAt.toISOString(),
          }
        : null,
    },
  };
};

export const loginWithPassword = async (input: {
  email: string;
  password: string;
  ipHash: string | null;
  userAgent: string | null;
  requestId: string;
}): Promise<PasswordLoginResult> => {
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");

  const user = await lookupPasswordBootstrapUser(email);

  const now = new Date();

  if (!user) {
    await createAuditLog({
      action: "AUTH_LOGIN_FAIL",
      entityType: "User",
      entityId: null,
      details: { reason: "INVALID_CREDENTIALS" },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
    throw new Error("Invalid email or password");
  }

  if (user.lockedUntil && user.lockedUntil.getTime() > now.getTime()) {
    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId || undefined,
      orgId: user.orgId || undefined,
      action: "AUTH_LOGIN_LOCKED",
      entityType: "User",
      entityId: user.id,
      details: { lockedUntil: user.lockedUntil },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
    throw new Error("Account temporarily locked. Try again later.");
  }

  if (isDisabledUser(user)) {
    throw new Error("Account is disabled. Contact administrator.");
  }

  if (!user.passwordHash) {
    throw new Error("Account not activated. Please accept your invite or reset your password.");
  }

  if (!isVerifiedAccount(user)) {
    throw new Error("Verify your email before signing in.");
  }

  const ok = await verifyPassword(user.passwordHash, password);
  if (!ok) {
    const maxAttempts = getMaxLoginAttempts();
    await recordPasswordLoginFailure({
      normalizedEmail: email,
      attemptedAt: now,
      maxAttempts,
      lockoutMinutes: getLockoutMinutes(),
    });
    await createAuditLog({
      action: "AUTH_LOGIN_FAIL",
      entityType: "User",
      entityId: null,
      details: { reason: "INVALID_CREDENTIALS" },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);

    throw new Error("Invalid email or password");
  }

  const rlsContext = {
    userId: user.id,
    role: user.role,
    licenseeId: isManufacturerRole(user.role) ? null : user.licenseeId,
    manufacturerId: isManufacturerRole(user.role) ? user.id : null,
    organizationId: isManufacturerRole(user.role) ? null : user.orgId,
    isPlatformAdmin: isPlatformSuperAdminRole(user.role),
  };

  const upgradedPasswordHash = shouldRehashPassword(user.passwordHash) ? await hashPassword(password) : null;
  await withRlsPrototypeTransaction(prisma, rlsContext, (tx) =>
    tx.user.update({
      where: { id: user.id },
      data: {
        ...(upgradedPasswordHash ? { passwordHash: upgradedPasswordHash } : {}),
        failedLoginAttempts: 0,
        lockedUntil: null,
        lastLoginAt: now,
      },
    })
  );

  const risk = await assessAuthSessionRisk({
    userId: user.id,
    role: user.role,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    failedLoginAttempts: user.failedLoginAttempts || 0,
  });

  if (risk.shouldBlock && isPlatformSuperAdminRole(user.role)) {
    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId || undefined,
      orgId: user.orgId || undefined,
      action: "AUTH_LOGIN_BLOCKED_RISK",
      entityType: "User",
      entityId: user.id,
      details: {
        riskScore: risk.score,
        riskLevel: risk.riskLevel,
        reasons: risk.reasons,
      },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
    throw new Error("High-risk login blocked. Try from a trusted network or contact administrator.");
  }

  return withRlsPrototypeTransaction(prisma, rlsContext, async (tx) => {
    const mfaStatus: { enabled: boolean; lastUsedAt: Date | string | null } = isAdminMfaRequiredRole(user.role)
      ? await getAdminMfaStatus(user.id, tx)
      : { enabled: false, lastUsedAt: null };

    if (isAdminMfaRequiredRole(user.role)) {
      const lastUsedAt = mfaStatus?.lastUsedAt ? new Date(mfaStatus.lastUsedAt) : null;
      const hasValidLastUsedAt = Boolean(lastUsedAt && Number.isFinite(lastUsedAt.getTime()));
      const loginCycleDays = Math.max(1, getAdminLoginMfaCycleDays());
      const cycleThreshold = addDays(now, -loginCycleDays);
      const mfaFreshForLogin = Boolean(
        !isManufacturerRole(user.role) &&
          mfaStatus?.enabled &&
          hasValidLastUsedAt &&
          (lastUsedAt as Date).getTime() >= cycleThreshold.getTime()
      );

      if (mfaFreshForLogin) {
        const verifiedAt = (lastUsedAt as Date).getTime() > now.getTime() ? now : (lastUsedAt as Date);
        const session = await issueSessionForUser({
          userId: user.id,
          ipHash: input.ipHash,
          userAgent: input.userAgent,
          authAssurance: "ADMIN_MFA",
          authenticatedAt: now,
          mfaVerifiedAt: verifiedAt,
          now,
          requestId: input.requestId,
          purpose: "manufacturer-bootstrap",
        }, tx);

        await createAuditLog({
          userId: user.id,
          licenseeId: user.licenseeId || undefined,
          orgId: user.orgId || undefined,
          action: "AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA",
          entityType: "User",
          entityId: user.id,
          details: {
            role: user.role,
            riskScore: risk.score,
            riskLevel: risk.riskLevel,
            mfaEnabled: Boolean(mfaStatus.enabled),
            mfaVerifiedAt: verifiedAt.toISOString(),
            loginMfaCycleDays: loginCycleDays,
          },
          ipHash: input.ipHash || undefined,
          userAgent: input.userAgent || undefined,
        } as any);

        return session;
      }

      const bootstrapSession = await buildBootstrapSessionForUser({
        user,
        ipHash: input.ipHash,
        userAgent: input.userAgent,
        now,
        mfaEnrolled: Boolean(mfaStatus.enabled),
        riskScore: risk.score,
        riskLevel: risk.riskLevel,
        reasons: risk.reasons,
        requestId: input.requestId,
      }, tx);

      await createAuditLog({
        userId: user.id,
        licenseeId: user.licenseeId || undefined,
        orgId: user.orgId || undefined,
        action: mfaStatus.enabled ? "AUTH_LOGIN_MFA_CHALLENGE_REQUIRED" : "AUTH_LOGIN_MFA_SETUP_REQUIRED",
        entityType: "User",
        entityId: user.id,
        details: {
          role: user.role,
          riskScore: risk.score,
          riskLevel: risk.riskLevel,
          mfaEnabled: Boolean(mfaStatus.enabled),
        },
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
      } as any);

      return bootstrapSession;
    }

    const session = await issueSessionForUser({
      userId: user.id,
      ipHash: input.ipHash,
      userAgent: input.userAgent,
      authAssurance: "PASSWORD",
      authenticatedAt: now,
      mfaVerifiedAt: null,
      now,
      requestId: input.requestId,
      purpose: "manufacturer-bootstrap",
    }, tx);

    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId || undefined,
      orgId: user.orgId || undefined,
      action: "AUTH_LOGIN_SUCCESS",
      entityType: "User",
      entityId: user.id,
      details: {
        role: user.role,
        riskScore: risk.score,
        riskLevel: risk.riskLevel,
        mfaEnabled: false,
      },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);

    return session;
  });
};

export const refreshSession = async (input: {
  rawRefreshToken: string;
  ipHash: string | null;
  userAgent: string | null;
  requestId: string;
  requestedLicenseeId?: string | null;
  requestedScopeVersion?: string | null;
}): Promise<RefreshSessionResult> => {
  type ActiveRefreshPreparation = {
    kind: "active";
    state: ActiveSessionState;
    authAssurance: AuthAssuranceLevel;
    authenticatedAt: Date;
    mfaVerifiedAt: Date | null;
  };
  type BootstrapRefreshPreparation = { kind: "bootstrap"; session: BootstrapSessionResult };

  const rotated = await rotateRefreshToken<ActiveRefreshPreparation, BootstrapRefreshPreparation>({
    rawToken: input.rawRefreshToken,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    decide: async ({ tx, token, now }) => {
      const user = await tx.user.findUnique({ where: { id: token.userId }, select: authSessionUserSelect });
      if (!user || isDisabledUser(user)) {
        return { action: "deny", reason: "REVOKED", revokeScope: "all", revokeReason: "ACCOUNT_UNAVAILABLE" };
      }

      const mfaRequired = isAdminMfaRequiredRole(user.role);
      const mfaStatus = mfaRequired ? await getAdminMfaStatus(user.id, tx) : null;
      if (token.mfaVerifiedAt && mfaRequired && !mfaStatus?.enabled) {
        return { action: "deny", reason: "REVOKED", revokeScope: "all", revokeReason: "MFA_STATE_CHANGED" };
      }

      if (!token.mfaVerifiedAt && mfaRequired) {
        const bootstrapSession = await buildBootstrapSessionForUser({
          user,
          ipHash: input.ipHash,
          userAgent: input.userAgent,
          now,
          mfaEnrolled: Boolean(mfaStatus?.enabled),
          reasons: ["MFA verification is required before refreshing this session."],
          requestId: input.requestId,
          requestedLicenseeId: input.requestedLicenseeId,
          requestedScopeVersion: input.requestedScopeVersion,
        }, tx);
        return {
          action: "consume",
          value: { kind: "bootstrap", session: bootstrapSession },
          revokeScope: "password-only",
          revokeReason: "MFA_REQUIRED_AFTER_POLICY_CHANGE",
        };
      }

      const authAssurance: AuthAssuranceLevel = token.mfaVerifiedAt ? "ADMIN_MFA" : "PASSWORD";
      const explicitScopeSwitch = Boolean(input.requestedLicenseeId);
      const state = await loadActiveSessionState({
        userId: token.userId,
        authAssurance,
        requestedLicenseeId: explicitScopeSwitch ? input.requestedLicenseeId : undefined,
        requestedOrgId: explicitScopeSwitch ? undefined : token.orgId,
        requestedScopeVersion: explicitScopeSwitch ? input.requestedScopeVersion : undefined,
        requestId: explicitScopeSwitch ? input.requestId : undefined,
        purpose: explicitScopeSwitch ? "manufacturer-scope-switch" : undefined,
      }, tx);
      const authenticatedAt = token.authenticatedAt || now;
      return {
        action: "rotate",
        value: { kind: "active", state, authAssurance, authenticatedAt, mfaVerifiedAt: token.mfaVerifiedAt },
        orgId: state.sessionOrgId,
        authenticatedAt,
        mfaVerifiedAt: token.mfaVerifiedAt,
      };
    },
  });

  if (!rotated.ok) {
    if (rotated.reason === "REUSE_DETECTED" && rotated.userId) {
      await createAuditLog({
        userId: rotated.userId,
        action: "AUTH_REFRESH_REUSE_DETECTED",
        entityType: "RefreshToken",
        entityId: null,
        details: { reason: rotated.reason },
        ipHash: input.ipHash || undefined,
        userAgent: input.userAgent || undefined,
      } as any);
    }
    return { ok: false as const, reason: rotated.reason };
  }

  if (!rotated.rotated) {
    const bootstrapSession = rotated.value.session;
    await createAuditLog({
      userId: bootstrapSession.user.id,
      licenseeId: bootstrapSession.user.licenseeId || undefined,
      orgId: bootstrapSession.user.orgId || undefined,
      action: bootstrapSession.auth.mfaEnrolled ? "AUTH_REFRESH_MFA_CHALLENGE_REQUIRED" : "AUTH_REFRESH_MFA_SETUP_REQUIRED",
      entityType: "User",
      entityId: bootstrapSession.user.id,
      details: {
        role: bootstrapSession.user.role,
        mfaEnabled: bootstrapSession.auth.mfaEnrolled,
        revokedPasswordOnlyRefreshTokens: true,
      },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);
    return { ok: true as const, ...bootstrapSession };
  }

  const prepared = rotated.value;
  const session = buildActiveSessionResponse(prepared.state, {
    authAssurance: prepared.authAssurance,
    authenticatedAt: prepared.authenticatedAt,
    mfaVerifiedAt: prepared.mfaVerifiedAt,
  }, {
    rawToken: rotated.newRawToken,
    id: rotated.newTokenId,
    expiresAt: rotated.newExpiresAt,
  });
  return { ok: true as const, ...session };
};

export const logoutSession = async (input: {
  userId: string;
  rawRefreshToken: string | null;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  if (input.rawRefreshToken) {
    await revokeRefreshTokenByRaw({ rawToken: input.rawRefreshToken, reason: "LOGOUT" });
  }

  await createAuditLog({
    userId: input.userId,
    action: "AUTH_LOGOUT",
    entityType: "User",
    entityId: input.userId,
    details: {},
    ipHash: input.ipHash || undefined,
    userAgent: input.userAgent || undefined,
  } as any);
};

export const disableUserSessions = async (input: { userId: string; reason: string }) => {
  await revokeAllUserRefreshTokens({ userId: input.userId, reason: input.reason });
};

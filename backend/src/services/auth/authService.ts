import prisma from "../../config/database";
import { UserRole, UserStatus } from "@prisma/client";
import { verifyPassword, hashPassword, shouldRehashPassword } from "./passwordService";
import {
  signAccessToken,
  newCsrfToken,
  newRefreshToken,
  signMfaBootstrapToken,
  getMfaBootstrapTtlMinutes,
} from "./tokenService";
import { createRefreshToken, rotateRefreshToken, revokeAllUserRefreshTokens, revokeRefreshTokenByRaw } from "./refreshTokenService";
import { createAuditLog } from "../auditService";
import { assessAuthSessionRisk } from "./sessionRiskService";
import { listManufacturerLicenseeLinks, normalizeLinkedLicensees } from "../manufacturerScopeService";
import { isVerifiedAccount } from "./emailVerificationService";
import { getAdminMfaStatus } from "./mfaService";
import type { AuthAssuranceLevel, AuthSessionStage, StepUpMethod } from "../../types";

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
  isPlatformSuperAdminRole(role) || isOrgAdminRole(role);

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
  linkedLicenseeIds: u.linkedLicenseeIds || null,
  sessionStage: "ACTIVE" as const,
  authAssurance: u.authAssurance,
  authenticatedAt: u.authenticatedAt?.toISOString?.() || null,
  mfaVerifiedAt: u.mfaVerifiedAt?.toISOString?.() || null,
});

const mapLinkedLicenseesForSession = async (userId: string) => {
  const links = await listManufacturerLicenseeLinks(userId, prisma).catch(() => []);
  const linkedLicensees = normalizeLinkedLicensees(links);
  const linkedLicenseeIds = linkedLicensees.map((row) => row.id);
  return { linkedLicensees, linkedLicenseeIds };
};

export const issueSessionForUser = async (input: {
  userId: string;
  ipHash: string | null;
  userAgent: string | null;
  authAssurance?: AuthAssuranceLevel;
  authenticatedAt?: Date | null;
  mfaVerifiedAt?: Date | null;
  now?: Date;
}) => {
  const now = input.now || new Date();
  const authAssurance = input.authAssurance || "PASSWORD";
  const authenticatedAt = input.authenticatedAt || now;
  const mfaVerifiedAt = input.mfaVerifiedAt || null;

  const user = await prisma.user.findUnique({
    where: { id: input.userId },
    include: { licensee: { select: { id: true, name: true, prefix: true, brandName: true, orgId: true } } },
  });

  if (!user) throw new Error("User not found");
  if (isDisabledUser(user)) {
    throw new Error("Account is disabled");
  }

  const linkedScope = isManufacturerRole(user.role)
    ? await mapLinkedLicenseesForSession(user.id)
    : { linkedLicensees: [], linkedLicenseeIds: [] as string[] };
  const mfaStatus = isAdminMfaRequiredRole(user.role) ? await getAdminMfaStatus(user.id).catch(() => null) : null;
  const primaryLicensee =
    user.licensee ||
    linkedScope.linkedLicensees.find((row) => row.isPrimary) ||
    linkedScope.linkedLicensees[0] ||
    null;

  const payload = buildJwtPayloadForUser({
    id: user.id,
    email: user.email,
    role: user.role,
    licenseeId: primaryLicensee?.id || user.licenseeId,
    orgId: user.orgId || primaryLicensee?.orgId || null,
    linkedLicenseeIds: linkedScope.linkedLicenseeIds,
    authAssurance,
    authenticatedAt,
    mfaVerifiedAt,
  });

  const accessToken = signAccessToken(payload);
  const refreshToken = newRefreshToken();
  const csrfToken = newCsrfToken();

  const created = await createRefreshToken({
    userId: user.id,
    orgId: user.orgId,
    rawToken: refreshToken,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    authenticatedAt,
    mfaVerifiedAt,
    now,
  });

  return {
    sessionStage: "ACTIVE" as AuthSessionStage,
    accessToken,
    refreshToken,
    refreshTokenExpiresAt: created.expiresAt,
    sessionId: created.row.id,
    csrfToken,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      licenseeId: primaryLicensee?.id || user.licenseeId,
      orgId: user.orgId || primaryLicensee?.orgId || null,
      licensee: primaryLicensee
        ? {
            id: primaryLicensee.id,
            name: primaryLicensee.name,
            prefix: primaryLicensee.prefix,
            brandName: "brandName" in primaryLicensee ? primaryLicensee.brandName ?? null : null,
          }
        : null,
      linkedLicensees: linkedScope.linkedLicensees,
      emailVerifiedAt: user.emailVerifiedAt,
    },
    auth: {
      sessionStage: "ACTIVE" as const,
      authAssurance,
      mfaRequired: isAdminMfaRequiredRole(user.role),
      mfaEnrolled: isAdminMfaRequiredRole(user.role)
        ? Boolean(mfaStatus?.enabled || mfaStatus?.enrolled)
        : authAssurance === "ADMIN_MFA",
      availableMfaMethods: isAdminMfaRequiredRole(user.role) ? mfaStatus?.methods || [] : [],
      preferredMfaMethod: isAdminMfaRequiredRole(user.role) ? mfaStatus?.preferredMethod || null : null,
      authenticatedAt: authenticatedAt.toISOString(),
      mfaVerifiedAt: mfaVerifiedAt?.toISOString?.() || null,
      stepUpRequired: false,
      stepUpMethod: getSensitiveActionStepUpMethod(user.role),
      sessionId: created.row.id,
      sessionExpiresAt: created.expiresAt.toISOString(),
    },
  };
};

type SessionIssueResult = Awaited<ReturnType<typeof issueSessionForUser>>;

type BootstrapSessionResult = {
  sessionStage: "MFA_BOOTSTRAP";
  accessToken: string;
  refreshToken: null;
  refreshTokenExpiresAt: null;
  csrfToken: string;
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
    sessionId: null;
    sessionExpiresAt: string;
  };
};

export type PasswordLoginResult = SessionIssueResult | BootstrapSessionResult;

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
}) => {
  const linkedScope = isManufacturerRole(input.user.role)
    ? await mapLinkedLicenseesForSession(input.user.id)
    : { linkedLicensees: [], linkedLicenseeIds: [] as string[] };
  const mfaStatus = await getAdminMfaStatus(input.user.id).catch(() => null);
  const primaryLicensee =
    input.user.licensee ||
    linkedScope.linkedLicensees.find((row) => row.isPrimary) ||
    linkedScope.linkedLicensees[0] ||
    null;

  const accessToken = signMfaBootstrapToken({
    userId: input.user.id,
    email: input.user.email,
    role: input.user.role,
    licenseeId: primaryLicensee?.id || input.user.licenseeId,
    orgId: input.user.orgId || primaryLicensee?.orgId || null,
    linkedLicenseeIds: linkedScope.linkedLicenseeIds,
  });

  return {
    sessionStage: "MFA_BOOTSTRAP" as const,
    accessToken,
    refreshToken: null,
    refreshTokenExpiresAt: null,
    csrfToken: newCsrfToken(),
    user: {
      id: input.user.id,
      email: input.user.email,
      name: input.user.name,
      role: input.user.role,
      licenseeId: primaryLicensee?.id || input.user.licenseeId,
      orgId: input.user.orgId || primaryLicensee?.orgId || null,
      licensee: primaryLicensee
        ? {
            id: primaryLicensee.id,
            name: primaryLicensee.name,
            prefix: primaryLicensee.prefix,
            brandName: "brandName" in primaryLicensee ? primaryLicensee.brandName ?? null : null,
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
      stepUpMethod: "ADMIN_MFA" as const,
      sessionId: null,
      sessionExpiresAt: new Date(input.now.getTime() + getMfaBootstrapTtlMinutes() * 60 * 1000).toISOString(),
    },
  };
};

export const loginWithPassword = async (input: {
  email: string;
  password: string;
  ipHash: string | null;
  userAgent: string | null;
}): Promise<PasswordLoginResult> => {
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");

  const user = await prisma.user.findUnique({
    where: { email },
    include: { licensee: { select: { id: true, name: true, prefix: true } } },
  });

  const now = new Date();

  if (!user) {
    await createAuditLog({
      action: "AUTH_LOGIN_FAIL",
      entityType: "User",
      entityId: null,
      details: { email, reason: "USER_NOT_FOUND" },
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
    const nextAttempts = (user.failedLoginAttempts || 0) + 1;
    const maxAttempts = getMaxLoginAttempts();

    const lockout = nextAttempts >= maxAttempts ? addMinutes(now, getLockoutMinutes()) : null;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: nextAttempts,
        lockedUntil: lockout,
      },
    });

    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId || undefined,
      orgId: user.orgId || undefined,
      action: "AUTH_LOGIN_FAIL",
      entityType: "User",
      entityId: user.id,
      details: { email, reason: "BAD_PASSWORD", failedLoginAttempts: nextAttempts, lockedUntil: lockout },
      ipHash: input.ipHash || undefined,
      userAgent: input.userAgent || undefined,
    } as any);

    throw new Error("Invalid email or password");
  }

  // Opportunistic upgrade from legacy bcrypt.
  if (shouldRehashPassword(user.passwordHash)) {
    const upgraded = await hashPassword(password);
    await prisma.user.update({ where: { id: user.id }, data: { passwordHash: upgraded } });
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastLoginAt: now,
    },
  });

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

  const mfaStatus: { enabled: boolean; lastUsedAt: Date | string | null } = isAdminMfaRequiredRole(user.role)
    ? await getAdminMfaStatus(user.id).catch(() => ({ enabled: false, lastUsedAt: null }))
    : { enabled: false, lastUsedAt: null };

  if (isAdminMfaRequiredRole(user.role)) {
    const lastUsedAt = mfaStatus?.lastUsedAt ? new Date(mfaStatus.lastUsedAt) : null;
    const hasValidLastUsedAt = Boolean(lastUsedAt && Number.isFinite(lastUsedAt.getTime()));
    const loginCycleDays = Math.max(1, getAdminLoginMfaCycleDays());
    const cycleThreshold = addDays(now, -loginCycleDays);
    const mfaFreshForLogin = Boolean(
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
      });

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
    });

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
  });

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
};

export const refreshSession = async (input: {
  rawRefreshToken: string;
  ipHash: string | null;
  userAgent: string | null;
}) => {
  const rotated = await rotateRefreshToken({
    rawToken: input.rawRefreshToken,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
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

  const session = await issueSessionForUser({
    userId: rotated.userId,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
    authAssurance: rotated.mfaVerifiedAt ? "ADMIN_MFA" : "PASSWORD",
    authenticatedAt: rotated.authenticatedAt,
    mfaVerifiedAt: rotated.mfaVerifiedAt,
  });

  // Override with rotated refresh token
  return {
    ok: true as const,
    accessToken: session.accessToken,
    refreshToken: rotated.newRawToken,
    refreshTokenExpiresAt: rotated.newExpiresAt,
    csrfToken: session.csrfToken,
    user: session.user,
    auth: session.auth,
  };
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

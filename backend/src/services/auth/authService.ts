import prisma from "../../config/database";
import { UserRole, UserStatus } from "@prisma/client";
import { verifyPassword, hashPassword, shouldRehashPassword } from "./passwordService";
import { signAccessToken, newCsrfToken, newRefreshToken } from "./tokenService";
import { createRefreshToken, rotateRefreshToken, revokeAllUserRefreshTokens, revokeRefreshTokenByRaw } from "./refreshTokenService";
import { createAuditLog } from "../auditService";
import { assessAuthSessionRisk } from "./sessionRiskService";
import { createAdminMfaChallenge, getAdminMfaStatus } from "./mfaService";
import { listManufacturerLicenseeLinks, normalizeLinkedLicensees } from "../manufacturerScopeService";

const parseIntEnv = (key: string, fallback: number) => {
  const raw = String(process.env[key] || "").trim();
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
};

const getMaxLoginAttempts = () => parseIntEnv("AUTH_MAX_LOGIN_ATTEMPTS", 10);
const getLockoutMinutes = () => parseIntEnv("AUTH_LOCKOUT_MINUTES", 15);

const addMinutes = (d: Date, minutes: number) => new Date(d.getTime() + minutes * 60 * 1000);
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

export const isManufacturerRole = (role: UserRole) =>
  role === UserRole.MANUFACTURER || role === UserRole.MANUFACTURER_ADMIN || role === UserRole.MANUFACTURER_USER;

export const buildJwtPayloadForUser = (u: {
  id: string;
  email: string;
  role: UserRole;
  licenseeId: string | null;
  orgId: string | null;
  linkedLicenseeIds?: string[] | null;
}) => ({
  userId: u.id,
  email: u.email,
  role: u.role,
  licenseeId: u.licenseeId,
  orgId: u.orgId,
  linkedLicenseeIds: u.linkedLicenseeIds || null,
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
  now?: Date;
}) => {
  const now = input.now || new Date();

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
    now,
  });

  return {
    accessToken,
    refreshToken,
    refreshTokenExpiresAt: created.expiresAt,
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
    },
  };
};

type SessionIssueResult = Awaited<ReturnType<typeof issueSessionForUser>>;

export type PasswordLoginResult =
  | (SessionIssueResult & { mfaRequired?: false })
  | {
      mfaRequired: true;
      mfaTicket: string;
      mfaExpiresAt: string;
      riskScore: number;
      riskLevel: string;
      reasons: string[];
    };

export const loginWithPassword = async (input: {
  email: string;
  password: string;
  ipHash: string | null;
  userAgent: string | null;
  allowMfaChallenge?: boolean;
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

  const mfaStatus = await getAdminMfaStatus(user.id).catch(() => ({
    enrolled: false,
    enabled: false,
    verifiedAt: null,
    lastUsedAt: null,
    backupCodesRemaining: 0,
    createdAt: null,
    updatedAt: null,
  }));

  const allowMfaChallenge = input.allowMfaChallenge !== false;
  if (mfaStatus.enabled && allowMfaChallenge) {
    const challenge = await createAdminMfaChallenge({
      userId: user.id,
      riskScore: risk.score,
      riskLevel: risk.riskLevel,
      reasons: risk.reasons,
      ipHash: input.ipHash,
      userAgent: input.userAgent,
    });

    await createAuditLog({
      userId: user.id,
      licenseeId: user.licenseeId || undefined,
      orgId: user.orgId || undefined,
      action: "AUTH_MFA_CHALLENGE_ISSUED",
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

    return {
      mfaRequired: true,
      mfaTicket: challenge.ticket,
      mfaExpiresAt: challenge.expiresAt.toISOString(),
      riskScore: risk.score,
      riskLevel: risk.riskLevel,
      reasons: risk.reasons,
    };
  }

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

  const session = await issueSessionForUser({
    userId: user.id,
    ipHash: input.ipHash,
    userAgent: input.userAgent,
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
        mfaEnabled: mfaStatus.enabled,
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
  });

  // Override with rotated refresh token
  return {
    ok: true as const,
    accessToken: session.accessToken,
    refreshToken: rotated.newRawToken,
    refreshTokenExpiresAt: rotated.newExpiresAt,
    csrfToken: session.csrfToken,
    user: session.user,
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

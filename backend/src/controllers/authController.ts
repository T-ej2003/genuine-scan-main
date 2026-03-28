import { Request, Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { hashIp, normalizeUserAgent } from "../utils/security";
import {
  ACCESS_TOKEN_COOKIE,
  CSRF_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  getAccessTokenTtlMinutes,
  getRefreshTokenTtlDays,
  newCsrfToken,
} from "../services/auth/tokenService";
import { acceptInvite, createInvite, getInvitePreview } from "../services/auth/inviteService";
import {
  issueSessionForUser,
  loginWithPassword,
  logoutSession,
  refreshSession,
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../services/auth/authService";
import { confirmEmailVerification } from "../services/auth/emailVerificationService";
import { requestPasswordReset, resetPasswordWithToken } from "../services/auth/passwordResetService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { isManufacturerRole, listManufacturerLicenseeLinks, normalizeLinkedLicensees } from "../services/manufacturerScopeService";
import {
  beginAdminMfaSetup,
  completeAdminMfaChallenge,
  confirmAdminMfaSetup,
  disableAdminMfa,
  getAdminMfaStatus,
  rotateAdminMfaBackupCodes,
  verifyAdminMfaCode,
  createAdminMfaChallenge,
} from "../services/auth/mfaService";
import {
  beginAdminWebAuthnChallenge,
  beginAdminWebAuthnRegistration,
  completeAdminWebAuthnChallenge,
  completeAdminWebAuthnRegistration,
  deleteAdminWebAuthnCredential,
} from "../services/auth/webauthnService";
import { verifyPassword } from "../services/auth/passwordService";
import { createAuditLog } from "../services/auditService";
import type { AuthenticatedSessionClaims } from "../types";
import {
  findRefreshTokenByRaw,
  listActiveRefreshTokensForUser,
  revokeRefreshTokenById,
  revokeRefreshTokenByRaw,
} from "../services/auth/refreshTokenService";

const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
  password: z.string().min(6, "Password must be at least 6 characters"),
}).strict();

const inviteSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
  role: z.string().trim().min(2),
  name: z.string().trim().min(2).max(120).optional(),
  licenseeId: z.string().uuid().optional(),
  manufacturerId: z.string().uuid().optional(),
  allowExistingInvitedUser: z.boolean().optional(),
}).strict();

const acceptInviteSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
  name: z.string().trim().min(2).max(120).optional(),
}).strict();

const invitePreviewQuerySchema = z.object({
  token: z.string().trim().min(10),
}).strict();

const forgotPasswordSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
}).strict();

const resetPasswordSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
}).strict();

const verifyEmailSchema = z.object({
  token: z.string().trim().min(10),
}).strict();

const mfaCodeSchema = z.object({
  code: z.string().trim().min(6).max(32),
}).strict();

const mfaChallengeCompleteSchema = z.object({
  ticket: z.string().trim().min(10),
  code: z.string().trim().min(6).max(32),
}).strict();

const webAuthnRegistrationCompleteSchema = z.object({
  ticket: z.string().trim().min(10),
  label: z.string().trim().min(1).max(120).optional(),
  credential: z.object({
    id: z.string().trim().min(8),
    rawId: z.string().trim().min(8),
    type: z.literal("public-key"),
    response: z.object({
      clientDataJSON: z.string().trim().min(8),
      attestationObject: z.string().trim().min(8),
      authenticatorData: z.string().trim().min(8),
      publicKey: z.string().trim().min(8),
      publicKeyAlgorithm: z.number().int(),
      transports: z.array(z.string().trim().min(1).max(40)).max(12).optional(),
    }).strict(),
  }).strict(),
}).strict();

const webAuthnChallengeCompleteSchema = z.object({
  ticket: z.string().trim().min(10),
  credential: z.object({
    id: z.string().trim().min(8),
    rawId: z.string().trim().min(8),
    type: z.literal("public-key"),
    response: z.object({
      clientDataJSON: z.string().trim().min(8),
      authenticatorData: z.string().trim().min(8),
      signature: z.string().trim().min(8),
      userHandle: z.string().trim().max(512).optional().nullable(),
    }).strict(),
  }).strict(),
}).strict();

const webAuthnCredentialParamSchema = z.object({
  id: z.string().uuid("Invalid WebAuthn credential id"),
}).strict();

const disableMfaSchema = z.object({
  code: z.string().trim().min(6).max(32),
  currentPassword: z.string().min(8).max(200),
}).strict();

const passwordStepUpSchema = z.object({
  currentPassword: z.string().min(1).max(200),
}).strict();

const normalizeAuthError = (error: unknown): { status: number; error: string } => {
  const raw = error instanceof Error ? error.message : String(error || "Unknown error");
  const lower = raw.toLowerCase();

  if (lower.includes("invalid email or password")) {
    return { status: 401, error: "Invalid email or password" };
  }

  if (lower.includes("temporarily locked")) {
    return { status: 423, error: "Account temporarily locked. Try again later." };
  }

  if (lower.includes("high-risk login blocked")) {
    return { status: 403, error: "High-risk login blocked. Try from a trusted network or contact administrator." };
  }

  if (lower.includes("account is disabled")) {
    return { status: 403, error: "Account is disabled. Contact administrator." };
  }

  if (lower.includes("account not activated")) {
    return { status: 403, error: "Account not activated. Please accept your invite or reset your password." };
  }

  if (lower.includes("verify your email before signing in")) {
    return { status: 403, error: "Verify your email before signing in." };
  }

  if (
    lower.includes("environment variable not found: database_url") ||
    lower.includes("can't reach database server") ||
    lower.includes("p1001") ||
    lower.includes("server has closed the connection")
  ) {
    return { status: 503, error: "Database unavailable. Check DATABASE_URL / RDS connectivity." };
  }

  if (lower.includes("invalid `prisma.") || lower.includes("p20")) {
    return { status: 500, error: "Database query failed. Check Prisma schema/migrations." };
  }

  return {
    status: 500,
    error: process.env.NODE_ENV === "development" ? raw : "Internal server error",
  };
};

const parseBool = (v: unknown) => ["1", "true", "yes", "on"].includes(String(v || "").trim().toLowerCase());

const cookieSecure = () => parseBool(process.env.COOKIE_SECURE) || process.env.NODE_ENV === "production";

const cookieDomain = () => {
  const d = String(process.env.COOKIE_DOMAIN || "").trim();
  return d || undefined;
};

const authCookieOptions = () => ({
  httpOnly: true,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

const csrfCookieOptions = () => ({
  httpOnly: false,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

const allowLegacyTokenResponse = () => {
  const explicit = String(process.env.AUTH_LEGACY_TOKEN_RESPONSE_ENABLED || "").trim().toLowerCase();
  if (explicit === "true") return true;
  return process.env.NODE_ENV !== "production";
};

type CookieBackedAuthResponse = {
  sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
  accessToken: string;
  refreshToken: string | null;
  refreshTokenExpiresAt: Date | null;
  csrfToken: string;
  user: any;
  auth: any;
};

const authResponseData = (session: CookieBackedAuthResponse) => ({
  ...(allowLegacyTokenResponse() && session.sessionStage === "ACTIVE" ? { token: session.accessToken } : {}),
  user: session.user,
  auth: session.auth,
});

const getRefreshTokenFromRequest = (req: Request) => {
  const raw = (req as any).cookies?.[REFRESH_TOKEN_COOKIE];
  return typeof raw === "string" && raw.trim() ? raw.trim() : null;
};

const clearAuthCookies = (res: Response) => {
  res.clearCookie(ACCESS_TOKEN_COOKIE, authCookieOptions());
  res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
  res.clearCookie(CSRF_TOKEN_COOKIE, csrfCookieOptions());
};

const setAuthCookies = (res: Response, session: CookieBackedAuthResponse) => {
  const accessTtlMs = getAccessTokenTtlMinutes() * 60 * 1000;
  const refreshTtlMs = getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000;

  res.cookie(ACCESS_TOKEN_COOKIE, session.accessToken, { ...authCookieOptions(), maxAge: accessTtlMs });

  if (session.refreshToken) {
    res.cookie(REFRESH_TOKEN_COOKIE, session.refreshToken, { ...authCookieOptions(), maxAge: refreshTtlMs });
  } else {
    res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
  }

  res.cookie(CSRF_TOKEN_COOKIE, session.csrfToken, {
    ...csrfCookieOptions(),
    maxAge: session.refreshToken ? refreshTtlMs : accessTtlMs,
  });
};

const getAuthClaims = (req: Request) => ((req as any).user || null) as AuthenticatedSessionClaims | null;

const buildAuthState = async (
  claims: AuthenticatedSessionClaims,
  userRole: string,
  userId: string,
  currentSession?: { id: string; expiresAt: Date } | null
) => {
  const mfaRequired = isAdminMfaRequiredRole(userRole as any);
  const mfaStatus = mfaRequired ? await getAdminMfaStatus(userId).catch(() => null) : null;
  const stepUpMethod = getSensitiveActionStepUpMethod(userRole as any);
  const adminFreshEnough = (() => {
    if (!mfaRequired || claims.sessionStage !== "ACTIVE") return false;
    const verifiedAt = claims.mfaVerifiedAt ? new Date(claims.mfaVerifiedAt) : null;
    if (!verifiedAt || Number.isNaN(verifiedAt.getTime())) return false;
    return Date.now() - verifiedAt.getTime() <= getAdminStepUpWindowMinutes() * 60_000;
  })();
  const passwordFreshEnough = (() => {
    if (mfaRequired || claims.sessionStage !== "ACTIVE") return false;
    const authenticatedAt = claims.authenticatedAt ? new Date(claims.authenticatedAt) : null;
    if (!authenticatedAt || Number.isNaN(authenticatedAt.getTime())) return false;
    return Date.now() - authenticatedAt.getTime() <= getPasswordReauthWindowMinutes() * 60_000;
  })();

  return {
    sessionStage: claims.sessionStage,
    authAssurance: claims.authAssurance || "PASSWORD",
    mfaRequired,
    mfaEnrolled: mfaRequired ? Boolean(mfaStatus?.enabled || mfaStatus?.enrolled) : false,
    availableMfaMethods: mfaRequired ? mfaStatus?.methods || [] : [],
    preferredMfaMethod: mfaRequired ? mfaStatus?.preferredMethod || null : null,
    authenticatedAt: claims.authenticatedAt || null,
    mfaVerifiedAt: claims.mfaVerifiedAt || null,
    stepUpRequired: mfaRequired ? !adminFreshEnough : !passwordFreshEnough,
    stepUpMethod,
    sessionId: currentSession?.id || null,
    sessionExpiresAt: currentSession?.expiresAt?.toISOString?.() || null,
  };
};

export const login = async (req: Request, res: Response) => {
  try {
    const validation = loginSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        success: false,
        error: validation.error.errors[0]?.message ?? "Invalid request",
      });
    }

    const { email, password } = validation.data;

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    const session = await loginWithPassword({
      email,
      password,
      ipHash,
      userAgent,
    });

    setAuthCookies(res, session);

    return res.json({ success: true, data: authResponseData(session) });
  } catch (error) {
    console.error("Login error:", error);
    const out = normalizeAuthError(error);
    return res.status(out.status).json({ success: false, error: out.error });
  }
};

export const me = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    const userId = claims?.userId;

    if (!userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { licensee: true },
    });

    if (!user) {
      return res.status(404).json({ success: false, error: "User not found" });
    }

    const linkedLicensees = isManufacturerRole(user.role)
      ? normalizeLinkedLicensees(await listManufacturerLicenseeLinks(user.id, prisma))
      : [];
    const primaryLicensee =
      user.licensee ||
      linkedLicensees.find((row) => row.isPrimary) ||
      linkedLicensees[0] ||
      null;

    // Ensure CSRF cookie exists for cookie-auth flows.
    const hasCsrfCookie = Boolean((req as any).cookies?.[CSRF_TOKEN_COOKIE]);
    if (!hasCsrfCookie) {
      res.cookie(CSRF_TOKEN_COOKIE, newCsrfToken(), { ...csrfCookieOptions(), maxAge: getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000 });
    }

    const currentRefresh = getRefreshTokenFromRequest(req);
    const currentSession = currentRefresh
      ? await findRefreshTokenByRaw(currentRefresh).catch(() => null)
      : null;
    const auth = claims ? await buildAuthState(claims, user.role, user.id, currentSession) : null;

    return res.json({
      success: true,
      data: {
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
              brandName: primaryLicensee.brandName ?? null,
            }
          : null,
        linkedLicensees,
        emailVerifiedAt: user.emailVerifiedAt?.toISOString?.() || null,
        pendingEmail: user.pendingEmail || null,
        pendingEmailRequestedAt: user.pendingEmailRequestedAt?.toISOString?.() || null,
        auth,
      },
    });
  } catch (error) {
    console.error("Me error:", error);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const refresh = async (req: Request, res: Response) => {
  try {
    const rawRefresh = (req as any).cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    if (!rawRefresh) return res.status(401).json({ success: false, error: "No refresh token" });

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    const rotated = await refreshSession({
      rawRefreshToken: rawRefresh,
      ipHash,
      userAgent,
    });

    if (!rotated.ok) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
    }

    setAuthCookies(res, {
      sessionStage: "ACTIVE",
      accessToken: rotated.accessToken,
      refreshToken: rotated.refreshToken,
      refreshTokenExpiresAt: rotated.refreshTokenExpiresAt,
      csrfToken: rotated.csrfToken,
      user: rotated.user,
      auth: rotated.auth,
    });

    return res.json({
      success: true,
      data: authResponseData({
        sessionStage: "ACTIVE",
        accessToken: rotated.accessToken,
        refreshToken: rotated.refreshToken,
        refreshTokenExpiresAt: rotated.refreshTokenExpiresAt,
        csrfToken: rotated.csrfToken,
        user: rotated.user,
        auth: rotated.auth,
      }),
    });
  } catch (e: any) {
    console.error("Refresh error:", e);
    return res.status(401).json({ success: false, error: "Session expired. Please sign in again." });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const userId = getAuthClaims(req)?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const rawRefresh = (req as any).cookies?.[REFRESH_TOKEN_COOKIE] as string | undefined;
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));

    await logoutSession({ userId, rawRefreshToken: rawRefresh || null, ipHash, userAgent });

    clearAuthCookies(res);

    return res.json({ success: true, data: { loggedOut: true } });
  } catch (e: any) {
    console.error("Logout error:", e);
    return res.status(500).json({ success: false, error: "Logout failed" });
  }
};

export const listSessions = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const currentRefresh = getRefreshTokenFromRequest(req);
    const currentSession = currentRefresh ? await findRefreshTokenByRaw(currentRefresh).catch(() => null) : null;
    const sessions = await listActiveRefreshTokensForUser(claims.userId);

    return res.json({
      success: true,
      data: {
        items: sessions.map((session) => ({
          id: session.id,
          current: session.id === currentSession?.id,
          createdAt: session.createdAt.toISOString(),
          lastUsedAt: session.lastUsedAt?.toISOString?.() || null,
          expiresAt: session.expiresAt.toISOString(),
          authenticatedAt: session.authenticatedAt?.toISOString?.() || null,
          mfaVerifiedAt: session.mfaVerifiedAt?.toISOString?.() || null,
          userAgent: session.createdUserAgent || null,
          ipHash: session.createdIpHash || null,
        })),
      },
    });
  } catch (error) {
    console.error("listSessions error:", error);
    return res.status(500).json({ success: false, error: "Could not load active sessions." });
  }
};

export const revokeSessionController = async (req: Request, res: Response) => {
  try {
    const claims = getAuthClaims(req);
    if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
      return res.status(401).json({ success: false, error: "An active authenticated session is required." });
    }

    const sessionId = String(req.params?.id || "").trim();
    if (!sessionId) {
      return res.status(400).json({ success: false, error: "Session id is required." });
    }

    const currentRefresh = getRefreshTokenFromRequest(req);
    const currentSession = currentRefresh ? await findRefreshTokenByRaw(currentRefresh).catch(() => null) : null;
    const revoked = await revokeRefreshTokenById({
      sessionId,
      userId: claims.userId,
      reason: "SESSION_REVOKED_BY_USER",
    });

    if (!revoked) {
      return res.status(404).json({ success: false, error: "Session not found." });
    }

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_SESSION_REVOKED",
      entityType: "RefreshToken",
      entityId: sessionId,
      details: {
        currentSessionRevoked: sessionId === currentSession?.id,
      },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    if (sessionId === currentSession?.id) {
      clearAuthCookies(res);
    }

    return res.json({
      success: true,
      data: {
        revoked: true,
        currentSessionRevoked: sessionId === currentSession?.id,
      },
    });
  } catch (error) {
    console.error("revokeSession error:", error);
    return res.status(500).json({ success: false, error: "Could not revoke session." });
  }
};

export const passwordStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  if (isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin accounts must use MFA step-up verification." });
  }

  const parsed = passwordStepUpSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, passwordHash: true },
  });

  if (!user?.passwordHash) {
    return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
  }

  const passwordOk = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
  if (!passwordOk) {
    return res.status(400).json({ success: false, error: "Current password is incorrect." });
  }

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));
  const now = new Date();
  const session = await issueSessionForUser({
    userId: claims.userId,
    ipHash,
    userAgent,
    authAssurance: "PASSWORD",
    authenticatedAt: now,
    mfaVerifiedAt: null,
    now,
  });

  const currentRefresh = getRefreshTokenFromRequest(req);
  if (currentRefresh) {
    await revokeRefreshTokenByRaw({ rawToken: currentRefresh, reason: "STEP_UP_REPLACED" });
  }

  await createAuditLog({
    userId: claims.userId,
    action: "AUTH_STEP_UP_PASSWORD_SUCCESS",
    entityType: "User",
    entityId: claims.userId,
    details: {
      method: "PASSWORD_REAUTH",
    },
    ipHash: ipHash || undefined,
    userAgent: userAgent || undefined,
  } as any);

  setAuthCookies(res, session);
  return res.json({ success: true, data: authResponseData(session) });
};

export const adminMfaStepUpController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "Admin MFA step-up is only available for admin roles." });
  }

  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code });

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const session = await issueSessionForUser({
      userId: claims.userId,
      ipHash,
      userAgent,
      authAssurance: "ADMIN_MFA",
      authenticatedAt: now,
      mfaVerifiedAt: now,
      now,
    });

    const currentRefresh = getRefreshTokenFromRequest(req);
    if (currentRefresh) {
      await revokeRefreshTokenByRaw({ rawToken: currentRefresh, reason: "STEP_UP_REPLACED" });
    }

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_MFA_STEP_UP_SUCCESS",
      entityType: "User",
      entityId: claims.userId,
      details: {
        method: "ADMIN_MFA",
      },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: "Could not verify the MFA code. Try again." });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  const parsed = forgotPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    await requestPasswordReset({ email: parsed.data.email, ipHash, userAgent });
  } catch (e) {
    console.error("forgotPassword error:", e);
    // Always return success to prevent email enumeration.
  }

  return res.json({ success: true, data: { ok: true } });
};

export const resetPassword = async (req: Request, res: Response) => {
  const parsed = resetPasswordSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    await resetPasswordWithToken({ rawToken: parsed.data.token, newPassword: parsed.data.password, ipHash, userAgent });
    return res.json({ success: true, data: { ok: true } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e?.message || "Reset failed" });
  }
};

export const invite = async (req: Request, res: Response) => {
  const parsed = inviteSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const authReq = req as any;
  const actorUserId = authReq.user?.userId as string | undefined;
  if (!actorUserId) return res.status(401).json({ success: false, error: "Not authenticated" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    const out = await createInvite({
      email: parsed.data.email,
      role: parsed.data.role,
      name: parsed.data.name || null,
      licenseeId: parsed.data.licenseeId || null,
      manufacturerId: parsed.data.manufacturerId || null,
      allowExistingInvitedUser: parsed.data.allowExistingInvitedUser || false,
      createdByUserId: actorUserId,
      ipHash,
      userAgent,
    });
    return res.status(201).json({ success: true, data: out });
  } catch (e: any) {
    console.error("Invite error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Invite failed" });
  }
};

export const acceptInviteController = async (req: Request, res: Response) => {
  const parsed = acceptInviteSchema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));

  try {
    const user = await acceptInvite({
      rawToken: parsed.data.token,
      password: parsed.data.password,
      name: parsed.data.name || null,
      ipHash,
      userAgent,
    });

    // Auto sign-in after accepting invite
    const session = await loginWithPassword({
      email: user.email,
      password: parsed.data.password,
      ipHash,
      userAgent,
    });

    setAuthCookies(res, session);

    return res.status(200).json({ success: true, data: authResponseData(session) });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e?.message || "Invite acceptance failed" });
  }
};

export const verifyEmailController = async (req: Request, res: Response) => {
  const parsed = verifyEmailSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const result = await confirmEmailVerification({
      rawToken: parsed.data.token,
      actorIpAddress: req.ip,
      actorUserAgent: req.get("user-agent"),
    });
    return res.json({ success: true, data: result });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: error?.message || "Verification failed" });
  }
};

export const invitePreviewController = async (req: Request, res: Response) => {
  const parsed = invitePreviewQuerySchema.safeParse(req.query || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: "Missing invite token." });
  }

  try {
    const preview = await getInvitePreview(parsed.data.token);
    return res.json({ success: true, data: preview });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e?.message || "Invite preview unavailable" });
  }
};

export const getAdminMfaStatusController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.json({
      success: true,
      data: {
        required: false,
        sessionStage: claims.sessionStage,
        enrolled: false,
        enabled: false,
      },
    });
  }

  const status = await getAdminMfaStatus(claims.userId);
  return res.json({
    success: true,
    data: {
      required: true,
      sessionStage: claims.sessionStage,
      ...status,
    },
  });
};

export const beginAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  const setup = await beginAdminMfaSetup({
    userId: claims.userId,
    email: claims.email,
  });

  return res.json({ success: true, data: setup });
};

export const beginAdminWebAuthnSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  try {
    const user = await prisma.user.findUnique({
      where: { id: claims.userId },
      select: { id: true, email: true, name: true },
    });
    if (!user) {
      return res.status(404).json({ success: false, error: "User not found." });
    }

    const setup = await beginAdminWebAuthnRegistration({
      userId: claims.userId,
      email: user.email,
      displayName: user.name || user.email,
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    return res.json({ success: true, data: setup });
  } catch (error: any) {
    console.error("beginAdminWebAuthnSetupController error:", error);
    return res.status(409).json({ success: false, error: "Could not start WebAuthn setup right now." });
  }
};

export const confirmAdminMfaSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    await confirmAdminMfaSetup({ userId: claims.userId, code: parsed.data.code });

    if (claims.sessionStage === "MFA_BOOTSTRAP") {
      const ipHash = hashIp(req.ip);
      const userAgent = normalizeUserAgent(req.get("user-agent"));
      const now = new Date();
      const session = await issueSessionForUser({
        userId: claims.userId,
        ipHash,
        userAgent,
        authAssurance: "ADMIN_MFA",
        authenticatedAt: now,
        mfaVerifiedAt: now,
        now,
      });

      await createAuditLog({
        userId: claims.userId,
        action: "AUTH_MFA_ENROLLED",
        entityType: "User",
        entityId: claims.userId,
        details: { source: "LOGIN_BOOTSTRAP" },
        ipHash: ipHash || undefined,
        userAgent: userAgent || undefined,
      } as any);

      setAuthCookies(res, session);
      return res.json({ success: true, data: authResponseData(session) });
    }

    return res.json({ success: true, data: { enabled: true } });
  } catch (error: any) {
    const message = String(error?.message || "");
    const status = message === "INVALID_MFA_CODE" ? 400 : 409;
    return res.status(status).json({ success: false, error: message === "INVALID_MFA_CODE" ? "Invalid authentication code." : "MFA setup could not be completed." });
  }
};

export const completeAdminWebAuthnSetupController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const parsed = webAuthnRegistrationCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid WebAuthn payload" });
  }

  try {
    await completeAdminWebAuthnRegistration({
      userId: claims.userId,
      ticket: parsed.data.ticket,
      label: parsed.data.label,
      credential: parsed.data.credential,
    });

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_WEBAUTHN_ENROLLED",
      entityType: "User",
      entityId: claims.userId,
      details: {
        label: parsed.data.label || "Security key",
      },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    const status = await getAdminMfaStatus(claims.userId);
    return res.json({ success: true, data: { enrolled: true, status } });
  } catch (error: any) {
    console.error("completeAdminWebAuthnSetupController error:", error);
    return res.status(409).json({ success: false, error: "Could not complete WebAuthn setup." });
  }
};

export const beginAdminMfaChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "MFA is not required for this role." });
  }

  const ipHash = hashIp(req.ip);
  const userAgent = normalizeUserAgent(req.get("user-agent"));
  const challenge = await createAdminMfaChallenge({
    userId: claims.userId,
    riskScore: 0,
    riskLevel: "LOW",
    reasons: ["Admin login requires MFA confirmation."],
    ipHash,
    userAgent,
  });

  return res.json({
    success: true,
    data: {
      ticket: challenge.ticket,
      expiresAt: challenge.expiresAt,
    },
  });
};

export const beginAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  try {
    const challenge = await beginAdminWebAuthnChallenge({
      userId: claims.userId,
      purpose: claims.sessionStage === "MFA_BOOTSTRAP" ? "LOGIN" : "STEP_UP",
      ipHash: hashIp(req.ip),
      userAgent: normalizeUserAgent(req.get("user-agent")),
    });

    return res.json({ success: true, data: challenge });
  } catch (error: any) {
    const message = String(error?.message || "");
    const status = message === "WEBAUTHN_NOT_ENROLLED" ? 404 : 409;
    return res.status(status).json({
      success: false,
      error: message === "WEBAUTHN_NOT_ENROLLED" ? "No WebAuthn credential is enrolled for this account." : "Could not start WebAuthn verification.",
    });
  }
};

export const completeAdminMfaChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  const parsed = mfaChallengeCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const completed = await completeAdminMfaChallenge({
      ticket: parsed.data.ticket,
      code: parsed.data.code,
      ipHash,
      userAgent,
    });

    if (completed.userId !== claims.userId) {
      return res.status(403).json({ success: false, error: "MFA challenge does not match the active bootstrap session." });
    }

    const session = await issueSessionForUser({
      userId: claims.userId,
      ipHash,
      userAgent,
      authAssurance: "ADMIN_MFA",
      authenticatedAt: now,
      mfaVerifiedAt: now,
      now,
    });

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_MFA_LOGIN_COMPLETE",
      entityType: "User",
      entityId: claims.userId,
      details: {
        riskScore: completed.riskScore,
        riskLevel: completed.riskLevel,
        reasons: completed.reasons,
      },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    const raw = String(error?.message || "");
    const status = raw === "INVALID_MFA_CODE" ? 400 : raw === "MFA_CHALLENGE_NOT_FOUND" ? 410 : 409;
    const message =
      raw === "INVALID_MFA_CODE"
        ? "Invalid authentication code."
        : raw === "MFA_CHALLENGE_NOT_FOUND"
          ? "This MFA challenge expired. Start again."
          : "MFA challenge could not be completed.";
    return res.status(status).json({ success: false, error: message });
  }
};

export const completeAdminWebAuthnChallengeController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId) return res.status(401).json({ success: false, error: "Not authenticated" });
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const parsed = webAuthnChallengeCompleteSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid WebAuthn payload" });
  }

  try {
    const completed = await completeAdminWebAuthnChallenge({
      userId: claims.userId,
      ticket: parsed.data.ticket,
      credential: parsed.data.credential,
    });

    const ipHash = hashIp(req.ip);
    const userAgent = normalizeUserAgent(req.get("user-agent"));
    const now = new Date();
    const session = await issueSessionForUser({
      userId: claims.userId,
      ipHash,
      userAgent,
      authAssurance: "ADMIN_MFA",
      authenticatedAt: now,
      mfaVerifiedAt: now,
      now,
    });

    const currentRefresh = getRefreshTokenFromRequest(req);
    if (currentRefresh) {
      await revokeRefreshTokenByRaw({ rawToken: currentRefresh, reason: "STEP_UP_REPLACED" });
    }

    await createAuditLog({
      userId: claims.userId,
      action: completed.purpose === "LOGIN" ? "AUTH_WEBAUTHN_LOGIN_COMPLETE" : "AUTH_WEBAUTHN_STEP_UP_SUCCESS",
      entityType: "User",
      entityId: claims.userId,
      details: {
        method: "WEBAUTHN",
        purpose: completed.purpose,
      },
      ipHash: ipHash || undefined,
      userAgent: userAgent || undefined,
    } as any);

    setAuthCookies(res, session);
    return res.json({ success: true, data: authResponseData(session) });
  } catch (error: any) {
    const raw = String(error?.message || "");
    const status = raw === "WEBAUTHN_CHALLENGE_NOT_FOUND" ? 410 : 400;
    const message = raw === "WEBAUTHN_CHALLENGE_NOT_FOUND" ? "This WebAuthn challenge expired. Start again." : "Could not verify the security key.";
    return res.status(status).json({ success: false, error: message });
  }
};

export const rotateAdminMfaBackupCodesController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  const parsed = mfaCodeSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  try {
    const rotated = await rotateAdminMfaBackupCodes({ userId: claims.userId, code: parsed.data.code });
    return res.json({ success: true, data: rotated });
  } catch (error: any) {
    return res.status(400).json({ success: false, error: "Could not rotate backup codes. Check the authentication code and try again." });
  }
};

export const disableAdminMfaController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }

  const parsed = disableMfaSchema.safeParse(req.body || {});
  if (!parsed.success) {
    return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid request" });
  }

  const user = await prisma.user.findUnique({
    where: { id: claims.userId },
    select: { id: true, passwordHash: true, role: true },
  });

  if (!user?.passwordHash) {
    return res.status(400).json({ success: false, error: "Password confirmation is unavailable for this account." });
  }

  const passwordOk = await verifyPassword(user.passwordHash, parsed.data.currentPassword);
  if (!passwordOk) {
    return res.status(400).json({ success: false, error: "Current password is incorrect." });
  }

  try {
    await verifyAdminMfaCode({ userId: claims.userId, code: parsed.data.code });
    await disableAdminMfa(claims.userId);
    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_MFA_DISABLED",
      entityType: "User",
      entityId: claims.userId,
      details: { actorUserId: claims.userId },
      ipAddress: req.ip,
    } as any);
    return res.json({ success: true, data: { enabled: false } });
  } catch {
    return res.status(400).json({ success: false, error: "Could not disable MFA. Check the code and try again." });
  }
};

export const deleteAdminWebAuthnCredentialController = async (req: Request, res: Response) => {
  const claims = getAuthClaims(req);
  if (!claims?.userId || claims.sessionStage !== "ACTIVE") {
    return res.status(401).json({ success: false, error: "An active authenticated session is required." });
  }
  if (!isAdminMfaRequiredRole(claims.role)) {
    return res.status(403).json({ success: false, error: "WebAuthn is only available for admin MFA." });
  }

  const paramsParsed = webAuthnCredentialParamSchema.safeParse(req.params || {});
  if (!paramsParsed.success) {
    return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid WebAuthn credential id" });
  }

  const currentStatus = await getAdminMfaStatus(claims.userId);
  if (!currentStatus.totpEnabled && (currentStatus.webauthnCredentials?.length || 0) <= 1) {
    return res.status(409).json({ success: false, error: "Add another MFA method before removing the last WebAuthn credential." });
  }

  try {
    const deleted = await deleteAdminWebAuthnCredential({
      userId: claims.userId,
      credentialId: paramsParsed.data.id,
    });
    if (!deleted.deleted) {
      return res.status(404).json({ success: false, error: "WebAuthn credential not found." });
    }

    await createAuditLog({
      userId: claims.userId,
      action: "AUTH_WEBAUTHN_CREDENTIAL_REMOVED",
      entityType: "User",
      entityId: claims.userId,
      details: {
        credentialId: paramsParsed.data.id,
      },
      ipHash: hashIp(req.ip) || undefined,
      userAgent: normalizeUserAgent(req.get("user-agent")) || undefined,
    } as any);

    const status = await getAdminMfaStatus(claims.userId);
    return res.json({ success: true, data: { deleted: true, status } });
  } catch (error: any) {
    console.error("deleteAdminWebAuthnCredentialController error:", error);
    return res.status(500).json({ success: false, error: "Could not remove that WebAuthn credential." });
  }
};

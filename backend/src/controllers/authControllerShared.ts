import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import {
  ACCESS_TOKEN_COOKIE,
  CSRF_TOKEN_COOKIE,
  REFRESH_TOKEN_COOKIE,
  getAccessTokenTtlMinutes,
  getRefreshTokenTtlDays,
  newCsrfToken,
} from "../services/auth/tokenService";
import { readCookie } from "../utils/cookies";
import { openCookieToken, sealCookieToken } from "../services/auth/cookieTokenProtectionService";
import {
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../services/auth/authService";
import { getAdminMfaStatus } from "../services/auth/mfaService";
import { findRefreshTokenByRaw } from "../services/auth/refreshTokenService";
import { isValidEmailAddress, normalizeEmailAddress } from "../utils/email";
import { hashIp, normalizeUserAgent } from "../utils/security";
import type { AuthenticatedSessionClaims } from "../types";

export const loginSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
  password: z.string().min(6, "Password must be at least 6 characters"),
}).strict();

export const inviteSchema = z.object({
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

export const acceptInviteSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
  name: z.string().trim().min(2).max(120).optional(),
}).strict();

export const invitePreviewQuerySchema = z.object({
  token: z.string().trim().min(10),
}).strict();

export const forgotPasswordSchema = z.object({
  email: z
    .string()
    .trim()
    .min(3)
    .max(320)
    .refine((value) => isValidEmailAddress(value), "Invalid email format")
    .transform((value) => normalizeEmailAddress(value) as string),
}).strict();

export const resetPasswordSchema = z.object({
  token: z.string().trim().min(10),
  password: z.string().min(8).max(200),
}).strict();

export const verifyEmailSchema = z.object({
  token: z.string().trim().min(10),
}).strict();

export const mfaCodeSchema = z.object({
  code: z.string().trim().min(6).max(32),
}).strict();

export const mfaChallengeCompleteSchema = z.object({
  ticket: z.string().trim().min(10),
  code: z.string().trim().min(6).max(32),
}).strict();

export const webAuthnRegistrationCompleteSchema = z.object({
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

export const webAuthnChallengeCompleteSchema = z.object({
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

export const webAuthnCredentialParamSchema = z.object({
  id: z.string().uuid("Invalid WebAuthn credential id"),
}).strict();

export const disableMfaSchema = z.object({
  code: z.string().trim().min(6).max(32),
  currentPassword: z.string().min(8).max(200),
}).strict();

export const passwordStepUpSchema = z.object({
  currentPassword: z.string().min(1).max(200),
}).strict();

export const normalizeAuthError = (error: unknown): { status: number; error: string } => {
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

const parseBool = (value: unknown) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const cookieSecure = () => parseBool(process.env.COOKIE_SECURE) || process.env.NODE_ENV === "production";

const cookieDomain = () => {
  const domain = String(process.env.COOKIE_DOMAIN || "").trim();
  return domain || undefined;
};

export const authCookieOptions = () => ({
  httpOnly: true,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

export const csrfCookieOptions = () => ({
  httpOnly: false,
  secure: cookieSecure(),
  sameSite: "lax" as const,
  path: "/",
  domain: cookieDomain(),
});

export type CookieBackedAuthResponse = {
  sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
  accessToken: string;
  refreshToken: string | null;
  refreshTokenExpiresAt: Date | null;
  user: any;
  auth: any;
};

export const authResponseData = (session: CookieBackedAuthResponse) => ({
  user: session.user,
  auth: session.auth,
});

export const getRefreshTokenFromRequest = (req: Request) => {
  const raw = readCookie(req, REFRESH_TOKEN_COOKIE);
  return typeof raw === "string" && raw.trim() ? openCookieToken(raw, "auth.refresh") : null;
};

export const clearAuthCookies = (res: Response) => {
  res.clearCookie(ACCESS_TOKEN_COOKIE, authCookieOptions());
  res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
  res.clearCookie(CSRF_TOKEN_COOKIE, csrfCookieOptions());
};

export const setAuthCookies = (res: Response, session: CookieBackedAuthResponse) => {
  const accessTtlMs = getAccessTokenTtlMinutes() * 60 * 1000;
  const refreshTtlMs = getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000;
  const csrfToken = newCsrfToken();

  res.cookie(ACCESS_TOKEN_COOKIE, sealCookieToken(session.accessToken, "auth.access"), {
    ...authCookieOptions(),
    maxAge: accessTtlMs,
  });

  if (session.refreshToken) {
    res.cookie(REFRESH_TOKEN_COOKIE, sealCookieToken(session.refreshToken, "auth.refresh"), {
      ...authCookieOptions(),
      maxAge: refreshTtlMs,
    });
  } else {
    res.clearCookie(REFRESH_TOKEN_COOKIE, authCookieOptions());
  }

  res.cookie(CSRF_TOKEN_COOKIE, csrfToken, {
    ...csrfCookieOptions(),
    maxAge: session.refreshToken ? refreshTtlMs : accessTtlMs,
  });
};

export const getAuthClaims = (req: Request) => ((req as any).user || null) as AuthenticatedSessionClaims | null;

export const buildAuthState = async (
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

export const getCurrentRefreshSession = async (req: Request) => {
  const currentRefresh = getRefreshTokenFromRequest(req);
  return currentRefresh ? await findRefreshTokenByRaw(currentRefresh).catch(() => null) : null;
};

export const ensureCsrfCookie = (req: Request, res: Response) => {
  const hasCsrfCookie = Boolean(readCookie(req, CSRF_TOKEN_COOKIE));
  if (!hasCsrfCookie) {
    res.cookie(CSRF_TOKEN_COOKIE, newCsrfToken(), {
      ...csrfCookieOptions(),
      maxAge: getRefreshTokenTtlDays() * 24 * 60 * 60 * 1000,
    });
  }
};

export { hashIp, isAdminMfaRequiredRole, normalizeUserAgent, prisma };

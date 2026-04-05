import { Request, Response, NextFunction } from "express";
import prisma from "../config/database";
import { AuthenticatedSessionClaims, JWTPayload } from "../types";
import { UserRole } from "@prisma/client";
import { ACCESS_TOKEN_COOKIE, verifyAccessToken, verifyMfaBootstrapToken } from "../services/auth/tokenService";
import { isManufacturerRole, listManufacturerLinkedLicenseeIds } from "../services/manufacturerScopeService";
import {
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../services/auth/authService";

export interface AuthRequest extends Request {
  user?: AuthenticatedSessionClaims;
  authMode?: "bearer" | "cookie";
}

const getBearerToken = (req: Request) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.split(" ")[1] || null;
};

const getCookieAccessToken = (req: Request) => {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const token = cookies?.[ACCESS_TOKEN_COOKIE];
  return token ? String(token) : null;
};

async function hydrateTenantIfNeeded(payload: AuthenticatedSessionClaims): Promise<AuthenticatedSessionClaims> {
  if (!payload?.userId || !payload?.role) return payload;

  if (payload.role === UserRole.SUPER_ADMIN || payload.role === UserRole.PLATFORM_SUPER_ADMIN) return payload;
  if (isManufacturerRole(payload.role) && Array.isArray(payload.linkedLicenseeIds) && payload.linkedLicenseeIds.length > 0) {
    return payload;
  }
  if (!isManufacturerRole(payload.role) && payload.licenseeId && payload.orgId) return payload;

  const u = await prisma.user.findUnique({
    where: { id: payload.userId },
    select: {
      licenseeId: true,
      orgId: true,
    },
  });

  const linkedLicenseeIds = isManufacturerRole(payload.role)
    ? await listManufacturerLinkedLicenseeIds(payload.userId, prisma).catch(() => [])
    : Array.isArray(payload.linkedLicenseeIds)
      ? payload.linkedLicenseeIds
      : [];

  return {
    ...payload,
    licenseeId: u?.licenseeId ?? payload.licenseeId ?? linkedLicenseeIds?.[0] ?? null,
    orgId: u?.orgId ?? payload.orgId ?? null,
    linkedLicenseeIds: linkedLicenseeIds.length ? linkedLicenseeIds : payload.linkedLicenseeIds ?? null,
  };
}

const parseAnySessionToken = async (token: string): Promise<AuthenticatedSessionClaims> => {
  try {
    const decoded = verifyAccessToken(token);
    return hydrateTenantIfNeeded(decoded);
  } catch {
    const decoded = verifyMfaBootstrapToken(token);
    return hydrateTenantIfNeeded({
      userId: decoded.userId,
      email: decoded.email,
      role: decoded.role,
      licenseeId: decoded.licenseeId ?? null,
      orgId: decoded.orgId ?? null,
      linkedLicenseeIds: decoded.linkedLicenseeIds ?? null,
      sessionStage: "MFA_BOOTSTRAP",
      authAssurance: "PASSWORD",
      authenticatedAt: null,
      mfaVerifiedAt: null,
    });
  }
};

const allowSseQueryToken = () => {
  if (String(process.env.AUTH_SSE_QUERY_TOKEN_ENABLED || "").trim().toLowerCase() === "true") return true;
  return process.env.NODE_ENV !== "production";
};

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const bearer = getBearerToken(req);
  const cookieToken = bearer ? null : getCookieAccessToken(req);
  const token = bearer || cookieToken;
  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = verifyAccessToken(token);
    req.user = await hydrateTenantIfNeeded(decoded);
    req.authMode = bearer ? "bearer" : "cookie";
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

export const authenticateAnySession = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const bearer = getBearerToken(req);
  const cookieToken = bearer ? null : getCookieAccessToken(req);
  const token = bearer || cookieToken;
  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    req.user = await parseAnySessionToken(token);
    req.authMode = bearer ? "bearer" : "cookie";
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

export const optionalAuth = async (req: AuthRequest, _res: Response, next: NextFunction) => {
  const bearer = getBearerToken(req);
  const cookieToken = bearer ? null : getCookieAccessToken(req);
  const token = bearer || cookieToken;
  if (!token) return next();

  try {
    const decoded = verifyAccessToken(token);
    req.user = await hydrateTenantIfNeeded(decoded);
    req.authMode = bearer ? "bearer" : "cookie";
  } catch {
    // ignore
  }
  return next();
};

/**
 * SSE auth supports:
 * - ?token= (temporary compatibility only when explicitly enabled or outside production)
 * - Authorization: Bearer (normal)
 * - Cookie access token (preferred; avoids putting tokens in URLs)
 */
export const authenticateSSE = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const queryToken = allowSseQueryToken() ? (req.query.token as string | undefined) || "" : "";
  const headerToken = getBearerToken(req) || "";
  const cookieToken = !queryToken && !headerToken ? getCookieAccessToken(req) || "" : "";
  const token = queryToken || headerToken || cookieToken;

  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = verifyAccessToken(token);
    req.user = await hydrateTenantIfNeeded(decoded);
    req.authMode = queryToken ? "bearer" : headerToken ? "bearer" : "cookie";
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

const stepUpRequired = (
  res: Response,
  input: {
    message: string;
    method: "ADMIN_MFA" | "PASSWORD_REAUTH";
  }
) =>
  res.status(428).json({
    success: false,
    error: input.message,
    code: "STEP_UP_REQUIRED",
    data: {
      stepUpRequired: true,
      stepUpMethod: input.method,
    },
  });

export const requireRecentAdminMfa = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: "Authentication required" });
  }

  if (!isAdminMfaRequiredRole(req.user.role)) {
    return next();
  }

  if (req.user.sessionStage !== "ACTIVE") {
    return stepUpRequired(res, {
      message: "Admin MFA verification is required before continuing.",
      method: "ADMIN_MFA",
    });
  }

  const verifiedAt = req.user.mfaVerifiedAt ? new Date(req.user.mfaVerifiedAt) : null;
  if (!verifiedAt || Number.isNaN(verifiedAt.getTime())) {
    return stepUpRequired(res, {
      message: "Admin MFA verification is required before continuing.",
      method: "ADMIN_MFA",
    });
  }

  const maxAgeMs = getAdminStepUpWindowMinutes() * 60_000;
  if (Date.now() - verifiedAt.getTime() > maxAgeMs) {
    return stepUpRequired(res, {
      message: "Your admin verification is no longer fresh enough for this action. Confirm your authenticator code to continue.",
      method: "ADMIN_MFA",
    });
  }

  return next();
};

export const requireRecentSensitiveAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.user) {
    return res.status(401).json({ success: false, error: "Authentication required" });
  }

  if (isAdminMfaRequiredRole(req.user.role)) {
    return requireRecentAdminMfa(req, res, next);
  }

  if (req.user.sessionStage !== "ACTIVE") {
    return stepUpRequired(res, {
      message: "A fresh password confirmation is required before continuing.",
      method: getSensitiveActionStepUpMethod(req.user.role),
    });
  }

  const authenticatedAt = req.user.authenticatedAt ? new Date(req.user.authenticatedAt) : null;
  if (!authenticatedAt || Number.isNaN(authenticatedAt.getTime())) {
    return stepUpRequired(res, {
      message: "A fresh password confirmation is required before continuing.",
      method: getSensitiveActionStepUpMethod(req.user.role),
    });
  }

  const maxAgeMs = getPasswordReauthWindowMinutes() * 60_000;
  if (Date.now() - authenticatedAt.getTime() > maxAgeMs) {
    return stepUpRequired(res, {
      message: "Your password confirmation is no longer fresh enough for this action. Confirm your password to continue.",
      method: getSensitiveActionStepUpMethod(req.user.role),
    });
  }

  return next();
};

import { Request, Response, NextFunction } from "express";
import prisma from "../config/database";
import { AuthenticatedSessionClaims, JWTPayload } from "../types";
import { UserRole } from "@prisma/client";
import { ACCESS_TOKEN_COOKIE, verifyAccessToken, verifyMfaBootstrapToken } from "../services/auth/tokenService";
import { openCookieToken } from "../services/auth/cookieTokenProtectionService";
import {
  isLicenseeAdminRole,
  isManufacturerRole,
  isPlatformRole,
  resolveManufacturerSessionScope,
} from "../services/manufacturerScopeService";
import { isDisabledUserRecord } from "../services/accessControlService";
import { readCookie } from "../utils/cookies";
// rls-prototype-approved-import: verified signed claims establish hydration context.
import { withRlsPrototypeTransaction } from "../lib/rlsTransactionContextPrototype";
import {
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../services/auth/authService";
import { getAdminMfaStatus } from "../services/auth/mfaService";

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
  const token = readCookie(req, ACCESS_TOKEN_COOKIE) || "";
  return token ? openCookieToken(token, "auth.access") : null;
};

export async function hydrateTenantIfNeeded(payload: AuthenticatedSessionClaims): Promise<AuthenticatedSessionClaims> {
  if (!payload?.userId || !payload?.role) return payload;

  const { user: u, manufacturerScope, currentMfaEnabled } = await withRlsPrototypeTransaction(
    prisma,
    {
      userId: payload.userId,
      role: payload.role,
      licenseeId: isManufacturerRole(payload.role) ? null : payload.licenseeId,
      manufacturerId: isManufacturerRole(payload.role) ? payload.userId : null,
      organizationId: isManufacturerRole(payload.role) ? null : payload.orgId,
      // Hydration only needs actor-self visibility. Never elevate from a stale claim.
      isPlatformAdmin: false,
    },
    async (tx) => {
      const user = await tx.user.findUnique({
        where: { id: payload.userId },
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
      });
      if (user && user.role !== payload.role) {
        throw new Error("Account role changed");
      }
      const scope = user && isManufacturerRole(user.role)
        ? await resolveManufacturerSessionScope({
            manufacturerId: user.id,
            legacyLicenseeId: user.licenseeId,
            legacyOrgId: user.orgId,
            requestedLicenseeId: payload.licenseeId,
            requestedOrgId: payload.orgId,
            requestedScopeVersion: payload.scopeVersion,
          }, tx)
        : null;
      const mfaStatus = user && payload.sessionStage === "ACTIVE" && payload.authAssurance === "ADMIN_MFA" && isAdminMfaRequiredRole(user.role)
        ? await getAdminMfaStatus(user.id, tx)
        : null;
      return { user, manufacturerScope: scope, currentMfaEnabled: mfaStatus ? Boolean(mfaStatus.enabled) : null };
    }
  );

  if (!u || isDisabledUserRecord(u)) {
    throw new Error("Account is disabled");
  }
  if (payload.sessionStage === "ACTIVE" && payload.authAssurance === "ADMIN_MFA" && isAdminMfaRequiredRole(u.role) && !currentMfaEnabled) {
    throw new Error("Account MFA state changed");
  }

  const effectiveRole = u.role;
  const databaseLicenseeId = String(u.licenseeId || "").trim() || null;
  const databaseOrgId = String(u.orgId || "").trim() || null;
  const tokenLicenseeId = String(payload.licenseeId || "").trim() || null;
  const tokenOrgId = String(payload.orgId || "").trim() || null;

  if (isPlatformRole(effectiveRole)) {
    return { ...payload, email: u.email || payload.email, role: effectiveRole, licenseeId: null, orgId: null, scopeVersion: null, linkedLicenseeIds: [] };
  }

  if (isLicenseeAdminRole(effectiveRole)) {
    if (!databaseLicenseeId || !databaseOrgId) throw new Error("Account tenant scope is unavailable");
    if ((tokenLicenseeId && tokenLicenseeId !== databaseLicenseeId) || (tokenOrgId && tokenOrgId !== databaseOrgId)) {
      throw new Error("Account tenant scope changed");
    }
    return {
      ...payload,
      email: u.email || payload.email,
      role: effectiveRole,
      licenseeId: databaseLicenseeId,
      orgId: databaseOrgId,
      scopeVersion: null,
      linkedLicenseeIds: [],
    };
  }

  if (isManufacturerRole(effectiveRole)) {
    const selected = manufacturerScope?.selectedLicensee || null;
    return {
      ...payload,
      email: u.email || payload.email,
      role: effectiveRole,
      licenseeId: selected?.id || null,
      orgId: selected?.orgId || null,
      scopeVersion: selected?.scopeVersion || null,
      linkedLicenseeIds: manufacturerScope?.linkedLicenseeIds || [],
    };
  }

  return {
    ...payload,
    email: u.email || payload.email,
    role: effectiveRole,
    licenseeId: databaseLicenseeId,
    orgId: databaseOrgId,
    scopeVersion: null,
    linkedLicenseeIds: [],
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
      scopeVersion: decoded.scopeVersion ?? null,
      linkedLicenseeIds: decoded.linkedLicenseeIds ?? null,
      sessionStage: "MFA_BOOTSTRAP",
      authAssurance: "PASSWORD",
      authenticatedAt: null,
      mfaVerifiedAt: null,
      sessionId: decoded.sessionId,
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
      message: "MFA verification is required before continuing.",
      method: "ADMIN_MFA",
    });
  }

  const verifiedAt = req.user.mfaVerifiedAt ? new Date(req.user.mfaVerifiedAt) : null;
  if (!verifiedAt || Number.isNaN(verifiedAt.getTime())) {
    return stepUpRequired(res, {
      message: "MFA verification is required before continuing.",
      method: "ADMIN_MFA",
    });
  }

  const maxAgeMs = getAdminStepUpWindowMinutes() * 60_000;
  if (Date.now() - verifiedAt.getTime() > maxAgeMs) {
    return stepUpRequired(res, {
      message: "Your MFA verification is no longer fresh enough for this action. Confirm your authenticator code to continue.",
      method: "ADMIN_MFA",
    });
  }

  return next();
};

export const requireRecentAdminMfaForSetup = (req: AuthRequest, res: Response, next: NextFunction) =>
  req.user?.sessionStage === "MFA_BOOTSTRAP" ? next() : requireRecentAdminMfa(req, res, next);

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

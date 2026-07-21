import { Request, Response, NextFunction } from "express";
import { randomUUID } from "crypto";
import { AuthenticatedSessionClaims } from "../types";
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
import {
  getAdminStepUpWindowMinutes,
  getPasswordReauthWindowMinutes,
  getSensitiveActionStepUpMethod,
  isAdminMfaRequiredRole,
} from "../services/auth/authService";
import { clearAuthCookies } from "../controllers/authControllerShared";
import {
  isCanonicalAuthDenial,
  withCanonicalAuthClaims,
} from "../rls-waves/session-b/b01/canonicalAuthContext";
import {
  loadAuthenticatedActor,
  isRecentMfaDenial,
  RecentMfaDenial,
  requireRecentMfaSession,
} from "../rls-waves/session-b/b01/authenticatedSecurityRepository";

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

const requestIdFor = (req: Request) =>
  String((req as Request & { requestId?: string }).requestId || req.get("x-request-id") || randomUUID());

export async function hydrateTenantIfNeeded(
  payload: AuthenticatedSessionClaims,
  requestId: string = randomUUID()
): Promise<AuthenticatedSessionClaims> {
  if (!payload?.userId || !payload?.role) return payload;

  const { user: u, manufacturerScope, canonicalAssurance } = await withCanonicalAuthClaims(
    payload,
    { requestId, purpose: "auth-session-hydration" },
    async (tx, context) => {
      const user = await loadAuthenticatedActor(tx);
      if (user.id !== context.userId || user.role !== context.role) throw new Error("Authenticated actor changed");
      const scope = user && isManufacturerRole(user.role)
        ? await resolveManufacturerSessionScope({
            manufacturerId: user.id,
            legacyLicenseeId: user.licenseeId,
            legacyOrgId: user.orgId,
            requestedLicenseeId: context.licenseeId,
            requestedOrgId: context.organizationId,
            requestedScopeVersion: payload.scopeVersion,
          }, tx)
        : null;
      return {
        user,
        manufacturerScope: scope,
        canonicalAssurance: context.authAssurance,
      };
    }
  );

  if (!u || isDisabledUserRecord(u)) {
    throw new Error("Account is disabled");
  }
  const hydratedPayload: AuthenticatedSessionClaims = {
    ...payload,
    sessionStage: canonicalAssurance === "mfa-bootstrap" ? "MFA_BOOTSTRAP" : "ACTIVE",
    authAssurance: canonicalAssurance === "mfa-verified" ? "ADMIN_MFA" : "PASSWORD",
  };

  const effectiveRole = u.role;
  const databaseLicenseeId = String(u.licenseeId || "").trim() || null;
  const databaseOrgId = String(u.orgId || "").trim() || null;
  const tokenLicenseeId = String(payload.licenseeId || "").trim() || null;
  const tokenOrgId = String(payload.orgId || "").trim() || null;

  if (isPlatformRole(effectiveRole)) {
    return { ...hydratedPayload, email: u.email || payload.email, role: effectiveRole, licenseeId: null, orgId: null, scopeVersion: null, linkedLicenseeIds: [] };
  }

  if (isLicenseeAdminRole(effectiveRole)) {
    if (!databaseLicenseeId || !databaseOrgId) throw new Error("Account tenant scope is unavailable");
    if ((tokenLicenseeId && tokenLicenseeId !== databaseLicenseeId) || (tokenOrgId && tokenOrgId !== databaseOrgId)) {
      throw new Error("Account tenant scope changed");
    }
    return {
      ...hydratedPayload,
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
      ...hydratedPayload,
      email: u.email || payload.email,
      role: effectiveRole,
      licenseeId: selected?.id || null,
      orgId: selected?.orgId || null,
      scopeVersion: selected?.scopeVersion || null,
      linkedLicenseeIds: manufacturerScope?.linkedLicenseeIds || [],
    };
  }

  return {
    ...hydratedPayload,
    email: u.email || payload.email,
    role: effectiveRole,
    licenseeId: databaseLicenseeId,
    orgId: databaseOrgId,
    scopeVersion: null,
    linkedLicenseeIds: [],
  };
}

const parseAnySessionToken = async (token: string, requestId: string): Promise<AuthenticatedSessionClaims> => {
  try {
    const decoded = verifyAccessToken(token);
    return hydrateTenantIfNeeded(decoded, requestId);
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
    }, requestId);
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
    req.user = await hydrateTenantIfNeeded(decoded, requestIdFor(req));
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
    req.user = await parseAnySessionToken(token, requestIdFor(req));
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
    req.user = await hydrateTenantIfNeeded(decoded, requestIdFor(req));
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
    req.user = await hydrateTenantIfNeeded(decoded, requestIdFor(req));
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

export const requireRecentAdminMfa = async (req: AuthRequest, res: Response, next: NextFunction) => {
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

  const maxAgeMinutes = getAdminStepUpWindowMinutes();
  try {
    await withCanonicalAuthClaims(
      req.user,
      { requestId: requestIdFor(req), purpose: "auth-recent-admin-mfa" },
      (tx, context) => {
        if (context.authAssurance !== "mfa-verified" && context.authAssurance !== "step-up-verified") {
          throw new RecentMfaDenial();
        }
        return requireRecentMfaSession({
          sessionId: req.user!.sessionId || "",
          checkedAt: new Date(),
          maxAgeMinutes,
        }, tx);
      }
    );
  } catch (error) {
    if (isCanonicalAuthDenial(error)) {
      clearAuthCookies(res);
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    if (isRecentMfaDenial(error)) {
      return stepUpRequired(res, {
        message: "Your MFA verification is no longer fresh enough for this action. Confirm your authenticator code to continue.",
        method: "ADMIN_MFA",
      });
    }
    return next(error);
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

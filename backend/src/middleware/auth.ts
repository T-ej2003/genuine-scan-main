import { Request, Response, NextFunction } from "express";
import prisma from "../config/database";
import { JWTPayload } from "../types";
import { UserRole } from "@prisma/client";
import { ACCESS_TOKEN_COOKIE, verifyAccessToken } from "../services/auth/tokenService";
import { isManufacturerRole, listManufacturerLinkedLicenseeIds } from "../services/manufacturerScopeService";

export interface AuthRequest extends Request {
  user?: JWTPayload;
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

async function hydrateTenantIfNeeded(payload: JWTPayload): Promise<JWTPayload> {
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

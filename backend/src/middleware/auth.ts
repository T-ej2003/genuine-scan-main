import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import prisma from "../config/database";
import { JWTPayload } from "../types";
import { UserRole } from "@prisma/client";
import { ACCESS_TOKEN_COOKIE } from "../services/auth/tokenService";

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
  if (payload.licenseeId && payload.orgId) return payload;

  // fallback: lookup the user to get licenseeId
  const u = await prisma.user.findUnique({
    where: { id: payload.userId },
    select: { licenseeId: true, orgId: true },
  });

  return { ...payload, licenseeId: u?.licenseeId ?? null, orgId: u?.orgId ?? null };
}

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const bearer = getBearerToken(req);
  const cookieToken = bearer ? null : getCookieAccessToken(req);
  const token = bearer || cookieToken;
  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
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
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
    req.user = await hydrateTenantIfNeeded(decoded);
    req.authMode = bearer ? "bearer" : "cookie";
  } catch {
    // ignore
  }
  return next();
};

/**
 * SSE auth supports:
 * - ?token= (for EventSource)
 * - Authorization: Bearer (normal)
 */
export const authenticateSSE = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const queryToken = (req.query.token as string | undefined) || "";
  const headerToken = getBearerToken(req) || "";
  const token = queryToken || headerToken;

  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
    req.user = await hydrateTenantIfNeeded(decoded);
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

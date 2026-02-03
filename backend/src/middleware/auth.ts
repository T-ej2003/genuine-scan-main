import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import prisma from "../config/database";
import { JWTPayload } from "../types";
import { UserRole } from "@prisma/client";

export interface AuthRequest extends Request {
  user?: JWTPayload;
}

const getBearerToken = (req: Request) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  return authHeader.split(" ")[1] || null;
};

async function hydrateTenantIfNeeded(payload: JWTPayload): Promise<JWTPayload> {
  if (!payload?.userId || !payload?.role) return payload;

  if (payload.role === UserRole.SUPER_ADMIN) return payload;
  if (payload.licenseeId) return payload;

  // fallback: lookup the user to get licenseeId
  const u = await prisma.user.findUnique({
    where: { id: payload.userId },
    select: { licenseeId: true },
  });

  return { ...payload, licenseeId: u?.licenseeId ?? null };
}

export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ success: false, error: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
    req.user = await hydrateTenantIfNeeded(decoded);
    return next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
};

export const optionalAuth = async (req: AuthRequest, _res: Response, next: NextFunction) => {
  const token = getBearerToken(req);
  if (!token) return next();

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JWTPayload;
    req.user = await hydrateTenantIfNeeded(decoded);
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


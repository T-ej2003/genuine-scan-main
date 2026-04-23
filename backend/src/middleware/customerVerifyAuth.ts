import { NextFunction, Request, Response } from "express";
import { createHash } from "crypto";

import {
  CustomerVerifyIdentity,
  verifyCustomerVerifyToken,
} from "../services/customerVerifyAuthService";
import {
  isCustomerVerifyBearerCompatEnabled,
  readCustomerVerifySessionCookie,
} from "../services/customerVerifyCookieService";
import { hashIp } from "../utils/security";
import { logger } from "../utils/logger";

export interface CustomerVerifyRequest extends Request {
  customer?: CustomerVerifyIdentity;
  customerAuthSource?: "cookie" | "bearer";
}

const getBearerToken = (req: Request) => {
  const authHeader = String(req.headers.authorization || "").trim();
  if (!authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim() || null;
};

const hashUserAgent = (value: string | undefined) => {
  const normalized = String(value || "").trim();
  if (!normalized) return null;
  return createHash("sha256").update(normalized).digest("hex").slice(0, 12);
};

const resolveAuthToken = (req: Request): { token: string | null; source: "cookie" | "bearer" | null } => {
  const cookieToken = readCustomerVerifySessionCookie(req);
  if (cookieToken) return { token: cookieToken, source: "cookie" };

  const bearerToken = getBearerToken(req);
  if (!bearerToken) return { token: null, source: null };
  if (!isCustomerVerifyBearerCompatEnabled()) return { token: null, source: null };
  return { token: bearerToken, source: "bearer" };
};

const recordLegacyBearerCompatUsage = (req: Request) => {
  logger.warn("verify_customer_auth_legacy_bearer", {
    metric: "verify_customer_auth_legacy_bearer",
    path: req.originalUrl.split("?")[0] || req.path || "/",
    method: req.method,
    ipRef: hashIp(req.ip),
    userAgentRef: hashUserAgent(req.get("user-agent") || ""),
  });
};

export const optionalCustomerVerifyAuth = (req: CustomerVerifyRequest, _res: Response, next: NextFunction) => {
  const { token, source } = resolveAuthToken(req);
  if (!token) {
    return next();
  }

  try {
    req.customer = verifyCustomerVerifyToken(token);
    if (source) {
      req.customerAuthSource = source;
      if (source === "bearer") {
        recordLegacyBearerCompatUsage(req);
      }
    }
  } catch {
    // Ignore invalid customer token for optional auth routes.
  }

  return next();
};

export const requireCustomerVerifyAuth = (req: CustomerVerifyRequest, res: Response, next: NextFunction) => {
  const { token, source } = resolveAuthToken(req);
  if (!token) {
    return res.status(401).json({
      success: false,
      error: "Customer authentication required",
    });
  }

  try {
    req.customer = verifyCustomerVerifyToken(token);
    if (source) {
      req.customerAuthSource = source;
      if (source === "bearer") {
        recordLegacyBearerCompatUsage(req);
      }
    }
    return next();
  } catch {
    return res.status(401).json({
      success: false,
      error: "Invalid or expired customer session",
    });
  }
};

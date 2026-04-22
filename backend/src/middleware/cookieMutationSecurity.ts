import { NextFunction, Request, Response } from "express";

import { ACCESS_TOKEN_COOKIE, CSRF_TOKEN_COOKIE, REFRESH_TOKEN_COOKIE } from "../services/auth/tokenService";
import {
  CUSTOMER_VERIFY_CSRF_COOKIE_NAME,
  CUSTOMER_VERIFY_SESSION_COOKIE_NAME,
} from "../services/customerVerifyCookieService";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const normalizeRoutePath = (req: Request) => {
  const raw = String(req.originalUrl || req.path || "").split("?")[0];
  return raw.startsWith("/api/") ? raw.slice(4) : raw;
};

const readCookie = (req: Request, cookieName: string) => {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  return String(cookies?.[cookieName] || "").trim();
};

const readHeaderToken = (req: Request) => {
  const direct = String(req.headers["x-csrf-token"] || "").trim();
  if (direct) return direct;
  return String(req.headers["X-CSRF-Token"] || "").trim();
};

const hasBearerAuth = (req: Request) => String(req.headers.authorization || "").trim().startsWith("Bearer ");

const isAdminCookieMutationRoute = (req: Request) => {
  const path = normalizeRoutePath(req);
  if (!path.startsWith("/auth/")) return false;
  if (SAFE_METHODS.has(String(req.method || "").toUpperCase())) return false;

  return ![
    "/auth/login",
    "/auth/accept-invite",
    "/auth/verify-email",
    "/auth/forgot-password",
    "/auth/reset-password",
  ].includes(path);
};

const isCustomerVerifyMutationRoute = (req: Request) => {
  const path = normalizeRoutePath(req);
  return path.startsWith("/verify/") && !SAFE_METHODS.has(String(req.method || "").toUpperCase());
};

const hasAdminAuthCookie = (req: Request) => Boolean(readCookie(req, ACCESS_TOKEN_COOKIE) || readCookie(req, REFRESH_TOKEN_COOKIE));
const hasCustomerVerifyCookie = (req: Request) => Boolean(readCookie(req, CUSTOMER_VERIFY_SESSION_COOKIE_NAME));

const rejectCsrf = (res: Response) => res.status(403).json({ success: false, error: "CSRF token missing or invalid" });

export const enforceCookieMutationSecurity = (req: Request, res: Response, next: NextFunction) => {
  if (SAFE_METHODS.has(String(req.method || "").toUpperCase()) || hasBearerAuth(req)) {
    return next();
  }

  if (isAdminCookieMutationRoute(req) || hasAdminAuthCookie(req)) {
    const cookieToken = readCookie(req, CSRF_TOKEN_COOKIE);
    const headerToken = readHeaderToken(req);
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return rejectCsrf(res);
    }
  }

  if (isCustomerVerifyMutationRoute(req) && hasCustomerVerifyCookie(req)) {
    const cookieToken = readCookie(req, CUSTOMER_VERIFY_CSRF_COOKIE_NAME);
    const headerToken = readHeaderToken(req);
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return rejectCsrf(res);
    }
  }

  return next();
};

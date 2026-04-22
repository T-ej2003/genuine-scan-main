import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";
import { CSRF_TOKEN_COOKIE } from "../services/auth/tokenService";
import { CustomerVerifyRequest } from "./customerVerifyAuth";
import { CUSTOMER_VERIFY_CSRF_COOKIE_NAME } from "../services/customerVerifyCookieService";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export const requireCsrf = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (SAFE_METHODS.has(String(req.method || "").toUpperCase())) return next();

  // If the request is authorized via Bearer token, CSRF is not applicable.
  const authHeader = String(req.headers.authorization || "");
  if (req.authMode === "bearer" || authHeader.startsWith("Bearer ")) return next();

  // Cookie-authenticated requests must pass double-submit token.
  const cookieToken = String((req as any).cookies?.[CSRF_TOKEN_COOKIE] || "").trim();
  const headerToken = String(req.headers["x-csrf-token"] || "").trim();

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ success: false, error: "CSRF token missing or invalid" });
  }

  return next();
};

export const requireCustomerVerifyCsrf = (req: CustomerVerifyRequest, res: Response, next: NextFunction) => {
  if (SAFE_METHODS.has(String(req.method || "").toUpperCase())) return next();

  const authHeader = String(req.headers.authorization || "");
  if (req.customerAuthSource === "bearer" || authHeader.startsWith("Bearer ")) return next();

  const cookieToken = String((req as any).cookies?.[CUSTOMER_VERIFY_CSRF_COOKIE_NAME] || "").trim();
  const headerToken = String(req.headers["x-csrf-token"] || "").trim();

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ success: false, error: "CSRF token missing or invalid" });
  }

  return next();
};

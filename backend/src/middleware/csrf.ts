import { Response, NextFunction } from "express";
import { AuthRequest } from "./auth";
import { CSRF_TOKEN_COOKIE } from "../services/auth/tokenService";

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


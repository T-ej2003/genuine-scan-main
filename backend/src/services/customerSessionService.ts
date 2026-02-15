import { randomUUID } from "crypto";
import type { Request, Response } from "express";
import jwt from "jsonwebtoken";

import { sha256Hash } from "./securityHashService";

type CustomerSessionPayload = {
  customerUserId: string;
  email: string;
  name?: string | null;
  provider?: string | null;
};

const SESSION_COOKIE_NAME = "customer_session";
const ANON_COOKIE_NAME = "anon_vid";
const SESSION_TTL_DAYS = Number(process.env.CUSTOMER_SESSION_TTL_DAYS || "30");
const ANON_TTL_DAYS = Number(process.env.ANON_VISITOR_TTL_DAYS || "180");

const normalizeCookieValue = (value: unknown) =>
  String(value || "")
    .trim()
    .replace(/[^a-zA-Z0-9._-]/g, "")
    .slice(0, 128);

const parseCookies = (headerValue?: string | null): Record<string, string> => {
  const out: Record<string, string> = {};
  const raw = String(headerValue || "").trim();
  if (!raw) return out;

  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = decodeURIComponent(v);
  }
  return out;
};

const getCookie = (req: Request, name: string) => {
  const cookies = parseCookies(req.headers.cookie);
  return cookies[name] || null;
};

const asBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const isProd = () => String(process.env.NODE_ENV || "").toLowerCase() === "production";

const cookieBase = (maxAgeSec: number, httpOnly: boolean) => {
  const parts = [
    "Path=/",
    `Max-Age=${Math.max(1, Math.floor(maxAgeSec))}`,
    "SameSite=Lax",
    httpOnly ? "HttpOnly" : "",
    isProd() || asBool(process.env.COOKIE_SECURE, false) ? "Secure" : "",
  ].filter(Boolean);

  return parts.join("; ");
};

const resolveSessionSecret = () => {
  const secret = String(process.env.SESSION_SECRET || process.env.JWT_SECRET || "").trim();
  if (!secret) throw new Error("SESSION_SECRET (or JWT_SECRET) is required for customer sessions");
  return secret;
};

export const issueCustomerSession = (
  res: Response,
  user: { id: string; email: string; name?: string | null; provider?: string | null }
) => {
  const payload: CustomerSessionPayload = {
    customerUserId: user.id,
    email: user.email,
    name: user.name || null,
    provider: user.provider || null,
  };

  const token = jwt.sign(payload, resolveSessionSecret(), {
    expiresIn: `${Math.max(1, SESSION_TTL_DAYS)}d`,
  });

  res.append(
    "Set-Cookie",
    `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; ${cookieBase(SESSION_TTL_DAYS * 24 * 60 * 60, true)}`
  );
};

export const clearCustomerSession = (res: Response) => {
  res.append("Set-Cookie", `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly`);
};

export const readCustomerSession = (
  req: Request
): { customerUserId: string; email: string; name?: string | null; provider?: string | null } | null => {
  const token = getCookie(req, SESSION_COOKIE_NAME);
  if (!token) return null;

  try {
    const decoded = jwt.verify(token, resolveSessionSecret()) as CustomerSessionPayload;
    if (!decoded?.customerUserId || !decoded?.email) return null;
    return {
      customerUserId: String(decoded.customerUserId),
      email: String(decoded.email).toLowerCase(),
      name: decoded.name || null,
      provider: decoded.provider || null,
    };
  } catch {
    return null;
  }
};

export const ensureAnonVisitorId = (req: Request, res: Response) => {
  const existing = normalizeCookieValue(getCookie(req, ANON_COOKIE_NAME));
  if (existing) return existing;

  const next = normalizeCookieValue(randomUUID());
  res.append(
    "Set-Cookie",
    `${ANON_COOKIE_NAME}=${encodeURIComponent(next)}; ${cookieBase(ANON_TTL_DAYS * 24 * 60 * 60, true)}`
  );
  return next;
};

export const getVisitorFingerprint = (req: Request) => {
  const fromHeader =
    String(req.headers["x-visitor-fp"] || "").trim() ||
    String(req.headers["x-device-fp"] || "").trim() ||
    String(req.query.visitorFp || "").trim();

  const normalized = normalizeCookieValue(fromHeader);
  return normalized || null;
};

export const getHashedIp = (req: Request) => sha256Hash(req.ip || null);

export const getCustomerIdentityContext = (req: Request, res: Response) => {
  const customer = readCustomerSession(req);
  const anonVisitorId = ensureAnonVisitorId(req, res);
  const visitorFingerprint = getVisitorFingerprint(req);

  return {
    customerUserId: customer?.customerUserId || null,
    customer,
    anonVisitorId,
    visitorFingerprint,
    ipHash: getHashedIp(req),
  };
};

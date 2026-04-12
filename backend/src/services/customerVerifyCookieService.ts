import { Request, Response } from "express";

const CUSTOMER_VERIFY_SESSION_COOKIE_NAME =
  String(process.env.CUSTOMER_VERIFY_SESSION_COOKIE_NAME || "").trim() || "mscqr_verify_session";

const parseBoolEnv = (value: unknown, fallback: boolean) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const parseIntEnv = (key: string, fallbackHours: number) => {
  const parsed = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(parsed) || parsed <= 0) return fallbackHours;
  return Math.floor(parsed);
};

const customerVerifyTokenTtlHours = () => parseIntEnv("CUSTOMER_VERIFY_TOKEN_TTL_HOURS", 24 * 30);

const customerVerifyCookieOptions = (maxAgeMs: number) => ({
  httpOnly: true,
  sameSite: "lax" as const,
  secure: parseBoolEnv(process.env.COOKIE_SECURE, process.env.NODE_ENV === "production"),
  path: "/api",
  maxAge: maxAgeMs,
});

export const isCustomerVerifyCookieAuthEnabled = () =>
  parseBoolEnv(process.env.VERIFY_CUSTOMER_COOKIE_AUTH_ENABLED, true);

export const isCustomerVerifyBearerCompatEnabled = () =>
  parseBoolEnv(process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED, true);

export const readCustomerVerifySessionCookie = (req: Request) => {
  if (!isCustomerVerifyCookieAuthEnabled()) return null;
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const raw = String(cookies?.[CUSTOMER_VERIFY_SESSION_COOKIE_NAME] || "").trim();
  return raw || null;
};

export const setCustomerVerifySessionCookie = (res: Response, token: string) => {
  if (!isCustomerVerifyCookieAuthEnabled()) return;
  const normalizedToken = String(token || "").trim();
  if (!normalizedToken) return;
  const maxAgeMs = customerVerifyTokenTtlHours() * 60 * 60 * 1000;
  res.cookie(CUSTOMER_VERIFY_SESSION_COOKIE_NAME, normalizedToken, customerVerifyCookieOptions(maxAgeMs));
};

export const clearCustomerVerifySessionCookie = (res: Response) => {
  if (!isCustomerVerifyCookieAuthEnabled()) return;
  res.clearCookie(CUSTOMER_VERIFY_SESSION_COOKIE_NAME, customerVerifyCookieOptions(0));
};


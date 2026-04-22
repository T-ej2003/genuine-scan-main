import type { Request } from "express";

const parseCookieHeader = (header: string) => {
  const pairs = header.split(";");
  const values: Record<string, string> = {};

  for (const pair of pairs) {
    const trimmed = pair.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.indexOf("=");
    if (separatorIndex <= 0) continue;
    const name = trimmed.slice(0, separatorIndex).trim();
    const rawValue = trimmed.slice(separatorIndex + 1).trim();
    if (!name) continue;
    try {
      values[name] = decodeURIComponent(rawValue);
    } catch {
      values[name] = rawValue;
    }
  }

  return values;
};

export const getRequestCookies = (req: Request) => {
  const parsedCookies = (req as Request & { cookies?: Record<string, string> }).cookies;
  if (parsedCookies && typeof parsedCookies === "object") {
    return parsedCookies;
  }

  const cookieHeader = String((req as Request & { headers?: Record<string, string | undefined> }).headers?.cookie || "").trim();
  if (!cookieHeader) return {};
  return parseCookieHeader(cookieHeader);
};

export const readCookie = (req: Request, name: string) => {
  const cookies = getRequestCookies(req);
  const raw = String(cookies?.[name] || "").trim();
  return raw || null;
};

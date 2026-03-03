import { createHmac } from "crypto";
import { Request } from "express";
import { getJwtSecret, normalizeUserAgent } from "./security";

const readCookie = (req: Request, name: string) => {
  const cookies = (req as any).cookies as Record<string, string> | undefined;
  const value = String(cookies?.[name] || "").trim();
  return value || "";
};

const getFingerprintSecret = () =>
  String(process.env.SCAN_FINGERPRINT_SECRET || "").trim() ||
  String(process.env.TOKEN_HASH_SECRET || "").trim() ||
  getJwtSecret();

export const deriveRequestDeviceFingerprint = (
  req: Request,
  options?: { allowClientHint?: boolean }
) => {
  const allowClientHint = options?.allowClientHint !== false;
  const clientHint = allowClientHint
    ? String(req.get("x-device-fp") || "").trim().slice(0, 128)
    : "";
  const deviceClaimCookie = readCookie(req, "gs_device_claim");
  const anonDeviceCookie = readCookie(req, "aq_vid");
  const userAgent = normalizeUserAgent(req.get("user-agent") || null) || "";
  const ip = String(req.ip || "").trim();
  const input = [ip, userAgent, deviceClaimCookie, anonDeviceCookie, clientHint].join("|");
  return createHmac("sha256", getFingerprintSecret()).update(input).digest("hex");
};

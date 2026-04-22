import { createHmac } from "crypto";
import { Request } from "express";
import { getJwtSecret, normalizeUserAgent } from "./security";
import { normalizeClientIp } from "./ipAddress";
import { readCookie } from "./cookies";

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
  const ip = normalizeClientIp(req.ip || req.socket?.remoteAddress || "");
  const input = [ip, userAgent, deviceClaimCookie, anonDeviceCookie, clientHint].join("|");
  return createHmac("sha256", getFingerprintSecret()).update(input).digest("hex");
};

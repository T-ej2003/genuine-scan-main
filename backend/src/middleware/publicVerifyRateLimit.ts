import { createHash } from "crypto";
import { Request } from "express";

export type PublicVerifyRateLimitScope = "verify" | "scan";

const shortHash = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 16);

const normalizeString = (value: unknown, max = 180) => String(value || "").trim().slice(0, max);

const readBearerToken = (req: Request) => {
  const header = normalizeString(req.get("authorization"), 4096);
  if (!header.toLowerCase().startsWith("bearer ")) return "";
  return normalizeString(header.slice(7), 2048);
};

const readDeviceId = (req: Request) => {
  const value = Array.isArray(req.query?.device) ? req.query.device[0] : req.query?.device;
  return normalizeString(value, 256);
};

const readResourceKey = (req: Request, scope: PublicVerifyRateLimitScope) => {
  if (scope === "verify") {
    const code = normalizeString(req.params?.code, 128).toUpperCase();
    return code ? `code:${code}` : "code:unknown";
  }

  const token = normalizeString(Array.isArray(req.query?.t) ? req.query.t[0] : req.query?.t, 2048);
  return token ? `token:${shortHash(token)}` : "token:unknown";
};

const readActorKey = (req: Request) => {
  const bearerToken = readBearerToken(req);
  if (bearerToken) return `cust:${shortHash(bearerToken)}`;

  const deviceId = readDeviceId(req);
  if (deviceId) return `device:${shortHash(deviceId)}`;

  const ip = normalizeString(req.ip || req.socket?.remoteAddress || "unknown", 256).toLowerCase();
  return `ip:${shortHash(ip)}`;
};

export const buildPublicVerifyRateLimitKey = (req: Request, scope: PublicVerifyRateLimitScope) => {
  return `public:${scope}:${readResourceKey(req, scope)}:${readActorKey(req)}`;
};

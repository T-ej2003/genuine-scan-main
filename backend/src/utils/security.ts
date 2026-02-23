import { createHmac, randomBytes } from "crypto";

const must = (key: string) => {
  const v = String(process.env[key] || "").trim();
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
};

export const getJwtSecret = () => must("JWT_SECRET");

const getHashSecret = () => String(process.env.IP_HASH_SALT || "").trim() || getJwtSecret();

const getTokenHashSecret = () =>
  String(process.env.TOKEN_HASH_SECRET || "").trim() || String(process.env.JWT_SECRET || "").trim() || getHashSecret();

export const hmacSha256Hex = (value: string, secret: string) =>
  createHmac("sha256", secret).update(value).digest("hex");

export const hashIp = (ip: string | null | undefined) => {
  const v = String(ip || "").trim();
  if (!v) return null;
  return hmacSha256Hex(v, getHashSecret());
};

export const normalizeUserAgent = (ua: string | null | undefined) => {
  const v = String(ua || "").trim();
  if (!v) return null;
  // Avoid over-collecting; keep a reasonable cap.
  return v.slice(0, 300);
};

export const hashToken = (token: string) => {
  const v = String(token || "").trim();
  if (!v) throw new Error("Token is required");
  return hmacSha256Hex(v, getTokenHashSecret());
};

export const randomOpaqueToken = (bytes = 32) => randomBytes(bytes).toString("base64url");


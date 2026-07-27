import { createHmac, randomBytes } from "crypto";
import {
  getIpHashSecretSet,
  getJwtSecretSet,
  getTokenHashSecretSet,
  type SecretVersion,
} from "./secretConfig";
import { normalizeClientIp } from "./ipAddress";

const must = (key: string) => {
  const v = String(process.env[key] || "").trim();
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
};

const fingerprintWithVersion = (opaqueValue: string, version: SecretVersion) =>
  `${version.id}:${hmacSha256Hex(opaqueValue, version.value)}`;

const legacyFingerprint = (opaqueValue: string, legacyKeys: string[]) => {
  for (const key of legacyKeys) {
    const secret = String(process.env[key] || "").trim();
    if (secret) return hmacSha256Hex(opaqueValue, secret);
  }
  return "";
};

const legacyJwtSecret = () => {
  const legacy = String(process.env.JWT_SECRET || "").trim();
  return legacy || must("JWT_SECRET");
};

export const getJwtSecret = () => getJwtSecretSet().current.value;
export const getJwtSecretId = () => getJwtSecretSet().current.id;
export const getJwtSecretVersions = () => getJwtSecretSet().all;

export const buildHmacHashCandidates = (
  opaqueValue: string,
  resolver: () => { current: SecretVersion; previous: SecretVersion | null; all: SecretVersion[] },
  legacyKeys: string[] = []
) => {
  const normalized = String(opaqueValue || "").trim();
  if (!normalized) return [];

  const versions = resolver();
  const candidates = versions.all.map((version) => fingerprintWithVersion(normalized, version));
  const legacy = legacyFingerprint(normalized, legacyKeys);
  if (legacy) candidates.push(legacy);
  return Array.from(new Set(candidates));
};

export const matchesVersionedHmacHash = (
  opaqueValue: string,
  storedHash: string | null | undefined,
  resolver: () => { current: SecretVersion; previous: SecretVersion | null; all: SecretVersion[] },
  legacyKeys: string[] = []
) => {
  const normalizedStored = String(storedHash || "").trim();
  if (!normalizedStored) return false;
  return buildHmacHashCandidates(opaqueValue, resolver, legacyKeys).includes(normalizedStored);
};

/**
 * Keyed fingerprint for opaque tokens and operational metadata.
 * Passwords and MFA backup codes use their dedicated slow-hash services.
 */
export const hmacSha256Hex = (message: string, key: string) =>
  createHmac("sha256", key).update(message).digest("hex");

export const hashIp = (ip: string | null | undefined) => {
  const v = normalizeClientIp(ip);
  if (!v) return null;
  return fingerprintWithVersion(v, getIpHashSecretSet().current);
};

export const normalizeUserAgent = (ua: string | null | undefined) => {
  const v = String(ua || "").trim();
  if (!v) return null;
  // Avoid over-collecting; keep a reasonable cap.
  return v.slice(0, 300);
};

export const hashToken = (opaqueToken: string) => {
  const v = String(opaqueToken || "").trim();
  if (!v) throw new Error("Token is required");
  return fingerprintWithVersion(v, getTokenHashSecretSet().current);
};

export const randomOpaqueToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

export const buildTokenHashCandidates = (token: string) =>
  buildHmacHashCandidates(token, getTokenHashSecretSet, ["TOKEN_HASH_SECRET", "IP_HASH_SALT", "JWT_SECRET"]);

export const matchesHashedToken = (token: string, storedHash: string | null | undefined) =>
  matchesVersionedHmacHash(token, storedHash, getTokenHashSecretSet, ["TOKEN_HASH_SECRET", "IP_HASH_SALT", "JWT_SECRET"]);

export const buildIpHashCandidates = (ip: string) =>
  buildHmacHashCandidates(normalizeClientIp(ip), getIpHashSecretSet, ["IP_HASH_SALT", "JWT_SECRET"]);

export const verifyJwtWithCurrentOrPrevious = <T>(token: string, verify: (secret: string) => T) => {
  const versions = getJwtSecretVersions();
  let lastError: unknown = null;

  for (const version of versions) {
    try {
      return verify(version.value);
    } catch (error) {
      lastError = error;
    }
  }

  const legacy = legacyJwtSecret();
  for (const version of versions) {
    if (version.value === legacy) {
      throw lastError instanceof Error ? lastError : new Error("Invalid token");
    }
  }

  return verify(legacy);
};

export const getSecretVersionId = (resolver: () => { current: SecretVersion }) => resolver().current.id;

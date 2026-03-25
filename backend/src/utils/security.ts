import { createHmac, randomBytes } from "crypto";
import {
  getIpHashSecretSet,
  getJwtSecretSet,
  getTokenHashSecretSet,
  type SecretVersion,
} from "./secretConfig";

const must = (key: string) => {
  const v = String(process.env[key] || "").trim();
  if (!v) throw new Error(`Missing required env var: ${key}`);
  return v;
};

const hashWithVersion = (value: string, version: SecretVersion) => `${version.id}:${hmacSha256Hex(value, version.value)}`;

const legacyHash = (value: string, legacyKeys: string[]) => {
  for (const key of legacyKeys) {
    const secret = String(process.env[key] || "").trim();
    if (secret) return hmacSha256Hex(value, secret);
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
  value: string,
  resolver: () => { current: SecretVersion; previous: SecretVersion | null; all: SecretVersion[] },
  legacyKeys: string[] = []
) => {
  const normalized = String(value || "").trim();
  if (!normalized) return [];

  const versions = resolver();
  const candidates = versions.all.map((version) => hashWithVersion(normalized, version));
  const legacy = legacyHash(normalized, legacyKeys);
  if (legacy) candidates.push(legacy);
  return Array.from(new Set(candidates));
};

export const matchesVersionedHmacHash = (
  value: string,
  storedHash: string | null | undefined,
  resolver: () => { current: SecretVersion; previous: SecretVersion | null; all: SecretVersion[] },
  legacyKeys: string[] = []
) => {
  const normalizedStored = String(storedHash || "").trim();
  if (!normalizedStored) return false;
  return buildHmacHashCandidates(value, resolver, legacyKeys).includes(normalizedStored);
};

export const hmacSha256Hex = (value: string, secret: string) =>
  createHmac("sha256", secret).update(value).digest("hex");

export const hashIp = (ip: string | null | undefined) => {
  const v = String(ip || "").trim();
  if (!v) return null;
  return hashWithVersion(v, getIpHashSecretSet().current);
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
  return hashWithVersion(v, getTokenHashSecretSet().current);
};

export const randomOpaqueToken = (bytes = 32) => randomBytes(bytes).toString("base64url");

export const buildTokenHashCandidates = (token: string) =>
  buildHmacHashCandidates(token, getTokenHashSecretSet, ["TOKEN_HASH_SECRET", "IP_HASH_SALT", "JWT_SECRET"]);

export const matchesHashedToken = (token: string, storedHash: string | null | undefined) =>
  matchesVersionedHmacHash(token, storedHash, getTokenHashSecretSet, ["TOKEN_HASH_SECRET", "IP_HASH_SALT", "JWT_SECRET"]);

export const buildIpHashCandidates = (ip: string) =>
  buildHmacHashCandidates(ip, getIpHashSecretSet, ["IP_HASH_SALT", "JWT_SECRET"]);

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

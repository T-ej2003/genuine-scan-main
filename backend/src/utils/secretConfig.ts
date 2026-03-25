import { createHash } from "crypto";

export type SecretVersion = {
  id: string;
  value: string;
  source: string;
};

const readSecret = (key: string) => String(process.env[key] || "").trim();

const secretVersionId = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 12);

const uniqueById = (versions: SecretVersion[]) => {
  const seen = new Set<string>();
  const ordered: SecretVersion[] = [];
  for (const version of versions) {
    if (!version.value || seen.has(version.id)) continue;
    seen.add(version.id);
    ordered.push(version);
  }
  return ordered;
};

const readFirstConfiguredSecret = (keys: string[]) => {
  for (const key of keys) {
    const value = readSecret(key);
    if (value) return value;
  }
  return "";
};

const toSecretVersion = (source: string, value: string): SecretVersion | null => {
  const trimmed = String(value || "").trim();
  if (!trimmed) return null;
  return {
    id: secretVersionId(trimmed),
    value: trimmed,
    source,
  };
};

export const hasConfiguredSecret = (key: string) => Boolean(readSecret(key));

export const usesLegacySecretFallback = (primaryKey: string, fallbackKeys: string[] = []) =>
  !hasConfiguredSecret(primaryKey) && fallbackKeys.some((key) => hasConfiguredSecret(key));

export const getRequiredSecret = (primaryKey: string, fallbackKeys: string[] = []) => {
  const value = readFirstConfiguredSecret([primaryKey, ...fallbackKeys]);
  if (!value) {
    const acceptedKeys = [primaryKey, ...fallbackKeys].join(" or ");
    throw new Error(`Missing required env var: ${acceptedKeys}`);
  }
  return value;
};

export const getCurrentAndPreviousSecrets = (params: {
  currentKeys: string[];
  previousKeys?: string[];
  legacyFallbackKeys?: string[];
}) => {
  const current =
    params.currentKeys
      .map((key) => toSecretVersion(key, readSecret(key)))
      .find(Boolean) ||
    params.legacyFallbackKeys
      ?.map((key) => toSecretVersion(key, readSecret(key)))
      .find(Boolean) ||
    null;

  if (!current) {
    const acceptedKeys = [...params.currentKeys, ...(params.legacyFallbackKeys || [])].join(" or ");
    throw new Error(`Missing required env var: ${acceptedKeys}`);
  }

  const previous = (params.previousKeys || [])
    .map((key) => toSecretVersion(key, readSecret(key)))
    .find((entry) => Boolean(entry && entry.id !== current.id)) || null;

  return {
    current,
    previous,
    all: uniqueById([current, ...(previous ? [previous] : [])]),
  };
};

export const getJwtSecretSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["JWT_SECRET_CURRENT"],
    previousKeys: ["JWT_SECRET_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET"],
  });

export const getTokenHashSecretSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["TOKEN_HASH_SECRET_CURRENT", "TOKEN_HASH_SECRET"],
    previousKeys: ["TOKEN_HASH_SECRET_PREVIOUS", "IP_HASH_SALT_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET", "IP_HASH_SALT"],
  });

export const getIpHashSecretSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["IP_HASH_SALT_CURRENT", "IP_HASH_SALT"],
    previousKeys: ["IP_HASH_SALT_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET"],
  });

export const getIncidentHashSaltSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["INCIDENT_HASH_SALT_CURRENT", "INCIDENT_HASH_SALT"],
    previousKeys: ["INCIDENT_HASH_SALT_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET"],
  });

export const getPrinterSseSignSecretSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["PRINTER_SSE_SIGN_SECRET_CURRENT", "PRINTER_SSE_SIGN_SECRET"],
    previousKeys: ["PRINTER_SSE_SIGN_SECRET_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET"],
  });

export const getQrSigningHmacSecretSet = () =>
  getCurrentAndPreviousSecrets({
    currentKeys: ["QR_SIGN_HMAC_SECRET_CURRENT", "QR_SIGN_HMAC_SECRET"],
    previousKeys: ["QR_SIGN_HMAC_SECRET_PREVIOUS"],
    legacyFallbackKeys: ["JWT_SECRET"],
  });

export const getQrSigningHmacSecret = () => getQrSigningHmacSecretSet().current.value;
export const getIncidentHashSalt = () => getIncidentHashSaltSet().current.value;
export const getPrinterSseSignSecret = () => getPrinterSseSignSecretSet().current.value;

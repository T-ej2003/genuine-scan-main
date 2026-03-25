const readSecret = (key: string) => String(process.env[key] || "").trim();

const readFirstConfiguredSecret = (keys: string[]) => {
  for (const key of keys) {
    const value = readSecret(key);
    if (value) return value;
  }
  return "";
};

export const hasConfiguredSecret = (key: string) => Boolean(readSecret(key));

export const usesLegacySecretFallback = (primaryKey: string, fallbackKeys: string[] = []) =>
  !hasConfiguredSecret(primaryKey) && fallbackKeys.some((key) => hasConfiguredSecret(key));

// Centralize secret lookup so runtime services stop carrying their own fallback strings.
export const getRequiredSecret = (primaryKey: string, fallbackKeys: string[] = []) => {
  const value = readFirstConfiguredSecret([primaryKey, ...fallbackKeys]);
  if (!value) {
    const acceptedKeys = [primaryKey, ...fallbackKeys].join(" or ");
    throw new Error(`Missing required env var: ${acceptedKeys}`);
  }
  return value;
};

export const getQrSigningHmacSecret = () => getRequiredSecret("QR_SIGN_HMAC_SECRET", ["JWT_SECRET"]);
export const getIncidentHashSalt = () => getRequiredSecret("INCIDENT_HASH_SALT", ["JWT_SECRET"]);
export const getPrinterSseSignSecret = () => getRequiredSecret("PRINTER_SSE_SIGN_SECRET", ["JWT_SECRET"]);

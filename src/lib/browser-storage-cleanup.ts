export const DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS = [
  "__3g4_session_id",
  "_3g4_session_id",
  "auth_token",
  "auth_user",
  "authenticqr-theme",
  "authenticqr_verify_customer_email",
  "authenticqr_verify_customer_token",
  "loglevel",
  "mscqr_verify_customer_email",
  "mscqr_verify_customer_token",
  "mscqr_verify_last_geo",
  "qr_public_base_url",
] as const;

export type BrowserStorageCleanupResult = {
  removedLocalStorageKeys: string[];
};

export const cleanupDangerousLegacyBrowserStorage = (): BrowserStorageCleanupResult => {
  const removedLocalStorageKeys: string[] = [];

  if (typeof window === "undefined" || !window.localStorage) {
    return { removedLocalStorageKeys };
  }

  for (const key of DANGEROUS_LEGACY_LOCAL_STORAGE_KEYS) {
    try {
      if (window.localStorage.getItem(key) == null) continue;
      window.localStorage.removeItem(key);
      removedLocalStorageKeys.push(key);
    } catch {
      // Storage cleanup must never block app boot.
    }
  }

  return { removedLocalStorageKeys };
};

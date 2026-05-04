export type ConsentCategory = "strictly_necessary" | "functional" | "analytics" | "marketing";

export type ConsentState = {
  version: 1;
  updatedAt: string;
  categories: {
    functional: boolean;
    analytics: boolean;
    marketing: boolean;
  };
};

type OptionalConsentCategory = Exclude<ConsentCategory, "strictly_necessary">;

type CookieOptions = {
  path?: string;
  maxAgeSeconds?: number;
  sameSite?: "Lax" | "Strict" | "None";
  secure?: boolean;
};

export const CONSENT_STORAGE_KEY = "mscqr_cookie_consent_state:v1";
const LEGACY_CONSENT_STORAGE_KEY = "mscqr_cookie_consent_choice:v1";
export const CONSENT_CHANGED_EVENT = "mscqr:consent-changed";

const optionalCategories: OptionalConsentCategory[] = ["functional", "analytics", "marketing"];

const functionalLocalStorageExactKeys = ["aq_missing_help_requests", "theme"] as const;
const functionalLocalStoragePrefixes = ["manufacturer-printer-onboarding:", "printer-calibration:"] as const;
const functionalSessionStoragePrefixes = ["manufacturer-printer-dialog-opened:"] as const;
const functionalCookieNames = ["sidebar:state"] as const;

const emptyConsentState = (): ConsentState => ({
  version: 1,
  updatedAt: new Date(0).toISOString(),
  categories: {
    functional: false,
    analytics: false,
    marketing: false,
  },
});

const getLocalStorage = () => {
  if (typeof window === "undefined") return null;
  try {
    return window.localStorage || null;
  } catch {
    return null;
  }
};

const getSessionStorage = () => {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage || null;
  } catch {
    return null;
  }
};

const normalizeConsentState = (value: unknown): ConsentState | null => {
  if (!value || typeof value !== "object") return null;
  const raw = value as Partial<ConsentState>;
  const categories = raw.categories;
  if (!categories || typeof categories !== "object") return null;
  return {
    version: 1,
    updatedAt: typeof raw.updatedAt === "string" && raw.updatedAt ? raw.updatedAt : new Date().toISOString(),
    categories: {
      functional: Boolean(categories.functional),
      analytics: Boolean(categories.analytics),
      marketing: Boolean(categories.marketing),
    },
  };
};

const readLegacyConsentState = (): ConsentState | null => {
  const storage = getLocalStorage();
  if (!storage) return null;
  try {
    const raw = String(storage.getItem(LEGACY_CONSENT_STORAGE_KEY) || "").trim();
    if (raw === "accepted") {
      return {
        version: 1,
        updatedAt: new Date().toISOString(),
        categories: { functional: true, analytics: true, marketing: true },
      };
    }
    if (raw === "essential_only") {
      return {
        version: 1,
        updatedAt: new Date().toISOString(),
        categories: { functional: false, analytics: false, marketing: false },
      };
    }
  } catch {
    return null;
  }
  return null;
};

export const readConsentState = (): ConsentState => {
  const storage = getLocalStorage();
  if (!storage) return emptyConsentState();
  try {
    const raw = storage.getItem(CONSENT_STORAGE_KEY);
    if (raw) {
      const parsed = normalizeConsentState(JSON.parse(raw));
      if (parsed) return parsed;
    }

    const legacy = readLegacyConsentState();
    if (legacy) {
      storage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(legacy));
      storage.removeItem(LEGACY_CONSENT_STORAGE_KEY);
      return legacy;
    }
  } catch {
    return emptyConsentState();
  }
  return emptyConsentState();
};

export const hasStoredConsentChoice = () => {
  const storage = getLocalStorage();
  if (!storage) return false;
  try {
    return Boolean(storage.getItem(CONSENT_STORAGE_KEY) || storage.getItem(LEGACY_CONSENT_STORAGE_KEY));
  } catch {
    return false;
  }
};

export const hasConsent = (category: ConsentCategory) => {
  if (category === "strictly_necessary") return true;
  return readConsentState().categories[category];
};

export const cleanupNonEssentialBrowserState = (state = readConsentState()) => {
  if (typeof window !== "undefined" && !state.categories.functional) {
    const localStorage = getLocalStorage();
    try {
      if (localStorage) {
        for (const key of functionalLocalStorageExactKeys) {
          localStorage.removeItem(key);
        }
        for (let i = localStorage.length - 1; i >= 0; i -= 1) {
          const key = localStorage.key(i);
          if (!key) continue;
          if (functionalLocalStoragePrefixes.some((prefix) => key.startsWith(prefix))) {
            localStorage.removeItem(key);
          }
        }
      }
    } catch {
      // Best-effort cleanup only.
    }

    const sessionStorage = getSessionStorage();
    try {
      if (sessionStorage) {
        for (let i = sessionStorage.length - 1; i >= 0; i -= 1) {
          const key = sessionStorage.key(i);
          if (!key) continue;
          if (functionalSessionStoragePrefixes.some((prefix) => key.startsWith(prefix))) {
            sessionStorage.removeItem(key);
          }
        }
      }
    } catch {
      // Best-effort cleanup only.
    }

    for (const name of functionalCookieNames) {
      deleteCookie(name);
    }
  }
};

export const writeConsentState = (categories: ConsentState["categories"]) => {
  const state: ConsentState = {
    version: 1,
    updatedAt: new Date().toISOString(),
    categories: {
      functional: Boolean(categories.functional),
      analytics: Boolean(categories.analytics),
      marketing: Boolean(categories.marketing),
    },
  };

  const storage = getLocalStorage();
  if (storage) {
    try {
      storage.setItem(CONSENT_STORAGE_KEY, JSON.stringify(state));
      storage.removeItem(LEGACY_CONSENT_STORAGE_KEY);
    } catch {
      // If storage is unavailable, keep runtime behavior fail-closed for optional categories.
    }
  }

  cleanupNonEssentialBrowserState(state);

  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent(CONSENT_CHANGED_EVENT, { detail: state }));
  }

  return state;
};

export const grantAllConsent = () =>
  writeConsentState({
    functional: true,
    analytics: true,
    marketing: true,
  });

export const setEssentialOnlyConsent = () =>
  writeConsentState({
    functional: false,
    analytics: false,
    marketing: false,
  });

export const updateConsentCategory = (category: OptionalConsentCategory, enabled: boolean) => {
  const current = readConsentState();
  return writeConsentState({
    ...current.categories,
    [category]: enabled,
  });
};

export const canActivateOptionalCategory = (category: OptionalConsentCategory) => hasConsent(category);

export const getOptionalLocalStorageItem = (category: OptionalConsentCategory, key: string) => {
  const storage = getLocalStorage();
  if (!hasConsent(category) || !storage) return null;
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
};

export const setOptionalLocalStorageItem = (category: OptionalConsentCategory, key: string, value: string) => {
  const storage = getLocalStorage();
  if (!hasConsent(category) || !storage) return false;
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
};

export const removeOptionalLocalStorageItem = (key: string) => {
  const storage = getLocalStorage();
  if (!storage) return;
  try {
    storage.removeItem(key);
  } catch {
    // Ignore storage errors.
  }
};

export const getOptionalSessionStorageItem = (category: OptionalConsentCategory, key: string) => {
  const storage = getSessionStorage();
  if (!hasConsent(category) || !storage) return null;
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
};

export const setOptionalSessionStorageItem = (category: OptionalConsentCategory, key: string, value: string) => {
  const storage = getSessionStorage();
  if (!hasConsent(category) || !storage) return false;
  try {
    storage.setItem(key, value);
    return true;
  } catch {
    return false;
  }
};

export const removeOptionalSessionStorageItem = (key: string) => {
  const storage = getSessionStorage();
  if (!storage) return;
  try {
    storage.removeItem(key);
  } catch {
    // Ignore storage errors.
  }
};

export const setOptionalCookie = (category: OptionalConsentCategory, name: string, value: string, options: CookieOptions = {}) => {
  if (!hasConsent(category) || typeof document === "undefined") {
    deleteCookie(name, options.path);
    return false;
  }

  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${options.path || "/"}`,
    `SameSite=${options.sameSite || "Lax"}`,
  ];
  if (typeof options.maxAgeSeconds === "number") parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`);
  if (options.secure ?? (typeof window !== "undefined" && window.location.protocol === "https:")) parts.push("Secure");

  document.cookie = parts.join("; ");
  return true;
};

export function deleteCookie(name: string, path = "/") {
  if (typeof document === "undefined") return;
  const secure = typeof window !== "undefined" && window.location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `${name}=; Max-Age=0; Path=${path}; SameSite=Lax${secure}`;
}

export const consentCategories = {
  optional: optionalCategories,
  all: ["strictly_necessary", ...optionalCategories] as ConsentCategory[],
};

export type AdminMfaStatus = {
  required: boolean;
  sessionStage: "ACTIVE" | "MFA_BOOTSTRAP";
  enrolled: boolean;
  enabled: boolean;
  totpEnabled?: boolean;
  hasWebAuthn?: boolean;
  methods?: Array<"TOTP" | "WEBAUTHN">;
  preferredMethod?: "TOTP" | "WEBAUTHN" | null;
  backupCodesRemaining?: number;
  verifiedAt?: string | null;
  lastUsedAt?: string | null;
  webauthnCredentials?: Array<{
    id: string;
    label: string;
    transports?: string[];
    lastUsedAt?: string | null;
  }>;
};

export type ActiveSessionItem = {
  id: string;
  current: boolean;
  createdAt: string;
  lastUsedAt?: string | null;
  expiresAt: string;
  authenticatedAt?: string | null;
  mfaVerifiedAt?: string | null;
  userAgent?: string | null;
  ipHash?: string | null;
  security: {
    riskScore: number;
    riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
    riskReasons: string[];
    internalIpReputation: "trusted" | "new" | "elevated" | "high_risk" | "unknown";
    possibleImpossibleTravel: boolean;
    possibleImpossibleTravelReason?: string | null;
  };
};

export type BrowserStorageSummary = {
  cookieNames: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
};

export type SessionSecuritySummary = {
  highestRiskScore: number;
  highestRiskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  highRiskSessionCount: number;
  elevatedRiskSessionCount: number;
  distinctIpHashes24h: number;
  possibleImpossibleTravel: boolean;
  internalIpReputation: "trusted" | "new" | "elevated" | "high_risk" | "unknown";
};

export const STORAGE_RISK_KEYS = [
  "auth_token",
  "auth_user",
  "mscqr_verify_customer_token",
  "authenticqr_verify_customer_token",
  "_3g4_session_id",
  "authenticqr-theme",
  "loglevel",
  "qr_public_base_url",
];

export const readBrowserStorageSummary = (): BrowserStorageSummary => {
  if (typeof window === "undefined") {
    return { cookieNames: [], localStorageKeys: [], sessionStorageKeys: [] };
  }

  const readKeys = (storage: Storage) => {
    try {
      return Array.from({ length: storage.length }, (_, index) => storage.key(index)).filter(Boolean) as string[];
    } catch {
      return [];
    }
  };

  const cookieNames = String(document.cookie || "")
    .split(";")
    .map((entry) => entry.trim().split("=")[0])
    .filter(Boolean);

  return {
    cookieNames,
    localStorageKeys: readKeys(window.localStorage),
    sessionStorageKeys: readKeys(window.sessionStorage),
  };
};

export const RISK_BADGE_CLASSNAME: Record<ActiveSessionItem["security"]["riskLevel"], string> = {
  LOW: "border-emerald-200 bg-emerald-50 text-emerald-800",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-900",
  HIGH: "border-orange-200 bg-orange-50 text-orange-900",
  CRITICAL: "border-red-200 bg-red-50 text-red-900",
};

export const IP_REPUTATION_BADGE_CLASSNAME: Record<ActiveSessionItem["security"]["internalIpReputation"], string> = {
  trusted: "border-emerald-200 bg-emerald-50 text-emerald-800",
  new: "border-sky-200 bg-sky-50 text-sky-800",
  elevated: "border-amber-200 bg-amber-50 text-amber-900",
  high_risk: "border-red-200 bg-red-50 text-red-900",
  unknown: "border-slate-200 bg-slate-50 text-slate-700",
};

export const formatRiskLevel = (value: ActiveSessionItem["security"]["riskLevel"]) => {
  if (value === "CRITICAL") return "Critical risk";
  if (value === "HIGH") return "High risk";
  if (value === "MEDIUM") return "Elevated risk";
  return "Low risk";
};

export const formatIpReputation = (value: ActiveSessionItem["security"]["internalIpReputation"]) => {
  if (value === "high_risk") return "Network check: high risk";
  if (value === "elevated") return "Network check: elevated";
  if (value === "trusted") return "Network check: trusted";
  if (value === "new") return "Network check: new";
  return "Network check: unknown";
};

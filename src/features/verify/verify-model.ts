import apiClient from "@/lib/api-client";

export type VerificationClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE";

export type OwnershipStatus = {
  isClaimed: boolean;
  claimedAt: string | null;
  isOwnedByRequester: boolean;
  isClaimedByAnother: boolean;
  canClaim: boolean;
  state?: "unclaimed" | "owned_by_you" | "owned_by_someone_else" | "claim_not_available";
  matchMethod?: "user" | "device_token" | null;
};

export type VerificationProofSource = "SIGNED_LABEL" | "MANUAL_CODE_LOOKUP";

export type OwnershipTransferView = {
  state?:
    | "none"
    | "pending_owner_action"
    | "pending_buyer_action"
    | "ready_to_accept"
    | "accepted"
    | "cancelled"
    | "expired"
    | "invalid";
  active?: boolean;
  canCreate?: boolean;
  canCancel?: boolean;
  canAccept?: boolean;
  initiatedByYou?: boolean;
  recipientEmailMasked?: string | null;
  initiatedAt?: string | null;
  expiresAt?: string | null;
  acceptedAt?: string | null;
  invalidReason?: string | null;
  transferId?: string | null;
  acceptUrl?: string | null;
};

export type ScanSummary = {
  totalScans: number;
  firstVerifiedAt: string | null;
  latestVerifiedAt: string | null;
  firstVerifiedLocation?: string | null;
  latestVerifiedLocation?: string | null;
};

export type VerificationActivitySummary = {
  state?: "first_scan" | "trusted_repeat" | "mixed_repeat" | "external_activity" | "normal_repeat";
  summary?: string;
  trustedOwnerScanCount24h?: number;
  trustedOwnerScanCount10m?: number;
  untrustedScanCount24h?: number;
  untrustedScanCount10m?: number;
  distinctTrustedActorCount24h?: number;
  distinctUntrustedDeviceCount24h?: number;
  currentActorTrustedOwnerContext?: boolean;
};

export type VerifyPayload = {
  isAuthentic: boolean;
  message?: string;
  warningMessage?: string | null;
  proofSource?: VerificationProofSource;
  proof?: {
    title?: string;
    detail?: string;
  } | null;
  code?: string;
  status?: string;
  scanOutcome?: string;
  classification?: VerificationClassification;
  reasons?: string[];
  activitySummary?: VerificationActivitySummary | null;
  scanSummary?: ScanSummary;
  ownershipStatus?: OwnershipStatus;
  ownershipTransfer?: OwnershipTransferView | null;
  verificationTimeline?: {
    firstSeen?: string | null;
    latestSeen?: string | null;
    anomalyReason?: string | null;
    visualSignal?: "stable" | "warning" | "critical";
  } | null;
  riskExplanation?: {
    level?: "low" | "medium" | "elevated" | "high";
    title?: string;
    details?: string[];
    recommendedAction?: string;
  } | null;
  verifyUxPolicy?: {
    showTimelineCard?: boolean;
    showRiskCards?: boolean;
    allowOwnershipClaim?: boolean;
    allowFraudReport?: boolean;
    mobileCameraAssist?: boolean;
  } | null;
  isBlocked?: boolean;
  isReady?: boolean;
  totalScans?: number;
  firstVerifiedAt?: string | null;
  latestVerifiedAt?: string | null;
  isFirstScan?: boolean;
  scanCount?: number;
  firstScanAt?: string | null;
  firstScanLocation?: string | null;
  latestScanAt?: string | null;
  latestScanLocation?: string | null;
  previousScanAt?: string | null;
  previousScanLocation?: string | null;
  policy?: Record<string, unknown> | null;
  scanSignals?: {
    scanCount24h?: number;
    distinctDeviceCount24h?: number;
    recentScanCount10m?: number;
    distinctCountryCount24h?: number;
    seenOnCurrentDeviceBefore?: boolean;
    previousScanSameDevice?: boolean | null;
    currentActorTrustedOwnerContext?: boolean;
    seenByCurrentTrustedActorBefore?: boolean;
    previousScanSameTrustedActor?: boolean | null;
    trustedOwnerScanCount24h?: number;
    trustedOwnerScanCount10m?: number;
    untrustedScanCount24h?: number;
    untrustedScanCount10m?: number;
    distinctTrustedActorCount24h?: number;
    distinctUntrustedDeviceCount24h?: number;
    distinctUntrustedCountryCount24h?: number;
  } | null;
  licensee?: {
    id: string;
    name: string;
    prefix: string;
    brandName?: string | null;
    location?: string | null;
    website?: string | null;
    supportEmail?: string | null;
    supportPhone?: string | null;
  } | null;
  batch?: {
    id: string;
    name: string;
    printedAt?: string | null;
    manufacturer?: {
      id: string;
      name: string;
      email?: string | null;
      location?: string | null;
      website?: string | null;
    } | null;
  } | null;
};

export type VerifyRequestResponse =
  | Awaited<ReturnType<typeof apiClient.verifyQRCode>>
  | Awaited<ReturnType<typeof apiClient.scanToken>>;

export const DEFAULT_VERIFY_POLICY = {
  showTimelineCard: true,
  showRiskCards: true,
  allowOwnershipClaim: true,
  allowFraudReport: true,
  mobileCameraAssist: true,
};

export const INCIDENT_TYPE_OPTIONS = [
  { value: "counterfeit_suspected", label: "Counterfeit suspected" },
  { value: "duplicate_scan", label: "Duplicate scan" },
  { value: "tampered_label", label: "Tampered label" },
  { value: "wrong_product", label: "Wrong product" },
  { value: "other", label: "Other" },
] as const;

export const CUSTOMER_TOKEN_KEY = "mscqr_verify_customer_token";
export const LEGACY_CUSTOMER_TOKEN_KEY = "authenticqr_verify_customer_token";
export const CUSTOMER_EMAIL_KEY = "mscqr_verify_customer_email";
export const LEGACY_CUSTOMER_EMAIL_KEY = "authenticqr_verify_customer_email";
export const TRANSFER_TOKEN_KEY_PREFIX = "mscqr_verify_transfer_token:";
export const LEGACY_TRANSFER_TOKEN_KEY_PREFIX = "authenticqr_verify_transfer_token:";
export const APP_NAME = "MSCQR";
export const VERIFY_GEO_CACHE_KEY = "mscqr_verify_last_geo";
export const VERIFY_GEO_CACHE_MAX_AGE_MS = 1000 * 60 * 10;

export const DEFAULT_OWNERSHIP_STATUS: OwnershipStatus = {
  isClaimed: false,
  claimedAt: null,
  isOwnedByRequester: false,
  isClaimedByAnother: false,
  canClaim: false,
};

export const inferClassification = (result: VerifyPayload | null): VerificationClassification => {
  if (result?.classification) return result.classification;
  const status = String(result?.status || "").trim().toUpperCase();
  const scanOutcome = String(result?.scanOutcome || "").trim().toUpperCase();

  if (result?.isBlocked || status === "BLOCKED" || scanOutcome === "BLOCKED") return "BLOCKED_BY_SECURITY";
  if (result?.isReady === false || ["DORMANT", "ALLOCATED", "ACTIVATED"].includes(status) || scanOutcome === "NOT_READY") {
    return "NOT_READY_FOR_CUSTOMER_USE";
  }
  if (scanOutcome === "SUSPICIOUS_DUPLICATE") return "SUSPICIOUS_DUPLICATE";
  if (result?.isFirstScan || result?.scanCount === 1 || scanOutcome === "FIRST_SCAN") return "FIRST_SCAN";
  return "LEGIT_REPEAT";
};

export const deriveReasons = (result: VerifyPayload | null, classification: VerificationClassification): string[] => {
  if (Array.isArray(result?.reasons) && result.reasons.length > 0) return result.reasons;

  const signals = result?.scanSignals || {};
  switch (classification) {
    case "FIRST_SCAN":
      return ["This is the first customer-facing verification recorded for this code."];
    case "LEGIT_REPEAT":
      return [
        signals.seenByCurrentTrustedActorBefore || signals.previousScanSameTrustedActor
          ? "Repeat checks match the same trusted owner context."
          : "Verification history looks consistent with normal repeat checks.",
      ];
    case "SUSPICIOUS_DUPLICATE":
      return [
        "Recent scan activity does not match the expected ownership pattern.",
        signals.distinctUntrustedDeviceCount24h
          ? `${signals.distinctUntrustedDeviceCount24h} unfamiliar devices scanned this code in the last 24 hours.`
          : "Unexpected external devices scanned this code recently.",
      ];
    case "BLOCKED_BY_SECURITY":
      return ["Security rules blocked this code because scan activity exceeded allowed risk thresholds."];
    default:
      return ["This product is not ready for customer verification yet."];
  }
};

export const deriveScanSummary = (result: VerifyPayload | null): ScanSummary => ({
  totalScans: Number(result?.totalScans ?? result?.scanCount ?? 0),
  firstVerifiedAt: result?.scanSummary?.firstVerifiedAt || result?.firstVerifiedAt || result?.firstScanAt || null,
  latestVerifiedAt: result?.scanSummary?.latestVerifiedAt || result?.latestVerifiedAt || result?.latestScanAt || null,
  firstVerifiedLocation:
    result?.scanSummary?.firstVerifiedLocation || result?.firstScanLocation || result?.licensee?.location || null,
  latestVerifiedLocation:
    result?.scanSummary?.latestVerifiedLocation || result?.latestScanLocation || result?.licensee?.location || null,
});

export const formatDateTime = (value: string | null | undefined) => {
  if (!value) return "Not available";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not available";
  return date.toLocaleString();
};

export const toLabel = (value?: string | null) =>
  String(value || "")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (match) => match.toUpperCase());

export const normalizeVerifyCode = (value?: string | null) => String(value || "").trim().toUpperCase();

export const getTransferTokenStorageKey = (value?: string | null) => {
  const normalized = normalizeVerifyCode(value);
  return normalized ? `${TRANSFER_TOKEN_KEY_PREFIX}${normalized}` : "";
};

export const readStoredValue = (...keys: string[]) => {
  for (const key of keys) {
    try {
      const value = window.localStorage.getItem(key);
      if (value) return value;
    } catch {
      // Ignore storage issues.
    }
  }
  return "";
};

export const readCachedGeo = () => {
  try {
    const raw = window.localStorage.getItem(VERIFY_GEO_CACHE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as { lat?: number; lon?: number; acc?: number; at?: number };
    if (!parsed?.at || Date.now() - parsed.at > VERIFY_GEO_CACHE_MAX_AGE_MS) return {};
    return { lat: parsed.lat, lon: parsed.lon, acc: parsed.acc };
  } catch {
    return {};
  }
};

export const writeCachedGeo = (value: { lat?: number; lon?: number; acc?: number }) => {
  try {
    window.localStorage.setItem(
      VERIFY_GEO_CACHE_KEY,
      JSON.stringify({
        ...value,
        at: Date.now(),
      })
    );
  } catch {
    // Ignore storage issues.
  }
};

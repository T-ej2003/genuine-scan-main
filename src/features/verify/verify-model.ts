import apiClient from "@/lib/api-client";

export type VerificationClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE"
  | "NOT_FOUND";

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
export type VerificationProofTier = "SIGNED_LABEL" | "MANUAL_REGISTRY_LOOKUP" | "DEGRADED";
export type VerificationRiskBand = "LOW" | "ELEVATED" | "HIGH" | "CRITICAL";
export type VerificationReplacementStatus = "NONE" | "ACTIVE_REPLACEMENT" | "REPLACED_LABEL";
export type VerificationDegradationMode = "NORMAL" | "QUEUE_AND_RETRY" | "FAIL_CLOSED";
export type VerificationPublicOutcome =
  | "SIGNED_LABEL_ACTIVE"
  | "MANUAL_RECORD_FOUND"
  | "LIMITED_PROVENANCE"
  | "REVIEW_REQUIRED"
  | "BLOCKED"
  | "NOT_READY"
  | "NOT_FOUND"
  | "INTEGRITY_ERROR"
  | "PRINTER_SETUP_ONLY";
export type VerificationRiskDisposition = "CLEAR" | "MONITOR" | "REVIEW_REQUIRED" | "BLOCKED";
export type CustomerTrustLevel =
  | "ANONYMOUS"
  | "DEVICE_TRUSTED"
  | "ACCOUNT_TRUSTED"
  | "PASSKEY_VERIFIED"
  | "OPERATOR_REVIEWED";

export type CustomerVerificationEntryMethod = "SIGNED_SCAN" | "MANUAL_CODE";
export type CustomerVerificationAuthState = "PENDING" | "VERIFIED";

export type CustomerTrustIntake = {
  purchaseChannel: "online" | "offline" | "gifted" | "unknown";
  sourceCategory?: "marketplace" | "direct_brand" | "retail_store" | "reseller" | "gift" | "unknown" | null;
  platformName?: string | null;
  sellerName?: string | null;
  listingUrl?: string | null;
  orderReference?: string | null;
  storeName?: string | null;
  purchaseCity?: string | null;
  purchaseCountry?: string | null;
  purchaseDate?: string | null;
  packagingState?: "sealed" | "opened" | "damaged" | "unsure" | null;
  packagingConcern?: "none" | "minor" | "major" | "unsure" | null;
  scanReason: "routine_check" | "new_seller" | "pricing_concern" | "packaging_concern" | "authenticity_concern";
  ownershipIntent: "verify_only" | "claim_ownership" | "report_concern" | "contact_support";
  notes?: string | null;
};

export type VerificationSessionSummary = {
  sessionId: string;
  decisionId: string;
  code?: string | null;
  maskedCode?: string | null;
  brandName?: string | null;
  entryMethod: CustomerVerificationEntryMethod;
  authState: CustomerVerificationAuthState;
  intakeCompleted: boolean;
  revealed: boolean;
  startedAt: string;
  revealAt?: string | null;
  proofTier?: VerificationProofTier | string | null;
  proofSource?: VerificationProofSource | string | null;
  labelState?: string | null;
  printTrustState?: string | null;
  challengeRequired?: boolean;
  challengeCompleted?: boolean;
  challengeCompletedBy?: string | null;
  verificationLocked?: boolean;
  proofBindingRequired?: boolean;
  proofBindingExpiresAt?: string | null;
  sessionProofToken?: string | null;
  intake?: CustomerTrustIntake | null;
  verification?: VerifyPayload | null;
};

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
  decisionId?: string | null;
  decisionVersion?: number;
  message?: string;
  warningMessage?: string | null;
  proofSource?: VerificationProofSource;
  proofTier?: VerificationProofTier;
  publicOutcome?: VerificationPublicOutcome | string | null;
  riskDisposition?: VerificationRiskDisposition | string | null;
  messageKey?: string | null;
  nextActionKey?: string | null;
  reasonCodes?: string[];
  riskBand?: VerificationRiskBand;
  replacementStatus?: VerificationReplacementStatus;
  degradationMode?: VerificationDegradationMode;
  customerTrustLevel?: CustomerTrustLevel;
  replacementChainId?: string | null;
  labelState?: string;
  printTrustState?: string;
  issuanceMode?: string | null;
  customerVerifiableAt?: string | null;
  latestDecisionOutcome?: string | null;
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
  challenge?: {
    required?: boolean;
    methods?: string[];
    reason?: string | null;
    completed?: boolean;
    completedBy?: string | null;
  } | null;
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
  const publicOutcome = String(result?.publicOutcome || "").trim().toUpperCase();

  if (publicOutcome === "NOT_FOUND" || scanOutcome === "NOT_FOUND") return "NOT_FOUND";
  if (publicOutcome === "REVIEW_REQUIRED") return "SUSPICIOUS_DUPLICATE";
  if (publicOutcome === "BLOCKED" || publicOutcome === "INTEGRITY_ERROR") return "BLOCKED_BY_SECURITY";
  if (publicOutcome === "NOT_READY") return "NOT_READY_FOR_CUSTOMER_USE";
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
  if (result?.messageKey === "manual_record_signed_history") {
    return [
      "MSCQR found the registry record for this code, but the label already has prior signed-label verification history.",
      "If the original label is available, re-scan it instead of relying on manual entry.",
    ];
  }
  if (result?.publicOutcome === "MANUAL_RECORD_FOUND") {
    return ["MSCQR found a live registry record for this code and confirmed its current lifecycle state."];
  }
  if (result?.publicOutcome === "LIMITED_PROVENANCE") {
    return ["MSCQR found a live signed-label record, but governed print provenance is not available for this label."];
  }
  switch (classification) {
    case "FIRST_SCAN":
      return ["This is the first customer-facing verification recorded for this code."];
    case "LEGIT_REPEAT":
      return [
        signals.seenByCurrentTrustedActorBefore || signals.previousScanSameTrustedActor
          ? "Repeat checks match the same trusted owner context."
          : "This code has been checked before, and the history looks consistent with normal repeat use.",
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
    case "NOT_FOUND":
      return ["MSCQR could not find a live registry record for this code."];
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

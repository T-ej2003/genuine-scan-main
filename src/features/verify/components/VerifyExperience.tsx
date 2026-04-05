import React, { startTransition, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AlertTriangle, Ban, Clock3, Loader2, Lock, SearchX, Shield, ShieldCheck, WifiOff } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { getOrCreateAnonDeviceId } from "@/lib/anon-device";
import { friendlyReferenceLabel } from "@/lib/friendly-reference";
import { getSupportStatusLabel, getVerificationCopy } from "@/lib/ui-copy";
import { cn } from "@/lib/utils";
import { PremiumScanLoader } from "@/components/premium/PremiumScanLoader";
import { PREMIUM_PALETTE } from "@/components/premium/palette";
import {
  VerificationConfidenceMeter,
  deriveVerificationConfidence,
} from "@/components/premium/VerificationConfidenceMeter";
import { VerifiedAuthenticStamp } from "@/components/premium/VerifiedAuthenticStamp";
import { PremiumSectionAccordion } from "@/components/premium/PremiumSectionAccordion";
import {
  isWebAuthnSupported,
  startWebAuthnAuthentication,
  startWebAuthnRegistration,
  type WebAuthnCredentialSummary,
} from "@/lib/webauthn";
import {
  APP_NAME,
  CUSTOMER_EMAIL_KEY,
  CUSTOMER_TOKEN_KEY,
  DEFAULT_OWNERSHIP_STATUS,
  DEFAULT_VERIFY_POLICY,
  INCIDENT_TYPE_OPTIONS,
  LEGACY_CUSTOMER_EMAIL_KEY,
  LEGACY_CUSTOMER_TOKEN_KEY,
  LEGACY_TRANSFER_TOKEN_KEY_PREFIX,
  deriveReasons,
  deriveScanSummary,
  formatDateTime,
  getTransferTokenStorageKey,
  inferClassification,
  normalizeVerifyCode,
  readCachedGeo,
  readStoredValue,
  toLabel,
  writeCachedGeo,
  type VerificationClassification,
  type VerificationProofSource,
  type VerifyPayload,
  type VerifyRequestResponse,
} from "@/features/verify/verify-model";

const CLASS_META: Record<
  VerificationClassification,
  {
    title: string;
    subtitle: string;
    badge: string;
    bannerClass: string;
    badgeClass: string;
    icon: React.ReactNode;
  }
> = {
  FIRST_SCAN: {
    title: "Verified Authentic",
    subtitle: "First customer verification completed successfully.",
    badge: "Authentic",
    bannerClass: "border border-emerald-600 bg-emerald-800 text-emerald-50 shadow-[0_12px_28px_rgba(6,78,59,0.25)]",
    badgeClass: "border-emerald-200/30 bg-emerald-50/15 text-emerald-50",
    icon: <ShieldCheck className="h-6 w-6" />,
  },
  LEGIT_REPEAT: {
    title: "Verified Again",
    subtitle: "Product is authentic and repeat verification signals are consistent.",
    badge: "Authentic",
    bannerClass: "border border-emerald-500/70 bg-emerald-700 text-emerald-50 shadow-[0_12px_28px_rgba(6,95,70,0.24)]",
    badgeClass: "border-emerald-200/30 bg-emerald-50/15 text-emerald-50",
    icon: <ShieldCheck className="h-6 w-6" />,
  },
  SUSPICIOUS_DUPLICATE: {
    title: "Suspicious Duplicate",
    subtitle: "Scan pattern requires additional authenticity checks.",
    badge: "Fraud Risk",
    bannerClass: "border border-amber-500/60 bg-amber-700 text-amber-50 shadow-[0_10px_24px_rgba(146,95,22,0.24)]",
    badgeClass: "border-amber-200/30 bg-amber-50/20 text-amber-50",
    icon: <AlertTriangle className="h-6 w-6" />,
  },
  BLOCKED_BY_SECURITY: {
    title: "Blocked by Security",
    subtitle: "Security controls currently block this code.",
    badge: "Blocked",
    bannerClass: "border border-rose-400/35 bg-rose-900 text-rose-50 shadow-[0_10px_24px_rgba(76,5,25,0.26)]",
    badgeClass: "border-rose-200/30 bg-rose-50/15 text-rose-50",
    icon: <Ban className="h-6 w-6" />,
  },
  NOT_READY_FOR_CUSTOMER_USE: {
    title: "Not Ready for Customer Use",
    subtitle: "Code lifecycle is incomplete or unavailable for customer verification.",
    badge: "Not Ready",
    bannerClass: "border border-slate-500 bg-slate-800 text-slate-50 shadow-[0_10px_24px_rgba(15,23,42,0.24)]",
    badgeClass: "border-slate-300/35 bg-slate-100/15 text-slate-50",
    icon: <SearchX className="h-6 w-6" />,
  },
};

const SkeletonBlock = ({ className }: { className?: string }) => (
  <div aria-hidden className={cn("premium-shimmer rounded-md bg-[#bccad6]/45", className)} />
);

export default function VerifyExperience() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { toast } = useToast();

  const token = searchParams.get("t")?.trim() || "";
  const transferToken = searchParams.get("transfer")?.trim() || "";
  const codeParam = (() => {
    const raw = String(code || "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return raw.trim();
    }
  })();
  const initialCustomerToken = readStoredValue(CUSTOMER_TOKEN_KEY, LEGACY_CUSTOMER_TOKEN_KEY);
  const initialCustomerEmail = readStoredValue(CUSTOMER_EMAIL_KEY, LEGACY_CUSTOMER_EMAIL_KEY);
  const initialPersistedTransferToken = transferToken
    ? ""
    : readStoredValue(
        getTransferTokenStorageKey(codeParam),
        normalizeVerifyCode(codeParam) ? `${LEGACY_TRANSFER_TOKEN_KEY_PREFIX}${normalizeVerifyCode(codeParam)}` : ""
      );

  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isOffline, setIsOffline] = useState<boolean>(() => !navigator.onLine);
  const [retryAttempt, setRetryAttempt] = useState(0);
  const [retryNotice, setRetryNotice] = useState<string>("");

  const [customerToken, setCustomerToken] = useState<string>(initialCustomerToken);
  const [customerEmail, setCustomerEmail] = useState<string>(initialCustomerEmail);

  const [otpEmail, setOtpEmail] = useState(initialCustomerEmail);
  const [otpChallengeToken, setOtpChallengeToken] = useState("");
  const [otpMaskedEmail, setOtpMaskedEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);
  const [passkeyCredentials, setPasskeyCredentials] = useState<WebAuthnCredentialSummary[]>([]);
  const [loadingPasskeys, setLoadingPasskeys] = useState(false);
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [assertingPasskey, setAssertingPasskey] = useState(false);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState("");

  const [claiming, setClaiming] = useState(false);
  const [linkingClaim, setLinkingClaim] = useState(false);
  const [claimConfirmOpen, setClaimConfirmOpen] = useState(false);
  const [transferOpen, setTransferOpen] = useState(false);
  const [transferRecipientEmail, setTransferRecipientEmail] = useState("");
  const [transferSubmitting, setTransferSubmitting] = useState(false);
  const [transferAccepting, setTransferAccepting] = useState(false);
  const [transferCancelling, setTransferCancelling] = useState(false);
  const [issuedTransferLink, setIssuedTransferLink] = useState<string | null>(null);
  const [persistedTransferToken, setPersistedTransferToken] = useState(initialPersistedTransferToken);
  const [queueTransferDialogAfterSignIn, setQueueTransferDialogAfterSignIn] = useState(false);

  const [reportOpen, setReportOpen] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reportReference, setReportReference] = useState<string | null>(null);
  const [reportSupportRef, setReportSupportRef] = useState<string | null>(null);
  const [reportSupportStatus, setReportSupportStatus] = useState<string | null>(null);
  const [reportSupportSla, setReportSupportSla] = useState<string | null>(null);
  const [reportTamperSummary, setReportTamperSummary] = useState<string | null>(null);
  const [trackReference, setTrackReference] = useState("");
  const [trackEmail, setTrackEmail] = useState("");
  const [trackingTicket, setTrackingTicket] = useState(false);
  const [trackedTicket, setTrackedTicket] = useState<{
    referenceCode?: string;
    status?: string;
    handoffStage?: string;
    sla?: { dueAt?: string; isBreached?: boolean; remainingMinutes?: number } | null;
  } | null>(null);
  const [reportType, setReportType] = useState<string>(INCIDENT_TYPE_OPTIONS[0].value);
  const [reportDescription, setReportDescription] = useState("");
  const [reportEmail, setReportEmail] = useState("");
  const [reportPhotos, setReportPhotos] = useState<File[]>([]);
  const [loadingStage, setLoadingStage] = useState<0 | 1>(0);

  const transferStorageKey = useMemo(() => getTransferTokenStorageKey(result?.code || codeParam), [codeParam, result?.code]);
  const legacyTransferStorageKey = useMemo(() => {
    const normalized = normalizeVerifyCode(result?.code || codeParam);
    return normalized ? `${LEGACY_TRANSFER_TOKEN_KEY_PREFIX}${normalized}` : "";
  }, [codeParam, result?.code]);
  const activeTransferToken = useMemo(
    () => transferToken || (customerToken ? persistedTransferToken : ""),
    [customerToken, persistedTransferToken, transferToken]
  );
  const requestKey = useMemo(() => {
    if (token) return `token:${token}|cust:${customerToken.slice(-10)}`;
    if (codeParam) return `code:${codeParam.toUpperCase()}|transfer:${activeTransferToken.slice(-10)}|cust:${customerToken.slice(-10)}`;
    return "";
  }, [activeTransferToken, codeParam, customerToken, token]);

  const deviceId = useMemo(() => getOrCreateAnonDeviceId(), []);
  const inFlightRef = useRef(new Map<string, Promise<VerifyRequestResponse>>());
  const verifyStartedAtRef = useRef<number>(0);
  const sentDroppedMetricRef = useRef(false);
  const protectionSignInRef = useRef<HTMLDivElement | null>(null);

  const displayedCode = result?.code || codeParam || "—";
  const classification = useMemo(() => inferClassification(result), [result]);
  const classMeta = CLASS_META[classification];
  const verificationCopy = useMemo(() => getVerificationCopy(classification), [classification]);
  const reasons = useMemo(() => deriveReasons(result, classification), [classification, result]);
  const scanSummary = useMemo(() => deriveScanSummary(result), [result]);
  const activitySummary = result?.activitySummary || null;
  const ownershipStatus = result?.ownershipStatus || DEFAULT_OWNERSHIP_STATUS;
  const ownershipTransfer = result?.ownershipTransfer || null;
  const verifyUxPolicy = { ...DEFAULT_VERIFY_POLICY, ...(result?.verifyUxPolicy || {}) };
  const shareableTransferLink = issuedTransferLink || ownershipTransfer?.acceptUrl || "";
  const showLinkClaim =
    Boolean(customerToken) && ownershipStatus.isOwnedByRequester && ownershipStatus.matchMethod && ownershipStatus.matchMethod !== "user";
  const transferLinkIsInvalid = ownershipTransfer?.state === "invalid";
  const showOwnerTransferSignInPrompt = ownershipStatus.isOwnedByRequester && !customerToken;
  const showRecipientTransferSignInPrompt = Boolean(transferToken) && !customerToken && !transferLinkIsInvalid;
  const signInCardTitle = showRecipientTransferSignInPrompt
      ? "Sign in to accept transfer"
    : queueTransferDialogAfterSignIn
      ? "Sign in to start transfer"
      : "Sign in for better protection (optional)";
  const signInCardDescription = showRecipientTransferSignInPrompt
    ? "Accepting a transfer links this product to your signed-in customer account."
    : queueTransferDialogAfterSignIn
      ? "Complete sign-in below. The transfer form will open automatically."
      : "Sign-in makes ownership portable across devices. Device-only claims stay on this browser and device until you sign in.";
  const showAuthenticStamp = classification === "FIRST_SCAN" || classification === "LEGIT_REPEAT";
  const confidenceScore = useMemo(
    () =>
      deriveVerificationConfidence({
        classification,
        totalScans: scanSummary.totalScans,
        distinctDeviceCount24h: result?.scanSignals?.distinctDeviceCount24h,
        recentScanCount10m: result?.scanSignals?.recentScanCount10m,
        distinctCountryCount24h: result?.scanSignals?.distinctCountryCount24h,
        distinctUntrustedDeviceCount24h: result?.scanSignals?.distinctUntrustedDeviceCount24h,
        untrustedScanCount10m: result?.scanSignals?.untrustedScanCount10m,
        trustedOwnerScanCount24h: result?.scanSignals?.trustedOwnerScanCount24h,
        warningMessage: result?.warningMessage || null,
      }),
    [
      classification,
      scanSummary.totalScans,
      result?.scanSignals?.distinctDeviceCount24h,
      result?.scanSignals?.recentScanCount10m,
      result?.scanSignals?.distinctCountryCount24h,
      result?.scanSignals?.distinctUntrustedDeviceCount24h,
      result?.scanSignals?.untrustedScanCount10m,
      result?.scanSignals?.trustedOwnerScanCount24h,
      result?.warningMessage,
    ]
  );
  const claimUnavailableReason =
    !verifyUxPolicy.allowOwnershipClaim
      ? "Ownership claim is currently disabled by brand policy."
      : classification === "BLOCKED_BY_SECURITY"
        ? "Claiming is unavailable while this code is blocked by security."
        : classification === "NOT_READY_FOR_CUSTOMER_USE"
          ? "Claiming starts once the product is ready for customer use."
          : "Claiming is currently unavailable.";
  const verificationTimeline = result?.verificationTimeline || {
    firstSeen: scanSummary.firstVerifiedAt,
    latestSeen: scanSummary.latestVerifiedAt,
    anomalyReason:
      classification === "SUSPICIOUS_DUPLICATE" || classification === "BLOCKED_BY_SECURITY" ? reasons[0] || null : null,
    visualSignal:
      classification === "FIRST_SCAN" || classification === "LEGIT_REPEAT"
        ? "stable"
        : classification === "SUSPICIOUS_DUPLICATE"
          ? "warning"
          : "critical",
  };
  const riskExplanation = result?.riskExplanation || {
    level: classification === "SUSPICIOUS_DUPLICATE" ? "elevated" : classification === "BLOCKED_BY_SECURITY" ? "high" : "low",
    title:
      classification === "SUSPICIOUS_DUPLICATE"
        ? activitySummary?.currentActorTrustedOwnerContext && Number(activitySummary?.untrustedScanCount24h ?? 0) > 0
          ? "External scan activity needs review"
          : "Duplicate risk indicators detected"
        : classification === "BLOCKED_BY_SECURITY"
          ? "Security controls blocked this code"
          : activitySummary?.state === "trusted_repeat"
            ? "Repeat checks match the same owner context"
          : "No high-risk anomaly detected",
    details: reasons,
    recommendedAction:
      classification === "SUSPICIOUS_DUPLICATE" || classification === "BLOCKED_BY_SECURITY"
        ? "Review purchase source and report suspicious activity."
        : activitySummary?.state === "trusted_repeat"
          ? "Normal re-checks are fine. Keep proof of purchase for future verification."
          : "Keep proof of purchase for future verification.",
  };
  const proofSource = (result?.proofSource || (token ? "SIGNED_LABEL" : "MANUAL_CODE_LOOKUP")) as VerificationProofSource;
  const proofDescriptor = result?.proof || (
    proofSource === "SIGNED_LABEL"
      ? {
          title: "Signed label verification",
          detail: "This result is tied to an issued MSCQR label signature.",
        }
      : {
          title: "Manual registry lookup",
          detail: "This result confirms registry state and lifecycle, but not the physical label binding.",
        }
  );
  const proofTierLabel =
    result?.proofTier === "SIGNED_LABEL"
      ? "Proof tier: signed label"
      : result?.proofTier === "MANUAL_REGISTRY_LOOKUP"
        ? "Proof tier: manual registry lookup"
        : result?.proofTier === "DEGRADED"
          ? "Proof tier: degraded"
          : null;
  const trustLevelLabel =
    result?.customerTrustLevel === "ACCOUNT_TRUSTED"
      ? "Requester trust: signed-in account"
      : result?.customerTrustLevel === "PASSKEY_VERIFIED"
        ? "Requester trust: passkey verified"
      : result?.customerTrustLevel === "DEVICE_TRUSTED"
        ? "Requester trust: trusted device"
        : result?.customerTrustLevel === "OPERATOR_REVIEWED"
          ? "Requester trust: operator reviewed"
          : "Requester trust: anonymous";
  const replacementStatusLabel =
    result?.replacementStatus === "ACTIVE_REPLACEMENT"
      ? "Replacement state: active replacement label"
      : result?.replacementStatus === "REPLACED_LABEL"
        ? "Replacement state: superseded label"
        : null;
  const degradationLabel =
    result?.degradationMode === "QUEUE_AND_RETRY"
      ? "Audit mode: queue and retry"
      : result?.degradationMode === "FAIL_CLOSED"
        ? "Audit mode: fail closed"
        : result?.degradationMode === "NORMAL"
          ? "Audit mode: normal"
          : null;
  const trustedRepeatCount = Number(activitySummary?.trustedOwnerScanCount24h ?? result?.scanSignals?.trustedOwnerScanCount24h ?? 0);
  const externalScanCount = Number(activitySummary?.untrustedScanCount24h ?? result?.scanSignals?.untrustedScanCount24h ?? 0);
  const externalDeviceCount = Number(
    activitySummary?.distinctUntrustedDeviceCount24h ?? result?.scanSignals?.distinctUntrustedDeviceCount24h ?? 0
  );

  const googleOauthUrl = String(import.meta.env.VITE_GOOGLE_OAUTH_URL || "").trim();
  const passkeySupported = isWebAuthnSupported();
  const hasPasskeyTrust = result?.customerTrustLevel === "PASSKEY_VERIFIED";
  const showSkeleton = loading && !result && !error;
  const motionButtonClass = "transition-transform duration-200 hover:scale-[1.02] active:scale-[0.99]";

  const syncPersistedTransferToken = useCallback(
    (nextToken: string | null) => {
      const normalized = String(nextToken || "").trim();
      setPersistedTransferToken(normalized);

      if ((!transferStorageKey && !legacyTransferStorageKey) || transferToken) return;

      try {
        if (normalized) {
          if (transferStorageKey) window.localStorage.setItem(transferStorageKey, normalized);
          if (legacyTransferStorageKey) window.localStorage.removeItem(legacyTransferStorageKey);
        } else {
          if (transferStorageKey) window.localStorage.removeItem(transferStorageKey);
          if (legacyTransferStorageKey) window.localStorage.removeItem(legacyTransferStorageKey);
        }
      } catch {
        // ignore storage issues
      }
    },
    [legacyTransferStorageKey, transferStorageKey, transferToken]
  );

  const persistCustomerSession = useCallback((nextToken: string, nextEmail: string) => {
    const tokenValue = String(nextToken || "").trim();
    const emailValue = String(nextEmail || "").trim();

    setCustomerToken(tokenValue);
    setCustomerEmail(emailValue);
    if (emailValue) setOtpEmail(emailValue);

    try {
      if (tokenValue) {
        window.localStorage.setItem(CUSTOMER_TOKEN_KEY, tokenValue);
      } else {
        window.localStorage.removeItem(CUSTOMER_TOKEN_KEY);
      }

      if (emailValue) {
        window.localStorage.setItem(CUSTOMER_EMAIL_KEY, emailValue);
      } else {
        window.localStorage.removeItem(CUSTOMER_EMAIL_KEY);
      }

      window.localStorage.removeItem(LEGACY_CUSTOMER_TOKEN_KEY);
      window.localStorage.removeItem(LEGACY_CUSTOMER_EMAIL_KEY);
    } catch {
      // ignore storage issues
    }
  }, []);

  const clearCustomerSession = useCallback(() => {
    setCustomerToken("");
    setCustomerEmail("");
    setPasskeyCredentials([]);
    setOtpChallengeToken("");
    setOtpCode("");
    setQueueTransferDialogAfterSignIn(false);

    try {
      window.localStorage.removeItem(CUSTOMER_TOKEN_KEY);
      window.localStorage.removeItem(CUSTOMER_EMAIL_KEY);
      window.localStorage.removeItem(LEGACY_CUSTOMER_TOKEN_KEY);
      window.localStorage.removeItem(LEGACY_CUSTOMER_EMAIL_KEY);
    } catch {
      // ignore storage issues
    }
  }, []);

  const loadCustomerPasskeys = useCallback(
    async (sessionToken?: string) => {
      const activeToken = String(sessionToken || customerToken || "").trim();
      if (!activeToken || !passkeySupported) {
        startTransition(() => {
          setPasskeyCredentials([]);
          setLoadingPasskeys(false);
        });
        return;
      }

      setLoadingPasskeys(true);
      try {
        const response = await apiClient.getCustomerPasskeyCredentials(activeToken);
        startTransition(() => {
          setPasskeyCredentials(response.success ? response.data?.items || [] : []);
        });
      } finally {
        setLoadingPasskeys(false);
      }
    },
    [customerToken, passkeySupported]
  );

  const fetchVerification = useCallback(async () => {
    if (!requestKey) {
      setLoading(false);
      setResult({ isAuthentic: false, message: "Missing verification code" });
      return;
    }

    setLoading(true);
    setError(null);
    setRetryAttempt(0);
    setRetryNotice("");
    sentDroppedMetricRef.current = false;
    verifyStartedAtRef.current = typeof performance !== "undefined" ? performance.now() : Date.now();

    try {
      const runRequest = async () => {
        let pending = inFlightRef.current.get(requestKey);
        if (pending) return pending;

        pending = (async () => {
          const getGeo = () =>
            new Promise<{ lat?: number; lon?: number; acc?: number }>((resolve) => {
              const cached = readCachedGeo();
              if (!navigator?.geolocation) return resolve(cached);
              navigator.geolocation.getCurrentPosition(
                (pos) => {
                  const nextGeo = {
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    acc: pos.coords.accuracy,
                  };
                  writeCachedGeo(nextGeo);
                  resolve(nextGeo);
                },
                () => resolve(cached),
                { enableHighAccuracy: false, timeout: 4000, maximumAge: 300_000 }
              );
            });

          const geo = await getGeo();
          if (token) {
            return apiClient.scanToken(token, {
              device: deviceId,
              lat: geo.lat,
              lon: geo.lon,
              acc: geo.acc,
              customerToken: customerToken || undefined,
            });
          }

          return apiClient.verifyQRCode(codeParam, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
            customerToken: customerToken || undefined,
            transferToken: activeTransferToken || undefined,
          });
        })();

        inFlightRef.current.set(requestKey, pending);
        return pending;
      };

      const maxAttempts = 4;
      let response: VerifyRequestResponse | null = null;
      let lastError = "";

      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        if (!navigator.onLine) {
          setIsOffline(true);
          lastError = "You appear to be offline. Please reconnect and retry.";
          break;
        }

        setRetryAttempt(attempt - 1);
        response = await runRequest();
        inFlightRef.current.delete(requestKey);
        if (response?.success) break;

        lastError = String(response?.error || "Verification failed");
        const retryable = /network|timed out|timeout|unavailable|internal server error/i.test(lastError);
        if (!retryable || attempt >= maxAttempts) break;

        const waitMs = Math.min(1200 * 2 ** (attempt - 1), 5000);
        setRetryNotice(`Poor network detected. Retrying (${attempt}/${maxAttempts - 1})...`);
        await new Promise((resolve) => window.setTimeout(resolve, waitMs));
      }

      if (!response?.success) {
        setError(lastError || response?.error || "Verification failed");
        setResult(null);
        const now = typeof performance !== "undefined" ? performance.now() : Date.now();
        const elapsed = Math.max(0, Math.round(now - verifyStartedAtRef.current));
        apiClient
          .captureRouteTransition({
            routeFrom: "/verify",
            routeTo: window.location.pathname,
            source: "verify_request",
            transitionMs: elapsed,
            verifyCodePresent: true,
            verifyResult: "ERROR",
            dropped: false,
            online: navigator.onLine,
          })
          .catch(() => {
            // best effort telemetry
          });
        return;
      }

      setResult((response.data as VerifyPayload) || null);
      setRetryNotice("");
      if (token && typeof (response.data as VerifyPayload | null)?.code === "string") {
        navigate(
          `/verify/${encodeURIComponent(String((response.data as VerifyPayload).code || "").trim())}?t=${encodeURIComponent(token)}`,
          { replace: true }
        );
      }
      const finalClassification = inferClassification((response.data as VerifyPayload) || null);
      const now = typeof performance !== "undefined" ? performance.now() : Date.now();
      const elapsed = Math.max(0, Math.round(now - verifyStartedAtRef.current));
      apiClient
        .captureRouteTransition({
          routeFrom: "/verify",
          routeTo: window.location.pathname,
          source: "verify_request",
          transitionMs: elapsed,
          verifyCodePresent: true,
          verifyResult: finalClassification,
          dropped: false,
          online: navigator.onLine,
        })
        .catch(() => {
          // best effort telemetry
        });
    } catch (err: unknown) {
      inFlightRef.current.delete(requestKey);
      setError(err instanceof Error ? err.message : "Verification failed");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [activeTransferToken, codeParam, customerToken, deviceId, navigate, requestKey, token]);

  useEffect(() => {
    setIssuedTransferLink(null);
    setQueueTransferDialogAfterSignIn(false);
    setTransferRecipientEmail("");
  }, [transferStorageKey]);

  useEffect(() => {
    if (!transferStorageKey || transferToken) {
      setPersistedTransferToken("");
      return;
    }

    try {
      setPersistedTransferToken(window.localStorage.getItem(transferStorageKey) || "");
    } catch {
      setPersistedTransferToken("");
    }
  }, [transferStorageKey, transferToken]);

  useEffect(() => {
    if (!transferStorageKey || !legacyTransferStorageKey || transferToken) return;
    try {
      const nextValue = window.localStorage.getItem(transferStorageKey);
      if (nextValue) return;
      const legacyValue = window.localStorage.getItem(legacyTransferStorageKey);
      if (!legacyValue) return;
      window.localStorage.setItem(transferStorageKey, legacyValue);
      window.localStorage.removeItem(legacyTransferStorageKey);
      setPersistedTransferToken(legacyValue);
    } catch {
      // ignore storage issues
    }
  }, [legacyTransferStorageKey, transferStorageKey, transferToken]);

  useEffect(() => {
    fetchVerification();
  }, [fetchVerification]);

  useEffect(() => {
    loadCustomerPasskeys();
  }, [loadCustomerPasskeys]);

  useEffect(() => {
    if (ownershipTransfer?.acceptUrl) {
      setIssuedTransferLink(ownershipTransfer.acceptUrl);
    }
  }, [ownershipTransfer?.acceptUrl]);

  useEffect(() => {
    if (!customerToken || transferToken) return;
    const state = String(ownershipTransfer?.state || "");
    if (!["accepted", "cancelled", "expired", "invalid"].includes(state)) return;
    if (!persistedTransferToken && !issuedTransferLink) return;

    syncPersistedTransferToken(null);
    setIssuedTransferLink(null);
  }, [customerToken, issuedTransferLink, ownershipTransfer?.state, persistedTransferToken, syncPersistedTransferToken, transferToken]);

  useEffect(() => {
    if (!queueTransferDialogAfterSignIn) return;
    if (!customerToken) return;
    if (!ownershipTransfer?.canCreate) return;

    setTransferOpen(true);
    setQueueTransferDialogAfterSignIn(false);
  }, [customerToken, ownershipTransfer?.canCreate, queueTransferDialogAfterSignIn]);

  useEffect(() => {
    const onOnline = () => {
      setIsOffline(false);
      setRetryNotice("");
    };
    const onOffline = () => {
      setIsOffline(true);
      setRetryNotice("You are offline. Verification will retry once connection is restored.");
    };

    window.addEventListener("online", onOnline);
    window.addEventListener("offline", onOffline);
    return () => {
      window.removeEventListener("online", onOnline);
      window.removeEventListener("offline", onOffline);
    };
  }, []);

  useEffect(() => {
    return () => {
      if (!loading || sentDroppedMetricRef.current) return;
      sentDroppedMetricRef.current = true;
      const now = typeof performance !== "undefined" ? performance.now() : Date.now();
      const elapsed = Math.max(0, Math.round(now - verifyStartedAtRef.current));
      apiClient
        .captureRouteTransition({
          routeFrom: "/verify",
          routeTo: window.location.pathname,
          source: "verify_request",
          transitionMs: elapsed,
          verifyCodePresent: true,
          verifyResult: null,
          dropped: true,
          online: navigator.onLine,
        })
        .catch(() => {
          // best effort telemetry
        });
    };
  }, [loading]);

  useEffect(() => {
    if (!loading) {
      setLoadingStage(0);
      return;
    }
    setLoadingStage(0);
    const timer = window.setTimeout(() => setLoadingStage(1), 1200);
    return () => window.clearTimeout(timer);
  }, [loading]);

  useEffect(() => {
    if (isOffline) return;
    if (!error) return;
    if (!/offline|network|timed out|timeout|unavailable/i.test(error)) return;
    fetchVerification();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOffline]);

  const handleRequestOtp = async () => {
    const email = otpEmail.trim();
    if (!email) {
      toast({ title: "Email required", description: "Enter your email to receive OTP.", variant: "destructive" });
      return;
    }

    setOtpSending(true);
    try {
      const response = await apiClient.requestVerifyEmailOtp(email);
      if (!response.success || !response.data) {
        toast({
          title: "Could not send OTP",
          description: response.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      setOtpChallengeToken(response.data.challengeToken);
      setOtpMaskedEmail(response.data.maskedEmail);
      toast({ title: "OTP sent", description: `Code sent to ${response.data.maskedEmail}` });
    } finally {
      setOtpSending(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!otpChallengeToken) {
      toast({ title: "OTP not requested", description: "Request an OTP first.", variant: "destructive" });
      return;
    }

    if (otpCode.trim().length < 6) {
      toast({ title: "Invalid OTP", description: "Enter the 6-digit code.", variant: "destructive" });
      return;
    }

    setOtpVerifying(true);
    try {
      const response = await apiClient.verifyEmailOtp(otpChallengeToken, otpCode.trim());
      if (!response.success || !response.data?.token) {
        toast({
          title: "OTP verification failed",
          description: response.error || "Please check the code and try again.",
          variant: "destructive",
        });
        return;
      }

      const tokenValue = response.data.token;
      const emailValue = response.data.customer?.email || otpEmail.trim();

      persistCustomerSession(tokenValue, emailValue);
      setOtpChallengeToken("");
      setOtpCode("");

      toast({ title: "Signed in", description: "Protection sign-in is active for this device." });
    } finally {
      setOtpVerifying(false);
    }
  };

  const handleSignOut = async () => {
    clearCustomerSession();
  };

  const handleRegisterPasskey = async () => {
    if (!customerToken) {
      toast({ title: "Sign-in required", description: "Sign in before adding a passkey.", variant: "destructive" });
      return;
    }

    if (!passkeySupported) {
      toast({ title: "Passkeys unavailable", description: "This browser does not support WebAuthn passkeys.", variant: "destructive" });
      return;
    }

    setRegisteringPasskey(true);
    try {
      const beginResponse = await apiClient.beginCustomerPasskeyRegistration(customerToken);
      if (!beginResponse.success || !beginResponse.data) {
        toast({
          title: "Could not start passkey setup",
          description: beginResponse.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      const credential = await startWebAuthnRegistration(beginResponse.data, `${APP_NAME} protection`);
      const finishResponse = await apiClient.finishCustomerPasskeyRegistration(customerToken, credential);
      if (!finishResponse.success || !finishResponse.data?.token) {
        toast({
          title: "Could not finish passkey setup",
          description: finishResponse.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      const nextEmail = finishResponse.data.customer?.email || customerEmail || otpEmail.trim();
      persistCustomerSession(finishResponse.data.token, nextEmail);
      await loadCustomerPasskeys(finishResponse.data.token);
      toast({
        title: "Passkey added",
        description: "Future ownership checks can use this passkey for stronger protection.",
      });
    } catch (error: unknown) {
      toast({
        title: "Could not add passkey",
        description: error instanceof Error ? error.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setRegisteringPasskey(false);
    }
  };

  const handleAssertPasskey = async () => {
    if (!customerToken) {
      toast({ title: "Sign-in required", description: "Sign in before using a passkey.", variant: "destructive" });
      return;
    }

    if (!passkeySupported) {
      toast({ title: "Passkeys unavailable", description: "This browser does not support WebAuthn passkeys.", variant: "destructive" });
      return;
    }

    setAssertingPasskey(true);
    try {
      const beginResponse = await apiClient.beginCustomerPasskeyAssertion(undefined, customerToken);
      if (!beginResponse.success || !beginResponse.data) {
        toast({
          title: "Could not start passkey check",
          description: beginResponse.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      const assertion = await startWebAuthnAuthentication(beginResponse.data);
      const finishResponse = await apiClient.finishCustomerPasskeyAssertion(assertion, customerToken);
      if (!finishResponse.success || !finishResponse.data?.token) {
        toast({
          title: "Passkey verification failed",
          description: finishResponse.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      const nextEmail = finishResponse.data.customer?.email || customerEmail || otpEmail.trim();
      persistCustomerSession(finishResponse.data.token, nextEmail);
      await loadCustomerPasskeys(finishResponse.data.token);
      toast({
        title: "Passkey verified",
        description: "This session now carries stronger ownership proof.",
      });
    } catch (error: unknown) {
      toast({
        title: "Passkey verification failed",
        description: error instanceof Error ? error.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setAssertingPasskey(false);
    }
  };

  const handleDeletePasskey = async (credentialId: string) => {
    if (!customerToken || !credentialId) return;

    setDeletingPasskeyId(credentialId);
    try {
      const response = await apiClient.deleteCustomerPasskeyCredential(customerToken, credentialId);
      if (!response.success) {
        toast({
          title: "Could not remove passkey",
          description: response.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      await loadCustomerPasskeys(customerToken);
      toast({ title: "Passkey removed", description: "That passkey can no longer be used for ownership step-up." });
    } finally {
      setDeletingPasskeyId("");
    }
  };

  const handleClaimProduct = async () => {
    if (!displayedCode || displayedCode === "—") {
      toast({ title: "Invalid code", description: "Cannot claim without a valid verification code.", variant: "destructive" });
      return;
    }

    setClaiming(true);
    try {
      const response = await apiClient.claimVerifiedProduct(displayedCode, customerToken || undefined);
      if (!response.success || !response.data) {
        toast({ title: "Claim failed", description: response.error || "Could not claim this product.", variant: "destructive" });
        return;
      }

      if (response.data.claimResult === "OWNED_BY_ANOTHER_USER") {
        toast({
          title: "Ownership conflict",
          description: response.data.warningMessage || "This product is already claimed by another account.",
          variant: "destructive",
        });
      }

      const claimData = response.data;
      if (!claimData) return;

      if (claimData.claimResult === "ALREADY_OWNED_BY_YOU") {
        toast({ title: "Already owned", description: "This product is already linked to your account." });
      } else if (claimData.claimResult === "LINKED_TO_SIGNED_IN_ACCOUNT") {
        toast({ title: "Ownership linked", description: "Your device claim is now linked to your signed-in account." });
      } else {
        toast({
          title: "Ownership claimed",
          description:
            claimData.claimResult === "CLAIMED_DEVICE"
              ? "Claim saved for this device/network. Sign in for portable protection."
              : "Product ownership is now linked to your account.",
        });
      }

      const nextOwnership = claimData.ownershipStatus || DEFAULT_OWNERSHIP_STATUS;
      setResult((prev) =>
        prev
          ? {
              ...prev,
              classification: (claimData.classification as VerificationClassification | undefined) || prev.classification,
              reasons: claimData.reasons || prev.reasons,
              warningMessage: claimData.warningMessage || prev.warningMessage,
              ownershipStatus: nextOwnership,
            }
          : prev
      );
      setClaimConfirmOpen(false);
    } finally {
      setClaiming(false);
    }
  };

  const handleLinkClaimToAccount = async () => {
    if (!customerToken || !displayedCode || displayedCode === "—") return;
    setLinkingClaim(true);
    try {
      const response = await apiClient.linkDeviceClaimToUser(displayedCode, customerToken);
      if (!response.success) {
        toast({
          title: "Link failed",
          description: response.error || "Could not link this device claim.",
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Linked to your account", description: "Ownership is now portable across your signed-in sessions." });
      setResult((prev) =>
        prev
          ? {
              ...prev,
              ownershipStatus: response.data?.ownershipStatus || prev.ownershipStatus,
            }
          : prev
      );
    } finally {
      setLinkingClaim(false);
    }
  };

  const handleCreateTransfer = async () => {
    if (!customerToken || !displayedCode || displayedCode === "—") {
      toast({ title: "Sign-in required", description: "Sign in before starting a transfer.", variant: "destructive" });
      return;
    }

    setTransferSubmitting(true);
    try {
      const response = await apiClient.createOwnershipTransfer(
        displayedCode,
        { recipientEmail: transferRecipientEmail.trim() || undefined },
        customerToken
      );
      if (!response.success || !response.data) {
        toast({
          title: "Transfer unavailable",
          description: response.error || "Could not start the ownership transfer.",
          variant: "destructive",
        });
        return;
      }

      setIssuedTransferLink(response.data.transferLink || response.data.ownershipTransfer?.acceptUrl || null);
      syncPersistedTransferToken(response.data.transferToken || null);
      setResult((prev) =>
        prev
          ? {
              ...prev,
              ownershipStatus: response.data?.ownershipStatus || prev.ownershipStatus,
              ownershipTransfer: response.data?.ownershipTransfer || prev.ownershipTransfer,
            }
          : prev
      );
      toast({
        title: "Transfer ready",
        description: response.data.message || "Share the secure transfer link with the next owner.",
      });
      setQueueTransferDialogAfterSignIn(false);
      setTransferOpen(false);
    } finally {
      setTransferSubmitting(false);
    }
  };

  const handleCancelTransfer = async () => {
    if (!customerToken || !displayedCode || !ownershipTransfer?.transferId) return;
    setTransferCancelling(true);
    try {
      const response = await apiClient.cancelOwnershipTransfer(
        displayedCode,
        { transferId: ownershipTransfer.transferId || undefined },
        customerToken
      );
      if (!response.success) {
        toast({
          title: "Cancel failed",
          description: response.error || "Could not cancel the transfer.",
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Transfer cancelled", description: response.data?.message || "Pending transfer cancelled." });
      syncPersistedTransferToken(null);
      setIssuedTransferLink(null);
      setResult((prev) =>
        prev
          ? {
              ...prev,
              ownershipTransfer: response.data?.ownershipTransfer || prev.ownershipTransfer,
            }
          : prev
      );
    } finally {
      setTransferCancelling(false);
    }
  };

  const handleAcceptTransfer = async () => {
    if (!customerToken || !transferToken) {
      toast({ title: "Sign-in required", description: "Sign in before accepting the transfer.", variant: "destructive" });
      return;
    }
    setTransferAccepting(true);
    try {
      const response = await apiClient.acceptOwnershipTransfer({ token: transferToken }, customerToken);
      if (!response.success) {
        toast({
          title: "Accept failed",
          description: response.error || "Could not accept the transfer.",
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Ownership transferred",
        description: response.data?.message || "This product is now linked to your account.",
      });
      setIssuedTransferLink(null);
      setResult((prev) =>
        prev
          ? {
              ...prev,
              code: response.data?.code || prev.code,
              ownershipStatus: response.data?.ownershipStatus || prev.ownershipStatus,
              ownershipTransfer: response.data?.ownershipTransfer || prev.ownershipTransfer,
            }
          : prev
      );
    } finally {
      setTransferAccepting(false);
    }
  };

  const handleCopyTransferLink = async () => {
    const link = shareableTransferLink;
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      toast({ title: "Transfer link copied", description: "Send this secure acceptance link to the next owner." });
    } catch {
      toast({ title: "Copy failed", description: "Could not copy the transfer link.", variant: "destructive" });
    }
  };

  const handleTransferSignInIntent = () => {
    setQueueTransferDialogAfterSignIn(true);
    protectionSignInRef.current?.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  const handleSubmitReport = async () => {
    const codeValue = String(displayedCode || "").trim();
    if (!codeValue || codeValue === "—") {
      toast({ title: "Report failed", description: "No valid code available.", variant: "destructive" });
      return;
    }

    if (reportDescription.trim().length < 6) {
      toast({
        title: "More detail required",
        description: "Please describe what looked suspicious.",
        variant: "destructive",
      });
      return;
    }

    setReporting(true);
    try {
      const formData = new FormData();
      formData.append("code", codeValue);
      formData.append("incidentType", reportType);
      formData.append("reason", reasons[0] || classification);
      formData.append("description", reportDescription.trim());
      if (reportEmail.trim()) formData.append("contactEmail", reportEmail.trim());
      formData.append("consentToContact", String(Boolean(reportEmail.trim())));
      formData.append("preferredContactMethod", reportEmail.trim() ? "email" : "none");
      formData.append("tags", JSON.stringify(["verify_page_report", `classification_${classification.toLowerCase()}`]));
      for (const photo of reportPhotos.slice(0, 4)) {
        formData.append("photos", photo);
      }

      const response = await apiClient.submitFraudReport(formData, customerToken || undefined);
      if (!response.success) {
        toast({ title: "Report failed", description: response.error || "Please try again.", variant: "destructive" });
        return;
      }

      const payload = (response.data || {}) as {
        reportId?: string;
        supportTicketRef?: string;
        supportTicketStatus?: string;
        supportTicketSla?: { dueAt?: string } | null;
        tamperChecks?: { summary?: string | null } | null;
      };
      setReportReference(payload.reportId || null);
      setReportSupportRef(payload.supportTicketRef || null);
      setReportSupportStatus(payload.supportTicketStatus || null);
      setReportTamperSummary(payload?.tamperChecks?.summary || null);
      if (payload?.supportTicketSla?.dueAt) {
        setReportSupportSla(new Date(payload.supportTicketSla.dueAt).toLocaleString());
      } else {
        setReportSupportSla(null);
      }

      if (payload.supportTicketRef) {
        const tracking = await apiClient.trackSupportTicket(payload.supportTicketRef, reportEmail.trim() || undefined);
        if (tracking.success) {
          const trackData = (tracking.data || {}) as {
            status?: string;
            sla?: { dueAt?: string } | null;
          };
          setReportSupportStatus(trackData.status || payload.supportTicketStatus || null);
          if (trackData?.sla?.dueAt) {
            setReportSupportSla(new Date(trackData.sla.dueAt).toLocaleString());
          }
        }
      }

      toast({ title: "Report submitted", description: "Security team has received your report." });
    } finally {
      setReporting(false);
    }
  };

  const handleTrackTicket = async () => {
    const reference = trackReference.trim().toUpperCase();
    if (!reference) {
      toast({ title: "Reference required", description: "Enter your support ticket reference.", variant: "destructive" });
      return;
    }

    setTrackingTicket(true);
    try {
      const response = await apiClient.trackSupportTicket(reference, trackEmail.trim() || undefined);
      if (!response.success) {
        setTrackedTicket(null);
        toast({ title: "Tracking failed", description: response.error || "Could not find this support ticket.", variant: "destructive" });
        return;
      }

      setTrackedTicket(
        (response.data as
          | {
              referenceCode?: string;
              status?: string;
              handoffStage?: string;
              sla?: { dueAt?: string; isBreached?: boolean; remainingMinutes?: number } | null;
            }
          | null) || null
      );
    } finally {
      setTrackingTicket(false);
    }
  };

  const supportEmail = result?.licensee?.supportEmail || "";
  const supportPhone = result?.licensee?.supportPhone || "";
  const supportWebsite = result?.licensee?.website || "";
  const isReportDraftDirty =
    reportDescription.trim().length > 0 ||
    reportEmail.trim().length > 0 ||
    reportPhotos.length > 0 ||
    reportType !== INCIDENT_TYPE_OPTIONS[0].value;
  const handleReportDialogOpenChange = (open: boolean) => {
    if (!open && !reporting && !reportReference && isReportDraftDirty) {
      const shouldDiscard = window.confirm("Discard this report draft?");
      if (!shouldDiscard) return;
    }
    setReportOpen(open);
  };
  const friendlyVerifyError = (() => {
    const msg = String(error || "").toLowerCase();
    if (!msg) return "Verification service unavailable";
    if (msg.includes("network") || msg.includes("offline") || msg.includes("timed out") || msg.includes("timeout")) {
      return "Network connection is unstable. Reconnect and retry verification.";
    }
    if (msg.includes("internal server error") || msg.includes("service unavailable")) {
      return "The secure registry is temporarily unavailable. Please retry in a moment.";
    }
    return "Verification is unavailable right now. Please retry.";
  })();

  return (
    <div
      className="relative min-h-screen px-4 py-8"
      style={{
        background:
          "radial-gradient(circle at 8% 8%, rgba(141,157,182,0.34), transparent 40%), radial-gradient(circle at 88% 14%, rgba(241,227,221,0.78), transparent 42%), linear-gradient(160deg, #f7fafd 0%, #eef3f9 46%, #f1e3dd 100%)",
      }}
    >
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {loading
          ? loadingStage === 0
            ? "Securely verifying QR code."
            : "Checking secure registry."
          : error
            ? "Verification service unavailable."
            : `${verificationCopy.title}. ${verificationCopy.subtitle}`}
      </div>
      <div className="mx-auto w-full max-w-4xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link to="/verify" className="inline-flex items-center gap-2 text-slate-900">
            <Shield className="h-6 w-6" />
            <span className="text-xl font-semibold tracking-tight">{APP_NAME} Verification</span>
          </Link>
          <Button asChild variant="outline" className={motionButtonClass}>
            <Link to="/verify">Verify another code</Link>
          </Button>
        </div>

        <Card
          className="relative overflow-hidden border shadow-[0_20px_44px_rgba(102,114,146,0.18)] premium-surface-in"
          style={{ borderColor: `${PREMIUM_PALETTE.steel}77` }}
          aria-busy={loading}
        >
          {error ? (
            <CardContent className="space-y-3 py-12 text-center">
              <SearchX className="mx-auto h-8 w-8 text-rose-900" />
              <p className="text-lg font-semibold text-slate-900">Verification service unavailable</p>
              <p className="text-sm text-slate-600">{friendlyVerifyError}</p>
              <div className="flex items-center justify-center gap-2">
                <Button variant="outline" onClick={fetchVerification} disabled={loading}>
                  Retry now
                </Button>
                {isOffline ? (
                  <Badge variant="outline" className="border-amber-300 text-amber-900">
                    Offline
                  </Badge>
                ) : null}
              </div>
              <details className="mx-auto max-w-xl rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-left text-xs text-slate-600">
                <summary className="cursor-pointer font-medium text-slate-700">Technical details</summary>
                <p className="mt-2 break-all">{error}</p>
              </details>
            </CardContent>
          ) : (
            <CardContent className={cn("space-y-6 p-5 sm:p-6", !showSkeleton && "animate-fade-in")}>
              {showSkeleton ? (
                <>
                  <section className="space-y-3">
                    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
                      <SkeletonBlock className="h-4 w-44" />
                      <SkeletonBlock className="mt-3 h-7 w-64" />
                      <SkeletonBlock className="mt-3 h-4 w-full" />
                      <SkeletonBlock className="mt-2 h-4 w-5/6" />
                    </div>
                    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-sm">
                      <SkeletonBlock className="h-3 w-full" />
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                      <SkeletonBlock className="h-4 w-32" />
                      <SkeletonBlock className="mt-2 h-8 w-72" />
                      <SkeletonBlock className="mt-4 h-3 w-24" />
                      <SkeletonBlock className="mt-2 h-3 w-full" />
                      <SkeletonBlock className="mt-2 h-3 w-5/6" />
                    </div>
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <SkeletonBlock className="h-4 w-32" />
                    <div className="mt-4 grid gap-3 md:grid-cols-3">
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/80 p-4">
                        <SkeletonBlock className="h-3 w-20" />
                        <SkeletonBlock className="mt-3 h-8 w-16" />
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/80 p-4">
                        <SkeletonBlock className="h-3 w-28" />
                        <SkeletonBlock className="mt-3 h-4 w-full" />
                        <SkeletonBlock className="mt-2 h-3 w-2/3" />
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/80 p-4">
                        <SkeletonBlock className="h-3 w-28" />
                        <SkeletonBlock className="mt-3 h-4 w-full" />
                        <SkeletonBlock className="mt-2 h-3 w-2/3" />
                      </div>
                    </div>
                  </section>

                  <section className="rounded-xl border border-[#8d9db668] bg-white/95 p-4 shadow-sm premium-surface-in">
                    <SkeletonBlock className="h-4 w-32" />
                    <SkeletonBlock className="mt-4 h-20 w-full" />
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <SkeletonBlock className="h-4 w-28" />
                    <SkeletonBlock className="mt-4 h-10 w-56" />
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <SkeletonBlock className="h-4 w-24" />
                    <SkeletonBlock className="mt-3 h-3 w-full" />
                    <SkeletonBlock className="mt-2 h-3 w-11/12" />
                    <SkeletonBlock className="mt-2 h-3 w-4/5" />
                  </section>
                </>
              ) : (
                <>
                  {isOffline ? (
                    <div className="rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900">
                      <div className="flex items-start gap-2">
                        <WifiOff className="mt-0.5 h-4 w-4" />
                        <div>
                          <p className="font-semibold">Offline mode detected</p>
                          <p className="mt-1">Reconnect to continue secure verification checks.</p>
                          <Button
                            variant="outline"
                            className={cn("mt-2 border-amber-300 bg-white text-amber-900 hover:bg-amber-100", motionButtonClass)}
                            onClick={fetchVerification}
                            disabled={loading}
                          >
                            Retry verification
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : null}

                  {retryNotice ? (
                    <div className="rounded-xl border border-cyan-200 bg-cyan-50 p-3 text-sm text-cyan-900">
                      <div className="flex items-start gap-2">
                        <Clock3 className="mt-0.5 h-4 w-4" />
                        <div>
                          <p className="font-semibold">{retryNotice}</p>
                          {retryAttempt > 0 ? <p className="mt-1 text-xs text-cyan-800">Retry attempts: {retryAttempt}</p> : null}
                        </div>
                      </div>
                    </div>
                  ) : null}

                  <section className="space-y-3">
                    <div
                      className={cn("rounded-2xl p-5 shadow-[0_18px_34px_rgba(102,114,146,0.2)] sm:p-6", classMeta.bannerClass)}
                      role="status"
                      aria-live="polite"
                      aria-atomic="true"
                    >
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="flex min-w-0 gap-4">
                          <div className="mt-0.5 rounded-xl bg-white/15 p-2.5 ring-1 ring-white/25">{classMeta.icon}</div>
                          <div className="min-w-0">
                            <h1 className="mt-1 text-2xl font-semibold tracking-tight">{verificationCopy.title}</h1>
                            <p className="mt-2 text-sm leading-relaxed text-white/90">{verificationCopy.subtitle}</p>
                            <p className="mt-2 text-sm leading-relaxed text-white/90">{result?.message || "Verification completed."}</p>
                            {result?.warningMessage ? (
                              <p className="mt-2 text-sm leading-relaxed text-white/90">{result.warningMessage}</p>
                            ) : null}
                            {showAuthenticStamp ? <VerifiedAuthenticStamp className="mt-3" /> : null}
                          </div>
                        </div>
                        <div className="flex items-start gap-2 sm:gap-3">
                          <Badge className={cn("h-fit text-[11px] font-semibold uppercase tracking-wide", classMeta.badgeClass)}>
                            {verificationCopy.badge}
                          </Badge>
                          <VerificationConfidenceMeter
                            classification={classification}
                            totalScans={scanSummary.totalScans}
                            distinctDeviceCount24h={result?.scanSignals?.distinctDeviceCount24h}
                            recentScanCount10m={result?.scanSignals?.recentScanCount10m}
                            distinctCountryCount24h={result?.scanSignals?.distinctCountryCount24h}
                            distinctUntrustedDeviceCount24h={result?.scanSignals?.distinctUntrustedDeviceCount24h}
                            untrustedScanCount10m={result?.scanSignals?.untrustedScanCount10m}
                            trustedOwnerScanCount24h={result?.scanSignals?.trustedOwnerScanCount24h}
                            warningMessage={result?.warningMessage || null}
                            className="w-[182px]"
                          />
                        </div>
                      </div>
                    </div>

                    <div className="rounded-xl border border-[#8d9db65e] bg-white/90 px-3 py-2 shadow-sm premium-surface-in">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
                        <span className="inline-flex items-center gap-1.5">
                          <Shield className="h-3.5 w-3.5 text-slate-700" />
                          {proofDescriptor.title}
                        </span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span>{proofDescriptor.detail}</span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        {proofTierLabel ? <span className="font-medium text-slate-700">{proofTierLabel}</span> : null}
                        {proofTierLabel ? <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" /> : null}
                        <span className="font-medium text-slate-700">{trustLevelLabel}</span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span className="font-medium text-slate-700">
                          Print trust: {result?.printTrustState ? toLabel(result.printTrustState) : "not disclosed"}
                        </span>
                        {replacementStatusLabel ? <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" /> : null}
                        {replacementStatusLabel ? <span className="font-medium text-slate-700">{replacementStatusLabel}</span> : null}
                        {degradationLabel ? <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" /> : null}
                        {degradationLabel ? <span className="font-medium text-slate-700">{degradationLabel}</span> : null}
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span className="font-medium text-slate-700">Scan history recorded server-side for fraud review</span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span className="font-medium text-slate-700">Confidence {confidenceScore}%</span>
                      </div>
                    </div>

                    <PremiumSectionAccordion
                      defaultOpen={["risk-signals"]}
                      items={[
                        {
                          value: "risk-signals",
                          title: "Risk Signals",
                          subtitle: "Model-derived explanation from current verification evidence",
                          content: verifyUxPolicy.showRiskCards ? (
                            <div
                              className={cn(
                                "rounded-xl border p-4 shadow-sm",
                                riskExplanation.level === "high"
                                  ? "border-rose-300 bg-rose-50"
                                  : riskExplanation.level === "elevated" || riskExplanation.level === "medium"
                                    ? "border-amber-300 bg-amber-50"
                                    : "border-emerald-200 bg-emerald-50"
                              )}
                            >
                              <p className="text-xs uppercase tracking-wide text-slate-600">Risk explanation</p>
                              <p className="mt-1 text-sm font-semibold text-slate-900">{riskExplanation.title}</p>
                              {Array.isArray(riskExplanation.details) && riskExplanation.details.length ? (
                                <ul className="mt-2 list-disc space-y-1 pl-5 text-xs text-slate-700">
                                  {riskExplanation.details.slice(0, 4).map((detail) => (
                                    <li key={detail}>{detail}</li>
                                  ))}
                                </ul>
                              ) : null}
                              <p className="mt-2 text-xs text-slate-700">{riskExplanation.recommendedAction}</p>
                            </div>
                          ) : (
                            <p className="text-sm text-slate-600">Risk card display is disabled by policy for this verification.</p>
                          ),
                        },
                        {
                          value: "verification-reasons",
                          title: "Verification Reasons",
                          subtitle: "Human-readable summary mapped from scan signals",
                          badge: <Badge className="border-[#8d9db65e] bg-[#bccad638] text-[#4f5b75]">{verificationCopy.badge}</Badge>,
                          content: (
                            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                              <p className="text-xs uppercase tracking-wide text-slate-500">Verified Code</p>
                              <p className="mt-1 font-mono text-xl font-semibold tracking-tight text-slate-900">{displayedCode}</p>
                              <div className="mt-4 space-y-1.5">
                                <p className="text-xs uppercase tracking-wide text-slate-500">Reasons</p>
                                <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-700">
                                  {reasons.map((reason) => (
                                    <li key={reason}>{reason}</li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          ),
                        },
                        {
                          value: "decision-trace",
                          title: "Decision Trace",
                          subtitle: "Versioned proof, trust, and lifecycle evidence behind this result",
                          content: (
                            <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                              <div className="grid gap-3 text-sm text-slate-700 sm:grid-cols-2">
                                <div>
                                  <p className="text-xs uppercase tracking-wide text-slate-500">Decision version</p>
                                  <p className="mt-1 font-medium text-slate-900">
                                    {result?.decisionVersion ? `v${result.decisionVersion}` : "Current"}
                                  </p>
                                </div>
                                <div>
                                  <p className="text-xs uppercase tracking-wide text-slate-500">Decision id</p>
                                  <p className="mt-1 font-mono text-xs text-slate-900">{result?.decisionId || "Not disclosed"}</p>
                                </div>
                                <div>
                                  <p className="text-xs uppercase tracking-wide text-slate-500">Label state</p>
                                  <p className="mt-1 font-medium text-slate-900">{toLabel(result?.labelState || result?.status || "unknown")}</p>
                                </div>
                                <div>
                                  <p className="text-xs uppercase tracking-wide text-slate-500">Latest decision outcome</p>
                                  <p className="mt-1 font-medium text-slate-900">{toLabel(result?.latestDecisionOutcome || result?.scanOutcome || "unknown")}</p>
                                </div>
                              </div>
                              {Array.isArray(result?.reasonCodes) && result.reasonCodes.length ? (
                                <div className="mt-4">
                                  <p className="text-xs uppercase tracking-wide text-slate-500">Decision reason codes</p>
                                  <div className="mt-2 flex flex-wrap gap-2">
                                    {result.reasonCodes.slice(0, 6).map((code) => (
                                      <Badge key={code} variant="outline" className="border-slate-200 bg-slate-50 text-slate-700">
                                        {code}
                                      </Badge>
                                    ))}
                                  </div>
                                </div>
                              ) : null}
                            </div>
                          ),
                        },
                      ]}
                    />
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <p className="text-sm font-semibold text-slate-900">Scan summary</p>
                    {activitySummary?.summary ? (
                      <div className="mt-3 rounded-lg border border-slate-200 bg-slate-50/80 px-4 py-3 text-sm text-slate-700">
                        {activitySummary.summary}
                      </div>
                    ) : null}
                    <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Total scans</p>
                        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">{scanSummary.totalScans}</p>
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Trusted repeat activity (24h)</p>
                        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">{trustedRepeatCount}</p>
                        <p className="mt-1 text-xs text-slate-500">
                          {activitySummary?.currentActorTrustedOwnerContext
                            ? "Matches your owner or trusted device context"
                            : "Trusted owner-linked checks in the last 24 hours"}
                        </p>
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">External scans (24h)</p>
                        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">{externalScanCount}</p>
                        <p className="mt-1 text-xs text-slate-500">Scans outside the trusted owner context</p>
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">New external devices (24h)</p>
                        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">{externalDeviceCount}</p>
                        <p className="mt-1 text-xs text-slate-500">Distinct devices not matched to the trusted owner</p>
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">First verified</p>
                        <p className="mt-2 text-sm font-medium text-slate-900">{formatDateTime(scanSummary.firstVerifiedAt)}</p>
                        <p className="mt-1 text-xs text-slate-500">{scanSummary.firstVerifiedLocation || "Location unavailable"}</p>
                      </div>
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Latest verified</p>
                        <p className="mt-2 text-sm font-medium text-slate-900">{formatDateTime(scanSummary.latestVerifiedAt)}</p>
                        <p className="mt-1 text-xs text-slate-500">{scanSummary.latestVerifiedLocation || "Location unavailable"}</p>
                      </div>
                    </div>

                    <PremiumSectionAccordion
                      className="mt-4"
                      defaultOpen={verifyUxPolicy.showTimelineCard ? ["timeline"] : ["supply-chain"]}
                      items={[
                        {
                          value: "timeline",
                          title: "Verification Timeline",
                          subtitle: "First and latest verified observations",
                          content: verifyUxPolicy.showTimelineCard ? (
                            <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                              <div className="grid gap-3 sm:grid-cols-2">
                                <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                                  <p className="text-[11px] uppercase tracking-wide text-slate-500">First seen</p>
                                  <p className="text-sm font-medium text-slate-900">{formatDateTime(verificationTimeline.firstSeen)}</p>
                                </div>
                                <div className="rounded-md border border-slate-200 bg-slate-50 px-3 py-2">
                                  <p className="text-[11px] uppercase tracking-wide text-slate-500">Latest seen</p>
                                  <p className="text-sm font-medium text-slate-900">{formatDateTime(verificationTimeline.latestSeen)}</p>
                                </div>
                              </div>
                              {verificationTimeline.anomalyReason ? (
                                <div
                                  className={cn(
                                    "mt-3 rounded-md border px-3 py-2 text-xs",
                                    verificationTimeline.visualSignal === "critical"
                                      ? "border-rose-300 bg-rose-50 text-rose-900"
                                      : "border-amber-300 bg-amber-50 text-amber-900"
                                  )}
                                >
                                  Anomaly reason: {verificationTimeline.anomalyReason}
                                </div>
                              ) : (
                                <div className="mt-3 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-900">
                                  Timeline signals are consistent with normal verification usage.
                                </div>
                              )}
                            </div>
                          ) : (
                            <p className="text-sm text-slate-600">Timeline display is disabled by policy for this verification.</p>
                          ),
                        },
                        {
                          value: "supply-chain",
                          title: "Supply Chain Details",
                          subtitle: "Brand and manufacturer metadata from the secure registry",
                          content: (
                            <div className="grid gap-3 lg:grid-cols-2">
                              <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                                <p className="text-xs uppercase tracking-wide text-slate-500">Brand owner</p>
                                <p className="mt-1 text-sm font-semibold text-slate-900">
                                  {result?.licensee?.brandName || result?.licensee?.name || "Not provided"}
                                </p>
                                <div className="mt-3 space-y-1.5 text-xs text-slate-600">
                                  <p>
                                    <span className="font-medium text-slate-700">Location:</span> {result?.licensee?.location || "Not provided"}
                                  </p>
                                  <p>
                                    <span className="font-medium text-slate-700">Support email:</span> {result?.licensee?.supportEmail || "Not provided"}
                                  </p>
                                  <p>
                                    <span className="font-medium text-slate-700">Support phone:</span> {result?.licensee?.supportPhone || "Not provided"}
                                  </p>
                                  <p>
                                    <span className="font-medium text-slate-700">Website:</span> {result?.licensee?.website || "Not provided"}
                                  </p>
                                </div>
                              </div>

                              <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                                <p className="text-xs uppercase tracking-wide text-slate-500">Manufacturer</p>
                                <p className="mt-1 text-sm font-semibold text-slate-900">
                                  {result?.batch?.manufacturer?.name || "Not provided"}
                                </p>
                                <div className="mt-3 space-y-1.5 text-xs text-slate-600">
                                  <p>
                                    <span className="font-medium text-slate-700">Email:</span> {result?.batch?.manufacturer?.email || "Not provided"}
                                  </p>
                                  <p>
                                    <span className="font-medium text-slate-700">Location:</span> {result?.batch?.manufacturer?.location || "Not provided"}
                                  </p>
                                  <p>
                                    <span className="font-medium text-slate-700">Website:</span> {result?.batch?.manufacturer?.website || "Not provided"}
                                  </p>
                                </div>
                              </div>
                            </div>
                          ),
                        },
                      ]}
                    />
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-900">Protection</p>
                      {customerToken ? <Badge variant="outline">Signed in for protection</Badge> : null}
                    </div>
                    <div className="mt-3 space-y-4">
                      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                        <p className="font-medium">Protect this item</p>
                        <p className="mt-1">
                          Protecting this item helps MSCQR recognise trusted repeat checks and speeds up help if something looks wrong.
                        </p>
                        <p className="mt-2 text-xs text-slate-600">
                          You can protect it on this device right away, or sign in for protection that follows you across devices.
                        </p>
                      </div>

                      {ownershipStatus.isOwnedByRequester ? (
                        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                          <p className="font-semibold">Owned by you</p>
                          <p className="mt-1">Claimed at: {formatDateTime(ownershipStatus.claimedAt)}</p>
                          {ownershipStatus.matchMethod === "device_token" ? (
                            <p className="mt-1 text-xs text-emerald-800">
                              Current proof: this device.
                            </p>
                          ) : null}
                        </div>
                      ) : ownershipStatus.isClaimedByAnother ? (
                        <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                          <p className="font-semibold">Already claimed</p>
                          <p className="mt-1">This code is already claimed. If unexpected, submit a counterfeit report.</p>
                        </div>
                      ) : ownershipStatus.canClaim ? (
                        <div className="flex flex-wrap items-center gap-2">
                          <Button
                            type="button"
                            onClick={() => setClaimConfirmOpen(true)}
                            disabled={loading || claiming}
                            className={cn("bg-slate-900 text-white hover:bg-slate-800", motionButtonClass)}
                          >
                            {claiming ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Claiming
                              </>
                            ) : (
                              "Protect on this device"
                            )}
                          </Button>
                          {googleOauthUrl && !customerToken ? (
                            <Button asChild variant="outline" className={motionButtonClass} disabled={loading || claiming}>
                              <a href={googleOauthUrl}>Sign in with Google for stronger protection</a>
                            </Button>
                          ) : null}
                        </div>
                      ) : (
                        <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                          <p className="font-semibold">Claim currently unavailable</p>
                          <p className="mt-1">{claimUnavailableReason}</p>
                        </div>
                      )}

                      {showLinkClaim ? (
                        <Button
                          type="button"
                          variant="outline"
                          onClick={handleLinkClaimToAccount}
                          disabled={loading || linkingClaim}
                          className={motionButtonClass}
                        >
                          {linkingClaim ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Linking
                            </>
                          ) : (
                            "Move this device protection to your account"
                          )}
                        </Button>
                      ) : null}

                      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <p className="font-medium text-slate-900">Transfer to a new owner</p>
                            <p className="mt-1 text-xs text-slate-600">
                              Use this when selling or handing over a genuine item. The next owner accepts from a secure link.
                            </p>
                          </div>
                          {ownershipTransfer?.state && ownershipTransfer.state !== "none" ? (
                            <Badge variant="outline">{toLabel(ownershipTransfer.state)}</Badge>
                          ) : null}
                        </div>

                        <div className="mt-3 space-y-3">
                          {ownershipTransfer?.state === "invalid" ? (
                            <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                              {ownershipTransfer.invalidReason || "This transfer link is invalid or has expired."}
                            </div>
                          ) : null}

                          {showOwnerTransferSignInPrompt ? (
                            <div className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-900">
                              <p className="font-medium">
                                {ownershipTransfer?.active
                                  ? "Sign in below to manage or resend your active transfer."
                                  : "Sign in below to start a secure ownership transfer."}
                              </p>
                              <p className="mt-1">
                                Transfers start from a signed-in customer session so the next owner can accept from a secure link.
                              </p>
                              <Button
                                type="button"
                                variant="outline"
                                onClick={handleTransferSignInIntent}
                                className="mt-3 border-sky-300 bg-white text-sky-900 hover:bg-sky-100"
                              >
                                Sign in to continue
                              </Button>
                            </div>
                          ) : null}

                          {showRecipientTransferSignInPrompt ? (
                            <div className="rounded-md border border-sky-200 bg-sky-50 px-3 py-2 text-xs text-sky-900">
                              Sign in below, then accept the transfer to link this product to your account.
                            </div>
                          ) : null}

                          {ownershipTransfer?.active ? (
                            <div className="rounded-md border border-slate-200 bg-white px-3 py-2 text-xs text-slate-700">
                              <p>Started: {formatDateTime(ownershipTransfer.initiatedAt)}</p>
                              <p>Expires: {formatDateTime(ownershipTransfer.expiresAt)}</p>
                              {ownershipTransfer.recipientEmailMasked ? <p>Recipient: {ownershipTransfer.recipientEmailMasked}</p> : null}
                            </div>
                          ) : null}

                          {ownershipTransfer?.canCreate ? (
                            <div className="flex flex-wrap items-center gap-2">
                              <Button type="button" variant="outline" onClick={() => setTransferOpen(true)} className={motionButtonClass}>
                                Start ownership transfer
                              </Button>
                              {issuedTransferLink ? (
                                <Button type="button" variant="outline" onClick={handleCopyTransferLink}>
                                  Copy latest handover link
                                </Button>
                              ) : null}
                            </div>
                          ) : null}

                          {ownershipTransfer?.canCreate && ownershipStatus.matchMethod && ownershipStatus.matchMethod !== "user" ? (
                            <p className="text-xs text-slate-600">
                              Starting a transfer will also link this device claim to your signed-in account automatically.
                            </p>
                          ) : null}

                          {ownershipTransfer?.canCancel ? (
                            <div className="space-y-2">
                              <div className="flex flex-wrap items-center gap-2">
                                <Button type="button" variant="outline" onClick={handleCopyTransferLink} disabled={!shareableTransferLink}>
                                  Copy handover link
                                </Button>
                                <Button
                                  type="button"
                                  variant="outline"
                                  onClick={handleCancelTransfer}
                                  disabled={transferCancelling}
                                  className="border-rose-300 text-rose-800 hover:bg-rose-50"
                                >
                                  {transferCancelling ? (
                                    <>
                                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                      Cancelling
                                    </>
                                  ) : (
                                    "Cancel transfer"
                                  )}
                                </Button>
                              </div>
                              {!shareableTransferLink ? (
                                <p className="text-xs text-slate-600">
                                  The secure link is only available on the device that created it or in the transfer email. Cancel and create a fresh transfer if you need a new link.
                                </p>
                              ) : null}
                            </div>
                          ) : null}

                          {ownershipTransfer?.state === "accepted" && ownershipTransfer?.acceptedAt ? (
                            <p className="text-xs text-slate-600">Accepted: {formatDateTime(ownershipTransfer.acceptedAt)}</p>
                          ) : null}

                          {ownershipTransfer?.state === "expired" ? (
                            <p className="text-xs text-slate-600">This transfer expired. Start a new one if you still need to hand over ownership.</p>
                          ) : null}

                          {ownershipTransfer?.state === "cancelled" ? (
                            <p className="text-xs text-slate-600">This transfer was cancelled. You can create a fresh transfer when you are ready.</p>
                          ) : null}

                          {ownershipTransfer?.canAccept ? (
                            <div className="flex flex-wrap items-center gap-2">
                              <Button
                                type="button"
                                onClick={handleAcceptTransfer}
                                disabled={transferAccepting}
                                className={cn("bg-slate-900 text-white hover:bg-slate-800", motionButtonClass)}
                              >
                                {transferAccepting ? (
                                  <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Accepting
                                  </>
                                ) : (
                                  "Accept transfer"
                                )}
                              </Button>
                              <p className="text-xs text-slate-600">Sign-in is required so the new owner gets protection that follows their account.</p>
                            </div>
                          ) : null}
                        </div>
                      </div>

                      {!customerToken ? (
                        <div ref={protectionSignInRef} className="space-y-3 rounded-lg border border-slate-200 p-3">
                          <p className="text-sm font-medium text-slate-900">{signInCardTitle}</p>
                          <p className="text-xs text-slate-600">{signInCardDescription}</p>
                          {googleOauthUrl ? (
                            <Button asChild variant="outline" className={motionButtonClass}>
                              <a href={googleOauthUrl}>Continue with Google</a>
                            </Button>
                          ) : null}
                          <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
                            <div className="space-y-2">
                              <Label>Email OTP sign-in</Label>
                              <Input
                                type="email"
                                value={otpEmail}
                                onChange={(e) => setOtpEmail(e.target.value)}
                                placeholder="you@example.com"
                                disabled={loading || claiming}
                              />
                            </div>
                            <Button
                              type="button"
                              onClick={handleRequestOtp}
                              disabled={loading || claiming || otpSending}
                              className={cn("bg-slate-900 text-white hover:bg-slate-800", motionButtonClass)}
                            >
                              {otpSending ? (
                                <>
                                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                  Sending OTP
                                </>
                              ) : (
                                "Send OTP"
                              )}
                            </Button>
                          </div>
                          {otpChallengeToken ? (
                            <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
                              <div className="space-y-2">
                                <Label>One-time code</Label>
                                <Input
                                  value={otpCode}
                                  onChange={(e) => setOtpCode(e.target.value)}
                                  maxLength={6}
                                  placeholder="123456"
                                  disabled={loading || claiming}
                                />
                              </div>
                              <Button
                                type="button"
                                onClick={handleVerifyOtp}
                                disabled={loading || claiming || otpVerifying}
                                className={cn("bg-slate-900 text-white hover:bg-slate-800", motionButtonClass)}
                              >
                                {otpVerifying ? (
                                  <>
                                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                    Verifying
                                  </>
                                ) : (
                                  "Verify OTP"
                                )}
                              </Button>
                            </div>
                          ) : null}
                          {otpChallengeToken ? (
                            <p className="text-xs text-slate-600">OTP sent to {otpMaskedEmail || "your email"}.</p>
                          ) : null}
                        </div>
                      ) : (
                        <div className="space-y-3">
                          <div className="flex flex-wrap items-center gap-3">
                            <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                              Signed in as {customerEmail}
                            </div>
                            <Button type="button" variant="outline" onClick={handleSignOut} disabled={loading} className={motionButtonClass}>
                              Sign out
                            </Button>
                          </div>

                          {passkeySupported ? (
                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div>
                                  <p className="font-medium text-slate-900">Passkey protection</p>
                                  <p className="mt-1 text-xs text-slate-600">
                                    {hasPasskeyTrust
                                      ? "This session is currently backed by a passkey assertion."
                                      : passkeyCredentials.length
                                        ? "Use your passkey to strengthen this session before sensitive ownership actions."
                                        : "Add a passkey to make future ownership recovery and transfer checks harder to spoof."}
                                  </p>
                                </div>
                                <Badge variant="outline">
                                  {hasPasskeyTrust ? "Passkey verified" : passkeyCredentials.length ? `${passkeyCredentials.length} enrolled` : "Optional"}
                                </Badge>
                              </div>

                              <div className="mt-3 flex flex-wrap items-center gap-2">
                                <Button
                                  type="button"
                                  variant="outline"
                                  onClick={handleRegisterPasskey}
                                  disabled={registeringPasskey || loadingPasskeys}
                                  className={motionButtonClass}
                                >
                                  {registeringPasskey ? (
                                    <>
                                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                      Adding passkey
                                    </>
                                  ) : passkeyCredentials.length ? (
                                    "Add another passkey"
                                  ) : (
                                    "Add passkey for stronger ownership protection"
                                  )}
                                </Button>
                                {passkeyCredentials.length ? (
                                  <Button
                                    type="button"
                                    onClick={handleAssertPasskey}
                                    disabled={assertingPasskey || loadingPasskeys || hasPasskeyTrust}
                                    className={cn("bg-slate-900 text-white hover:bg-slate-800", motionButtonClass)}
                                  >
                                    {assertingPasskey ? (
                                      <>
                                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                        Verifying passkey
                                      </>
                                    ) : hasPasskeyTrust ? (
                                      "Passkey active"
                                    ) : (
                                      "Use passkey on this device"
                                    )}
                                  </Button>
                                ) : null}
                              </div>

                              {loadingPasskeys ? (
                                <p className="mt-3 text-xs text-slate-500">Loading enrolled passkeys...</p>
                              ) : passkeyCredentials.length ? (
                                <div className="mt-3 space-y-2">
                                  {passkeyCredentials.map((credential) => (
                                    <div
                                      key={credential.id}
                                      className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-slate-200 bg-white px-3 py-2"
                                    >
                                      <div className="min-w-0">
                                        <p className="font-medium text-slate-900">{credential.label || "Passkey"}</p>
                                        <p className="mt-1 text-xs text-slate-600">
                                          Added {formatDateTime(credential.createdAt)}. Last used {formatDateTime(credential.lastUsedAt)}.
                                        </p>
                                      </div>
                                      <Button
                                        type="button"
                                        variant="ghost"
                                        size="sm"
                                        onClick={() => handleDeletePasskey(credential.id)}
                                        disabled={deletingPasskeyId === credential.id}
                                        className="text-slate-600 hover:text-rose-800"
                                      >
                                        {deletingPasskeyId === credential.id ? (
                                          <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Removing
                                          </>
                                        ) : (
                                          "Remove"
                                        )}
                                      </Button>
                                    </div>
                                  ))}
                                </div>
                              ) : (
                                <p className="mt-3 text-xs text-slate-600">
                                  Email sign-in still works, but passkeys give higher-assurance ownership proof on supported devices.
                                </p>
                              )}
                            </div>
                          ) : (
                            <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">
                              Passkey protection is available on browsers and devices that support WebAuthn security keys.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-900">Get help with this product</p>
                      {verifyUxPolicy.allowFraudReport ? (
                        <Button
                          data-testid="verify-open-incident-drawer"
                          type="button"
                          variant="outline"
                          disabled={loading || claiming}
                          onClick={() => {
                            setReportReference(null);
                            setReportSupportRef(null);
                            setReportSupportStatus(null);
                            setReportSupportSla(null);
                            setReportTamperSummary(null);
                            setReportOpen(true);
                          }}
                          className={cn("border-rose-300 text-rose-800 hover:bg-rose-50 hover:text-rose-900", motionButtonClass)}
                        >
                          Report a problem
                        </Button>
                      ) : (
                        <Badge variant="outline">Help requests are handled by your product team</Badge>
                      )}
                    </div>
                    <p className="mt-3 text-sm leading-relaxed text-slate-700">
                      {verifyUxPolicy.allowFraudReport
                        ? "MSCQR adds the verification result, safety signals, and product details for you automatically."
                        : "Help for this product is currently handled through the product owner's support channel."}
                    </p>

                    <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Track an existing help request</p>
                      <div className="mt-2 grid gap-2 md:grid-cols-[1fr_1fr_auto]">
                        <Input
                          value={trackReference}
                          onChange={(e) => setTrackReference(e.target.value)}
                          placeholder="SUP-XXXXXXXXXX"
                        />
                        <Input
                          value={trackEmail}
                          onChange={(e) => setTrackEmail(e.target.value)}
                          placeholder="Contact email (optional)"
                        />
                        <Button data-testid="verify-track-ticket" variant="outline" onClick={handleTrackTicket} disabled={trackingTicket || loading}>
                          {trackingTicket ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Tracking
                            </>
                          ) : (
                            "Check status"
                          )}
                        </Button>
                      </div>

                      {trackedTicket ? (
                        <div className="mt-3 rounded-md border border-slate-200 bg-white p-3 text-xs text-slate-700">
                          <p>
                            Reference:{" "}
                            <span className="font-semibold">
                              {friendlyReferenceLabel(trackedTicket.referenceCode || trackReference, "Ticket")}
                            </span>
                          </p>
                          <p className="font-mono text-[11px] text-slate-500">{trackedTicket.referenceCode || trackReference}</p>
                          <p>Status: {getSupportStatusLabel(trackedTicket.status || "open")}</p>
                          {trackedTicket.handoffStage ? <p>Current stage: {toLabel(trackedTicket.handoffStage)}</p> : null}
                          {trackedTicket.sla?.dueAt ? (
                            <p>
                              SLA due: {new Date(trackedTicket.sla.dueAt).toLocaleString()}
                              {trackedTicket.sla?.isBreached ? " (Breached)" : ""}
                            </p>
                          ) : null}
                        </div>
                      ) : null}
                    </div>
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <p className="text-sm font-semibold text-slate-900">Privacy note</p>
                    <ul className="mt-3 list-disc space-y-1.5 pl-5 text-sm leading-relaxed text-slate-700">
                      <li>Sign-in is optional.</li>
                      <li>Platform stores scan events to detect duplicates.</li>
                      <li>Only coarse location context may be stored.</li>
                      <li>No precise tracking interface is shown to customers.</li>
                    </ul>
                  </section>

                  {(supportEmail || supportPhone || supportWebsite) && (
                    <section className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-700 shadow-sm">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Support Contact</p>
                      <div className="mt-2 space-y-1">
                        {supportEmail ? <p>Email: {supportEmail}</p> : null}
                        {supportPhone ? <p>Phone: {supportPhone}</p> : null}
                        {supportWebsite ? <p>Website: {supportWebsite}</p> : null}
                      </div>
                    </section>
                  )}
                </>
              )}
            </CardContent>
          )}

          {loading ? (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#66729242] backdrop-blur-[4px]">
              <PremiumScanLoader />
            </div>
          ) : null}
        </Card>
      </div>

      <Dialog open={claimConfirmOpen} onOpenChange={setClaimConfirmOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Confirm protection on this device</DialogTitle>
            <DialogDescription>
              This will protect the item on this device first.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
            <p>
              This protection stays tied to this device first. For stronger protection that follows your account, sign in with Google or email code.
            </p>
            <p className="text-xs text-slate-600">MSCQR does not show your raw IP address in the product UI.</p>
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setClaimConfirmOpen(false)} disabled={claiming}>
              Cancel
            </Button>
            <Button
              type="button"
              onClick={handleClaimProduct}
              disabled={claiming || loading}
              className="bg-slate-900 text-white hover:bg-slate-800"
            >
              {claiming ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Protecting
                </>
              ) : (
                "Confirm protection"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={transferOpen} onOpenChange={setTransferOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Start ownership transfer</DialogTitle>
            <DialogDescription>
              Create a short-lived secure link for the next owner. They can verify the product and accept the handover from that link.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-2">
              <Label>Recipient email (optional)</Label>
              <Input
                type="email"
                value={transferRecipientEmail}
                onChange={(e) => setTransferRecipientEmail(e.target.value)}
                placeholder="buyer@example.com"
                disabled={transferSubmitting}
              />
              <p className="text-xs text-slate-600">
                Leave this blank if you only want to copy the link and share it yourself.
              </p>
            </div>
            {issuedTransferLink ? (
              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs text-slate-700">
                <p className="font-medium text-slate-900">Latest handover link</p>
                <p className="mt-2 break-all font-mono">{issuedTransferLink}</p>
              </div>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setTransferOpen(false)} disabled={transferSubmitting}>
              Cancel
            </Button>
            {issuedTransferLink ? (
              <Button type="button" variant="outline" onClick={handleCopyTransferLink} disabled={transferSubmitting}>
                Copy link
              </Button>
            ) : null}
            <Button
              type="button"
              onClick={handleCreateTransfer}
              disabled={transferSubmitting}
              className="bg-slate-900 text-white hover:bg-slate-800"
            >
              {transferSubmitting ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Creating
                </>
              ) : (
                "Create handover link"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Sheet open={reportOpen} onOpenChange={handleReportDialogOpenChange}>
        <SheetContent
          data-testid="verify-report-sheet"
          side="right"
          className="w-full border-l-[#8d9db65f] bg-[linear-gradient(165deg,#fff_0%,#f9fbfd_36%,#f1e3dd_100%)] p-0 sm:max-w-[640px]"
        >
          <div className="flex h-full flex-col">
            <SheetHeader className="border-b border-[#8d9db63f] bg-white/70 px-6 py-5 text-left">
              <SheetTitle className="text-[#4f5b75]">Report a problem with this product</SheetTitle>
              <SheetDescription>
                Tell us what looked wrong. MSCQR adds the verification details for you automatically.
              </SheetDescription>
            </SheetHeader>

            <div className="flex-1 overflow-y-auto px-6 py-5">
              {reportReference ? (
                <div className="space-y-3 rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
                  <p>
                    Report submitted successfully. Case reference:{" "}
                    <span className="font-semibold">{friendlyReferenceLabel(reportReference, "Case")}</span>
                  </p>
                  <p className="font-mono text-xs text-emerald-950">{reportReference}</p>
                  {reportSupportRef ? (
                    <div className="rounded-md border border-emerald-300 bg-white/80 p-3 text-xs text-emerald-950">
                      <p>
                        Support ticket: <span className="font-semibold">{friendlyReferenceLabel(reportSupportRef, "Ticket")}</span>
                      </p>
                      <p data-testid="verify-report-support-ticket-raw" className="font-mono text-[11px]">{reportSupportRef}</p>
                      {reportSupportStatus ? <p>Status: {toLabel(reportSupportStatus)}</p> : null}
                      {reportSupportSla ? <p>SLA due by: {reportSupportSla}</p> : null}
                    </div>
                  ) : null}
                  {reportTamperSummary ? (
                    <p className="text-xs text-emerald-950">Attachment tamper checks: {reportTamperSummary}</p>
                  ) : null}
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label>Issue type</Label>
                    <Select value={reportType} onValueChange={setReportType}>
                      <SelectTrigger data-testid="verify-report-type">
                        <SelectValue placeholder="Select issue type" />
                      </SelectTrigger>
                      <SelectContent>
                        {INCIDENT_TYPE_OPTIONS.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Description</Label>
                    <Textarea
                      data-testid="verify-report-description"
                      value={reportDescription}
                      onChange={(e) => setReportDescription(e.target.value)}
                      placeholder="Describe what looked wrong or unexpected."
                      rows={4}
                      maxLength={2000}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Email (optional)</Label>
                    <Input
                      data-testid="verify-report-email"
                      type="email"
                      value={reportEmail}
                      onChange={(e) => setReportEmail(e.target.value)}
                      placeholder="you@example.com"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Attachment (optional)</Label>
                    <Input
                      type="file"
                      multiple
                      accept="image/png,image/jpeg,image/jpg,image/webp"
                      onChange={(e) => setReportPhotos(Array.from(e.target.files || []))}
                    />
                    <p className="text-xs text-slate-500">You can upload up to 4 images.</p>
                  </div>
                </div>
              )}
            </div>

            <SheetFooter className="border-t border-[#8d9db63f] bg-white/75 px-6 py-4">
              <Button type="button" variant="outline" onClick={() => setReportOpen(false)} disabled={loading || reporting}>
                {reportReference ? "Close" : "Cancel"}
              </Button>
              {!reportReference ? (
                <Button
                  data-testid="verify-report-submit"
                  type="button"
                  onClick={handleSubmitReport}
                  disabled={loading || reporting}
                  className={cn("bg-rose-900 text-white hover:bg-rose-950", motionButtonClass)}
                >
                  {reporting ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Submitting
                    </>
                  ) : (
                    "Send help request"
                  )}
                </Button>
              ) : null}
            </SheetFooter>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

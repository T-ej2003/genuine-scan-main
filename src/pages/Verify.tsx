import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
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
import { cn } from "@/lib/utils";
import { PremiumScanLoader } from "@/components/premium/PremiumScanLoader";
import { PREMIUM_PALETTE } from "@/components/premium/palette";
import {
  VerificationConfidenceMeter,
  deriveVerificationConfidence,
} from "@/components/premium/VerificationConfidenceMeter";
import { VerifiedAuthenticStamp } from "@/components/premium/VerifiedAuthenticStamp";
import { PremiumSectionAccordion } from "@/components/premium/PremiumSectionAccordion";

type VerificationClassification =
  | "FIRST_SCAN"
  | "LEGIT_REPEAT"
  | "SUSPICIOUS_DUPLICATE"
  | "BLOCKED_BY_SECURITY"
  | "NOT_READY_FOR_CUSTOMER_USE";

type OwnershipStatus = {
  isClaimed: boolean;
  claimedAt: string | null;
  isOwnedByRequester: boolean;
  isClaimedByAnother: boolean;
  canClaim: boolean;
  state?: "unclaimed" | "owned_by_you" | "owned_by_someone_else" | "claim_not_available";
  matchMethod?: "user" | "device_token" | "ip_fallback" | null;
};

type ScanSummary = {
  totalScans: number;
  firstVerifiedAt: string | null;
  latestVerifiedAt: string | null;
  firstVerifiedLocation?: string | null;
  latestVerifiedLocation?: string | null;
};

type VerifyPayload = {
  isAuthentic: boolean;
  message?: string;
  warningMessage?: string | null;
  code?: string;
  status?: string;
  scanOutcome?: string;

  classification?: VerificationClassification;
  reasons?: string[];
  scanSummary?: ScanSummary;
  ownershipStatus?: OwnershipStatus;
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

  policy?: any;
  scanSignals?: {
    distinctDeviceCount24h?: number;
    recentScanCount10m?: number;
    distinctCountryCount24h?: number;
    seenOnCurrentDeviceBefore?: boolean;
    previousScanSameDevice?: boolean | null;
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

const DEFAULT_VERIFY_POLICY = {
  showTimelineCard: true,
  showRiskCards: true,
  allowOwnershipClaim: true,
  allowFraudReport: true,
  mobileCameraAssist: true,
};

const INCIDENT_TYPE_OPTIONS = [
  { value: "counterfeit_suspected", label: "Counterfeit suspected" },
  { value: "duplicate_scan", label: "Duplicate scan" },
  { value: "tampered_label", label: "Tampered label" },
  { value: "wrong_product", label: "Wrong product" },
  { value: "other", label: "Other" },
] as const;

const CUSTOMER_TOKEN_KEY = "authenticqr_verify_customer_token";
const CUSTOMER_EMAIL_KEY = "authenticqr_verify_customer_email";
const APP_NAME = "AUTHENTIC QR";

const DEFAULT_OWNERSHIP_STATUS: OwnershipStatus = {
  isClaimed: false,
  claimedAt: null,
  isOwnedByRequester: false,
  isClaimedByAnother: false,
  canClaim: false,
};

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

const inferClassification = (result: VerifyPayload | null): VerificationClassification => {
  const explicit = String(result?.classification || "").toUpperCase();
  if (
    explicit === "FIRST_SCAN" ||
    explicit === "LEGIT_REPEAT" ||
    explicit === "SUSPICIOUS_DUPLICATE" ||
    explicit === "BLOCKED_BY_SECURITY" ||
    explicit === "NOT_READY_FOR_CUSTOMER_USE"
  ) {
    return explicit as VerificationClassification;
  }

  const status = String(result?.status || "").toUpperCase();
  const scanOutcome = String(result?.scanOutcome || "").toUpperCase();

  if (status === "BLOCKED" || scanOutcome === "BLOCKED") return "BLOCKED_BY_SECURITY";
  if (status === "DORMANT" || status === "ACTIVE" || status === "ALLOCATED" || status === "ACTIVATED") {
    return "NOT_READY_FOR_CUSTOMER_USE";
  }

  if (Boolean(result?.isAuthentic) && Boolean(result?.isFirstScan)) return "FIRST_SCAN";

  const duplicateSignals =
    Number(result?.scanSignals?.distinctDeviceCount24h ?? 0) > 1 ||
    Number(result?.scanSignals?.recentScanCount10m ?? 0) >= 3 ||
    Number(result?.scanSignals?.distinctCountryCount24h ?? 0) > 1 ||
    Number(result?.scanCount ?? 0) >= 4;

  if (Boolean(result?.isAuthentic) && duplicateSignals) return "SUSPICIOUS_DUPLICATE";
  if (Boolean(result?.isAuthentic)) return "LEGIT_REPEAT";

  return "NOT_READY_FOR_CUSTOMER_USE";
};

const deriveReasons = (result: VerifyPayload | null, classification: VerificationClassification): string[] => {
  if (Array.isArray(result?.reasons) && result?.reasons.length) return result.reasons;

  if (classification === "FIRST_SCAN") {
    return ["First successful verification recorded."];
  }

  if (classification === "LEGIT_REPEAT") {
    return ["Repeat verification behavior appears normal."];
  }

  if (classification === "BLOCKED_BY_SECURITY") {
    return ["Code is blocked by security policy or containment workflow."];
  }

  if (classification === "SUSPICIOUS_DUPLICATE") {
    const reasons: string[] = [];
    if (Number(result?.scanSignals?.distinctDeviceCount24h ?? 0) > 1) reasons.push("Multiple devices scanned this code recently.");
    if (Number(result?.scanSignals?.recentScanCount10m ?? 0) >= 3) reasons.push("High short-window scan burst detected.");
    if (Number(result?.scanSignals?.distinctCountryCount24h ?? 0) > 1) reasons.push("Recent scans came from multiple countries.");
    if (Number(result?.scanCount ?? 0) >= 4) reasons.push("High repeat scan count detected.");
    return reasons.length ? reasons : ["Unusual scan pattern requires caution."];
  }

  return ["Code lifecycle is not ready for customer verification."];
};

const deriveScanSummary = (result: VerifyPayload | null): ScanSummary => {
  if (result?.scanSummary) {
    return {
      totalScans: Number(result.scanSummary.totalScans || 0),
      firstVerifiedAt: result.scanSummary.firstVerifiedAt || null,
      latestVerifiedAt: result.scanSummary.latestVerifiedAt || null,
      firstVerifiedLocation: result.scanSummary.firstVerifiedLocation || null,
      latestVerifiedLocation: result.scanSummary.latestVerifiedLocation || null,
    };
  }

  const firstVerifiedAt = result?.firstVerifiedAt || result?.firstScanAt || null;
  const latestVerifiedAt = result?.latestVerifiedAt || result?.latestScanAt || null;

  return {
    totalScans: Number(result?.totalScans ?? result?.scanCount ?? 0),
    firstVerifiedAt,
    latestVerifiedAt,
    firstVerifiedLocation: result?.firstScanLocation || null,
    latestVerifiedLocation: result?.latestScanLocation || result?.previousScanLocation || null,
  };
};

const formatDateTime = (value: string | null | undefined) => {
  if (!value) return "Not available";
  const dt = new Date(value);
  if (!Number.isFinite(dt.getTime())) return "Not available";
  return dt.toLocaleString();
};

const toLabel = (value?: string | null) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

const SkeletonBlock = ({ className }: { className?: string }) => (
  <div aria-hidden className={cn("premium-shimmer rounded-md bg-[#bccad6]/45", className)} />
);

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isOffline, setIsOffline] = useState<boolean>(() => !navigator.onLine);
  const [retryAttempt, setRetryAttempt] = useState(0);
  const [retryNotice, setRetryNotice] = useState<string>("");

  const [customerToken, setCustomerToken] = useState<string>("");
  const [customerEmail, setCustomerEmail] = useState<string>("");

  const [otpEmail, setOtpEmail] = useState("");
  const [otpChallengeToken, setOtpChallengeToken] = useState("");
  const [otpMaskedEmail, setOtpMaskedEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);

  const [claiming, setClaiming] = useState(false);
  const [linkingClaim, setLinkingClaim] = useState(false);
  const [claimConfirmOpen, setClaimConfirmOpen] = useState(false);

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

  const token = useMemo(() => searchParams.get("t")?.trim() || "", [searchParams]);
  const codeParam = useMemo(() => {
    const raw = String(code || "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return raw.trim();
    }
  }, [code]);

  const requestKey = useMemo(() => {
    if (token) return `token:${token}|cust:${customerToken.slice(-10)}`;
    if (codeParam) return `code:${codeParam.toUpperCase()}|cust:${customerToken.slice(-10)}`;
    return "";
  }, [codeParam, customerToken, token]);

  const deviceId = useMemo(() => getOrCreateAnonDeviceId(), []);
  const inFlightRef = useRef(new Map<string, Promise<any>>());
  const verifyStartedAtRef = useRef<number>(0);
  const sentDroppedMetricRef = useRef(false);

  const displayedCode = result?.code || codeParam || "—";
  const classification = useMemo(() => inferClassification(result), [result]);
  const classMeta = CLASS_META[classification];
  const reasons = useMemo(() => deriveReasons(result, classification), [classification, result]);
  const scanSummary = useMemo(() => deriveScanSummary(result), [result]);
  const ownershipStatus = result?.ownershipStatus || DEFAULT_OWNERSHIP_STATUS;
  const verifyUxPolicy = { ...DEFAULT_VERIFY_POLICY, ...(result?.verifyUxPolicy || {}) };
  const showLinkClaim =
    Boolean(customerToken) && ownershipStatus.isOwnedByRequester && ownershipStatus.matchMethod && ownershipStatus.matchMethod !== "user";
  const showAuthenticStamp = classification === "FIRST_SCAN" || classification === "LEGIT_REPEAT";
  const confidenceScore = useMemo(
    () =>
      deriveVerificationConfidence({
        classification,
        totalScans: scanSummary.totalScans,
        distinctDeviceCount24h: result?.scanSignals?.distinctDeviceCount24h,
        recentScanCount10m: result?.scanSignals?.recentScanCount10m,
        distinctCountryCount24h: result?.scanSignals?.distinctCountryCount24h,
        warningMessage: result?.warningMessage || null,
      }),
    [
      classification,
      scanSummary.totalScans,
      result?.scanSignals?.distinctDeviceCount24h,
      result?.scanSignals?.recentScanCount10m,
      result?.scanSignals?.distinctCountryCount24h,
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
        ? "Duplicate risk indicators detected"
        : classification === "BLOCKED_BY_SECURITY"
          ? "Security controls blocked this code"
          : "No high-risk anomaly detected",
    details: reasons,
    recommendedAction:
      classification === "SUSPICIOUS_DUPLICATE" || classification === "BLOCKED_BY_SECURITY"
        ? "Review purchase source and report suspicious activity."
        : "Keep proof of purchase for future verification.",
  };

  const googleOauthUrl = String(import.meta.env.VITE_GOOGLE_OAUTH_URL || "").trim();
  const showSkeleton = loading && !result && !error;
  const motionButtonClass = "transition-transform duration-200 hover:scale-[1.02] active:scale-[0.99]";

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
              if (!navigator?.geolocation) return resolve({});
              navigator.geolocation.getCurrentPosition(
                (pos) =>
                  resolve({
                    lat: pos.coords.latitude,
                    lon: pos.coords.longitude,
                    acc: pos.coords.accuracy,
                  }),
                () => resolve({}),
                { enableHighAccuracy: false, timeout: 1500 }
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
          });
        })();

        inFlightRef.current.set(requestKey, pending);
        return pending;
      };

      const maxAttempts = 4;
      let response: any = null;
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
    } catch (err: any) {
      inFlightRef.current.delete(requestKey);
      setError(err?.message || "Verification failed");
      setResult(null);
    } finally {
      setLoading(false);
    }
  }, [codeParam, customerToken, deviceId, requestKey, token]);

  useEffect(() => {
    try {
      const savedToken = window.localStorage.getItem(CUSTOMER_TOKEN_KEY) || "";
      const savedEmail = window.localStorage.getItem(CUSTOMER_EMAIL_KEY) || "";
      setCustomerToken(savedToken);
      setCustomerEmail(savedEmail);
      if (!otpEmail && savedEmail) setOtpEmail(savedEmail);
    } catch {
      // ignore storage access issues
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    fetchVerification();
  }, [fetchVerification]);

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

      setCustomerToken(tokenValue);
      setCustomerEmail(emailValue);
      setOtpChallengeToken("");
      setOtpCode("");

      try {
        window.localStorage.setItem(CUSTOMER_TOKEN_KEY, tokenValue);
        window.localStorage.setItem(CUSTOMER_EMAIL_KEY, emailValue);
      } catch {
        // ignore storage issues
      }

      toast({ title: "Signed in", description: "Protection sign-in is active for this device." });
      await fetchVerification();
    } finally {
      setOtpVerifying(false);
    }
  };

  const handleSignOut = async () => {
    setCustomerToken("");
    setCustomerEmail("");
    setOtpChallengeToken("");
    setOtpCode("");

    try {
      window.localStorage.removeItem(CUSTOMER_TOKEN_KEY);
      window.localStorage.removeItem(CUSTOMER_EMAIL_KEY);
    } catch {
      // ignore storage issues
    }

    await fetchVerification();
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
      } else if (response.data.claimResult === "ALREADY_OWNED_BY_YOU") {
        toast({ title: "Already owned", description: "This product is already linked to your account." });
      } else if (response.data.claimResult === "LINKED_TO_SIGNED_IN_ACCOUNT") {
        toast({ title: "Ownership linked", description: "Your device claim is now linked to your signed-in account." });
      } else {
        toast({
          title: "Ownership claimed",
          description:
            response.data.claimResult === "CLAIMED_DEVICE"
              ? "Claim saved for this device/network. Sign in for portable protection."
              : "Product ownership is now linked to your account.",
        });
      }

      const nextOwnership = response.data.ownershipStatus || DEFAULT_OWNERSHIP_STATUS;
      setResult((prev) =>
        prev
          ? {
              ...prev,
              classification:
                (response.data.classification as VerificationClassification | undefined) || prev.classification,
              reasons: response.data.reasons || prev.reasons,
              warningMessage: response.data.warningMessage || prev.warningMessage,
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

      const payload: any = response.data || {};
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
          const trackData: any = tracking.data || {};
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

      setTrackedTicket((response.data as any) || null);
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
            : `${classMeta.title}. ${classMeta.subtitle}`}
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
                            <h1 className="mt-1 text-2xl font-semibold tracking-tight">{classMeta.title}</h1>
                            <p className="mt-2 text-sm leading-relaxed text-white/90">{classMeta.subtitle}</p>
                            <p className="mt-2 text-sm leading-relaxed text-white/90">{result?.message || "Verification completed."}</p>
                            {result?.warningMessage ? (
                              <p className="mt-2 text-sm leading-relaxed text-white/90">{result.warningMessage}</p>
                            ) : null}
                            {showAuthenticStamp ? <VerifiedAuthenticStamp className="mt-3" /> : null}
                          </div>
                        </div>
                        <div className="flex items-start gap-2 sm:gap-3">
                          <Badge className={cn("h-fit text-[11px] font-semibold uppercase tracking-wide", classMeta.badgeClass)}>
                            {classMeta.badge}
                          </Badge>
                          <VerificationConfidenceMeter
                            classification={classification}
                            totalScans={scanSummary.totalScans}
                            distinctDeviceCount24h={result?.scanSignals?.distinctDeviceCount24h}
                            recentScanCount10m={result?.scanSignals?.recentScanCount10m}
                            distinctCountryCount24h={result?.scanSignals?.distinctCountryCount24h}
                            warningMessage={result?.warningMessage || null}
                            className="w-[182px]"
                          />
                        </div>
                      </div>
                    </div>

                    <div className="rounded-xl border border-[#8d9db65e] bg-white/90 px-3 py-2 shadow-sm premium-surface-in">
                      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-600">
                        <span className="inline-flex items-center gap-1.5">
                          <Lock className="h-3.5 w-3.5 text-slate-700" />
                          Encrypted verification
                        </span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span>Scan securely recorded for fraud prevention</span>
                        <span className="hidden h-1 w-1 rounded-full bg-slate-300 sm:inline-block" />
                        <span className="font-medium text-slate-700">Secured by {APP_NAME}</span>
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
                          badge: <Badge className="border-[#8d9db65e] bg-[#bccad638] text-[#4f5b75]">{classMeta.badge}</Badge>,
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
                      ]}
                    />
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                    <p className="text-sm font-semibold text-slate-900">Scan summary</p>
                    <div className="mt-4 grid gap-3 md:grid-cols-3">
                      <div className="rounded-lg border border-slate-200/90 bg-slate-50/70 p-4 shadow-sm">
                        <p className="text-xs uppercase tracking-wide text-slate-500">Total scans</p>
                        <p className="mt-2 text-3xl font-semibold tracking-tight text-slate-900">{scanSummary.totalScans}</p>
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
                      <p className="text-sm font-semibold text-slate-900">Ownership</p>
                      {customerToken ? <Badge variant="outline">Signed in for protection</Badge> : null}
                    </div>
                    <div className="mt-3 space-y-4">
                      <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                        <p className="font-medium">Claim ownership</p>
                        <p className="mt-1">
                          Claiming helps protect you from duplicates and supports faster help if something looks wrong.
                        </p>
                        <p className="mt-2 text-xs text-slate-600">
                          Device claim uses a secure device cookie plus hashed network evidence. Raw IP is never shown.
                        </p>
                      </div>

                      {ownershipStatus.isOwnedByRequester ? (
                        <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                          <p className="font-semibold">Owned by you</p>
                          <p className="mt-1">Claimed at: {formatDateTime(ownershipStatus.claimedAt)}</p>
                          {ownershipStatus.matchMethod && ownershipStatus.matchMethod !== "user" ? (
                            <p className="mt-1 text-xs text-emerald-800">
                              Current proof: {ownershipStatus.matchMethod === "device_token" ? "this device" : "network evidence"}.
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
                              "Claim on this device"
                            )}
                          </Button>
                          {googleOauthUrl && !customerToken ? (
                            <Button asChild variant="outline" className={motionButtonClass} disabled={loading || claiming}>
                              <a href={googleOauthUrl}>Sign in with Google for better protection</a>
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
                            "Link this device claim to your account"
                          )}
                        </Button>
                      ) : null}

                      {!customerToken ? (
                        <div className="space-y-3 rounded-lg border border-slate-200 p-3">
                          <p className="text-sm font-medium text-slate-900">Sign in for better protection (optional)</p>
                          <p className="text-xs text-slate-600">
                            Sign-in makes ownership portable across devices. Device-only claim may be less reliable if your network changes.
                          </p>
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
                        <div className="flex flex-wrap items-center gap-3">
                          <div className="rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                            Signed in as {customerEmail}
                          </div>
                          <Button type="button" variant="outline" onClick={handleSignOut} disabled={loading} className={motionButtonClass}>
                            Sign out
                          </Button>
                        </div>
                      )}
                    </div>
                  </section>

                  <section className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-900">Report</p>
                      {verifyUxPolicy.allowFraudReport ? (
                        <Button
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
                          Open incident drawer
                        </Button>
                      ) : (
                        <Badge variant="outline">Reporting managed by tenant policy</Badge>
                      )}
                    </div>
                    <p className="mt-3 text-sm leading-relaxed text-slate-700">
                      {verifyUxPolicy.allowFraudReport
                        ? "Reporting sends classification, reason summary, scan summary, ownership status, and tamper checks automatically."
                        : "Counterfeit reporting is currently handled through your product owner support channel."}
                    </p>

                    <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <p className="text-xs uppercase tracking-wide text-slate-500">Track existing support ticket</p>
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
                        <Button variant="outline" onClick={handleTrackTicket} disabled={trackingTicket || loading}>
                          {trackingTicket ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Tracking
                            </>
                          ) : (
                            "Track status"
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
                          <p>Status: {toLabel(trackedTicket.status || "open")}</p>
                          {trackedTicket.handoffStage ? <p>Workflow stage: {toLabel(trackedTicket.handoffStage)}</p> : null}
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
            <DialogTitle>Confirm device claim</DialogTitle>
            <DialogDescription>
              This will claim ownership on this device using secure device and network evidence.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
            <p>
              This claim is tied to this device/network and may be weaker if your network changes. For stronger, portable ownership, sign in with Google or OTP and link the claim.
            </p>
            <p className="text-xs text-slate-600">Privacy: IP is hashed server-side and never displayed.</p>
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
                  Claiming
                </>
              ) : (
                "Confirm claim"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Sheet open={reportOpen} onOpenChange={handleReportDialogOpenChange}>
        <SheetContent
          side="right"
          className="w-full border-l-[#8d9db65f] bg-[linear-gradient(165deg,#fff_0%,#f9fbfd_36%,#f1e3dd_100%)] p-0 sm:max-w-[640px]"
        >
          <div className="flex h-full flex-col">
            <SheetHeader className="border-b border-[#8d9db63f] bg-white/70 px-6 py-5 text-left">
              <SheetTitle className="text-[#4f5b75]">Report Suspected Counterfeit</SheetTitle>
              <SheetDescription>
                Provide investigation details. Verification metadata will be attached automatically.
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
                      <p className="font-mono text-[11px]">{reportSupportRef}</p>
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
                      <SelectTrigger>
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
                      value={reportDescription}
                      onChange={(e) => setReportDescription(e.target.value)}
                      placeholder="Describe what looked suspicious."
                      rows={4}
                      maxLength={2000}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Email (optional)</Label>
                    <Input
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
                    <p className="text-xs text-slate-500">Up to 4 images can be uploaded.</p>
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
                    "Submit report"
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

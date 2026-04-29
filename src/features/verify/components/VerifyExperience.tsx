import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  CheckCircle2,
  CircleDashed,
  ExternalLink,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  MapPin,
  ShieldCheck,
  ShoppingBag,
  Store,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { getOrCreateAnonDeviceId } from "@/lib/anon-device";
import { BASE_URL } from "@/lib/api/internal-client-core";
import {
  APP_NAME,
  deriveReasons,
  formatDateTime,
  inferClassification,
  normalizeVerifyCode,
  readCachedGeo,
  toLabel,
  type CustomerTrustIntake,
  type VerificationClassification,
  type VerificationSessionSummary,
  type VerifyPayload,
} from "@/features/verify/verify-model";
import {
  isWebAuthnSupported,
  startWebAuthnAuthentication,
  startWebAuthnRegistration,
  type WebAuthnCredentialSummary,
} from "@/lib/webauthn";

type FlowStep = "identity" | "purchase" | "source" | "context" | "concern" | "intent" | "result";

type ProviderOption = {
  id: "google";
  label: string;
};

type CustomerResultCategory = "genuine" | "suspicious" | "invalid" | "blocked" | "pending";

const RESULT_COPY: Record<
  CustomerResultCategory,
  {
    title: string;
    subtitle: string;
    explanation: string;
    badge: string;
    cardClass: string;
    iconClass: string;
  }
> = {
  genuine: {
    title: "This garment is genuine",
    subtitle: "Verified by MSCQR",
    explanation: "This QR label matches a brand record and passed the available verification checks.",
    badge: "Verified",
    cardClass: "border-emerald-200 bg-emerald-50 text-emerald-950",
    iconClass: "bg-emerald-100 text-emerald-700",
  },
  suspicious: {
    title: "We could not fully verify this item",
    subtitle: "Some scan details need review.",
    explanation:
      "This can happen when a QR label is scanned unusually often, from unexpected locations, or when the label status needs checking.",
    badge: "Review needed",
    cardClass: "border-amber-200 bg-amber-50 text-amber-950",
    iconClass: "bg-amber-100 text-amber-700",
  },
  invalid: {
    title: "We could not find this QR label",
    subtitle: "The code was not found.",
    explanation: "Check that the code is correct. If this came from a garment tag, you can report it to the brand.",
    badge: "Not found",
    cardClass: "border-slate-200 bg-slate-50 text-slate-950",
    iconClass: "bg-slate-100 text-slate-700",
  },
  blocked: {
    title: "This QR label is blocked",
    subtitle: "The brand has blocked this label.",
    explanation: "The brand has blocked this label from verification. Please contact the seller or brand before purchasing.",
    badge: "Blocked",
    cardClass: "border-red-200 bg-red-50 text-red-950",
    iconClass: "bg-red-100 text-red-700",
  },
  pending: {
    title: "We could not fully verify this item",
    subtitle: "This label is not ready for customer verification.",
    explanation: "The brand record exists, but this QR label is not ready to be shown as verified yet.",
    badge: "Not ready",
    cardClass: "border-indigo-200 bg-indigo-50 text-indigo-950",
    iconClass: "bg-indigo-100 text-indigo-700",
  },
};

const LABEL_STATUS_COPY: Record<string, string> = {
  DORMANT: "Not active yet",
  ACTIVE: "Active",
  ALLOCATED: "Assigned",
  PRINTED: "Printed",
  REDEEMED: "First scan completed",
  SCANNED: "Scanned",
  BLOCKED: "Blocked",
  PRINT_CONFIRMED: "Printed",
  NOT_CONFIRMED: "Not confirmed",
  UNKNOWN: "Not available",
};

const LEGACY_VERIFY_EMAIL_STORAGE_KEYS = ["mscqr_verify_customer_email", "authenticqr_verify_customer_email"] as const;

const DEFAULT_INTAKE: CustomerTrustIntake = {
  purchaseChannel: "online",
  sourceCategory: "marketplace",
  platformName: "",
  sellerName: "",
  listingUrl: "",
  orderReference: "",
  storeName: "",
  purchaseCity: "",
  purchaseCountry: "",
  purchaseDate: "",
  packagingState: "sealed",
  packagingConcern: "none",
  scanReason: "routine_check",
  ownershipIntent: "verify_only",
  notes: "",
};

const maskCode = (value?: string | null) => {
  const normalized = normalizeVerifyCode(value);
  if (!normalized) return "MSCQR";
  return `${normalized.slice(0, Math.min(4, normalized.length))}${normalized.length > 4 ? `-${normalized.slice(-4)}` : ""}`;
};

const clearLegacyStoredCustomerSession = () => {
  try {
    for (const key of LEGACY_VERIFY_EMAIL_STORAGE_KEYS) {
      window.localStorage.removeItem(key);
    }
  } catch {
    // Ignore storage issues.
  }
};

const sessionProofStorageKey = (sessionId: string) => `mscqr_verify_session_proof:${sessionId}`;

const persistSessionProofToken = (sessionId: string, token: string | null | undefined) => {
  const normalizedSessionId = String(sessionId || "").trim();
  if (!normalizedSessionId) return;
  try {
    const normalizedToken = String(token || "").trim();
    if (normalizedToken) window.sessionStorage.setItem(sessionProofStorageKey(normalizedSessionId), normalizedToken);
    else window.sessionStorage.removeItem(sessionProofStorageKey(normalizedSessionId));
  } catch {
    // Ignore storage issues.
  }
};

const readSessionProofToken = (sessionId: string) => {
  const normalizedSessionId = String(sessionId || "").trim();
  if (!normalizedSessionId) return "";
  try {
    return String(window.sessionStorage.getItem(sessionProofStorageKey(normalizedSessionId)) || "").trim();
  } catch {
    return "";
  }
};

const buildProviderHref = (provider: ProviderOption["id"], returnTo: string) => {
  const params = new URLSearchParams({ returnTo });
  return `${BASE_URL}/verify/auth/oauth/${provider}/start?${params.toString()}`;
};

const validateStep = (step: FlowStep, intake: CustomerTrustIntake) => {
  switch (step) {
    case "purchase":
      return Boolean(intake.purchaseChannel);
    case "source":
      if (intake.purchaseChannel === "online") {
        return Boolean(String(intake.platformName || "").trim());
      }
      if (intake.purchaseChannel === "offline") {
        return Boolean(String(intake.storeName || "").trim() && String(intake.purchaseCountry || "").trim());
      }
      return true;
    case "context":
      return Boolean(intake.packagingState && intake.packagingConcern);
    case "concern":
      return Boolean(intake.scanReason);
    case "intent":
      return Boolean(intake.ownershipIntent);
    default:
      return true;
  }
};

function SectionFrame({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <Card className="border-mscqr-border bg-white text-mscqr-primary shadow-sm">
      <CardHeader className="space-y-3 border-b border-mscqr-border px-4 pb-5 pt-5 sm:px-6 sm:pb-6 sm:pt-6">
        <div className="text-sm font-semibold text-mscqr-accent">{eyebrow}</div>
        <div className="space-y-2">
          <CardTitle className="text-xl text-mscqr-primary sm:text-2xl">{title}</CardTitle>
          <CardDescription className="max-w-2xl text-sm leading-6 text-mscqr-secondary">{description}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-6 p-4 sm:p-8">{children}</CardContent>
    </Card>
  );
}

function ProviderButton({ provider }: { provider: ProviderOption }) {
  return (
    <a
      href={buildProviderHref(provider.id, `${window.location.origin}${window.location.pathname}${window.location.search}`)}
      className="flex items-center justify-between rounded-2xl border border-mscqr-border bg-white px-4 py-4 text-sm font-medium text-mscqr-primary transition hover:border-mscqr-accent/50 hover:bg-mscqr-surface-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent/35"
    >
      <span>Continue with {provider.label}</span>
      <ExternalLink className="h-4 w-4 text-mscqr-muted" />
    </a>
  );
}

const plainStatus = (value?: string | null) => {
  const key = String(value || "UNKNOWN").trim().toUpperCase();
  return LABEL_STATUS_COPY[key] || toLabel(key);
};

const getCustomerResultCategory = (
  payload: VerifyPayload | null,
  classification: VerificationClassification
): CustomerResultCategory => {
  const outcome = String(payload?.publicOutcome || "").toUpperCase();
  const status = String(payload?.status || payload?.labelState || "").toUpperCase();
  if (payload?.isBlocked || classification === "BLOCKED_BY_SECURITY" || status === "BLOCKED" || outcome === "BLOCKED") {
    return "blocked";
  }
  if (classification === "NOT_FOUND" || outcome === "NOT_FOUND" || outcome === "INTEGRITY_ERROR") {
    return "invalid";
  }
  if (classification === "NOT_READY_FOR_CUSTOMER_USE") {
    return "pending";
  }
  if (
    classification === "SUSPICIOUS_DUPLICATE" ||
    outcome === "REVIEW_REQUIRED" ||
    outcome === "LIMITED_PROVENANCE" ||
    String(payload?.riskDisposition || "").toUpperCase().includes("REVIEW")
  ) {
    return "suspicious";
  }
  return payload?.isAuthentic ? "genuine" : "suspicious";
};

const getScanHistoryLabel = (payload: VerifyPayload | null) => {
  if (!payload) return "Not available";
  if (payload.isFirstScan || payload.classification === "FIRST_SCAN") return "First scan completed";
  const count = payload.scanCount || payload.totalScans || payload.scanSummary?.totalScans;
  if (count && count > 1) return `${count} scans recorded`;
  if (payload.latestScanAt || payload.latestVerifiedAt) return "Scanned before";
  return "No scan history available";
};

const getPrintCheckLabel = (payload: VerifyPayload | null, session?: VerificationSessionSummary | null) => {
  const printState = payload?.printTrustState || session?.printTrustState || "";
  if (!printState) return payload?.batch?.printedAt ? "Printed" : "Not available";
  return plainStatus(printState);
};

const getLastCheckedLabel = (payload: VerifyPayload | null) => {
  const timestamp =
    payload?.latestVerifiedAt ||
    payload?.latestScanAt ||
    payload?.verificationTimeline?.latestSeen ||
    payload?.scanSummary?.latestVerifiedAt ||
    null;
  return timestamp ? formatDateTime(timestamp) : "Checked just now";
};

function ResultIcon({ category }: { category: CustomerResultCategory }) {
  if (category === "genuine") return <CheckCircle2 className="h-7 w-7" aria-hidden="true" />;
  if (category === "blocked") return <Ban className="h-7 w-7" aria-hidden="true" />;
  if (category === "invalid" || category === "pending") return <CircleDashed className="h-7 w-7" aria-hidden="true" />;
  return <AlertTriangle className="h-7 w-7" aria-hidden="true" />;
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-mscqr-border bg-mscqr-surface-muted/45 px-4 py-3">
      <div className="text-sm font-medium text-mscqr-secondary">{label}</div>
      <div className="mt-1 text-base font-semibold text-mscqr-primary">{value}</div>
    </div>
  );
}

export default function VerifyExperience() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { toast } = useToast();

  const token = String(searchParams.get("t") || "").trim();
  const sessionIdFromUrl = String(searchParams.get("session") || "").trim();
  const codeParam = useMemo(() => {
    const raw = String(code || "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return raw.trim();
    }
  }, [code]);

  const [customerAuthenticated, setCustomerAuthenticated] = useState(false);
  const [customerEmail, setCustomerEmail] = useState("");
  const [session, setSession] = useState<VerificationSessionSummary | null>(null);
  const [lockedResult, setLockedResult] = useState<VerifyPayload | null>(null);
  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [booting, setBooting] = useState(true);
  const [oauthResolved, setOauthResolved] = useState(false);

  const [otpEmail, setOtpEmail] = useState("");
  const [otpChallengeToken, setOtpChallengeToken] = useState("");
  const [otpMaskedEmail, setOtpMaskedEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);

  const [intake, setIntake] = useState<CustomerTrustIntake>(DEFAULT_INTAKE);
  const [, setFlowStep] = useState<FlowStep>("identity");
  const [submittingReveal, setSubmittingReveal] = useState(false);
  const [challengeRetrying, setChallengeRetrying] = useState(false);

  const [passkeyCredentials, setPasskeyCredentials] = useState<WebAuthnCredentialSummary[]>([]);
  const [loadingPasskeys, setLoadingPasskeys] = useState(false);
  const [registeringPasskey, setRegisteringPasskey] = useState(false);
  const [assertingPasskey, setAssertingPasskey] = useState(false);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState("");

  const [claiming, setClaiming] = useState(false);
  const [acceptingTransfer, setAcceptingTransfer] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reportReason, setReportReason] = useState("counterfeit_suspected");
  const [lastSupportTicketRef, setLastSupportTicketRef] = useState("");
  const [showConcernForm, setShowConcernForm] = useState(false);
  const [socialProviders, setSocialProviders] = useState<ProviderOption[]>([]);

  const deviceId = useMemo(() => getOrCreateAnonDeviceId(), []);
  const passkeySupported = isWebAuthnSupported();
  const classification = useMemo(
    () => inferClassification(result || lockedResult || session?.verification || null),
    [lockedResult, result, session?.verification]
  );
  const reasonList = useMemo(
    () => deriveReasons(result || lockedResult || session?.verification || null, classification),
    [classification, lockedResult, result, session?.verification]
  );
  const currentCode = normalizeVerifyCode(result?.code || lockedResult?.code || session?.verification?.code || session?.code || codeParam);
  const authReady = customerAuthenticated || session?.authState === "VERIFIED";
  const displaySessionSummary = session || null;
  const challengeRequired = Boolean(result?.challenge?.required || lockedResult?.challenge?.required || session?.challengeRequired);
  const challengeCompleted = Boolean(result?.challenge?.completed || lockedResult?.challenge?.completed || session?.challengeCompleted);
  const challengeCompletedBy =
    result?.challenge?.completedBy || lockedResult?.challenge?.completedBy || session?.challengeCompletedBy || null;

  const updateIntake = useCallback(<K extends keyof CustomerTrustIntake>(key: K, value: CustomerTrustIntake[K]) => {
    setIntake((prev) => ({ ...prev, [key]: value }));
  }, []);

  const loadCustomerPasskeys = useCallback(async () => {
    if (!passkeySupported || !customerAuthenticated) {
      setPasskeyCredentials([]);
      setLoadingPasskeys(false);
      return;
    }

    setLoadingPasskeys(true);
    try {
      const response = await apiClient.getCustomerPasskeyCredentials();
      setPasskeyCredentials(response.success ? response.data?.items || [] : []);
    } finally {
      setLoadingPasskeys(false);
    }
  }, [customerAuthenticated, passkeySupported]);

  const applySignedInCustomer = useCallback(
    (emailValue: string) => {
      const normalizedEmail = String(emailValue || "").trim();
      setCustomerAuthenticated(Boolean(normalizedEmail));
      setCustomerEmail(normalizedEmail);
      setOtpEmail(normalizedEmail);
      setFlowStep("purchase");
    },
    []
  );

  const hydrateCustomerAuthSession = useCallback(
    (nextState?: { customer?: { email?: string | null } | null; auth?: { authenticated?: boolean } | null } | null) => {
      const authenticated = Boolean(nextState?.auth?.authenticated && nextState?.customer?.email);
      if (!authenticated) {
        setCustomerAuthenticated(false);
        return;
      }

      const nextEmail = String(nextState?.customer?.email || "").trim();
      if (!nextEmail) {
        setCustomerAuthenticated(false);
        return;
      }

      applySignedInCustomer(nextEmail);
    },
    [applySignedInCustomer]
  );

  const loadGeoContext = useCallback(async () => {
    return new Promise<{ lat?: number; lon?: number; acc?: number }>((resolve) => {
      const cached = readCachedGeo();
      if (!navigator.geolocation) return resolve(cached);
      navigator.geolocation.getCurrentPosition(
        (position) => {
          resolve({
            lat: position.coords.latitude,
            lon: position.coords.longitude,
            acc: position.coords.accuracy,
          });
        },
        () => resolve(cached),
        { enableHighAccuracy: false, timeout: 4_000, maximumAge: 300_000 }
      );
    });
  }, []);

  useEffect(() => {
    clearLegacyStoredCustomerSession();
  }, []);

  useEffect(() => {
    let cancelled = false;

    const handleProviderReturn = async () => {
      const hashParams = new URLSearchParams(window.location.hash.startsWith("#") ? window.location.hash.slice(1) : window.location.hash);
      const ticket = String(hashParams.get("customer_auth_exchange") || "").trim();
      const authError = String(hashParams.get("customer_auth_error") || "").trim();
      const clearHash = () => {
        window.history.replaceState({}, document.title, `${window.location.pathname}${window.location.search}`);
      };

      if (authError) {
        clearHash();
        toast({
          title: "Could not complete social sign-in",
          description: authError.replace(/_/g, " "),
          variant: "destructive",
        });
        if (!cancelled) setOauthResolved(true);
        return;
      }

      if (!ticket) {
        if (!cancelled) setOauthResolved(true);
        return;
      }

      setBooting(true);
      try {
        const response = await apiClient.exchangeCustomerOAuth(ticket);
        if (!response.success || !response.data?.customer?.email) {
          throw new Error(response.error || "Could not complete social sign-in.");
        }
        clearHash();
        hydrateCustomerAuthSession(response.data);
        if (!cancelled) {
          setBooting(false);
          setOauthResolved(true);
        }
      } catch (nextError: unknown) {
        clearHash();
        toast({
          title: "Could not complete social sign-in",
          description: nextError instanceof Error ? nextError.message : "Please try again.",
          variant: "destructive",
        });
        if (!cancelled) {
          setBooting(false);
          setOauthResolved(true);
        }
      }
    };

    void handleProviderReturn();

    return () => {
      cancelled = true;
    };
  }, [hydrateCustomerAuthSession, toast]);

  useEffect(() => {
    let cancelled = false;

    const loadProviders = async () => {
      const response = await apiClient.getCustomerAuthProviders();
      if (cancelled) return;
      setSocialProviders(response.success ? response.data?.items || [] : []);
    };

    void loadProviders();

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;

    const loadCustomerAuthSession = async () => {
      const response = await apiClient.getCustomerAuthSession();
      if (cancelled || !response.success) return;
      hydrateCustomerAuthSession(response.data || null);
    };

    void loadCustomerAuthSession();

    return () => {
      cancelled = true;
    };
  }, [hydrateCustomerAuthSession]);

  const bootstrapSession = useCallback(async () => {
    setBooting(true);
    setError(null);

    try {
      if (sessionIdFromUrl) {
        const sessionProofToken = readSessionProofToken(sessionIdFromUrl);
        const sessionResponse = await apiClient.getVerificationSession(sessionIdFromUrl, sessionProofToken || undefined);
        if (!sessionResponse.success || !sessionResponse.data) {
          throw new Error(sessionResponse.error || "Could not load verification session.");
        }

        const nextSession = sessionResponse.data as unknown as VerificationSessionSummary;
        if (nextSession.sessionProofToken) {
          persistSessionProofToken(nextSession.sessionId, nextSession.sessionProofToken);
        }
        setSession(nextSession);
        const nextVerification = (nextSession.verification as VerifyPayload | null) || null;
        const sessionCode = normalizeVerifyCode(nextVerification?.code || nextSession.code || codeParam);
        setLockedResult((prev) =>
          nextVerification || (normalizeVerifyCode(prev?.code || "") === sessionCode ? prev : null)
        );
        setResult((prev) =>
          nextVerification || (normalizeVerifyCode(prev?.code || "") === sessionCode ? prev : null)
        );
        if (nextSession.intake) {
          setIntake((prev) => ({ ...prev, ...(nextSession.intake as CustomerTrustIntake) }));
        }

        if (nextSession.revealed && nextSession.verification) {
          setFlowStep("result");
        } else if (nextSession.authState === "VERIFIED" || customerAuthenticated) {
          setFlowStep(nextSession.intakeCompleted ? "intent" : "purchase");
        } else {
          setFlowStep("identity");
        }
        return;
      }

      const geo = await loadGeoContext();

      const verificationResponse = token
        ? await apiClient.scanToken(token, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
          })
        : await apiClient.verifyQRCode(codeParam, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
          });

      if (!verificationResponse.success || !verificationResponse.data) {
        throw new Error(verificationResponse.error || "Verification service unavailable.");
      }

      const nextResult = verificationResponse.data as VerifyPayload;
      setLockedResult(nextResult);

      if (!nextResult.decisionId) {
        setResult(nextResult);
        setFlowStep("result");
        return;
      }

      const sessionResponse = await apiClient.startVerificationSession(
        nextResult.decisionId,
        token ? "SIGNED_SCAN" : "MANUAL_CODE"
      );

      if (!sessionResponse.success || !sessionResponse.data) {
        throw new Error(sessionResponse.error || "Could not prepare secure verification.");
      }

      const nextSession = sessionResponse.data as unknown as VerificationSessionSummary;
      if (nextSession.sessionProofToken) {
        persistSessionProofToken(nextSession.sessionId, nextSession.sessionProofToken);
      }
      setSession(nextSession);

      const canonicalCode = normalizeVerifyCode(nextResult.code || nextSession.code || codeParam);
      const params = new URLSearchParams();
      params.set("session", nextSession.sessionId);
      if (token) params.set("t", token);
      navigate(`/verify/${encodeURIComponent(canonicalCode)}?${params.toString()}`, { replace: true });

      if (nextSession.authState === "VERIFIED" || customerAuthenticated) {
        setFlowStep("purchase");
      } else {
        setFlowStep("identity");
      }
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : "Could not load verification flow.");
    } finally {
      setBooting(false);
    }
  }, [codeParam, customerAuthenticated, deviceId, loadGeoContext, navigate, sessionIdFromUrl, token]);

  useEffect(() => {
    if (!oauthResolved) return;
    bootstrapSession();
  }, [bootstrapSession, oauthResolved]);

  useEffect(() => {
    if (!authReady) return;
    loadCustomerPasskeys();
  }, [authReady, loadCustomerPasskeys]);

  const handleRequestOtp = async () => {
    const email = otpEmail.trim();
    if (!email) {
      toast({ title: "Email required", description: "Enter your email to continue.", variant: "destructive" });
      return;
    }

    setOtpSending(true);
    try {
      const response = await apiClient.requestVerifyEmailOtp(email);
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not send OTP.");
      }
      setOtpChallengeToken(response.data.challengeToken);
      setOtpMaskedEmail(response.data.maskedEmail);
      toast({ title: "Code sent", description: `Verification code sent to ${response.data.maskedEmail}.` });
    } catch (nextError: unknown) {
      toast({
        title: "Could not send code",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setOtpSending(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (!otpChallengeToken || otpCode.trim().length < 6) {
      toast({ title: "Invalid code", description: "Enter the 6-digit code from your email.", variant: "destructive" });
      return;
    }

    setOtpVerifying(true);
    try {
      const response = await apiClient.verifyEmailOtp(otpChallengeToken, otpCode.trim());
      if (!response.success || !response.data?.customer?.email) {
        throw new Error(response.error || "Could not verify the email code.");
      }

      applySignedInCustomer(response.data.customer.email || otpEmail.trim());
      setOtpChallengeToken("");
      setOtpCode("");
      toast({ title: "Signed in", description: "Your verification session is now tied to your identity." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not verify code",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setOtpVerifying(false);
    }
  };

  const handleCompleteChallenge = async () => {
    if (!authReady) {
      toast({
        title: "Sign in required",
        description: "Sign in first so MSCQR can re-check this label with your verified identity.",
        variant: "destructive",
      });
      return;
    }

    setChallengeRetrying(true);
    try {
      const geo = await loadGeoContext();
      const verificationResponse = token
        ? await apiClient.scanToken(token, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
          })
        : await apiClient.verifyQRCode(codeParam, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
          });

      if (!verificationResponse.success || !verificationResponse.data) {
        throw new Error(verificationResponse.error || "Could not re-check the label.");
      }

      const nextResult = verificationResponse.data as VerifyPayload;
      setLockedResult(nextResult);
      setResult(nextResult);

      if (!nextResult.decisionId) {
        setFlowStep("result");
        toast({
          title: "Review check updated",
          description: "MSCQR re-checked this label with your verified identity.",
        });
        return;
      }

      const sessionResponse = await apiClient.startVerificationSession(
        nextResult.decisionId,
        token ? "SIGNED_SCAN" : "MANUAL_CODE"
      );

      if (!sessionResponse.success || !sessionResponse.data) {
        throw new Error(sessionResponse.error || "Could not prepare the updated verification session.");
      }

      const nextSession = sessionResponse.data as unknown as VerificationSessionSummary;
      if (nextSession.sessionProofToken) {
        persistSessionProofToken(nextSession.sessionId, nextSession.sessionProofToken);
      }
      setSession(nextSession);

      const canonicalCode = normalizeVerifyCode(nextResult.code || nextSession.code || codeParam);
      const params = new URLSearchParams();
      params.set("session", nextSession.sessionId);
      if (token) params.set("t", token);
      navigate(`/verify/${encodeURIComponent(canonicalCode)}?${params.toString()}`, { replace: true });
      setFlowStep("purchase");

      toast({
        title: nextResult.challenge?.completed ? "Review check completed" : "Label re-checked",
        description: nextResult.challenge?.completed
          ? "MSCQR re-checked this repeat scan with your verified identity."
          : "MSCQR refreshed the label result using your verified identity.",
      });
    } catch (nextError: unknown) {
      toast({
        title: "Could not complete review check",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setChallengeRetrying(false);
    }
  };

  const handleSubmitIntakeAndReveal = useCallback(async (intakeOverride?: Partial<CustomerTrustIntake>) => {
    if (!session?.sessionId || !authReady) {
      toast({ title: "Sign in required", description: "Complete sign-in before revealing the result.", variant: "destructive" });
      return;
    }
    const intakePayload: CustomerTrustIntake = {
      ...intake,
      ...(intakeOverride || {}),
    };
    if (!validateStep("intent", intakePayload)) {
      toast({ title: "Complete this step", description: "Tell MSCQR what you want to do next.", variant: "destructive" });
      return;
    }

    if (intakeOverride) {
      setIntake((prev) => ({ ...prev, ...intakeOverride }));
    }

    setSubmittingReveal(true);
    try {
      const sessionProofToken = readSessionProofToken(session.sessionId);
      const intakeResponse = await apiClient.submitVerificationIntake(
        session.sessionId,
        intakePayload as Record<string, unknown>,
        sessionProofToken || undefined
      );
      if (!intakeResponse.success) {
        throw new Error(intakeResponse.error || "Could not save the verification intake.");
      }

      const revealResponse = await apiClient.revealVerificationSession(
        session.sessionId,
        sessionProofToken || undefined
      );
      if (!revealResponse.success || !revealResponse.data) {
        throw new Error(revealResponse.error || "Could not reveal the verification result.");
      }

      const nextSession = revealResponse.data as unknown as VerificationSessionSummary;
      setSession(nextSession);
      setResult((nextSession.verification as VerifyPayload | null) || lockedResult);
      setFlowStep("result");
      toast({ title: "Verification ready", description: "MSCQR has locked the label decision and recorded your purchase context." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not finish verification",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setSubmittingReveal(false);
    }
  }, [authReady, intake, lockedResult, session, toast]);

  const handleSkipOptionalQuestions = useCallback(() => {
    void handleSubmitIntakeAndReveal({
      purchaseChannel: "unknown",
      sourceCategory: "unknown",
      platformName: "",
      sellerName: "",
      listingUrl: "",
      orderReference: "",
      storeName: "",
      purchaseCity: "",
      purchaseCountry: "",
      purchaseDate: "",
      packagingState: "unsure",
      packagingConcern: "unsure",
      scanReason: "routine_check",
      ownershipIntent: "verify_only",
    });
  }, [handleSubmitIntakeAndReveal]);

  const handleClaimOwnership = async () => {
    if (!currentCode) return;
    setClaiming(true);
    try {
      const response = await apiClient.claimVerifiedProduct(currentCode);
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not claim this product.");
      }
      setResult((prev) =>
        prev
          ? {
              ...prev,
              ownershipStatus: response.data?.ownershipStatus || prev.ownershipStatus,
              warningMessage: response.data?.message || prev.warningMessage,
            }
          : prev
      );
      toast({ title: "Ownership updated", description: response.data.message || "Ownership state has been updated." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not claim ownership",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setClaiming(false);
    }
  };

  const handleAcceptTransfer = async () => {
    const transferToken = String(searchParams.get("transfer") || "").trim();
    if (!transferToken || !authReady) return;

    setAcceptingTransfer(true);
    try {
      const response = await apiClient.acceptOwnershipTransfer({ token: transferToken });
      if (!response.success) {
        throw new Error(response.error || "Could not accept the ownership transfer.");
      }
      toast({ title: "Transfer accepted", description: response.data?.message || "Ownership transfer completed." });
      await bootstrapSession();
    } catch (nextError: unknown) {
      toast({
        title: "Could not accept transfer",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setAcceptingTransfer(false);
    }
  };

  const handleReportConcern = async () => {
    if (!currentCode) return;
    setReporting(true);
    try {
      const response = await apiClient.reportFraud({
        code: currentCode,
        reason: reportReason,
        incidentType: reportReason,
        description: String(intake.notes || "").trim() || `Customer reported ${reportReason.replace(/_/g, " ")} during verification.`,
        contactEmail: customerEmail || undefined,
        observedStatus: result?.status,
        observedOutcome: result?.latestDecisionOutcome || result?.scanOutcome,
        pageUrl: window.location.href,
        sessionId: session?.sessionId,
        decisionId: result?.decisionId || session?.decisionId,
      });
      if (!response.success) {
        throw new Error(response.error || "Could not submit the concern.");
      }
      const reportData = (response.data || {}) as { supportTicketRef?: string | null };
      setLastSupportTicketRef(String(reportData.supportTicketRef || "").trim());
      setShowConcernForm(false);
      toast({
        title: "Concern submitted",
        description: reportData.supportTicketRef
          ? `Support ticket ${reportData.supportTicketRef} has been opened.`
          : "MSCQR support has received your report.",
      });
    } catch (nextError: unknown) {
      toast({
        title: "Could not report concern",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setReporting(false);
    }
  };

  const handleRegisterPasskey = async () => {
    if (!authReady) return;
    setRegisteringPasskey(true);
    try {
      const begin = await apiClient.beginCustomerPasskeyRegistration();
      if (!begin.success || !begin.data) throw new Error(begin.error || "Could not start passkey registration.");
      const credential = await startWebAuthnRegistration(begin.data, `${APP_NAME} customer protection`);
      const finish = await apiClient.finishCustomerPasskeyRegistration(credential);
      if (!finish.success || !finish.data?.customer?.email) throw new Error(finish.error || "Could not finish passkey registration.");
      applySignedInCustomer(finish.data.customer.email || customerEmail || otpEmail);
      await loadCustomerPasskeys();
      await bootstrapSession();
      toast({ title: "Passkey added", description: "Future ownership actions can use stronger proof on this device." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not add passkey",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setRegisteringPasskey(false);
    }
  };

  const handleAssertPasskey = async () => {
    if (!authReady) return;
    setAssertingPasskey(true);
    try {
      const begin = await apiClient.beginCustomerPasskeyAssertion();
      if (!begin.success || !begin.data) throw new Error(begin.error || "Could not start passkey verification.");
      const assertion = await startWebAuthnAuthentication(begin.data);
      const finish = await apiClient.finishCustomerPasskeyAssertion(assertion);
      if (!finish.success || !finish.data?.customer?.email) throw new Error(finish.error || "Could not verify the passkey.");
      applySignedInCustomer(finish.data.customer.email || customerEmail || otpEmail);
      await loadCustomerPasskeys();
      await bootstrapSession();
      toast({ title: "Passkey verified", description: "This session now carries stronger ownership proof." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not verify passkey",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setAssertingPasskey(false);
    }
  };

  const handleDeletePasskey = async (credentialId: string) => {
    if (!authReady) return;
    setDeletingPasskeyId(credentialId);
    try {
      const response = await apiClient.deleteCustomerPasskeyCredential(credentialId);
      if (!response.success) throw new Error(response.error || "Could not remove the passkey.");
      await loadCustomerPasskeys();
      toast({ title: "Passkey removed", description: "That device can no longer step up ownership automatically." });
    } catch (nextError: unknown) {
      toast({
        title: "Could not remove passkey",
        description: nextError instanceof Error ? nextError.message : "Please try again.",
        variant: "destructive",
      });
    } finally {
      setDeletingPasskeyId("");
    }
  };

  if (booting) {
    return (
      <div className="min-h-screen bg-mscqr-background-soft px-4 py-10 text-mscqr-primary">
        <div className="mx-auto max-w-3xl">
          <div className="rounded-[28px] border border-mscqr-border bg-white p-6 shadow-sm sm:p-10">
            <div className="space-y-4">
              <Badge variant="outline" className="bg-mscqr-surface-muted text-mscqr-secondary">
                {maskCode(codeParam)}
              </Badge>
              <h1 className="max-w-2xl text-3xl font-semibold text-mscqr-primary sm:text-4xl">Checking your garment QR label</h1>
              <p className="max-w-2xl text-sm leading-7 text-mscqr-secondary sm:text-base">
                MSCQR is checking the QR label, brand record, print status, and unusual scan patterns.
              </p>
            </div>
            <div className="mt-8 flex items-center gap-3 rounded-2xl border border-mscqr-border bg-mscqr-surface-muted px-5 py-4 text-mscqr-primary">
              <Loader2 className="h-5 w-5 animate-spin" />
              <div className="text-sm">{token ? "Reading the scanned QR label..." : "Checking the entered QR label..."}</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-mscqr-background-soft px-4 py-10 text-mscqr-primary">
        <div className="mx-auto max-w-3xl rounded-[28px] border border-mscqr-border bg-white p-8 shadow-sm">
          <Badge variant="outline" className="bg-mscqr-surface-muted text-mscqr-secondary">
            MSCQR verification
          </Badge>
          <h1 className="mt-4 text-3xl font-semibold">We could not check this garment</h1>
          <p className="mt-3 text-sm leading-7 text-mscqr-secondary">{error}</p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild>
              <Link to="/verify">Enter code again</Link>
            </Button>
            <Button variant="outline" asChild>
              <Link to="/trust">Trust & Security</Link>
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const canReveal = Boolean(session?.sessionId && authReady);
  const displayResult = result || lockedResult || session?.verification || null;
  const displayClassification = inferClassification(displayResult);
  const resultCategory = getCustomerResultCategory(displayResult, displayClassification);
  const resultCopy = RESULT_COPY[resultCategory];
  const brandName = displayResult?.licensee?.brandName || displayResult?.licensee?.name || displaySessionSummary?.brandName || "Brand";
  const manufacturerName = displayResult?.batch?.manufacturer?.name || "";
  const supportEmail = displayResult?.licensee?.supportEmail || "support@mscqr.com";
  const supportPhone = displayResult?.licensee?.supportPhone || "";
  const brandWebsite = displayResult?.licensee?.website || displayResult?.batch?.manufacturer?.website || "";
  const labelStatus = plainStatus(displayResult?.labelState || displayResult?.status || displaySessionSummary?.labelState);
  const showQuickCheck = !displayResult || (challengeRequired && !challengeCompleted && !authReady);
  const canClaimGarment = Boolean(displayResult?.ownershipStatus?.canClaim && authReady);
  const canReportConcern = Boolean(displayResult?.verifyUxPolicy?.allowFraudReport ?? true);

  return (
    <div className="min-h-screen bg-mscqr-background-soft px-3 py-4 text-mscqr-primary sm:px-6 sm:py-10">
      <div className="mx-auto max-w-6xl space-y-5 sm:space-y-7">
        <header className="rounded-[28px] border border-mscqr-border bg-white p-5 shadow-sm sm:p-8">
          <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className="bg-mscqr-surface-muted text-mscqr-secondary">
                  {brandName}
                </Badge>
                <Badge variant="outline" className="bg-white text-mscqr-secondary">
                  {displaySessionSummary?.maskedCode || maskCode(currentCode)}
                </Badge>
              </div>
              <div className={`rounded-[26px] border p-5 sm:p-6 ${showQuickCheck ? RESULT_COPY.suspicious.cardClass : resultCopy.cardClass}`}>
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start">
                  <div className={`inline-flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl ${showQuickCheck ? RESULT_COPY.suspicious.iconClass : resultCopy.iconClass}`}>
                    {showQuickCheck ? <AlertTriangle className="h-7 w-7" aria-hidden="true" /> : <ResultIcon category={resultCategory} />}
                  </div>
                  <div className="min-w-0 space-y-2">
                    <div className="text-sm font-semibold">{showQuickCheck ? "Quick check needed" : resultCopy.badge}</div>
                    <h1 className="text-3xl font-semibold tracking-tight sm:text-5xl">
                      {showQuickCheck ? "We need one quick check before showing the full result." : resultCopy.title}
                    </h1>
                    <p className="text-lg font-medium">{showQuickCheck ? "Sign in to continue." : resultCopy.subtitle}</p>
                    <p className="max-w-3xl text-sm leading-7 sm:text-base">
                      {showQuickCheck
                        ? "This helps protect customers and brands when a scan needs extra review."
                        : resultCopy.explanation}
                    </p>
                  </div>
                </div>
              </div>
              {displayResult ? (
                <div className="flex flex-wrap gap-3">
                  {canClaimGarment ? (
                    <Button onClick={handleClaimOwnership} disabled={claiming}>
                      {claiming ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                      Register this garment
                    </Button>
                  ) : !authReady ? (
                    <Button
                      onClick={() => document.getElementById("customer-sign-in")?.scrollIntoView({ behavior: "smooth", block: "start" })}
                    >
                      Save this verification
                    </Button>
                  ) : null}
                  {canReportConcern ? (
                    <Button variant="outline" onClick={() => setShowConcernForm(true)}>
                      <AlertTriangle className="mr-2 h-4 w-4" />
                      Report a concern
                    </Button>
                  ) : null}
                  <Button variant="ghost" asChild>
                    <Link to="/verify">Verify another garment</Link>
                  </Button>
                </div>
              ) : null}
            </div>

            <div className="rounded-2xl border border-mscqr-border bg-mscqr-surface-muted p-5 text-sm leading-6 text-mscqr-secondary lg:max-w-sm">
              <div className="flex items-center gap-2 font-semibold text-mscqr-primary">
                <ShieldCheck className="h-4 w-4" />
                What MSCQR checks
              </div>
              <p className="mt-3">
                MSCQR checks the QR label, brand record, print status, and unusual scan patterns. A QR code can be copied, so suspicious repeats may still need brand review.
              </p>
            </div>
          </div>
        </header>

        {displayResult ? (
          <SectionFrame
            eyebrow="Result details"
            title="What we found"
            description="Simple verification details are shown first. Support details are available below if a brand or MSCQR support team asks for them."
          >
            {challengeRequired && !challengeCompleted ? (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
                <div className="font-semibold">We need one quick check before showing the full result.</div>
                <div className="mt-1">This scan needs an extra review step before you rely on it.</div>
                <div className="mt-3">
                  {authReady ? (
                    <Button variant="outline" onClick={handleCompleteChallenge} disabled={challengeRetrying}>
                      {challengeRetrying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                      Complete quick check
                    </Button>
                  ) : (
                    <Button variant="outline" onClick={() => document.getElementById("customer-sign-in")?.scrollIntoView({ behavior: "smooth", block: "start" })}>
                      Sign in for quick check
                    </Button>
                  )}
                </div>
              </div>
            ) : null}
            {challengeCompleted ? (
              <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm leading-6 text-emerald-950">
                Additional review check completed{challengeCompletedBy === "CUSTOMER_IDENTITY" ? " with your verified identity." : "."}
              </div>
            ) : null}
            {displayResult.warningMessage ? (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
                {displayResult.warningMessage}
              </div>
            ) : null}
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
              <DetailRow label="Brand" value={brandName} />
              {manufacturerName ? <DetailRow label="Manufacturer" value={manufacturerName} /> : null}
              <DetailRow label="QR label" value={displaySessionSummary?.maskedCode || maskCode(currentCode)} />
              <DetailRow label="Status" value={labelStatus} />
              <DetailRow label="Scan history" value={getScanHistoryLabel(displayResult)} />
              <DetailRow label="Print check" value={getPrintCheckLabel(displayResult, displaySessionSummary)} />
              <DetailRow label="Last checked" value={getLastCheckedLabel(displayResult)} />
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5 text-sm leading-6 text-slate-700">
                <div className="font-semibold text-slate-950">What this means</div>
                <p className="mt-2">
                  {resultCategory === "genuine"
                    ? "The QR label matched an MSCQR brand record and passed the available checks."
                    : "The scan needs caution. Check the garment tag, seller details, and brand support guidance before relying on it."}
                </p>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-white p-5 text-sm leading-6 text-slate-700">
                <div className="font-semibold text-slate-950">A helpful note</div>
                <p className="mt-2">
                  MSCQR helps brands spot copied labels and unusual repeat scans, but no QR label can prove by itself that copying is impossible.
                </p>
              </div>
            </div>
            <details className="rounded-2xl border border-slate-200 bg-white p-5 text-sm text-slate-700">
              <summary className="cursor-pointer font-semibold text-slate-950">Technical details for support</summary>
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                <DetailRow label="Verification result" value={displayClassification.replace(/_/g, " ").toLowerCase()} />
                <DetailRow label="Verification confidence" value={plainStatus(displayResult.proofTier || "Not available")} />
                <DetailRow label="Scan risk" value={plainStatus(displayResult.riskDisposition || "Clear")} />
                <DetailRow label="Source check" value={plainStatus(displayResult.proofSource || "Not available")} />
                <DetailRow label="Decision reference" value={<span className="break-all font-mono text-sm">{displayResult.decisionId || session?.decisionId || "Not available"}</span>} />
                <DetailRow label="Session reference" value={<span className="break-all font-mono text-sm">{session?.sessionId || "Not available"}</span>} />
              </div>
              <div className="mt-4 rounded-xl bg-slate-50 p-4">
                <div className="font-medium text-slate-950">Support notes</div>
                <ul className="mt-2 list-disc space-y-1 pl-5">
                  {reasonList.length ? reasonList.map((reason) => <li key={reason}>{reason}</li>) : <li>No additional support notes were recorded.</li>}
                </ul>
              </div>
            </details>
          </SectionFrame>
        ) : null}

        {!displayResult && authReady && challengeRequired && !challengeCompleted ? (
          <SectionFrame
            eyebrow="Quick check"
            title="Complete one quick check"
            description="This scan needs an extra review step before MSCQR can show the full result."
          >
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
              <div className="font-semibold">We need one quick check before showing the full result.</div>
              <p className="mt-1">This helps the brand review unusual scan activity without changing the original verification decision.</p>
              <div className="mt-3">
                <Button variant="outline" onClick={handleCompleteChallenge} disabled={challengeRetrying}>
                  {challengeRetrying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  Complete quick check
                </Button>
              </div>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && canReveal ? (
          <SectionFrame
            eyebrow="Optional"
            title="Help the brand review this scan"
            description="These questions are optional. They help the brand understand suspicious scans and do not change the verification result."
          >
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="purchaseChannel">Where did you get this garment?</Label>
                <Select value={intake.purchaseChannel || "unknown"} onValueChange={(value) => updateIntake("purchaseChannel", value as CustomerTrustIntake["purchaseChannel"])}>
                  <SelectTrigger id="purchaseChannel">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="online">Bought online</SelectItem>
                    <SelectItem value="offline">Bought in store</SelectItem>
                    <SelectItem value="gifted">Gifted or transferred</SelectItem>
                    <SelectItem value="unknown">I am not sure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="sellerName">Seller or store name</Label>
                <Input id="sellerName" value={intake.sellerName || intake.storeName || ""} onChange={(event) => updateIntake("sellerName", event.target.value)} placeholder="Optional" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="purchaseCountry">Country</Label>
                <Input id="purchaseCountry" value={intake.purchaseCountry || ""} onChange={(event) => updateIntake("purchaseCountry", event.target.value)} placeholder="Optional" />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="packagingConcern">Is the QR tag damaged or copied?</Label>
                <Select value={intake.packagingConcern || "none"} onValueChange={(value) => updateIntake("packagingConcern", value as CustomerTrustIntake["packagingConcern"])}>
                  <SelectTrigger id="packagingConcern">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No concern</SelectItem>
                    <SelectItem value="minor">Maybe</SelectItem>
                    <SelectItem value="major">Yes, it looks concerning</SelectItem>
                    <SelectItem value="unsure">I am not sure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="scanReason">Why did you scan?</Label>
                <Select value={intake.scanReason || "routine_check"} onValueChange={(value) => updateIntake("scanReason", value as CustomerTrustIntake["scanReason"])}>
                  <SelectTrigger id="scanReason">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="routine_check">Routine check</SelectItem>
                    <SelectItem value="new_seller">New seller</SelectItem>
                    <SelectItem value="pricing_concern">Price looked unusual</SelectItem>
                    <SelectItem value="packaging_concern">Tag or packaging concern</SelectItem>
                    <SelectItem value="authenticity_concern">Authenticity concern</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="notes">Anything else you want the brand to know?</Label>
                <Textarea
                  id="notes"
                  value={intake.notes || ""}
                  onChange={(event) => updateIntake("notes", event.target.value)}
                  placeholder="Optional"
                  rows={4}
                />
              </div>
            </div>
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button variant="ghost" onClick={handleSkipOptionalQuestions} disabled={submittingReveal}>
                Skip optional questions
              </Button>
              <Button onClick={() => void handleSubmitIntakeAndReveal()} disabled={submittingReveal}>
                {submittingReveal ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                Save answers and update result
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {!authReady ? (
          <SectionFrame
            eyebrow="Optional sign-in"
            title={showQuickCheck ? "Sign in to continue" : "Sign in to save this item"}
            description={
              showQuickCheck
                ? "This scan needs one quick check before the full result can be shown."
                : "You can save proof of verification or register this garment if the brand supports it."
            }
          >
            <div id="customer-sign-in" className="grid gap-4 lg:grid-cols-[1.15fr,0.85fr]">
              <div className="space-y-4">
                {socialProviders.length ? (
                  <div className="grid gap-3 sm:grid-cols-2">
                    {socialProviders.map((provider) => (
                      <ProviderButton key={provider.id} provider={provider} />
                    ))}
                  </div>
                ) : null}
                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                    <Mail className="h-4 w-4" />
                    Continue with email
                  </div>
                  <div className="mt-4 grid gap-4">
                    <div className="grid gap-2">
                      <Label htmlFor="otp-email">Email</Label>
                      <Input
                        id="otp-email"
                        value={otpEmail}
                        onChange={(event) => setOtpEmail(event.target.value)}
                        placeholder="you@example.com"
                        type="email"
                      />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      <Button onClick={handleRequestOtp} disabled={otpSending}>
                        {otpSending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                        Send code
                      </Button>
                      {otpChallengeToken ? (
                        <Badge className="border-slate-300 bg-white text-slate-700">
                          Code sent to {otpMaskedEmail || "your inbox"}.
                        </Badge>
                      ) : null}
                    </div>
                    {otpChallengeToken ? (
                      <div className="grid gap-4 md:grid-cols-[1fr,auto] md:items-end">
                        <div className="grid gap-2">
                          <Label htmlFor="otp-code">6-digit code</Label>
                          <Input id="otp-code" value={otpCode} onChange={(event) => setOtpCode(event.target.value)} placeholder="123456" />
                        </div>
                        <Button onClick={handleVerifyOtp} disabled={otpVerifying}>
                          {otpVerifying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
                          Verify and continue
                        </Button>
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-white p-5 text-sm leading-6 text-slate-600">
                <div className="flex items-center gap-2 font-semibold text-slate-900">
                  <Lock className="h-4 w-4" />
                  Why sign in?
                </div>
                <p className="mt-3">
                  Sign-in is optional for normal scans. It helps you save this verification and gives the brand better context if you report a concern.
                </p>
              </div>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && (canClaimGarment || String(searchParams.get("transfer") || "").trim() || passkeySupported) ? (
          <SectionFrame
            eyebrow="Account"
            title="Save or protect this garment"
            description="These actions are optional and do not change the verification result."
          >
            <div className="grid gap-3">
              {canClaimGarment ? (
                <Button onClick={handleClaimOwnership} disabled={claiming}>
                  {claiming ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  Register this garment
                </Button>
              ) : null}
              {String(searchParams.get("transfer") || "").trim() ? (
                <Button variant="outline" onClick={handleAcceptTransfer} disabled={!authReady || acceptingTransfer}>
                  {acceptingTransfer ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  Accept ownership transfer
                </Button>
              ) : null}
              {passkeySupported ? (
                <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                    <KeyRound className="h-4 w-4" />
                    Extra sign-in protection
                  </div>
                  <div className="text-sm leading-6 text-slate-600">
                    A passkey can protect future saved garment and transfer actions for this account.
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <Button variant="outline" onClick={handleRegisterPasskey} disabled={registeringPasskey}>
                      {registeringPasskey ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <KeyRound className="mr-2 h-4 w-4" />}
                      Add passkey
                    </Button>
                    <Button variant="outline" onClick={handleAssertPasskey} disabled={assertingPasskey || !passkeyCredentials.length}>
                      {assertingPasskey ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <KeyRound className="mr-2 h-4 w-4" />}
                      Verify passkey
                    </Button>
                  </div>
                  {loadingPasskeys ? (
                    <div className="text-sm text-slate-500">Loading passkeys...</div>
                  ) : passkeyCredentials.length ? (
                    <div className="grid gap-2">
                      {passkeyCredentials.map((credential) => (
                        <div key={credential.id} className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm">
                          <div>
                            <div className="font-medium text-slate-900">{credential.label}</div>
                            <div className="text-slate-500">Last used: {formatDateTime(credential.lastUsedAt || null)}</div>
                          </div>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeletePasskey(credential.id)}
                            disabled={deletingPasskeyId === credential.id}
                          >
                            {deletingPasskeyId === credential.id ? <Loader2 className="h-4 w-4 animate-spin" /> : "Remove"}
                          </Button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-slate-500">No passkeys added yet.</div>
                  )}
                </div>
              ) : null}
            </div>
          </SectionFrame>
        ) : null}

        {showConcernForm && canReportConcern ? (
          <SectionFrame
            eyebrow="Report"
            title="Report a concern"
            description="Tell the brand what worried you. You can cancel and return to the result at any time."
          >
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="report-reason">What do you want to report?</Label>
                <Select value={reportReason} onValueChange={setReportReason}>
                  <SelectTrigger id="report-reason">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="counterfeit_suspected">I suspect this is not genuine</SelectItem>
                    <SelectItem value="duplicate_scan">This QR label has been scanned unusually</SelectItem>
                    <SelectItem value="tampered_label">The tag looks damaged or copied</SelectItem>
                    <SelectItem value="wrong_product">The label does not match the garment</SelectItem>
                    <SelectItem value="other">Something else</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="report-notes">What happened?</Label>
                <Textarea
                  id="report-notes"
                  value={intake.notes || ""}
                  onChange={(event) => updateIntake("notes", event.target.value)}
                  placeholder="Optional details for the brand"
                  rows={4}
                />
              </div>
            </div>
            <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
              <Button variant="ghost" onClick={() => setShowConcernForm(false)} disabled={reporting}>
                Cancel
              </Button>
              <Button data-testid="verify-report-concern" onClick={handleReportConcern} disabled={reporting}>
                {reporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <AlertTriangle className="mr-2 h-4 w-4" />}
                Submit concern
              </Button>
            </div>
            {lastSupportTicketRef ? (
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-950">
                Concern submitted. Support reference:{" "}
                <span data-testid="verify-report-support-ticket-raw" className="font-mono font-semibold">
                  {lastSupportTicketRef}
                </span>
              </div>
            ) : null}
          </SectionFrame>
        ) : lastSupportTicketRef ? (
          <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-950">
            Concern submitted. Support reference:{" "}
            <span data-testid="verify-report-support-ticket-raw" className="font-mono font-semibold">
              {lastSupportTicketRef}
            </span>
          </div>
        ) : null}

        <SectionFrame
          eyebrow="Support"
          title="Need help with this garment?"
          description="If the result is unclear, check the tag, contact the brand, or report a concern."
        >
          <div className="grid gap-3 text-sm leading-6 text-slate-700">
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="font-semibold text-slate-950">Brand support</div>
              <div className="mt-2 space-y-1">
                <div>{supportEmail}</div>
                {supportPhone ? <div>{supportPhone}</div> : null}
                {brandWebsite ? (
                  <a className="inline-flex items-center gap-1 text-mscqr-accent underline" href={brandWebsite} target="_blank" rel="noreferrer">
                    Visit brand site
                    <ExternalLink className="h-3 w-3" />
                  </a>
                ) : null}
              </div>
            </div>
          </div>
        </SectionFrame>

        <div className="flex flex-col gap-2 text-sm text-mscqr-muted sm:flex-row sm:items-center sm:justify-between">
          <Link to="/verify" className="inline-flex items-center gap-2 hover:text-mscqr-primary">
            <ArrowLeft className="h-4 w-4" />
            Verify another garment
          </Link>
          <Link to="/trust" className="inline-flex items-center gap-2 hover:text-mscqr-primary">
            Trust & Security
            <ExternalLink className="h-4 w-4" />
          </Link>
        </div>

        {authReady ? (
          <div className="flex items-center justify-end">
            <Button
              variant="ghost"
              onClick={async () => {
                await apiClient.logoutCustomerVerifySession();
                clearLegacyStoredCustomerSession();
                setCustomerAuthenticated(false);
                setSession((prev) => (prev ? { ...prev, authState: "PENDING" } : prev));
                setPasskeyCredentials([]);
                setFlowStep("identity");
              }}
            >
              Sign out
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

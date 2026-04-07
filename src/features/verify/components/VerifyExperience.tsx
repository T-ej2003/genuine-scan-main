import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
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
  Sparkles,
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
  CUSTOMER_EMAIL_KEY,
  CUSTOMER_TOKEN_KEY,
  LEGACY_CUSTOMER_EMAIL_KEY,
  LEGACY_CUSTOMER_TOKEN_KEY,
  deriveReasons,
  formatDateTime,
  inferClassification,
  normalizeVerifyCode,
  readCachedGeo,
  readStoredValue,
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

const FLOW_STEPS: Array<{ id: FlowStep; label: string }> = [
  { id: "identity", label: "Identity" },
  { id: "purchase", label: "Purchase" },
  { id: "source", label: "Source" },
  { id: "context", label: "Context" },
  { id: "concern", label: "Concern" },
  { id: "intent", label: "Reveal" },
];

const STEP_META: Record<
  VerificationClassification,
  {
    title: string;
    badge: string;
    tone: string;
    icon: React.ReactNode;
  }
> = {
  FIRST_SCAN: {
    title: "MSCQR confirmed this label",
    badge: "Confirmed",
    tone: "border-emerald-200 bg-emerald-50 text-emerald-950",
    icon: <ShieldCheck className="h-5 w-5" />,
  },
  LEGIT_REPEAT: {
    title: "MSCQR confirmed this code again",
    badge: "Recorded",
    tone: "border-emerald-200 bg-emerald-50 text-emerald-950",
    icon: <ShieldCheck className="h-5 w-5" />,
  },
  SUSPICIOUS_DUPLICATE: {
    title: "Review required",
    badge: "Review required",
    tone: "border-amber-200 bg-amber-50 text-amber-950",
    icon: <AlertTriangle className="h-5 w-5" />,
  },
  BLOCKED_BY_SECURITY: {
    title: "Do not rely on this code",
    badge: "Blocked",
    tone: "border-rose-200 bg-rose-50 text-rose-950",
    icon: <Ban className="h-5 w-5" />,
  },
  NOT_READY_FOR_CUSTOMER_USE: {
    title: "Not ready for customer verification",
    badge: "Not ready",
    tone: "border-slate-200 bg-slate-100 text-slate-950",
    icon: <CircleDashed className="h-5 w-5" />,
  },
  NOT_FOUND: {
    title: "Code not found",
    badge: "Not found",
    tone: "border-slate-200 bg-slate-100 text-slate-950",
    icon: <CircleDashed className="h-5 w-5" />,
  },
};

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

const persistCustomerSession = (token: string, email: string) => {
  const nextToken = String(token || "").trim();
  const nextEmail = String(email || "").trim();

  try {
    if (nextToken) window.localStorage.setItem(CUSTOMER_TOKEN_KEY, nextToken);
    else window.localStorage.removeItem(CUSTOMER_TOKEN_KEY);

    if (nextEmail) window.localStorage.setItem(CUSTOMER_EMAIL_KEY, nextEmail);
    else window.localStorage.removeItem(CUSTOMER_EMAIL_KEY);

    window.localStorage.removeItem(LEGACY_CUSTOMER_TOKEN_KEY);
    window.localStorage.removeItem(LEGACY_CUSTOMER_EMAIL_KEY);
  } catch {
    // Ignore storage issues.
  }
};

const clearStoredCustomerSession = () => {
  try {
    window.localStorage.removeItem(CUSTOMER_TOKEN_KEY);
    window.localStorage.removeItem(CUSTOMER_EMAIL_KEY);
    window.localStorage.removeItem(LEGACY_CUSTOMER_TOKEN_KEY);
    window.localStorage.removeItem(LEGACY_CUSTOMER_EMAIL_KEY);
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

function StepRail({ activeStep, authenticated }: { activeStep: FlowStep; authenticated: boolean }) {
  const visibleSteps = authenticated ? FLOW_STEPS : FLOW_STEPS.filter((step) => step.id === "identity");
  const activeIndex = visibleSteps.findIndex((step) => step.id === activeStep);

  return (
    <div className="grid gap-3 sm:grid-cols-3 xl:grid-cols-6">
      {visibleSteps.map((step, index) => {
        const done = index < activeIndex;
        const active = step.id === activeStep;
        return (
          <div
            key={step.id}
            className={`rounded-2xl border px-4 py-3 transition-all ${
              active
                ? "border-slate-900 bg-slate-950 text-white shadow-[0_18px_40px_rgba(15,23,42,0.22)]"
                : done
                  ? "border-emerald-200 bg-emerald-50 text-emerald-950"
                  : "border-slate-200 bg-white/80 text-slate-600"
            }`}
          >
            <div className="text-[11px] uppercase tracking-[0.18em]">{index + 1}</div>
            <div className="mt-1 text-sm font-semibold">{step.label}</div>
          </div>
        );
      })}
    </div>
  );
}

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
    <Card className="border-slate-200/80 bg-white/92 shadow-[0_24px_64px_rgba(15,23,42,0.08)]">
      <CardHeader className="space-y-3 border-b border-slate-100 pb-6">
        <div className="text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-500">{eyebrow}</div>
        <div className="space-y-2">
          <CardTitle className="text-2xl text-slate-950 sm:text-3xl">{title}</CardTitle>
          <CardDescription className="max-w-2xl text-sm leading-6 text-slate-600">{description}</CardDescription>
        </div>
      </CardHeader>
      <CardContent className="space-y-6 p-6 sm:p-8">{children}</CardContent>
    </Card>
  );
}

function ProviderButton({ provider }: { provider: ProviderOption }) {
  return (
    <a
      href={buildProviderHref(provider.id, `${window.location.origin}${window.location.pathname}${window.location.search}`)}
      className="flex items-center justify-between rounded-2xl border border-slate-200 bg-white px-4 py-4 text-sm font-medium text-slate-900 transition hover:-translate-y-0.5 hover:border-slate-900 hover:shadow-[0_16px_32px_rgba(15,23,42,0.12)]"
    >
      <span>Continue with {provider.label}</span>
      <ExternalLink className="h-4 w-4 text-slate-500" />
    </a>
  );
}

function QuestionOption({
  selected,
  title,
  body,
  onClick,
}: {
  selected: boolean;
  title: string;
  body: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-2xl border p-4 text-left transition ${
        selected
          ? "border-slate-900 bg-slate-950 text-white shadow-[0_16px_32px_rgba(15,23,42,0.18)]"
          : "border-slate-200 bg-white text-slate-900 hover:border-slate-400"
      }`}
    >
      <div className="text-sm font-semibold">{title}</div>
      <div className={`mt-1 text-sm ${selected ? "text-slate-200" : "text-slate-600"}`}>{body}</div>
    </button>
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

  const [customerToken, setCustomerToken] = useState(() => readStoredValue(CUSTOMER_TOKEN_KEY, LEGACY_CUSTOMER_TOKEN_KEY));
  const [customerEmail, setCustomerEmail] = useState(() => readStoredValue(CUSTOMER_EMAIL_KEY, LEGACY_CUSTOMER_EMAIL_KEY));
  const [session, setSession] = useState<VerificationSessionSummary | null>(null);
  const [lockedResult, setLockedResult] = useState<VerifyPayload | null>(null);
  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [booting, setBooting] = useState(true);
  const [oauthResolved, setOauthResolved] = useState(false);

  const [otpEmail, setOtpEmail] = useState(() => readStoredValue(CUSTOMER_EMAIL_KEY, LEGACY_CUSTOMER_EMAIL_KEY));
  const [otpChallengeToken, setOtpChallengeToken] = useState("");
  const [otpMaskedEmail, setOtpMaskedEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);

  const [intake, setIntake] = useState<CustomerTrustIntake>(DEFAULT_INTAKE);
  const [flowStep, setFlowStep] = useState<FlowStep>("identity");
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
  const [socialProviders, setSocialProviders] = useState<ProviderOption[]>([]);

  const deviceId = useMemo(() => getOrCreateAnonDeviceId(), []);
  const passkeySupported = isWebAuthnSupported();
  const classification = useMemo(() => inferClassification(result || lockedResult), [lockedResult, result]);
  const reasonList = useMemo(() => deriveReasons(result || lockedResult, classification), [classification, lockedResult, result]);
  const stepMeta = STEP_META[classification];
  const currentCode = normalizeVerifyCode(result?.code || session?.code || codeParam);
  const authReady = Boolean(customerToken);
  const displaySessionSummary = session || null;
  const challengeRequired = Boolean(result?.challenge?.required || lockedResult?.challenge?.required || session?.challengeRequired);
  const challengeCompleted = Boolean(result?.challenge?.completed || lockedResult?.challenge?.completed || session?.challengeCompleted);
  const challengeCompletedBy =
    result?.challenge?.completedBy || lockedResult?.challenge?.completedBy || session?.challengeCompletedBy || null;
  const trustLevelLabel =
    result?.customerTrustLevel === "PASSKEY_VERIFIED"
      ? "Passkey-verified requester"
      : result?.customerTrustLevel === "ACCOUNT_TRUSTED"
        ? "Signed-in requester"
        : result?.customerTrustLevel === "DEVICE_TRUSTED"
          ? "Device-trusted requester"
          : result?.customerTrustLevel === "OPERATOR_REVIEWED"
            ? "Operator-reviewed requester"
            : "Anonymous requester";

  const moveToNextStep = useCallback(() => {
    const stepOrder: FlowStep[] = authReady ? FLOW_STEPS.map((step) => step.id) : ["identity"];
    const currentIndex = stepOrder.indexOf(flowStep);
    if (currentIndex === -1) return;
    const nextStep = stepOrder[currentIndex + 1];
    if (nextStep) setFlowStep(nextStep);
  }, [authReady, flowStep]);

  const moveToPreviousStep = useCallback(() => {
    const stepOrder: FlowStep[] = authReady ? FLOW_STEPS.map((step) => step.id) : ["identity"];
    const currentIndex = stepOrder.indexOf(flowStep);
    if (currentIndex <= 0) return;
    setFlowStep(stepOrder[currentIndex - 1]);
  }, [authReady, flowStep]);

  const updateIntake = useCallback(<K extends keyof CustomerTrustIntake>(key: K, value: CustomerTrustIntake[K]) => {
    setIntake((prev) => ({ ...prev, [key]: value }));
  }, []);

  const loadCustomerPasskeys = useCallback(async (sessionToken?: string) => {
    const activeToken = String(sessionToken || customerToken || "").trim();
    if (!activeToken || !passkeySupported) {
      setPasskeyCredentials([]);
      setLoadingPasskeys(false);
      return;
    }

    setLoadingPasskeys(true);
    try {
      const response = await apiClient.getCustomerPasskeyCredentials(activeToken);
      setPasskeyCredentials(response.success ? response.data?.items || [] : []);
    } finally {
      setLoadingPasskeys(false);
    }
  }, [customerToken, passkeySupported]);

  const applySignedInCustomer = useCallback(
    (tokenValue: string, emailValue: string) => {
      persistCustomerSession(tokenValue, emailValue);
      setCustomerToken(tokenValue);
      setCustomerEmail(emailValue);
      setOtpEmail(emailValue);
      setFlowStep("purchase");
    },
    []
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
        if (!response.success || !response.data?.token) {
          throw new Error(response.error || "Could not complete social sign-in.");
        }
        persistCustomerSession(response.data.token, response.data.customer?.email || "");
        clearHash();
        window.location.replace(`${window.location.pathname}${window.location.search}`);
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
  }, [toast]);

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

  const bootstrapSession = useCallback(async () => {
    setBooting(true);
    setError(null);

    try {
      if (sessionIdFromUrl) {
        const sessionProofToken = readSessionProofToken(sessionIdFromUrl);
        const sessionResponse = await apiClient.getVerificationSession(
          sessionIdFromUrl,
          customerToken || undefined,
          sessionProofToken || undefined
        );
        if (!sessionResponse.success || !sessionResponse.data) {
          throw new Error(sessionResponse.error || "Could not load verification session.");
        }

        const nextSession = sessionResponse.data as unknown as VerificationSessionSummary;
        if (nextSession.sessionProofToken) {
          persistSessionProofToken(nextSession.sessionId, nextSession.sessionProofToken);
        }
        setSession(nextSession);
        setLockedResult((nextSession.verification as VerifyPayload | null) || null);
        setResult((nextSession.verification as VerifyPayload | null) || null);
        if (nextSession.intake) {
          setIntake((prev) => ({ ...prev, ...(nextSession.intake as CustomerTrustIntake) }));
        }

        if (nextSession.revealed && nextSession.verification) {
          setFlowStep("result");
        } else if (customerToken) {
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
            customerToken: customerToken || undefined,
          })
        : await apiClient.verifyQRCode(codeParam, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
            customerToken: customerToken || undefined,
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
        token ? "SIGNED_SCAN" : "MANUAL_CODE",
        customerToken || undefined
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

      if (customerToken) {
        setFlowStep("purchase");
      } else {
        setFlowStep("identity");
      }
    } catch (nextError: unknown) {
      setError(nextError instanceof Error ? nextError.message : "Could not load verification flow.");
    } finally {
      setBooting(false);
    }
  }, [codeParam, customerToken, deviceId, loadGeoContext, navigate, sessionIdFromUrl, token]);

  useEffect(() => {
    if (!oauthResolved) return;
    bootstrapSession();
  }, [bootstrapSession, oauthResolved]);

  useEffect(() => {
    if (!customerToken) return;
    loadCustomerPasskeys();
  }, [customerToken, loadCustomerPasskeys]);

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
      if (!response.success || !response.data?.token) {
        throw new Error(response.error || "Could not verify the email code.");
      }

      applySignedInCustomer(response.data.token, response.data.customer?.email || otpEmail.trim());
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
    if (!customerToken) {
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
            customerToken,
          })
        : await apiClient.verifyQRCode(codeParam, {
            device: deviceId,
            lat: geo.lat,
            lon: geo.lon,
            acc: geo.acc,
            customerToken,
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
        token ? "SIGNED_SCAN" : "MANUAL_CODE",
        customerToken
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

  const handleSubmitIntakeAndReveal = async () => {
    if (!session?.sessionId || !customerToken) {
      toast({ title: "Sign in required", description: "Complete sign-in before revealing the result.", variant: "destructive" });
      return;
    }
    if (!validateStep("intent", intake)) {
      toast({ title: "Complete this step", description: "Tell MSCQR what you want to do next.", variant: "destructive" });
      return;
    }

    setSubmittingReveal(true);
    try {
      const sessionProofToken = readSessionProofToken(session.sessionId);
      const intakeResponse = await apiClient.submitVerificationIntake(
        session.sessionId,
        intake as Record<string, unknown>,
        customerToken,
        sessionProofToken || undefined
      );
      if (!intakeResponse.success) {
        throw new Error(intakeResponse.error || "Could not save the verification intake.");
      }

      const revealResponse = await apiClient.revealVerificationSession(
        session.sessionId,
        customerToken,
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
  };

  const handleClaimOwnership = async () => {
    if (!currentCode) return;
    setClaiming(true);
    try {
      const response = await apiClient.claimVerifiedProduct(currentCode, customerToken || undefined);
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
    if (!transferToken || !customerToken) return;

    setAcceptingTransfer(true);
    try {
      const response = await apiClient.acceptOwnershipTransfer({ token: transferToken }, customerToken);
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
    if (!customerToken) return;
    setRegisteringPasskey(true);
    try {
      const begin = await apiClient.beginCustomerPasskeyRegistration(customerToken);
      if (!begin.success || !begin.data) throw new Error(begin.error || "Could not start passkey registration.");
      const credential = await startWebAuthnRegistration(begin.data, `${APP_NAME} customer protection`);
      const finish = await apiClient.finishCustomerPasskeyRegistration(customerToken, credential);
      if (!finish.success || !finish.data?.token) throw new Error(finish.error || "Could not finish passkey registration.");
      applySignedInCustomer(finish.data.token, finish.data.customer?.email || customerEmail || otpEmail);
      await loadCustomerPasskeys(finish.data.token);
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
    if (!customerToken) return;
    setAssertingPasskey(true);
    try {
      const begin = await apiClient.beginCustomerPasskeyAssertion(undefined, customerToken);
      if (!begin.success || !begin.data) throw new Error(begin.error || "Could not start passkey verification.");
      const assertion = await startWebAuthnAuthentication(begin.data);
      const finish = await apiClient.finishCustomerPasskeyAssertion(assertion, customerToken);
      if (!finish.success || !finish.data?.token) throw new Error(finish.error || "Could not verify the passkey.");
      applySignedInCustomer(finish.data.token, finish.data.customer?.email || customerEmail || otpEmail);
      await loadCustomerPasskeys(finish.data.token);
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
    if (!customerToken) return;
    setDeletingPasskeyId(credentialId);
    try {
      const response = await apiClient.deleteCustomerPasskeyCredential(customerToken, credentialId);
      if (!response.success) throw new Error(response.error || "Could not remove the passkey.");
      await loadCustomerPasskeys(customerToken);
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
      <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(15,23,42,0.1),transparent_40%),linear-gradient(180deg,#eef2f7_0%,#f8fafc_100%)] px-4 py-10">
        <div className="mx-auto max-w-5xl">
          <div className="rounded-[28px] border border-slate-200 bg-white/90 p-6 shadow-[0_32px_96px_rgba(15,23,42,0.12)] sm:p-10">
            <div className="flex items-start justify-between gap-6">
              <div className="space-y-4">
                <div className="text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-500">MSCQR Secure Verification</div>
                <h1 className="max-w-3xl text-3xl font-semibold text-slate-950 sm:text-5xl">
                  Locking the label decision before we ask for your purchase context.
                </h1>
                <p className="max-w-2xl text-sm leading-7 text-slate-600 sm:text-base">
                  MSCQR verifies the label in its governed issuance system first, then records your identity and purchase context separately so your answers never change the locked label result.
                </p>
              </div>
              <Badge className="border-slate-300 bg-slate-100 text-slate-700">{maskCode(codeParam)}</Badge>
            </div>
            <div className="mt-10 flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-950 px-5 py-4 text-white">
              <Loader2 className="h-5 w-5 animate-spin" />
              <div className="text-sm">
                {token ? "Validating signed label and preparing your secure session…" : "Validating label state and preparing your secure session…"}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-950 px-4 py-10 text-white">
        <div className="mx-auto max-w-3xl rounded-[28px] border border-white/10 bg-white/5 p-8 shadow-[0_32px_96px_rgba(0,0,0,0.28)]">
          <div className="text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-400">MSCQR Verification</div>
          <h1 className="mt-4 text-3xl font-semibold">Verification unavailable</h1>
          <p className="mt-3 text-sm leading-7 text-slate-300">{error}</p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild>
              <Link to="/verify">Verify another code</Link>
            </Button>
            <Button variant="outline" asChild className="border-white/20 bg-white/5 text-white hover:bg-white/10">
              <Link to="/trust">Open trust center</Link>
            </Button>
          </div>
        </div>
      </div>
    );
  }

  const canReveal = Boolean(session?.sessionId && authReady);
  const limitedProvenance = result?.publicOutcome === "LIMITED_PROVENANCE";
  const proofTitle =
    result?.proofTier === "SIGNED_LABEL"
      ? "Signed label check"
      : result?.proofTier === "MANUAL_REGISTRY_LOOKUP"
        ? "Manual code record check"
        : "Fail-safe verification";
  const proofDetail =
    result?.proofTier === "SIGNED_LABEL"
      ? "MSCQR confirmed the issued label token and the current lifecycle state of this label."
      : result?.proofTier === "MANUAL_REGISTRY_LOOKUP"
        ? "MSCQR confirmed the registry record and lifecycle state, but not a label-bound signature."
        : "MSCQR returned a degraded decision because a dependency had to fail safely.";
  const checkedItems =
    result?.publicOutcome === "INTEGRITY_ERROR"
      ? [
          "MSCQR could not validate the signed-label proof presented for this result.",
          "The platform did not accept this as a trusted signed-label check.",
          "Use the brand support channel if this label should still be valid.",
        ]
      : result?.publicOutcome === "NOT_FOUND" || classification === "NOT_FOUND"
      ? [
          "MSCQR could not match this code to a live governed registry record.",
          "No customer-ready lifecycle state could be confirmed for this code.",
          "No signed-label proof could be completed for this result.",
        ]
      : limitedProvenance
        ? [
            "MSCQR confirmed the signed label token and found a live platform record for this label.",
            "Governed print provenance is not available for this label, so this result is intentionally limited.",
            "Treat this as a weaker signed-label result than a governed print confirmation.",
          ]
      : classification === "NOT_READY_FOR_CUSTOMER_USE"
        ? [
            "The label exists inside MSCQR’s governed issuance registry.",
            "The lifecycle state is not yet released for customer verification.",
            proofDetail,
          ]
        : classification === "BLOCKED_BY_SECURITY"
          ? [
              "The label exists inside MSCQR’s governed issuance registry.",
              "MSCQR recorded a state or policy condition that currently blocks customer acceptance.",
              proofDetail,
            ]
          : [
              "The label exists inside MSCQR’s governed issuance registry.",
              "The current lifecycle state is suitable for customer verification.",
              proofDetail,
          ];
  const resultTone = limitedProvenance ? "border-amber-200 bg-amber-50 text-amber-950" : stepMeta.tone;
  const resultBadge = limitedProvenance ? "Limited provenance" : stepMeta.badge;
  const resultTitle = limitedProvenance ? "MSCQR found a weaker provenance path" : stepMeta.title;

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,_rgba(15,23,42,0.08),transparent_36%),linear-gradient(180deg,#f8fafc_0%,#edf2f7_46%,#f8fafc_100%)] px-4 py-8 sm:px-6 sm:py-12">
      <div className="mx-auto max-w-6xl space-y-8">
        <header className="grid gap-6 rounded-[32px] border border-slate-200/80 bg-white/90 p-6 shadow-[0_30px_100px_rgba(15,23,42,0.08)] sm:p-10 lg:grid-cols-[1.6fr,0.8fr]">
          <div className="space-y-5">
            <div className="flex flex-wrap items-center gap-3 text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-500">
              <span>MSCQR verification review</span>
              <span className="h-1 w-1 rounded-full bg-slate-300" />
              <span>{displaySessionSummary?.brandName || "Governed label verification"}</span>
            </div>
            <div className="space-y-3">
              <h1 className="max-w-3xl text-3xl font-semibold tracking-tight text-slate-950 sm:text-5xl">
                Review the MSCQR label result with clear proof boundaries.
              </h1>
              <p className="max-w-3xl text-sm leading-7 text-slate-600 sm:text-base">
                MSCQR locks the label result before revealing it. Your identity and purchase answers add context for review and support, but they do not rewrite the original verification outcome.
              </p>
            </div>
            <div className="flex flex-wrap gap-3 text-sm">
              <Badge className="border-slate-300 bg-slate-100 text-slate-700">{displaySessionSummary?.brandName || "MSCQR"}</Badge>
              <Badge className="border-slate-300 bg-white text-slate-700">{displaySessionSummary?.maskedCode || maskCode(currentCode)}</Badge>
              <Badge className="border-slate-300 bg-white text-slate-700">
                {displaySessionSummary?.entryMethod === "SIGNED_SCAN" ? "Signed scan session" : "Manual code session"}
              </Badge>
            </div>
          </div>
          <div className="rounded-[28px] border border-slate-200 bg-slate-950 p-6 text-white shadow-[0_24px_64px_rgba(15,23,42,0.18)]">
            <div className="text-[11px] font-semibold uppercase tracking-[0.26em] text-slate-400">What this result is based on</div>
            <div className="mt-4 space-y-3 text-sm leading-6 text-slate-200">
              <p>MSCQR checks whether the label exists in the governed issuance registry, whether its lifecycle state is customer-ready, and, when available, whether a signed label token still matches the issued record.</p>
              <p className="text-slate-400">MSCQR does not prove the physical item is impossible to counterfeit, and a manual code lookup is weaker than a signed-label check.</p>
            </div>
            <div className="mt-6 border-t border-white/10 pt-4 text-sm text-slate-300">
              Session status: {session?.revealed ? "result revealed" : authReady ? "identity verified" : "identity required"}
            </div>
          </div>
        </header>

        <StepRail activeStep={flowStep} authenticated={authReady} />

        {flowStep === "identity" ? (
          <SectionFrame
            eyebrow="Step 1"
            title="Verify who is checking this product"
            description="Sign in before MSCQR reveals the locked result. Your identity creates a customer trust context that stays separate from the label verdict."
          >
            {challengeRequired && !challengeCompleted ? (
              <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-950">
                This repeat scan needs an additional review check before it should be trusted normally. Sign in first, then MSCQR can re-check it with your verified identity.
              </div>
            ) : null}
            <div className="grid gap-4 lg:grid-cols-[1.15fr,0.85fr]">
              <div className="space-y-4">
                {socialProviders.length ? (
                  <div className="grid gap-3 sm:grid-cols-2">
                    {socialProviders.map((provider) => (
                      <ProviderButton key={provider.id} provider={provider} />
                    ))}
                  </div>
                ) : (
                  <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 px-4 py-5 text-sm text-slate-600">
                    Google sign-in is enabled when configured. Email verification stays the fallback for every customer journey.
                  </div>
                )}

                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                    <Mail className="h-4 w-4" />
                    Continue with email OTP
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

              <div className="rounded-2xl border border-slate-200 bg-white p-5">
                <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
                  <Lock className="h-4 w-4" />
                  Why MSCQR asks you to sign in first
                </div>
                <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-600">
                  <li>It creates a portable customer trust record instead of treating every visit as anonymous scan count.</li>
                  <li>It lets MSCQR separate the locked label result from purchase provenance and ownership intent.</li>
                  <li>It makes later ownership, support, and fraud handling much more defensible.</li>
                </ul>
              </div>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && flowStep === "purchase" ? (
          <SectionFrame
            eyebrow="Step 2"
            title="Tell MSCQR how you obtained the product"
            description="This is provenance evidence, not product proof. The label result was already locked when your session started."
          >
            {challengeRequired && !challengeCompleted ? (
              <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
                <div className="font-semibold">Additional review check required</div>
                <div className="mt-2 leading-6">
                  MSCQR detected a risky repeat context for this label. Re-check it with your verified identity before you rely on the result.
                </div>
                <div className="mt-3">
                  <Button variant="outline" onClick={handleCompleteChallenge} disabled={challengeRetrying}>
                    {challengeRetrying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                    Re-check with verified identity
                  </Button>
                </div>
              </div>
            ) : null}
            {challengeCompleted ? (
              <div className="mb-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-950">
                MSCQR completed the additional review check
                {challengeCompletedBy === "CUSTOMER_IDENTITY" ? " using your verified identity." : "."}
              </div>
            ) : null}
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <QuestionOption
                selected={intake.purchaseChannel === "online"}
                title="Bought online"
                body="Marketplace, brand site, or other e-commerce purchase."
                onClick={() => updateIntake("purchaseChannel", "online")}
              />
              <QuestionOption
                selected={intake.purchaseChannel === "offline"}
                title="Bought in store"
                body="Retail, pharmacy, pop-up, distributor, or local reseller."
                onClick={() => updateIntake("purchaseChannel", "offline")}
              />
              <QuestionOption
                selected={intake.purchaseChannel === "gifted"}
                title="Gifted or transferred"
                body="Someone else gave or sold the item to you."
                onClick={() => updateIntake("purchaseChannel", "gifted")}
              />
              <QuestionOption
                selected={intake.purchaseChannel === "unknown"}
                title="Unknown source"
                body="You are unsure where the item originally came from."
                onClick={() => updateIntake("purchaseChannel", "unknown")}
              />
            </div>
            <div className="flex justify-between">
              <Button variant="outline" onClick={() => setFlowStep("identity")}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
              <Button
                onClick={() => {
                  if (!validateStep("purchase", intake)) {
                    toast({ title: "Choose a purchase channel", description: "Pick how you obtained the product.", variant: "destructive" });
                    return;
                  }
                  moveToNextStep();
                }}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && flowStep === "source" ? (
          <SectionFrame
            eyebrow="Step 3"
            title="Capture seller or source details"
            description="MSCQR uses this as investigation context. It does not change the locked label result."
          >
            <div className="grid gap-4 md:grid-cols-2">
              {intake.purchaseChannel === "online" ? (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="platformName">Platform or marketplace</Label>
                    <Input id="platformName" value={intake.platformName || ""} onChange={(event) => updateIntake("platformName", event.target.value)} placeholder="Amazon, eBay, direct brand site…" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="sellerName">Seller name</Label>
                    <Input id="sellerName" value={intake.sellerName || ""} onChange={(event) => updateIntake("sellerName", event.target.value)} placeholder="Seller or storefront name" />
                  </div>
                  <div className="grid gap-2 md:col-span-2">
                    <Label htmlFor="listingUrl">Listing URL</Label>
                    <Input id="listingUrl" value={intake.listingUrl || ""} onChange={(event) => updateIntake("listingUrl", event.target.value)} placeholder="https://…" />
                  </div>
                  <div className="grid gap-2 md:col-span-2">
                    <Label htmlFor="orderReference">Order reference</Label>
                    <Input id="orderReference" value={intake.orderReference || ""} onChange={(event) => updateIntake("orderReference", event.target.value)} placeholder="Order number or receipt reference" />
                  </div>
                </>
              ) : intake.purchaseChannel === "offline" ? (
                <>
                  <div className="grid gap-2">
                    <Label htmlFor="storeName">Store name</Label>
                    <Input id="storeName" value={intake.storeName || ""} onChange={(event) => updateIntake("storeName", event.target.value)} placeholder="Retailer or location" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="purchaseCity">City</Label>
                    <Input id="purchaseCity" value={intake.purchaseCity || ""} onChange={(event) => updateIntake("purchaseCity", event.target.value)} placeholder="City" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="purchaseCountry">Country</Label>
                    <Input id="purchaseCountry" value={intake.purchaseCountry || ""} onChange={(event) => updateIntake("purchaseCountry", event.target.value)} placeholder="Country" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="purchaseDate">Approximate purchase date</Label>
                    <Input id="purchaseDate" type="date" value={intake.purchaseDate || ""} onChange={(event) => updateIntake("purchaseDate", event.target.value)} />
                  </div>
                </>
              ) : (
                <>
                  <div className="grid gap-2 md:col-span-2">
                    <Label htmlFor="sellerNameAlt">Who gave or sold it to you?</Label>
                    <Input id="sellerNameAlt" value={intake.sellerName || ""} onChange={(event) => updateIntake("sellerName", event.target.value)} placeholder="Friend, reseller, gift source, or unknown" />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="purchaseDateUnknown">Approximate date</Label>
                    <Input id="purchaseDateUnknown" type="date" value={intake.purchaseDate || ""} onChange={(event) => updateIntake("purchaseDate", event.target.value)} />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="sourceCategory">Context</Label>
                    <Select value={intake.sourceCategory || "unknown"} onValueChange={(value) => updateIntake("sourceCategory", value as CustomerTrustIntake["sourceCategory"])}>
                      <SelectTrigger id="sourceCategory">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="gift">Gift</SelectItem>
                        <SelectItem value="reseller">Reseller</SelectItem>
                        <SelectItem value="unknown">Unknown</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </>
              )}
            </div>
            <div className="flex justify-between">
              <Button variant="outline" onClick={moveToPreviousStep}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
              <Button
                onClick={() => {
                  if (!validateStep("source", intake)) {
                    toast({ title: "Add source details", description: "MSCQR needs enough purchase-source context to continue.", variant: "destructive" });
                    return;
                  }
                  moveToNextStep();
                }}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && flowStep === "context" ? (
          <SectionFrame
            eyebrow="Step 4"
            title="Describe the product condition you saw"
            description="These answers become customer trust and incident evidence. They do not change the label result already locked by MSCQR."
          >
            <div className="grid gap-4 md:grid-cols-2">
              <div className="grid gap-2">
                <Label htmlFor="packagingState">Packaging state</Label>
                <Select value={intake.packagingState || "sealed"} onValueChange={(value) => updateIntake("packagingState", value as CustomerTrustIntake["packagingState"])}>
                  <SelectTrigger id="packagingState">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sealed">Sealed</SelectItem>
                    <SelectItem value="opened">Opened</SelectItem>
                    <SelectItem value="damaged">Damaged</SelectItem>
                    <SelectItem value="unsure">Unsure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="packagingConcern">How concerning did it look?</Label>
                <Select value={intake.packagingConcern || "none"} onValueChange={(value) => updateIntake("packagingConcern", value as CustomerTrustIntake["packagingConcern"])}>
                  <SelectTrigger id="packagingConcern">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">No concern</SelectItem>
                    <SelectItem value="minor">Minor concern</SelectItem>
                    <SelectItem value="major">Major concern</SelectItem>
                    <SelectItem value="unsure">Unsure</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2 md:col-span-2">
                <Label htmlFor="notes">Anything unusual?</Label>
                <Textarea
                  id="notes"
                  value={intake.notes || ""}
                  onChange={(event) => updateIntake("notes", event.target.value)}
                  placeholder="Example: seal looked broken, print quality looked off, product felt different, or nothing unusual."
                  rows={5}
                />
              </div>
            </div>
            <div className="flex justify-between">
              <Button variant="outline" onClick={moveToPreviousStep}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
              <Button
                onClick={() => {
                  if (!validateStep("context", intake)) {
                    toast({ title: "Add product context", description: "Select the packaging state and concern level.", variant: "destructive" });
                    return;
                  }
                  moveToNextStep();
                }}
              >
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && flowStep === "concern" ? (
          <SectionFrame
            eyebrow="Step 5"
            title="Why did you choose to scan this item?"
            description="This creates fraud and support context. It helps MSCQR interpret the customer journey without altering the label verdict."
          >
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
              {[
                ["routine_check", "Routine check"],
                ["new_seller", "New seller"],
                ["pricing_concern", "Pricing concern"],
                ["packaging_concern", "Packaging concern"],
                ["authenticity_concern", "Authenticity concern"],
              ].map(([value, label]) => (
                <QuestionOption
                  key={value}
                  selected={intake.scanReason === value}
                  title={label}
                  body="Capture the motive for this verification."
                  onClick={() => updateIntake("scanReason", value as CustomerTrustIntake["scanReason"])}
                />
              ))}
            </div>
            <div className="flex justify-between">
              <Button variant="outline" onClick={moveToPreviousStep}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
              <Button onClick={moveToNextStep}>
                Continue
                <ArrowRight className="ml-2 h-4 w-4" />
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {authReady && flowStep === "intent" ? (
          <SectionFrame
            eyebrow="Step 6"
            title="Choose the next action lane, then reveal the result"
            description="MSCQR will keep your trust intake separate from the locked label result. Once you submit this step, the result is revealed together with your provenance record."
          >
            <div className="grid gap-6 lg:grid-cols-[0.95fr,1.05fr]">
              <div className="space-y-4">
                <div className="grid gap-3">
                  {[
                    ["verify_only", "Only verify this item"],
                    ["claim_ownership", "Verify and claim ownership"],
                    ["report_concern", "Reveal and report a concern"],
                    ["contact_support", "Reveal and contact support"],
                  ].map(([value, label]) => (
                    <QuestionOption
                      key={value}
                      selected={intake.ownershipIntent === value}
                      title={label}
                      body="This changes the recommended next actions after reveal, not the locked label result."
                      onClick={() => updateIntake("ownershipIntent", value as CustomerTrustIntake["ownershipIntent"])}
                    />
                  ))}
                </div>
                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-600">
                  Your answers create trust evidence and incident context only. They do not affect the verification basis, replacement status, or the label decision already locked by MSCQR.
                </div>
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-5">
                <div className="text-sm font-semibold text-slate-900">Review what MSCQR will record</div>
                <div className="mt-4 grid gap-3 text-sm">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="font-medium text-slate-900">Purchase channel</div>
                    <div className="mt-1 text-slate-600">{intake.purchaseChannel}</div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="font-medium text-slate-900">Source detail</div>
                    <div className="mt-1 text-slate-600">
                      {intake.purchaseChannel === "online"
                        ? `${intake.platformName || "No platform"} · ${intake.sellerName || "No seller"}`
                        : intake.purchaseChannel === "offline"
                          ? `${intake.storeName || "No store"} · ${intake.purchaseCity || "No city"}`
                          : intake.sellerName || "Gift / unknown source"}
                    </div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="font-medium text-slate-900">Condition observed</div>
                    <div className="mt-1 text-slate-600">{intake.packagingState} · {intake.packagingConcern} concern</div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="font-medium text-slate-900">Verification reason</div>
                    <div className="mt-1 text-slate-600">{intake.scanReason.replace(/_/g, " ")}</div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="font-medium text-slate-900">Next action intent</div>
                    <div className="mt-1 text-slate-600">{intake.ownershipIntent.replace(/_/g, " ")}</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-between">
              <Button variant="outline" onClick={moveToPreviousStep}>
                <ArrowLeft className="mr-2 h-4 w-4" />
                Back
              </Button>
              <Button onClick={handleSubmitIntakeAndReveal} disabled={!canReveal || submittingReveal}>
                {submittingReveal ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Sparkles className="mr-2 h-4 w-4" />}
                Submit and reveal result
              </Button>
            </div>
          </SectionFrame>
        ) : null}

        {flowStep === "result" && result ? (
          <div className="grid gap-6 xl:grid-cols-[1.15fr,0.85fr]">
            <SectionFrame
              eyebrow="Locked label result"
              title={resultTitle}
              description="This result was locked from the QR token or code and lifecycle state before MSCQR collected your trust answers."
            >
              <div className={`rounded-[26px] border p-5 ${resultTone}`}>
                <div className="flex flex-wrap items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="rounded-full bg-white/70 p-2">{stepMeta.icon}</div>
                    <div>
                      <div className="text-lg font-semibold">{result.message || resultTitle}</div>
                      <div className="mt-1 text-sm">{reasonList[0]}</div>
                    </div>
                  </div>
                  <Badge className="border-current/20 bg-white/60 text-current">{resultBadge}</Badge>
                </div>
              </div>

              {result.challenge?.required || result.challenge?.completed || result.warningMessage ? (
                <div
                  className={`rounded-2xl border p-5 ${
                    result.challenge?.completed
                      ? "border-emerald-200 bg-emerald-50 text-emerald-950"
                      : "border-amber-200 bg-amber-50 text-amber-950"
                  }`}
                >
                  <div className="text-sm font-semibold">
                    {result.challenge?.required
                      ? "Additional review is required for this repeat scan"
                      : result.challenge?.completed
                        ? "Additional review check completed"
                        : "Verification caution"}
                  </div>
                  <div className="mt-2 space-y-2 text-sm leading-6">
                    {result.challenge?.required ? (
                      <p>{result.challenge.reason || "MSCQR requires an additional challenge before this repeat scan should be trusted."}</p>
                    ) : null}
                    {result.challenge?.completed ? (
                      <p>
                        MSCQR re-checked this repeat scan
                        {result.challenge.completedBy === "CUSTOMER_IDENTITY" ? " with a verified customer identity." : "."}
                      </p>
                    ) : null}
                    {result.warningMessage ? <p>{result.warningMessage}</p> : null}
                  </div>
                  {result.challenge?.required ? (
                    <div className="mt-4">
                      {authReady ? (
                        <Button variant="outline" onClick={handleCompleteChallenge} disabled={challengeRetrying}>
                          {challengeRetrying ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                          Re-check with verified identity
                        </Button>
                      ) : (
                        <Button variant="outline" onClick={() => setFlowStep("identity")}>
                          <ArrowLeft className="mr-2 h-4 w-4" />
                          Return to sign-in
                        </Button>
                      )}
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="grid gap-4 md:grid-cols-2">
                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5">
                  <div className="text-sm font-semibold text-slate-900">What MSCQR checked</div>
                  <ul className="mt-3 space-y-2 text-sm leading-6 text-slate-600">
                    {checkedItems.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                </div>
                <div className="rounded-2xl border border-slate-200 bg-white p-5">
                  <div className="text-sm font-semibold text-slate-900">What this result does not prove</div>
                  <ul className="mt-3 space-y-2 text-sm leading-6 text-slate-600">
                    <li>MSCQR does not prove the physical item is impossible to counterfeit.</li>
                    <li>MSCQR does not guarantee that a copied label was never reused elsewhere.</li>
                    <li>Your answers add purchase trust context, not product-bound cryptographic proof.</li>
                  </ul>
                </div>
              </div>

              <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                <MetricCard title="Verification basis" value={proofTitle} icon={<Lock className="h-4 w-4" />} />
                <MetricCard title="Requester context" value={trustLevelLabel} icon={<ShieldCheck className="h-4 w-4" />} />
                <MetricCard
                  title="Controlled-print status"
                  value={toLabel(result.printTrustState || "Unknown")}
                  icon={<CheckCircle2 className="h-4 w-4" />}
                />
                <MetricCard
                  title="Label status"
                  value={toLabel(result.labelState || result.status || "Unknown")}
                  icon={<CircleDashed className="h-4 w-4" />}
                />
                <MetricCard
                  title="Replacement state"
                  value={result.replacementStatus ? result.replacementStatus.replace(/_/g, " ") : "None"}
                  icon={<ArrowRight className="h-4 w-4" />}
                />
                <MetricCard
                  title="Risk review state"
                  value={result.riskDisposition ? result.riskDisposition.replace(/_/g, " ") : "Clear"}
                  icon={<AlertTriangle className="h-4 w-4" />}
                />
              </div>

              <div className="rounded-2xl border border-slate-200 bg-white p-5">
                <div className="text-sm font-semibold text-slate-900">Verification notes</div>
                <ul className="mt-3 space-y-2 text-sm leading-6 text-slate-600">
                  {reasonList.length ? (
                    reasonList.map((reason) => <li key={reason}>{reason}</li>)
                  ) : (
                    <li>No additional verification notes were recorded for this result.</li>
                  )}
                </ul>
              </div>
            </SectionFrame>

            <div className="space-y-6">
              <SectionFrame
                eyebrow="Your purchase context"
                title="Customer provenance trust"
                description="These details are now attached to the verification session as customer trust evidence."
              >
                <div className="grid gap-4 text-sm">
                  <ContextRow icon={<ShoppingBag className="h-4 w-4" />} label="Purchase channel" value={intake.purchaseChannel} />
                  <ContextRow
                    icon={<Store className="h-4 w-4" />}
                    label="Seller or source"
                    value={
                      intake.purchaseChannel === "online"
                        ? `${intake.platformName || "Unknown platform"} · ${intake.sellerName || "Unknown seller"}`
                        : intake.purchaseChannel === "offline"
                          ? `${intake.storeName || "Unknown store"} · ${intake.purchaseCity || "Unknown city"}`
                          : intake.sellerName || "Gift / unknown source"
                    }
                  />
                  <ContextRow icon={<MapPin className="h-4 w-4" />} label="Purchase country" value={intake.purchaseCountry || "Not provided"} />
                  <ContextRow
                    icon={<AlertTriangle className="h-4 w-4" />}
                    label="Scan reason"
                    value={intake.scanReason.replace(/_/g, " ")}
                  />
                  <ContextRow icon={<ShieldCheck className="h-4 w-4" />} label="Intent" value={intake.ownershipIntent.replace(/_/g, " ")} />
                </div>
                <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-4 text-sm leading-6 text-slate-600">
                  Your answers did not change the label verdict. They help MSCQR interpret this purchase context, strengthen later ownership actions, and escalate suspicious cases intelligently.
                </div>
              </SectionFrame>

              <SectionFrame
                eyebrow="Next actions"
                title="What you can do now"
                description="Choose the operational path that matches your intent."
              >
                <div className="grid gap-3">
                  {intake.ownershipIntent === "claim_ownership" ? (
                    <Button onClick={handleClaimOwnership} disabled={claiming}>
                      {claiming ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                      Claim ownership
                    </Button>
                  ) : null}

                  {String(searchParams.get("transfer") || "").trim() ? (
                    <Button variant="outline" onClick={handleAcceptTransfer} disabled={!customerToken || acceptingTransfer}>
                      {acceptingTransfer ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ArrowRight className="mr-2 h-4 w-4" />}
                      Accept ownership transfer
                    </Button>
                  ) : null}

                  {passkeySupported ? (
                    <div className="grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-sm font-semibold text-slate-900">Stronger ownership protection</div>
                      <div className="text-sm leading-6 text-slate-600">Passkeys do not change this QR’s verdict. They strengthen future ownership and transfer actions for this account.</div>
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
                        <div className="text-sm text-slate-500">Loading passkeys…</div>
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
                        <div className="text-sm text-slate-500">No customer passkeys enrolled yet.</div>
                      )}
                    </div>
                  ) : null}

                  <div className="grid gap-3 rounded-2xl border border-slate-200 bg-white p-4">
                    <Label htmlFor="report-reason">Report a concern to MSCQR</Label>
                    <Select value={reportReason} onValueChange={setReportReason}>
                      <SelectTrigger id="report-reason">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="counterfeit_suspected">Counterfeit suspected</SelectItem>
                        <SelectItem value="duplicate_scan">Duplicate scan</SelectItem>
                        <SelectItem value="tampered_label">Tampered label</SelectItem>
                        <SelectItem value="wrong_product">Wrong product</SelectItem>
                        <SelectItem value="other">Other</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button variant="outline" onClick={handleReportConcern} disabled={reporting}>
                      {reporting ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <AlertTriangle className="mr-2 h-4 w-4" />}
                      Report concern
                    </Button>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-600">
                    <div className="font-semibold text-slate-900">Contact support</div>
                    <div className="mt-2 space-y-1">
                      <div>{result.licensee?.supportEmail || "support@mscqr.com"}</div>
                      {result.licensee?.supportPhone ? <div>{result.licensee.supportPhone}</div> : null}
                      {result.licensee?.website ? (
                        <a className="inline-flex items-center gap-1 text-slate-900 underline" href={result.licensee.website} target="_blank" rel="noreferrer">
                          Visit brand site
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ) : null}
                    </div>
                  </div>
                </div>
              </SectionFrame>
            </div>
          </div>
        ) : null}

        <div className="flex items-center justify-between text-sm text-slate-500">
          <Link to="/verify" className="inline-flex items-center gap-2 hover:text-slate-900">
            <ArrowLeft className="h-4 w-4" />
            Verify another code
          </Link>
          <Link to="/trust" className="inline-flex items-center gap-2 hover:text-slate-900">
            Read MSCQR trust model
            <ExternalLink className="h-4 w-4" />
          </Link>
        </div>

        {!customerToken && flowStep !== "identity" ? (
          <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            Your verification session is still locked, but result reveal is waiting for sign-in. Return to the identity step if you need to finish authentication.
          </div>
        ) : null}

        {customerToken ? (
          <div className="flex items-center justify-end">
            <Button
              variant="ghost"
              onClick={() => {
                clearStoredCustomerSession();
                setCustomerToken("");
                setCustomerEmail("");
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

function MetricCard({
  title,
  value,
  icon,
  mono = false,
}: {
  title: string;
  value: string;
  icon: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-center gap-2 text-sm font-medium text-slate-600">
        {icon}
        {title}
      </div>
      <div className={`mt-2 text-sm font-semibold text-slate-950 ${mono ? "font-mono text-[13px]" : ""}`}>{value}</div>
    </div>
  );
}

function ContextRow({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-start gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="mt-0.5 text-slate-500">{icon}</div>
      <div>
        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</div>
        <div className="mt-1 text-sm font-medium text-slate-900">{value}</div>
      </div>
    </div>
  );
}

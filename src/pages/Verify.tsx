import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";
import {
  Shield,
  CheckCircle2,
  AlertTriangle,
  Ban,
  SearchX,
  Building2,
  Factory,
  CalendarClock,
  Mail,
  Phone,
  Globe2,
  Loader2,
  Flag,
  ArrowRight,
  Sparkles,
  Star,
  UserCheck,
  LogIn,
  MapPin,
  RefreshCw,
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

declare global {
  interface Window {
    google?: any;
  }
}

type ScanClassification = "FIRST_SCAN" | "LEGIT_REPEAT" | "SUSPICIOUS_DUPLICATE";

type VerificationUser = {
  id: string;
  email: string;
  name?: string | null;
  provider?: string;
  createdAt?: string;
};

type OwnershipInfo = {
  ownerCustomerId: string;
  claimedAt: string;
  isOwnedByYou: boolean;
};

type VerifyPayload = {
  isAuthentic: boolean;
  message?: string;
  code?: string;
  status?: string;
  scanOutcome?: string;
  scanClassification?: ScanClassification;
  reasons?: string[];
  warningMessage?: string | null;
  claimRecommended?: boolean;
  anonVisitorId?: string | null;
  verifiedByYouCount?: number;
  topLocations?: Array<{ label: string; count: number }>;
  ownership?: OwnershipInfo | null;
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
  printedAt?: string | null;
  firstScanned?: string | null;
  firstScanAt?: string | null;
  firstScanLocation?: string | null;
  latestScanAt?: string | null;
  latestScanLocation?: string | null;
  previousScanAt?: string | null;
  previousScanLocation?: string | null;
  scanCount?: number;
};

type StatusKind =
  | "genuine"
  | "verifiedAgain"
  | "duplicate"
  | "suspicious"
  | "blocked"
  | "unassigned"
  | "invalid";

const INCIDENT_TYPE_OPTIONS = [
  { value: "counterfeit_suspected", label: "Counterfeit suspected" },
  { value: "duplicate_scan", label: "Duplicate scan" },
  { value: "tampered_label", label: "Tampered label" },
  { value: "wrong_product", label: "Wrong product" },
  { value: "other", label: "Other" },
] as const;

const SATISFACTION_OPTIONS = [
  { value: "very_satisfied", label: "Loved it" },
  { value: "satisfied", label: "Satisfied" },
  { value: "neutral", label: "Neutral" },
  { value: "disappointed", label: "Not great" },
  { value: "very_disappointed", label: "Disappointed" },
] as const;

type SatisfactionValue = (typeof SATISFACTION_OPTIONS)[number]["value"];

const VERIFY_LOADING_STEPS = [
  "Reading secure QR signature",
  "Checking authenticity records",
  "Computing duplicate-risk signals",
] as const;

const STATUS_META: Record<
  StatusKind,
  {
    title: string;
    subtitle: string;
    chip: string;
    panelClass: string;
    icon: React.ReactNode;
  }
> = {
  genuine: {
    title: "Verified Authentic",
    subtitle: "First-time verification completed successfully.",
    chip: "Authentic",
    panelClass: "from-emerald-600 to-teal-600",
    icon: <CheckCircle2 className="h-10 w-10 text-white" />,
  },
  verifiedAgain: {
    title: "Verified Again",
    subtitle: "Authentic product. You have verified this before.",
    chip: "Authentic",
    panelClass: "from-emerald-600 to-cyan-600",
    icon: <UserCheck className="h-10 w-10 text-white" />,
  },
  duplicate: {
    title: "Possible Duplicate",
    subtitle: "This QR shows unusual scan patterns that may indicate label copying.",
    chip: "Fraud Risk",
    panelClass: "from-orange-500 to-amber-600",
    icon: <AlertTriangle className="h-10 w-10 text-white" />,
  },
  suspicious: {
    title: "Verification Warning",
    subtitle: "Code exists, but lifecycle checks indicate abnormal state.",
    chip: "Suspicious",
    panelClass: "from-amber-500 to-orange-600",
    icon: <AlertTriangle className="h-10 w-10 text-white" />,
  },
  blocked: {
    title: "Blocked by Security",
    subtitle: "This code is blocked due to policy or fraud controls.",
    chip: "Blocked",
    panelClass: "from-red-600 to-rose-700",
    icon: <Ban className="h-10 w-10 text-white" />,
  },
  unassigned: {
    title: "Not Ready for Customer Use",
    subtitle: "Code exists but has not been finalized for product verification.",
    chip: "Not Active",
    panelClass: "from-slate-600 to-slate-700",
    icon: <SearchX className="h-10 w-10 text-white" />,
  },
  invalid: {
    title: "Verification Unavailable",
    subtitle: "This code could not be verified in the platform.",
    chip: "Unavailable",
    panelClass: "from-red-600 to-rose-700",
    icon: <SearchX className="h-10 w-10 text-white" />,
  },
};

const computeVisitorFingerprint = () => {
  if (typeof navigator === "undefined") return "";

  const raw = [
    navigator.userAgent || "",
    navigator.language || "",
    (navigator as any).platform || "",
    Intl.DateTimeFormat().resolvedOptions().timeZone || "",
  ].join("|");

  let hash = 2166136261;
  for (let i = 0; i < raw.length; i += 1) {
    hash ^= raw.charCodeAt(i);
    hash +=
      (hash << 1) +
      (hash << 4) +
      (hash << 7) +
      (hash << 8) +
      (hash << 24);
  }
  return `vf_${(hash >>> 0).toString(36)}`;
};

const parseGoogleClientId = () => {
  const id = String(import.meta.env.VITE_GOOGLE_CLIENT_ID || "").trim();
  return id || "";
};

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [viewer, setViewer] = useState<VerificationUser | null>(null);
  const [viewerLoading, setViewerLoading] = useState(true);

  const [scanRefreshKey, setScanRefreshKey] = useState(0);

  const [reportOpen, setReportOpen] = useState(false);
  const [incidentType, setIncidentType] = useState<string>(INCIDENT_TYPE_OPTIONS[1].value);
  const [reportDescription, setReportDescription] = useState("");
  const [purchasePlace, setPurchasePlace] = useState("");
  const [purchaseDate, setPurchaseDate] = useState("");
  const [productBatchNo, setProductBatchNo] = useState("");
  const [reportCustomerName, setReportCustomerName] = useState("");
  const [reportEmail, setReportEmail] = useState("");
  const [reportPhone, setReportPhone] = useState("");
  const [reportCountry, setReportCountry] = useState("");
  const [reportConsent, setReportConsent] = useState(true);
  const [reportPhotos, setReportPhotos] = useState<File[]>([]);
  const [reportReference, setReportReference] = useState<string | null>(null);
  const [reporting, setReporting] = useState(false);

  const [loadingStepIdx, setLoadingStepIdx] = useState(0);
  const [feedbackRating, setFeedbackRating] = useState(0);
  const [feedbackSatisfaction, setFeedbackSatisfaction] = useState<SatisfactionValue | "">("");
  const [feedbackNote, setFeedbackNote] = useState("");
  const [feedbackSubmitting, setFeedbackSubmitting] = useState(false);
  const [feedbackSubmitted, setFeedbackSubmitted] = useState(false);

  const [otpEmail, setOtpEmail] = useState("");
  const [otpName, setOtpName] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpRequested, setOtpRequested] = useState(false);
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);
  const [claiming, setClaiming] = useState(false);

  const visitorFp = useMemo(() => computeVisitorFingerprint(), []);
  const googleClientId = useMemo(() => parseGoogleClientId(), []);
  const googleButtonRef = useRef<HTMLDivElement | null>(null);

  const token = useMemo(() => searchParams.get("t")?.trim() || "", [searchParams.toString()]);
  const codeParam = useMemo(() => {
    const raw = String(code || "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return raw.trim();
    }
  }, [code]);

  const requestKey = token
    ? `token:${token}:refresh:${scanRefreshKey}`
    : codeParam
    ? `code:${codeParam.toUpperCase()}:refresh:${scanRefreshKey}`
    : "";
  const inFlightByKeyRef = useRef(new Map<string, Promise<any>>());

  const loadViewer = useCallback(async () => {
    setViewerLoading(true);
    try {
      const meRes = await apiClient.getVerificationMe();
      if (meRes.success) {
        setViewer((meRes.data as any)?.user || null);
      }
    } finally {
      setViewerLoading(false);
    }
  }, []);

  useEffect(() => {
    loadViewer();
  }, [loadViewer]);

  useEffect(() => {
    if (viewer?.email && !reportEmail) setReportEmail(viewer.email);
    if (viewer?.name && !reportCustomerName) setReportCustomerName(viewer.name);
    if (viewer?.name && !otpName) setOtpName(viewer.name);
  }, [otpName, reportCustomerName, reportEmail, viewer]);

  useEffect(() => {
    let active = true;

    if (!requestKey) {
      setIsLoading(false);
      setResult({ isAuthentic: false, message: "Missing verification code" });
      return () => {
        active = false;
      };
    }

    (async () => {
      setIsLoading(true);
      setError(null);

      try {
        let requestPromise = inFlightByKeyRef.current.get(requestKey);

        if (!requestPromise) {
          requestPromise = (async () => {
            const device = typeof navigator !== "undefined" ? navigator.userAgent : undefined;

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

            return token
              ? apiClient.scanToken(token, {
                  device,
                  lat: geo.lat,
                  lon: geo.lon,
                  acc: geo.acc,
                  visitorFp,
                })
              : apiClient.scanCode(codeParam, {
                  device,
                  lat: geo.lat,
                  lon: geo.lon,
                  acc: geo.acc,
                  visitorFp,
                });
          })();
          inFlightByKeyRef.current.set(requestKey, requestPromise);
        }

        const res = await requestPromise;
        inFlightByKeyRef.current.delete(requestKey);

        if (!active) return;

        if (!res.success) {
          setError(res.error || "Verification failed");
          setResult(null);
          return;
        }

        setResult((res.data as VerifyPayload) || null);
      } catch (e: any) {
        inFlightByKeyRef.current.delete(requestKey);
        if (!active) return;
        setError(e?.message || "Verification failed");
        setResult(null);
      } finally {
        if (active) setIsLoading(false);
      }
    })();

    return () => {
      active = false;
    };
  }, [codeParam, requestKey, token, visitorFp]);

  useEffect(() => {
    if (!isLoading) return;
    const timer = window.setInterval(() => {
      setLoadingStepIdx((prev) => (prev + 1) % VERIFY_LOADING_STEPS.length);
    }, 1100);
    return () => window.clearInterval(timer);
  }, [isLoading]);

  const statusKind: StatusKind = useMemo(() => {
    if (result?.status === "BLOCKED" || result?.scanOutcome === "BLOCKED") return "blocked";

    if (
      result?.scanClassification === "SUSPICIOUS_DUPLICATE" ||
      result?.scanOutcome === "SUSPICIOUS_DUPLICATE"
    ) {
      return "duplicate";
    }

    if (result?.scanClassification === "LEGIT_REPEAT" || result?.scanOutcome === "VALID_REPEAT") {
      return "verifiedAgain";
    }

    if (result?.scanClassification === "FIRST_SCAN" || result?.scanOutcome === "VALID" || result?.isAuthentic) {
      return "genuine";
    }

    if (
      result?.scanOutcome === "SUSPICIOUS" ||
      result?.status === "ALLOCATED" ||
      result?.status === "ACTIVATED"
    ) {
      return "suspicious";
    }

    if (result?.status === "DORMANT" || result?.status === "ACTIVE" || result?.scanOutcome === "NOT_PRINTED") {
      return "unassigned";
    }

    const lowerMessage = String(result?.message || "").toLowerCase();
    if (lowerMessage.includes("blocked")) return "blocked";
    if (lowerMessage.includes("duplicate")) return "duplicate";
    if (lowerMessage.includes("allocated but not yet printed")) return "suspicious";
    if (lowerMessage.includes("not been assigned")) return "unassigned";

    return "invalid";
  }, [
    result?.isAuthentic,
    result?.message,
    result?.scanClassification,
    result?.scanOutcome,
    result?.status,
  ]);

  const meta = STATUS_META[statusKind];
  const manufacturer = result?.batch?.manufacturer || null;
  const displayedCode = result?.code || codeParam || "—";
  const printedAt = result?.printedAt || result?.batch?.printedAt || null;
  const firstScanAt = result?.firstScanAt || result?.firstScanned || null;
  const latestScanAt = result?.latestScanAt || null;
  const previousScanAt = result?.previousScanAt || null;

  const firstScanLocation = result?.firstScanLocation || null;
  const latestScanLocation = result?.latestScanLocation || null;
  const previousScanLocation = result?.previousScanLocation || null;

  const isReportable = statusKind === "duplicate" || statusKind === "blocked" || statusKind === "suspicious";
  const canSubmitFeedback = displayedCode !== "—" && statusKind !== "invalid";

  const feedbackStorageKey = useMemo(() => {
    const normalized = String(displayedCode || "").trim().toUpperCase();
    return normalized && normalized !== "—" ? `authenticqr_feedback_${normalized}` : "";
  }, [displayedCode]);

  useEffect(() => {
    if (!feedbackStorageKey) {
      setFeedbackSubmitted(false);
      return;
    }
    try {
      setFeedbackSubmitted(window.localStorage.getItem(feedbackStorageKey) === "1");
    } catch {
      setFeedbackSubmitted(false);
    }
  }, [feedbackStorageKey]);

  useEffect(() => {
    setFeedbackRating(0);
    setFeedbackSatisfaction("");
    setFeedbackNote("");
  }, [feedbackStorageKey]);

  useEffect(() => {
    if (!googleClientId || !googleButtonRef.current || viewer) return;

    let cancelled = false;

    const loadGoogleScript = () => {
      return new Promise<void>((resolve, reject) => {
        if (window.google?.accounts?.id) {
          resolve();
          return;
        }

        const existing = document.getElementById("google-identity-script") as HTMLScriptElement | null;
        if (existing) {
          existing.addEventListener("load", () => resolve(), { once: true });
          existing.addEventListener("error", () => reject(new Error("Google script failed")), {
            once: true,
          });
          return;
        }

        const script = document.createElement("script");
        script.id = "google-identity-script";
        script.src = "https://accounts.google.com/gsi/client";
        script.async = true;
        script.defer = true;
        script.onload = () => resolve();
        script.onerror = () => reject(new Error("Google script failed"));
        document.head.appendChild(script);
      });
    };

    const setup = async () => {
      try {
        await loadGoogleScript();
        if (cancelled || !window.google?.accounts?.id || !googleButtonRef.current) return;

        window.google.accounts.id.initialize({
          client_id: googleClientId,
          callback: async (response: any) => {
            const credential = String(response?.credential || "").trim();
            if (!credential) return;

            const authRes = await apiClient.authGoogle(credential);
            if (!authRes.success) {
              toast({
                title: "Google sign-in failed",
                description: authRes.error || "Could not sign in with Google.",
                variant: "destructive",
              });
              return;
            }

            await loadViewer();
            setScanRefreshKey((k) => k + 1);
            toast({ title: "Signed in", description: "Ownership protection is now enabled." });
          },
        });

        googleButtonRef.current.innerHTML = "";
        window.google.accounts.id.renderButton(googleButtonRef.current, {
          theme: "outline",
          size: "large",
          shape: "pill",
          text: "continue_with",
          width: 260,
        });
      } catch {
        // keep email OTP fallback only
      }
    };

    setup();

    return () => {
      cancelled = true;
    };
  }, [googleClientId, loadViewer, toast, viewer]);

  const requestOtp = async () => {
    if (!otpEmail.trim()) {
      toast({ title: "Email required", description: "Enter your email to receive a one-time code.", variant: "destructive" });
      return;
    }

    setOtpSending(true);
    try {
      const res = await apiClient.requestVerificationOtp({
        email: otpEmail.trim(),
        name: otpName.trim() || undefined,
      });

      if (!res.success) {
        toast({
          title: "Could not send code",
          description: res.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      setOtpRequested(true);
      toast({ title: "Code sent", description: "Check your email for a one-time code." });
    } finally {
      setOtpSending(false);
    }
  };

  const verifyOtp = async () => {
    if (!otpCode.trim()) {
      toast({ title: "Code required", description: "Enter the OTP from your email.", variant: "destructive" });
      return;
    }

    setOtpVerifying(true);
    try {
      const res = await apiClient.verifyVerificationOtp({
        email: otpEmail.trim(),
        otp: otpCode.trim(),
        name: otpName.trim() || undefined,
      });

      if (!res.success) {
        toast({
          title: "Could not verify code",
          description: res.error || "Please check the code and try again.",
          variant: "destructive",
        });
        return;
      }

      await loadViewer();
      setOtpCode("");
      setOtpRequested(false);
      setScanRefreshKey((k) => k + 1);
      toast({ title: "Signed in", description: "You can now claim ownership of this product." });
    } finally {
      setOtpVerifying(false);
    }
  };

  const logoutViewer = async () => {
    await apiClient.logoutVerificationUser();
    setViewer(null);
    setScanRefreshKey((k) => k + 1);
  };

  const claimOwnership = async () => {
    if (!displayedCode || displayedCode === "—") return;

    setClaiming(true);
    try {
      const res = await apiClient.claimProduct(displayedCode);
      if (!res.success) {
        toast({
          title: "Could not claim product",
          description: res.error || "Please sign in and try again.",
          variant: "destructive",
        });
        return;
      }

      const ownership = (res.data as any)?.ownership;
      setResult((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          ownership,
          claimRecommended: false,
        };
      });

      setScanRefreshKey((k) => k + 1);
      toast({ title: "Ownership claimed", description: "This product is now linked to your account." });
    } finally {
      setClaiming(false);
    }
  };

  const submitReport = async () => {
    const normalizedCode = String(displayedCode || "").trim();
    if (!normalizedCode || normalizedCode === "—") {
      toast({
        title: "Report failed",
        description: "No valid code found to report.",
        variant: "destructive",
      });
      return;
    }

    if (reportDescription.trim().length < 6) {
      toast({
        title: "More details needed",
        description: "Please add a short description so the team can investigate.",
        variant: "destructive",
      });
      return;
    }

    setReporting(true);
    try {
      const formData = new FormData();
      formData.append("code", normalizedCode);
      formData.append("reason", reportDescription.trim());
      formData.append("notes", reportDescription.trim());
      formData.append("incidentType", incidentType);
      if (purchasePlace.trim()) formData.append("purchasePlace", purchasePlace.trim());
      if (purchaseDate.trim()) formData.append("purchaseDate", purchaseDate.trim());
      if (productBatchNo.trim()) formData.append("productBatchNo", productBatchNo.trim());
      if (reportCustomerName.trim()) formData.append("customerName", reportCustomerName.trim());
      if (reportEmail.trim()) formData.append("contactEmail", reportEmail.trim());
      if (reportPhone.trim()) formData.append("customerPhone", reportPhone.trim());
      if (reportCountry.trim()) formData.append("customerCountry", reportCountry.trim());

      formData.append("consentToContact", String(reportConsent));
      if (result?.scanClassification) formData.append("scanClassification", result.scanClassification);
      if (Array.isArray(result?.reasons)) formData.append("riskReasons", JSON.stringify(result.reasons));

      formData.append(
        "historySummary",
        JSON.stringify({
          totalScans: result?.scanCount ?? 0,
          firstScanAt,
          latestScanAt,
          previousScanAt,
          firstScanLocation,
          latestScanLocation,
          previousScanLocation,
          verifiedByYouCount: result?.verifiedByYouCount ?? 0,
          topLocations: result?.topLocations || [],
        })
      );

      if (typeof window !== "undefined" && window.location.href) {
        formData.append("pageUrl", window.location.href);
      }

      for (const photo of reportPhotos.slice(0, 4)) {
        formData.append("photos", photo);
      }

      const res = await apiClient.submitFraudReport(formData, visitorFp || undefined);

      if (!res.success) {
        toast({
          title: "Report failed",
          description: res.error || "Could not submit report.",
          variant: "destructive",
        });
        return;
      }

      toast({
        title: "Report submitted",
        description: "Our security team has received your report.",
      });

      setReportReference((res.data as any)?.reportId || (res.data as any)?.incidentId || null);
      setIncidentType(INCIDENT_TYPE_OPTIONS[1].value);
      setReportDescription("");
      setPurchasePlace("");
      setPurchaseDate("");
      setProductBatchNo("");
      setReportCustomerName(viewer?.name || "");
      setReportEmail(viewer?.email || "");
      setReportPhone("");
      setReportCountry("");
      setReportConsent(true);
      setReportPhotos([]);
    } finally {
      setReporting(false);
    }
  };

  const submitFeedback = async () => {
    if (!canSubmitFeedback) return;
    if (feedbackRating < 1 || !feedbackSatisfaction) {
      toast({
        title: "Add your rating",
        description: "Please select star rating and satisfaction level.",
        variant: "destructive",
      });
      return;
    }

    setFeedbackSubmitting(true);
    try {
      const res = await apiClient.submitProductFeedback({
        code: displayedCode,
        rating: feedbackRating,
        satisfaction: feedbackSatisfaction as SatisfactionValue,
        notes: feedbackNote.trim() || undefined,
        observedStatus: result?.status,
        observedOutcome: result?.scanOutcome,
        pageUrl: typeof window !== "undefined" ? window.location.href : undefined,
      });

      if (!res.success) {
        toast({
          title: "Could not submit feedback",
          description: res.error || "Please try again.",
          variant: "destructive",
        });
        return;
      }

      try {
        if (feedbackStorageKey) window.localStorage.setItem(feedbackStorageKey, "1");
      } catch {}

      setFeedbackSubmitted(true);
      toast({
        title: "Thanks for your feedback",
        description: "Your response was shared with the product team.",
      });
    } finally {
      setFeedbackSubmitting(false);
    }
  };

  const ownership = result?.ownership || null;
  const canClaim = Boolean(viewer && displayedCode !== "—" && (!ownership || !ownership.isOwnedByYou));

  return (
    <div className="relative min-h-screen overflow-hidden bg-[linear-gradient(145deg,#052f2f_0%,#0b3a53_45%,#0f2740_100%)] px-4 py-10">
      <style>{`
        @keyframes verify-scanline {
          0% { transform: translateY(-16%); opacity: 0; }
          18% { opacity: 1; }
          82% { opacity: 1; }
          100% { transform: translateY(260%); opacity: 0; }
        }
        @keyframes verify-orbit {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes verify-card-enter {
          from { opacity: 0; transform: translateY(10px) scale(0.99); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }
        @keyframes verify-icon-pulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.04); }
        }
      `}</style>

      <div className="pointer-events-none absolute -left-24 top-8 h-72 w-72 rounded-full bg-cyan-300/15 blur-3xl" />
      <div className="pointer-events-none absolute right-0 top-0 h-96 w-96 rounded-full bg-emerald-300/10 blur-3xl" />
      <div className="pointer-events-none absolute bottom-0 left-1/3 h-80 w-80 rounded-full bg-sky-300/10 blur-3xl" />

      <div className="relative mx-auto w-full max-w-3xl">
        <div className="mb-8 text-center">
          <Link to="/verify" className="inline-flex items-center gap-3 text-white">
            <span className="rounded-2xl border border-cyan-100/20 bg-white/10 p-2.5 backdrop-blur">
              <Shield className="h-8 w-8 text-cyan-200" />
            </span>
            <span className="text-3xl font-semibold tracking-tight">AuthenticQR</span>
          </Link>
          <p className="mt-3 text-sm uppercase tracking-[0.18em] text-cyan-100/80">Product Verification</p>
        </div>

        <Card className="overflow-hidden border-white/20 bg-white/95 shadow-[0_30px_80px_rgba(3,18,30,0.35)] backdrop-blur-sm">
          {isLoading ? (
            <CardContent className="py-14 sm:py-16">
              <div className="mx-auto flex max-w-md flex-col items-center gap-6 text-center">
                <div className="relative h-40 w-40">
                  <div className="absolute -inset-3 rounded-[2.1rem] border border-cyan-300/30" style={{ animation: "verify-orbit 2.4s linear infinite" }} />
                  <div className="absolute inset-0 rounded-[2rem] border border-cyan-200/70 bg-gradient-to-b from-cyan-100/60 to-white/80 shadow-inner" />
                  <div className="absolute inset-4 overflow-hidden rounded-[1.4rem] border border-cyan-200/90 bg-white/70">
                    <div
                      className="absolute left-0 right-0 top-0 h-12 bg-gradient-to-b from-cyan-400/35 to-transparent"
                      style={{ animation: "verify-scanline 1.8s ease-in-out infinite" }}
                    />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <Shield className="h-12 w-12 animate-pulse text-slate-700" />
                    </div>
                  </div>
                </div>
                <div className="space-y-1">
                  <p className="text-lg font-semibold text-slate-900">{VERIFY_LOADING_STEPS[loadingStepIdx]}</p>
                  <p className="text-sm text-slate-500">Please keep this screen open.</p>
                </div>
              </div>
            </CardContent>
          ) : error ? (
            <CardContent className="space-y-4 py-12 text-center">
              <SearchX className="mx-auto h-10 w-10 text-red-600" />
              <p className="text-xl font-semibold text-slate-900">Verification service unavailable</p>
              <p className="text-sm text-slate-600">{error}</p>
              <div className="mx-auto flex max-w-sm gap-2">
                <Button variant="outline" asChild className="flex-1">
                  <Link to="/verify">Try another code</Link>
                </Button>
                <Button type="button" className="flex-1 bg-slate-900 text-white hover:bg-slate-800" onClick={() => window.location.reload()}>
                  Retry
                </Button>
              </div>
            </CardContent>
          ) : (
            <div style={{ animation: "verify-card-enter 360ms cubic-bezier(.22,1,.36,1) both" }}>
              <div className={`bg-gradient-to-r ${meta.panelClass} px-6 py-7 text-white`}>
                <div className="mx-auto flex max-w-xl items-center gap-4">
                  <div className="inline-flex h-16 w-16 items-center justify-center rounded-2xl border border-white/30 bg-white/15" style={{ animation: "verify-icon-pulse 1.8s ease-in-out infinite" }}>
                    {meta.icon}
                  </div>
                  <div>
                    <h1 className="text-3xl font-semibold leading-tight">{meta.title}</h1>
                    <p className="mt-1 text-white/85">{meta.subtitle}</p>
                  </div>
                </div>
              </div>

              <CardContent className="space-y-6 p-6 md:p-8">
                <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 md:flex-row md:items-center md:justify-between">
                  <div>
                    <p className="text-xs font-medium uppercase tracking-wide text-slate-500">Verified code</p>
                    <p className="mt-1 font-mono text-2xl font-semibold tracking-tight text-slate-900">{displayedCode}</p>
                  </div>
                  <Badge className="w-fit border-transparent bg-slate-900 text-white">{meta.chip}</Badge>
                </div>

                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wide text-slate-500">
                      <Building2 className="h-4 w-4 text-teal-600" />
                      Licensed by
                    </div>
                    <p className="text-base font-semibold text-slate-900">{result?.licensee?.brandName || result?.licensee?.name || "—"}</p>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wide text-slate-500">
                      <Factory className="h-4 w-4 text-cyan-700" />
                      Manufacturer
                    </div>
                    <p className="text-base font-semibold text-slate-900">{manufacturer?.name || "—"}</p>
                  </div>

                  <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-wide text-slate-500">
                      <CalendarClock className="h-4 w-4 text-sky-700" />
                      Printed on
                    </div>
                    <p className="text-base font-semibold text-slate-900">
                      {printedAt ? new Date(printedAt).toLocaleDateString() : "Not available"}
                    </p>
                  </div>
                </div>

                {(result?.message || result?.warningMessage) && (
                  <div
                    className={
                      statusKind === "genuine" || statusKind === "verifiedAgain"
                        ? "rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900"
                        : "rounded-xl border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900"
                    }
                  >
                    <p className="font-medium">{result?.message || "Verification details"}</p>
                    {result?.warningMessage ? <p className="mt-1">{result.warningMessage}</p> : null}
                    {statusKind === "verifiedAgain" ? (
                      <p className="mt-1 text-emerald-800">You can safely show this screen again if someone asks for proof.</p>
                    ) : null}
                  </div>
                )}

                <div className="rounded-xl border border-slate-200 bg-white p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <p className="text-xs uppercase tracking-wide text-slate-500">Scan history summary</p>
                    <Badge variant="outline" className="text-xs">Coarse city/country only</Badge>
                  </div>

                  <div className="grid gap-3 md:grid-cols-4">
                    <div>
                      <p className="text-xs text-slate-500">Total scans</p>
                      <p className="text-xl font-semibold text-slate-900">{result?.scanCount ?? 0}</p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-500">First verified</p>
                      <p className="text-sm font-medium text-slate-900">{firstScanAt ? new Date(firstScanAt).toLocaleString() : "Not available"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-500">Last verified</p>
                      <p className="text-sm font-medium text-slate-900">{latestScanAt ? new Date(latestScanAt).toLocaleString() : "Not available"}</p>
                    </div>
                    <div>
                      <p className="text-xs text-slate-500">Verified by you</p>
                      <p className="text-xl font-semibold text-slate-900">{result?.verifiedByYouCount ?? 0}</p>
                    </div>
                  </div>

                  <div className="mt-3 grid gap-3 md:grid-cols-2">
                    <p className="text-xs text-slate-500">
                      First location: <span className="font-medium text-slate-700">{firstScanLocation || "Unavailable"}</span>
                    </p>
                    <p className="text-xs text-slate-500">
                      Last location: <span className="font-medium text-slate-700">{latestScanLocation || previousScanLocation || "Unavailable"}</span>
                    </p>
                  </div>

                  {result?.topLocations && result.topLocations.length > 0 ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {result.topLocations.map((entry) => (
                        <Badge key={`${entry.label}_${entry.count}`} variant="secondary" className="bg-slate-100 text-slate-700">
                          <MapPin className="mr-1 h-3 w-3" />
                          {entry.label} ({entry.count})
                        </Badge>
                      ))}
                    </div>
                  ) : null}
                </div>

                {(statusKind === "duplicate" || statusKind === "blocked") && (
                  <div className="rounded-xl border border-red-200 bg-red-50 p-4">
                    <p className="text-sm font-semibold text-red-800">Why this was flagged</p>
                    <ul className="mt-2 space-y-1 text-sm text-red-700">
                      {(result?.reasons || ["Unusual scan pattern detected"]).slice(0, 5).map((reason, idx) => (
                        <li key={`${reason}-${idx}`}>• {reason}</li>
                      ))}
                    </ul>
                    <p className="mt-2 text-xs text-red-700/90">
                      If this is your product, sign in and claim ownership to strengthen protection.
                    </p>
                  </div>
                )}

                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-slate-900">Ownership protection</p>
                      <p className="text-xs text-slate-600">
                        Sign-in is optional. We store scan events to detect duplicates and only keep coarse location signals.
                      </p>
                    </div>
                    {viewerLoading ? <Loader2 className="h-4 w-4 animate-spin text-slate-500" /> : null}
                  </div>

                  {viewer ? (
                    <div className="mt-4 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2">
                        <div>
                          <p className="text-xs text-slate-500">Signed in as</p>
                          <p className="text-sm font-medium text-slate-900">{viewer.email}</p>
                        </div>
                        <Button variant="outline" size="sm" onClick={logoutViewer}>
                          Sign out
                        </Button>
                      </div>

                      {ownership?.isOwnedByYou ? (
                        <div className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-900">
                          Claimed by you on {ownership.claimedAt ? new Date(ownership.claimedAt).toLocaleString() : "this account"}.
                        </div>
                      ) : canClaim ? (
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <p className="text-sm text-slate-700">Claim this product to mark your ownership and improve duplicate detection.</p>
                          <Button type="button" onClick={claimOwnership} disabled={claiming}>
                            {claiming ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Claiming...
                              </>
                            ) : (
                              "Claim this product"
                            )}
                          </Button>
                        </div>
                      ) : ownership && !ownership.isOwnedByYou ? (
                        <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                          This product is already claimed by another account.
                        </div>
                      ) : null}
                    </div>
                  ) : (
                    <div className="mt-4 space-y-4">
                      {googleClientId ? <div ref={googleButtonRef} className="min-h-10" /> : null}

                      <div className="grid gap-3 md:grid-cols-2">
                        <div className="space-y-2">
                          <Label>Email OTP sign-in</Label>
                          <Input
                            type="email"
                            value={otpEmail}
                            onChange={(e) => setOtpEmail(e.target.value)}
                            placeholder="you@example.com"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>Name (optional)</Label>
                          <Input value={otpName} onChange={(e) => setOtpName(e.target.value)} placeholder="Your name" />
                        </div>
                      </div>

                      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
                        <Button type="button" variant="outline" onClick={requestOtp} disabled={otpSending}>
                          {otpSending ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Sending code...
                            </>
                          ) : (
                            <>
                              <LogIn className="mr-2 h-4 w-4" />
                              Continue with email OTP
                            </>
                          )}
                        </Button>

                        {otpRequested ? (
                          <div className="flex w-full items-center gap-2 sm:w-auto">
                            <Input
                              value={otpCode}
                              onChange={(e) => setOtpCode(e.target.value)}
                              placeholder="Enter OTP"
                              className="sm:w-36"
                            />
                            <Button type="button" onClick={verifyOtp} disabled={otpVerifying}>
                              {otpVerifying ? (
                                <>
                                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                  Verifying...
                                </>
                              ) : (
                                "Verify"
                              )}
                            </Button>
                          </div>
                        ) : null}
                      </div>
                    </div>
                  )}
                </div>

                <div className="grid gap-3 md:grid-cols-3">
                  {result?.licensee?.supportEmail && (
                    <div className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700">
                      <Mail className="h-4 w-4 text-slate-500" />
                      <span className="truncate">{result.licensee.supportEmail}</span>
                    </div>
                  )}
                  {result?.licensee?.supportPhone && (
                    <div className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700">
                      <Phone className="h-4 w-4 text-slate-500" />
                      <span>{result.licensee.supportPhone}</span>
                    </div>
                  )}
                  {result?.licensee?.website && (
                    <a
                      href={result.licensee.website}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-sm text-slate-700 transition-colors hover:bg-slate-50"
                    >
                      <Globe2 className="h-4 w-4 text-slate-500" />
                      <span className="truncate">Official website</span>
                    </a>
                  )}
                </div>

                {canSubmitFeedback && (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 md:p-5">
                    <div className="flex items-start gap-2">
                      <Sparkles className="mt-0.5 h-4 w-4 text-cyan-700" />
                      <div>
                        <p className="text-sm font-semibold text-slate-900">How was this product?</p>
                        <p className="text-xs text-slate-500">Share a quick rating for this verified item.</p>
                      </div>
                    </div>

                    {feedbackSubmitted ? (
                      <div className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-900">
                        Thanks, your feedback was shared with the brand team.
                      </div>
                    ) : (
                      <div className="mt-4 space-y-4">
                        <div className="space-y-2">
                          <Label className="text-xs font-medium uppercase tracking-wide text-slate-500">Rating</Label>
                          <div className="flex flex-wrap gap-2">
                            {[1, 2, 3, 4, 5].map((star) => (
                              <button
                                key={star}
                                type="button"
                                onClick={() => setFeedbackRating(star)}
                                className={cn(
                                  "flex h-10 w-10 items-center justify-center rounded-full border transition-colors",
                                  feedbackRating >= star
                                    ? "border-amber-300 bg-amber-50 text-amber-500"
                                    : "border-slate-200 bg-white text-slate-300 hover:bg-slate-50"
                                )}
                                aria-label={`Rate ${star} star${star > 1 ? "s" : ""}`}
                              >
                                <Star className={cn("h-4 w-4", feedbackRating >= star ? "fill-current" : "")} />
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label className="text-xs font-medium uppercase tracking-wide text-slate-500">Satisfaction</Label>
                          <div className="flex flex-wrap gap-2">
                            {SATISFACTION_OPTIONS.map((option) => (
                              <button
                                key={option.value}
                                type="button"
                                onClick={() => setFeedbackSatisfaction(option.value)}
                                className={cn(
                                  "rounded-full border px-3 py-1.5 text-sm transition-colors",
                                  feedbackSatisfaction === option.value
                                    ? "border-slate-900 bg-slate-900 text-white"
                                    : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                                )}
                              >
                                {option.label}
                              </button>
                            ))}
                          </div>
                        </div>

                        <div className="space-y-2">
                          <Label className="text-xs font-medium uppercase tracking-wide text-slate-500">Comment (optional)</Label>
                          <Textarea
                            value={feedbackNote}
                            onChange={(e) => setFeedbackNote(e.target.value)}
                            placeholder="Anything you liked or want improved."
                            rows={3}
                            maxLength={500}
                            className="bg-white"
                          />
                        </div>

                        <div className="flex justify-end">
                          <Button type="button" onClick={submitFeedback} disabled={feedbackSubmitting} className="bg-slate-900 text-white hover:bg-slate-800">
                            {feedbackSubmitting ? (
                              <>
                                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                Sending...
                              </>
                            ) : (
                              "Submit feedback"
                            )}
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex flex-col-reverse gap-3 pt-1 md:flex-row md:justify-between">
                  <Button asChild variant="outline" className="md:w-auto">
                    <Link to="/verify">Verify another code</Link>
                  </Button>

                  <div className="flex flex-col gap-3 md:flex-row">
                    {isReportable && (
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setReportReference(null);
                          setReportOpen(true);
                        }}
                        className="border-red-200 text-red-700 hover:bg-red-50 hover:text-red-800"
                      >
                        <Flag className="mr-2 h-4 w-4" />
                        Report suspected counterfeit
                      </Button>
                    )}

                    {statusKind === "duplicate" && canClaim ? (
                      <Button type="button" onClick={claimOwnership} disabled={claiming} className="bg-slate-900 text-white hover:bg-slate-800">
                        {claiming ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Claiming...
                          </>
                        ) : (
                          "I'm the owner"
                        )}
                      </Button>
                    ) : null}

                    {result?.licensee?.supportEmail ? (
                      <Button asChild variant="outline">
                        <a href={`mailto:${result.licensee.supportEmail}`}>
                          Contact support
                        </a>
                      </Button>
                    ) : null}

                    <Button asChild className="bg-slate-900 text-white hover:bg-slate-800">
                      <Link to="/verify">
                        Check another product
                        <ArrowRight className="ml-2 h-4 w-4" />
                      </Link>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </div>
          )}
        </Card>

        <p className="mt-6 text-center text-sm text-cyan-100/90">Secure verification powered by AuthenticQR</p>
      </div>

      <Dialog open={reportOpen} onOpenChange={setReportOpen}>
        <DialogContent className="sm:max-w-[680px]">
          <DialogHeader>
            <DialogTitle>Report suspected counterfeit</DialogTitle>
            <DialogDescription>
              We will attach scan metadata automatically so investigators can act faster.
            </DialogDescription>
          </DialogHeader>

          {reportReference ? (
            <div className="space-y-4">
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4">
                <p className="text-sm font-semibold text-emerald-800">Report submitted successfully</p>
                <p className="mt-1 text-sm text-emerald-700">
                  Reference ID: <span className="font-mono font-semibold">{reportReference}</span>
                </p>
              </div>
              <p className="text-sm text-slate-600">
                Our team will review this and update you if contact consent was provided.
              </p>
            </div>
          ) : (
            <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1">
              <div className="rounded-lg border bg-slate-50 p-3 text-sm">
                <span className="text-slate-500">Code:</span>
                <span className="ml-2 font-mono font-semibold text-slate-900">{displayedCode}</span>
              </div>

              <div className="rounded-lg border bg-slate-50 p-3 text-sm text-slate-700">
                <p>
                  Classification: <span className="font-medium">{result?.scanClassification || "Unknown"}</span>
                </p>
                <p>
                  Risk reasons: <span className="font-medium">{(result?.reasons || []).join("; ") || "None"}</span>
                </p>
              </div>

              <div className="space-y-2">
                <Label>Incident type</Label>
                <Select value={incidentType} onValueChange={setIncidentType}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select incident type" />
                  </SelectTrigger>
                  <SelectContent>
                    {INCIDENT_TYPE_OPTIONS.map((reason) => (
                      <SelectItem key={reason.value} value={reason.value}>
                        {reason.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>What did you observe?</Label>
                <Textarea
                  value={reportDescription}
                  onChange={(e) => setReportDescription(e.target.value)}
                  placeholder="Describe what looked suspicious."
                  rows={4}
                  maxLength={2000}
                />
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Purchase place (optional)</Label>
                  <Input value={purchasePlace} onChange={(e) => setPurchasePlace(e.target.value)} placeholder="Store / seller name" />
                </div>
                <div className="space-y-2">
                  <Label>Purchase date (optional)</Label>
                  <Input type="date" value={purchaseDate} onChange={(e) => setPurchaseDate(e.target.value)} />
                </div>
              </div>

              <div className="space-y-2">
                <Label>Product batch number (optional)</Label>
                <Input value={productBatchNo} onChange={(e) => setProductBatchNo(e.target.value)} placeholder="Batch / lot code if available" />
              </div>

              <div className="space-y-2">
                <Label>Purchase proof (optional)</Label>
                <Input
                  type="file"
                  multiple
                  accept="image/png,image/jpeg,image/jpg,image/webp,application/pdf"
                  onChange={(e) => setReportPhotos(Array.from(e.target.files || []))}
                />
                <p className="text-xs text-slate-500">Up to 4 files, 5MB each.</p>
              </div>

              <div className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                <label className="flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    checked={reportConsent}
                    onChange={(e) => setReportConsent(e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-slate-300"
                  />
                  <span className="text-sm text-slate-700">
                    I consent to be contacted for investigation updates.
                  </span>
                </label>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Name (optional)</Label>
                  <Input value={reportCustomerName} onChange={(e) => setReportCustomerName(e.target.value)} placeholder="Your name" />
                </div>
                <div className="space-y-2">
                  <Label>Email (optional)</Label>
                  <Input type="email" value={reportEmail} onChange={(e) => setReportEmail(e.target.value)} placeholder="you@example.com" />
                </div>
              </div>

              <div className="grid gap-3 md:grid-cols-2">
                <div className="space-y-2">
                  <Label>Phone (optional)</Label>
                  <Input value={reportPhone} onChange={(e) => setReportPhone(e.target.value)} placeholder="+1 ..." />
                </div>
                <div className="space-y-2">
                  <Label>Country (optional)</Label>
                  <Input value={reportCountry} onChange={(e) => setReportCountry(e.target.value)} placeholder="Country" />
                </div>
              </div>
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setReportOpen(false)} disabled={reporting}>
              {reportReference ? "Close" : "Cancel"}
            </Button>
            {!reportReference ? (
              <Button type="button" onClick={submitReport} disabled={reporting} className="bg-red-600 text-white hover:bg-red-700">
                {reporting ? (
                  <>
                    <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                    Submitting...
                  </>
                ) : (
                  "Submit report"
                )}
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

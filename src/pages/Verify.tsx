import React, { useEffect, useMemo, useRef, useState } from "react";
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
  UserCheck,
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
} from "lucide-react";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

type VerifyPayload = {
  isAuthentic: boolean;
  message?: string;
  code?: string;
  status?: string;
  isFirstScan?: boolean;
  policy?: any;
  containment?: {
    qrUnderInvestigation?: { at: string; reason: string | null } | null;
    batchSuspended?: { at: string; reason: string | null } | null;
    orgSuspended?: { at: string; reason: string | null } | null;
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
  printedAt?: string | null;
  firstScanned?: string | null;
  firstScanAt?: string | null;
  firstScanLocation?: string | null;
  latestScanAt?: string | null;
  latestScanLocation?: string | null;
  previousScanAt?: string | null;
  previousScanLocation?: string | null;
  scanCount?: number;
  scanOutcome?: string;
  warningMessage?: string | null;
};

type StatusKind = "first" | "verified_again" | "possible_duplicate" | "blocked" | "suspicious" | "unassigned" | "invalid";

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
  "Checking print lifecycle",
  "Validating authenticity records",
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
  first: {
    title: "Verified Authentic",
    subtitle: "First-time verification completed successfully.",
    chip: "Authentic",
    panelClass: "from-emerald-600 to-teal-600",
    icon: <CheckCircle2 className="h-10 w-10 text-white" />,
  },
  verified_again: {
    title: "Verified Again",
    subtitle: "Authentic product. You have verified this before.",
    chip: "Authentic",
    panelClass: "from-emerald-600 to-cyan-600",
    icon: <UserCheck className="h-10 w-10 text-white" />,
  },
  possible_duplicate: {
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

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [reportOpen, setReportOpen] = useState(false);
  const [incidentType, setIncidentType] = useState<string>(INCIDENT_TYPE_OPTIONS[0].value);
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

  const token = useMemo(() => searchParams.get("t")?.trim() || "", [searchParams.toString()]);
  const codeParam = useMemo(() => {
    const raw = String(code || "");
    try {
      return decodeURIComponent(raw).trim();
    } catch {
      return raw.trim();
    }
  }, [code]);
  const requestKey = token ? `token:${token}` : codeParam ? `code:${codeParam.toUpperCase()}` : "";
  const inFlightByKeyRef = useRef(new Map<string, Promise<any>>());

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
                })
              : apiClient.verifyQRCode(codeParam, {
                  device,
                  lat: geo.lat,
                  lon: geo.lon,
                  acc: geo.acc,
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
  }, [codeParam, requestKey, token]);

  const statusKind: StatusKind = useMemo(() => {
    const scanOutcome = String(result?.scanOutcome || "").toUpperCase();
    const status = String(result?.status || "").toUpperCase();

    if (scanOutcome === "BLOCKED" || status === "BLOCKED") return "blocked";

    if (scanOutcome === "SUSPICIOUS" || status === "ALLOCATED" || status === "ACTIVATED") {
      return "suspicious";
    }

    if (status === "DORMANT" || status === "ACTIVE" || scanOutcome === "NOT_PRINTED") {
      return "unassigned";
    }

    const isAuthentic = Boolean(result?.isAuthentic);
    const isFirstScan = Boolean((result as any)?.isFirstScan);
    const policy: any = (result as any)?.policy || null;
    const triggered: any = policy?.triggered || {};
    const alerts: any[] = Array.isArray(policy?.alerts) ? policy.alerts : [];

    const hasDuplicateSignals =
      Boolean(triggered.multiScan || triggered.geoDrift || triggered.velocitySpike) ||
      alerts.some((a) => {
        const t = String(a?.alertType || "").toUpperCase();
        return ["POLICY_RULE", "MULTI_SCAN", "GEO_DRIFT", "VELOCITY_SPIKE", "AUTO_BLOCK_QR", "AUTO_BLOCK_BATCH"].includes(t);
      });

    const possibleDuplicate = isAuthentic && !isFirstScan && hasDuplicateSignals;

    if (isAuthentic) {
      if (possibleDuplicate) return "possible_duplicate";
      return isFirstScan ? "first" : "verified_again";
    }

    const lowerMessage = String(result?.message || "").toLowerCase();
    if (lowerMessage.includes("blocked")) return "blocked";
    if (lowerMessage.includes("allocated but not yet printed")) return "suspicious";
    if (lowerMessage.includes("not been assigned")) return "unassigned";
    return "invalid";
  }, [result]);

  const meta = STATUS_META[statusKind];
  const manufacturer = result?.batch?.manufacturer || null;
  const displayedCode = result?.code || codeParam || "—";
  const printedAt = result?.printedAt || result?.batch?.printedAt || null;
  const isReportable = statusKind === "possible_duplicate" || statusKind === "blocked" || statusKind === "suspicious" || statusKind === "invalid";
  const canSubmitFeedback = displayedCode !== "—" && statusKind !== "invalid";
  const firstScanAt = result?.firstScanAt || result?.firstScanned || null;
  const firstScanLocation = result?.firstScanLocation || null;
  const latestScanAt = result?.latestScanAt || null;
  const latestScanLocation = result?.latestScanLocation || null;
  const previousScanAt = result?.previousScanAt || null;
  const previousScanLocation = result?.previousScanLocation || null;

  const containment = result?.containment || null;
  const hasContainment =
    Boolean(containment?.qrUnderInvestigation) ||
    Boolean(containment?.batchSuspended) ||
    Boolean(containment?.orgSuspended);

  const policyAlerts = useMemo(() => {
    const alerts = (result as any)?.policy?.alerts;
    return Array.isArray(alerts) ? alerts : [];
  }, [result]);

  const riskReasons = useMemo(() => {
    if (statusKind !== "possible_duplicate") return [];
    const policy: any = (result as any)?.policy || null;
    const triggered: any = policy?.triggered || {};
    const reasons: string[] = [];
    if (triggered.multiScan) reasons.push("High repeat scan count for this QR.");
    if (triggered.geoDrift) reasons.push("Recent scans show large location drift.");
    if (triggered.velocitySpike) reasons.push("Unusually high scan frequency in this batch.");

    for (const a of policyAlerts) {
      const msg = String(a?.message || "").trim();
      if (msg && !reasons.includes(msg)) reasons.push(msg);
    }

    return reasons.slice(0, 6);
  }, [policyAlerts, result, statusKind]);

  const primaryMessage = useMemo(() => {
    if (statusKind === "first") return "This is a genuine product.";
    if (statusKind === "verified_again") return "Authentic item verified again.";
    if (statusKind === "possible_duplicate") return "Possible duplicate scan detected.";
    return result?.message || "Verification details";
  }, [result?.message, statusKind]);

  const messageTone = useMemo(() => {
    if (statusKind === "first" || statusKind === "verified_again") return "success";
    if (statusKind === "blocked" || statusKind === "invalid") return "danger";
    return "warning";
  }, [statusKind]);

  const showScanHistory =
    statusKind !== "invalid" &&
    (typeof result?.scanCount === "number" || Boolean(firstScanAt) || Boolean(latestScanAt));
  const feedbackStorageKey = useMemo(() => {
    const normalized = String(displayedCode || "").trim().toUpperCase();
    return normalized && normalized !== "—" ? `authenticqr_feedback_${normalized}` : "";
  }, [displayedCode]);

  useEffect(() => {
    if (!isLoading) return;
    const timer = window.setInterval(() => {
      setLoadingStepIdx((prev) => (prev + 1) % VERIFY_LOADING_STEPS.length);
    }, 1100);
    return () => window.clearInterval(timer);
  }, [isLoading]);

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
      formData.append("qrCodeValue", normalizedCode);
      formData.append("incidentType", incidentType);
      formData.append("description", reportDescription.trim());
      if (purchasePlace.trim()) formData.append("purchasePlace", purchasePlace.trim());
      if (purchaseDate.trim()) formData.append("purchaseDate", purchaseDate.trim());
      if (productBatchNo.trim()) formData.append("productBatchNo", productBatchNo.trim());
      if (reportCustomerName.trim()) formData.append("customerName", reportCustomerName.trim());
      if (reportEmail.trim()) formData.append("customerEmail", reportEmail.trim());
      if (reportPhone.trim()) formData.append("customerPhone", reportPhone.trim());
      if (reportCountry.trim()) formData.append("customerCountry", reportCountry.trim());
      formData.append("consentToContact", String(reportConsent));
      formData.append("preferredContactMethod", reportConsent && reportEmail.trim() ? "email" : "none");
      if (typeof window !== "undefined" && window.location.href) {
        formData.append("tags", JSON.stringify(["verify_page_report", `status_${String(result?.status || "unknown").toLowerCase()}`]));
      }
      for (const photo of reportPhotos.slice(0, 4)) {
        formData.append("photos", photo);
      }

      const res = await apiClient.submitIncidentReport(formData);

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
      setReportReference((res.data as any)?.reference || (res.data as any)?.incidentId || null);
      setIncidentType(INCIDENT_TYPE_OPTIONS[0].value);
      setReportDescription("");
      setPurchasePlace("");
      setPurchaseDate("");
      setProductBatchNo("");
      setReportCustomerName("");
      setReportEmail("");
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
                      <Shield className="h-12 w-12 text-slate-700 animate-pulse" />
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
                  <div
                    className="inline-flex h-16 w-16 items-center justify-center rounded-2xl border border-white/30 bg-white/15"
                    style={{ animation: "verify-icon-pulse 1.8s ease-in-out infinite" }}
                  >
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
                    <p className="text-base font-semibold text-slate-900">
                      {result?.licensee?.brandName || result?.licensee?.name || "—"}
                    </p>
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

                {hasContainment ? (
                  <div className="rounded-xl border border-orange-200 bg-orange-50 px-4 py-3 text-sm text-orange-900">
                    <p className="font-semibold">Under investigation</p>
                    <p className="mt-1 text-orange-900/90">
                      This product is currently under investigation. If you need help, contact the brand support details below.
                    </p>
                    {containment?.qrUnderInvestigation?.reason ? (
                      <p className="mt-1 text-xs text-orange-900/80">Reason: {containment.qrUnderInvestigation.reason}</p>
                    ) : null}
                  </div>
                ) : null}

                {(primaryMessage || result?.warningMessage) ? (
                  <div
                    className={cn(
                      "rounded-xl border px-4 py-3 text-sm",
                      messageTone === "success" && "border-emerald-200 bg-emerald-50 text-emerald-900",
                      messageTone === "warning" && "border-amber-300 bg-amber-50 text-amber-900",
                      messageTone === "danger" && "border-red-200 bg-red-50 text-red-900"
                    )}
                  >
                    <p className="font-medium">{primaryMessage}</p>
                    {statusKind === "verified_again" ? (
                      <div className="mt-1 space-y-1 text-emerald-900/90">
                        <p>You have verified this product before.</p>
                        <p>You can safely show this screen again if someone asks for proof.</p>
                      </div>
                    ) : null}
                    {statusKind === "possible_duplicate" ? (
                      <p className="mt-1 text-amber-900/90">
                        Review details below before trusting this label. If anything looks wrong, report it.
                      </p>
                    ) : null}
                    {result?.warningMessage ? (
                      <p
                        className={cn(
                          "mt-2",
                          messageTone === "success" && "text-emerald-900/80",
                          messageTone === "warning" && "text-amber-900/80",
                          messageTone === "danger" && "text-red-900/80"
                        )}
                      >
                        {result.warningMessage}
                      </p>
                    ) : null}
                  </div>
                ) : null}

                {statusKind === "possible_duplicate" ? (
                  <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-900">
                    <p className="font-semibold">Why this was flagged</p>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-red-900/90">
                      {(riskReasons.length > 0 ? riskReasons : ["Unusual scan pattern detected by security policy."]).map((r) => (
                        <li key={r}>{r}</li>
                      ))}
                    </ul>
                  </div>
                ) : null}

                {showScanHistory ? (
                  <div className="rounded-xl border border-slate-200 bg-white p-4">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Scan history summary</p>
                      <Badge variant="outline" className="text-xs">Coarse city/country only</Badge>
                    </div>
                    <div className="grid gap-3 md:grid-cols-3">
                      <div>
                        <p className="text-xs uppercase tracking-wide text-slate-500">Total scans</p>
                        <p className="mt-1 text-2xl font-semibold text-slate-900">{result?.scanCount ?? 0}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-slate-500">First verified</p>
                        <p className="mt-1 text-sm font-medium text-slate-900">
                          {firstScanAt ? new Date(firstScanAt).toLocaleString() : "Not available"}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">{firstScanLocation || "Location unavailable"}</p>
                      </div>
                      <div>
                        <p className="text-xs uppercase tracking-wide text-slate-500">Latest verified</p>
                        <p className="mt-1 text-sm font-medium text-slate-900">
                          {latestScanAt ? new Date(latestScanAt).toLocaleString() : "Not available"}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">
                          {latestScanLocation || previousScanLocation || "Location unavailable"}
                        </p>
                      </div>
                    </div>
                  </div>
                ) : null}

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
                <Label>Photos (optional)</Label>
                <Input
                  type="file"
                  multiple
                  accept="image/png,image/jpeg,image/jpg,image/webp"
                  onChange={(e) => setReportPhotos(Array.from(e.target.files || []))}
                />
                <p className="text-xs text-slate-500">Up to 4 photos, 5MB each.</p>
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
                {reporting ? "Submitting..." : "Submit report"}
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

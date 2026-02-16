import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { AlertTriangle, Ban, CheckCircle2, Loader2, SearchX, Shield, UserCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import apiClient from "@/lib/api-client";
import { getOrCreateAnonDeviceId } from "@/lib/anon-device";
import { cn } from "@/lib/utils";

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

const INCIDENT_TYPE_OPTIONS = [
  { value: "counterfeit_suspected", label: "Counterfeit suspected" },
  { value: "duplicate_scan", label: "Duplicate scan" },
  { value: "tampered_label", label: "Tampered label" },
  { value: "wrong_product", label: "Wrong product" },
  { value: "other", label: "Other" },
] as const;

const CUSTOMER_TOKEN_KEY = "authenticqr_verify_customer_token";
const CUSTOMER_EMAIL_KEY = "authenticqr_verify_customer_email";

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
    icon: React.ReactNode;
  }
> = {
  FIRST_SCAN: {
    title: "Verified Authentic",
    subtitle: "First customer verification completed successfully.",
    badge: "Authentic",
    bannerClass: "bg-emerald-700 text-white",
    icon: <CheckCircle2 className="h-6 w-6" />,
  },
  LEGIT_REPEAT: {
    title: "Verified Again",
    subtitle: "Product is authentic and repeat scans are consistent.",
    badge: "Authentic",
    bannerClass: "bg-teal-700 text-white",
    icon: <UserCheck className="h-6 w-6" />,
  },
  SUSPICIOUS_DUPLICATE: {
    title: "Suspicious Duplicate",
    subtitle: "Scan pattern indicates duplicate or cloned-label risk.",
    badge: "Fraud Risk",
    bannerClass: "bg-amber-700 text-white",
    icon: <AlertTriangle className="h-6 w-6" />,
  },
  BLOCKED_BY_SECURITY: {
    title: "Blocked by Security",
    subtitle: "This code is blocked by security or containment controls.",
    badge: "Blocked",
    bannerClass: "bg-rose-800 text-white",
    icon: <Ban className="h-6 w-6" />,
  },
  NOT_READY_FOR_CUSTOMER_USE: {
    title: "Not Ready for Customer Use",
    subtitle: "Code lifecycle is incomplete or unavailable for customer verification.",
    badge: "Not Ready",
    bannerClass: "bg-slate-700 text-white",
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

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const { toast } = useToast();

  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [customerToken, setCustomerToken] = useState<string>("");
  const [customerEmail, setCustomerEmail] = useState<string>("");

  const [otpEmail, setOtpEmail] = useState("");
  const [otpChallengeToken, setOtpChallengeToken] = useState("");
  const [otpMaskedEmail, setOtpMaskedEmail] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [otpSending, setOtpSending] = useState(false);
  const [otpVerifying, setOtpVerifying] = useState(false);

  const [claiming, setClaiming] = useState(false);

  const [reportOpen, setReportOpen] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reportReference, setReportReference] = useState<string | null>(null);
  const [reportType, setReportType] = useState<string>(INCIDENT_TYPE_OPTIONS[0].value);
  const [reportDescription, setReportDescription] = useState("");
  const [reportEmail, setReportEmail] = useState("");
  const [reportPhotos, setReportPhotos] = useState<File[]>([]);

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

  const displayedCode = result?.code || codeParam || "—";
  const classification = useMemo(() => inferClassification(result), [result]);
  const classMeta = CLASS_META[classification];
  const reasons = useMemo(() => deriveReasons(result, classification), [classification, result]);
  const scanSummary = useMemo(() => deriveScanSummary(result), [result]);
  const ownershipStatus = result?.ownershipStatus || DEFAULT_OWNERSHIP_STATUS;

  const isBlocked = Boolean(result?.isBlocked ?? (String(result?.status || "").toUpperCase() === "BLOCKED"));
  const isReady = Boolean(result?.isReady ?? !["DORMANT", "ACTIVE", "ALLOCATED", "ACTIVATED", "BLOCKED"].includes(String(result?.status || "").toUpperCase()));

  const googleOauthUrl = String(import.meta.env.VITE_GOOGLE_OAUTH_URL || "").trim();

  const fetchVerification = useCallback(async () => {
    if (!requestKey) {
      setLoading(false);
      setResult({ isAuthentic: false, message: "Missing verification code" });
      return;
    }

    setLoading(true);
    setError(null);

    try {
      let pending = inFlightRef.current.get(requestKey);

      if (!pending) {
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
      }

      const response = await pending;
      inFlightRef.current.delete(requestKey);

      if (!response.success) {
        setError(response.error || "Verification failed");
        setResult(null);
        return;
      }

      setResult((response.data as VerifyPayload) || null);
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
    if (!customerToken) {
      toast({ title: "Sign in required", description: "Sign in with email OTP to claim product ownership.", variant: "destructive" });
      return;
    }

    if (!displayedCode || displayedCode === "—") {
      toast({ title: "Invalid code", description: "Cannot claim without a valid verification code.", variant: "destructive" });
      return;
    }

    setClaiming(true);
    try {
      const response = await apiClient.claimVerifiedProduct(displayedCode, customerToken);
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
      } else {
        toast({ title: "Ownership claimed", description: "Product ownership is now linked to your account." });
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
    } finally {
      setClaiming(false);
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

      setReportReference((response.data as any)?.reportId || null);
      toast({ title: "Report submitted", description: "Security team has received your report." });
    } finally {
      setReporting(false);
    }
  };

  const supportEmail = result?.licensee?.supportEmail || "";
  const supportPhone = result?.licensee?.supportPhone || "";
  const supportWebsite = result?.licensee?.website || "";

  return (
    <div className="min-h-screen bg-slate-100 px-4 py-8">
      <div className="mx-auto w-full max-w-4xl space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Link to="/verify" className="inline-flex items-center gap-2 text-slate-900">
            <Shield className="h-6 w-6" />
            <span className="text-xl font-semibold">AuthenticQR Verification</span>
          </Link>
          <Button asChild variant="outline">
            <Link to="/verify">Verify another code</Link>
          </Button>
        </div>

        <Card className="border-slate-200 shadow-sm">
          {loading ? (
            <CardContent className="flex items-center justify-center py-16 text-slate-600">
              <Loader2 className="mr-2 h-5 w-5 animate-spin" />
              Verifying product authenticity...
            </CardContent>
          ) : error ? (
            <CardContent className="space-y-3 py-12 text-center">
              <SearchX className="mx-auto h-8 w-8 text-rose-700" />
              <p className="text-lg font-semibold text-slate-900">Verification service unavailable</p>
              <p className="text-sm text-slate-600">{error}</p>
            </CardContent>
          ) : (
            <CardContent className="space-y-6 p-5 sm:p-6">
              <section className="space-y-3">
                <div className={cn("rounded-xl p-4", classMeta.bannerClass)}>
                  <div className="flex items-start gap-3">
                    <div className="rounded-md bg-white/20 p-2">{classMeta.icon}</div>
                    <div className="min-w-0 flex-1">
                      <p className="text-xs uppercase tracking-wide text-white/80">1. Verification Result Banner</p>
                      <h1 className="text-2xl font-semibold">{classMeta.title}</h1>
                      <p className="mt-1 text-sm text-white/90">{classMeta.subtitle}</p>
                      <p className="mt-2 text-sm text-white/90">{result?.message || "Verification completed."}</p>
                      {result?.warningMessage ? <p className="mt-2 text-sm text-white/90">{result.warningMessage}</p> : null}
                    </div>
                    <Badge className="border-white/30 bg-white/20 text-white">{classMeta.badge}</Badge>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-200 bg-white p-4">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Verified Code</p>
                  <p className="mt-1 font-mono text-xl font-semibold text-slate-900">{displayedCode}</p>
                  <div className="mt-3 space-y-1">
                    <p className="text-xs uppercase tracking-wide text-slate-500">Reasons</p>
                    <ul className="list-disc space-y-1 pl-5 text-sm text-slate-700">
                      {reasons.map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">2. Scan Summary</p>
                <div className="mt-3 grid gap-3 md:grid-cols-3">
                  <div className="rounded-lg border border-slate-200 p-3">
                    <p className="text-xs text-slate-500">Total scans</p>
                    <p className="mt-1 text-2xl font-semibold text-slate-900">{scanSummary.totalScans}</p>
                  </div>
                  <div className="rounded-lg border border-slate-200 p-3">
                    <p className="text-xs text-slate-500">First verified</p>
                    <p className="mt-1 text-sm font-medium text-slate-900">{formatDateTime(scanSummary.firstVerifiedAt)}</p>
                    <p className="mt-1 text-xs text-slate-500">{scanSummary.firstVerifiedLocation || "Location unavailable"}</p>
                  </div>
                  <div className="rounded-lg border border-slate-200 p-3">
                    <p className="text-xs text-slate-500">Latest verified</p>
                    <p className="mt-1 text-sm font-medium text-slate-900">{formatDateTime(scanSummary.latestVerifiedAt)}</p>
                    <p className="mt-1 text-xs text-slate-500">{scanSummary.latestVerifiedLocation || "Location unavailable"}</p>
                  </div>
                </div>

                <div className="mt-3 grid gap-2 text-sm text-slate-700 md:grid-cols-2">
                  <p>
                    <span className="font-medium">Brand:</span> {result?.licensee?.brandName || result?.licensee?.name || "—"}
                  </p>
                  <p>
                    <span className="font-medium">Manufacturer:</span> {result?.batch?.manufacturer?.name || "—"}
                  </p>
                  <p>
                    <span className="font-medium">Blocked:</span> {isBlocked ? "Yes" : "No"}
                  </p>
                  <p>
                    <span className="font-medium">Ready for customer use:</span> {isReady ? "Yes" : "No"}
                  </p>
                </div>
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs uppercase tracking-wide text-slate-500">3. Ownership Section</p>
                  {customerToken ? <Badge variant="outline">Signed in for protection</Badge> : null}
                </div>

                {!customerToken ? (
                  <div className="mt-3 space-y-4">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                      <p className="font-medium">Sign in for better protection</p>
                      <p className="mt-1">Sign-in is optional. You can still verify without signing in.</p>
                    </div>

                    {googleOauthUrl ? (
                      <Button asChild variant="outline" className="w-full sm:w-auto">
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
                        />
                      </div>
                      <Button type="button" onClick={handleRequestOtp} disabled={otpSending} className="bg-slate-900 text-white hover:bg-slate-800">
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
                      <div className="space-y-3 rounded-lg border border-slate-200 p-3">
                        <p className="text-sm text-slate-700">Enter 6-digit OTP sent to {otpMaskedEmail || "your email"}.</p>
                        <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-end">
                          <div className="space-y-2">
                            <Label>One-time code</Label>
                            <Input value={otpCode} onChange={(e) => setOtpCode(e.target.value)} maxLength={6} placeholder="123456" />
                          </div>
                          <Button type="button" onClick={handleVerifyOtp} disabled={otpVerifying} className="bg-slate-900 text-white hover:bg-slate-800">
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
                      </div>
                    ) : null}
                  </div>
                ) : (
                  <div className="mt-3 space-y-3">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                      <p className="font-medium">Signed in as {customerEmail}</p>
                      <p className="mt-1">Use this session to claim ownership and strengthen duplicate protection.</p>
                    </div>

                    {ownershipStatus.isOwnedByRequester ? (
                      <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                        <p className="font-semibold">Owned by you</p>
                        <p className="mt-1">Claimed at: {formatDateTime(ownershipStatus.claimedAt)}</p>
                      </div>
                    ) : ownershipStatus.isClaimedByAnother ? (
                      <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                        <p className="font-semibold">Already claimed by another account</p>
                        <p className="mt-1">Do not trust this product blindly. Submit a counterfeit report for investigation.</p>
                      </div>
                    ) : (
                      <div className="flex flex-wrap items-center gap-3">
                        <Button
                          type="button"
                          onClick={handleClaimProduct}
                          disabled={claiming}
                          className="bg-slate-900 text-white hover:bg-slate-800"
                        >
                          {claiming ? (
                            <>
                              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                              Claiming
                            </>
                          ) : (
                            "Claim this product"
                          )}
                        </Button>
                      </div>
                    )}

                    <Button type="button" variant="outline" onClick={handleSignOut}>
                      Sign out
                    </Button>
                  </div>
                )}
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="text-xs uppercase tracking-wide text-slate-500">4. Report Section</p>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => {
                      setReportReference(null);
                      setReportOpen(true);
                    }}
                    className="border-rose-200 text-rose-700 hover:bg-rose-50 hover:text-rose-800"
                  >
                    Report suspected counterfeit
                  </Button>
                </div>
                <p className="mt-3 text-sm text-slate-700">
                  Reporting sends classification, reason summary, scan summary, and ownership status automatically to incident response.
                </p>
              </section>

              <section className="rounded-xl border border-slate-200 bg-white p-4">
                <p className="text-xs uppercase tracking-wide text-slate-500">5. Privacy Note</p>
                <ul className="mt-3 list-disc space-y-1 pl-5 text-sm text-slate-700">
                  <li>Sign-in is optional.</li>
                  <li>Platform stores scan events to detect duplicates.</li>
                  <li>Only coarse location context may be stored.</li>
                  <li>No precise tracking interface is shown to customers.</li>
                </ul>
              </section>

              {(supportEmail || supportPhone || supportWebsite) && (
                <section className="rounded-xl border border-slate-200 bg-white p-4 text-sm text-slate-700">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Support Contact</p>
                  <div className="mt-2 space-y-1">
                    {supportEmail ? <p>Email: {supportEmail}</p> : null}
                    {supportPhone ? <p>Phone: {supportPhone}</p> : null}
                    {supportWebsite ? <p>Website: {supportWebsite}</p> : null}
                  </div>
                </section>
              )}
            </CardContent>
          )}
        </Card>
      </div>

      <Dialog open={reportOpen} onOpenChange={setReportOpen}>
        <DialogContent className="sm:max-w-[640px]">
          <DialogHeader>
            <DialogTitle>Report suspected counterfeit</DialogTitle>
            <DialogDescription>
              Provide investigation details. Verification metadata will be attached automatically.
            </DialogDescription>
          </DialogHeader>

          {reportReference ? (
            <div className="rounded-lg border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
              Report submitted successfully. Reference ID: <span className="font-mono font-semibold">{reportReference}</span>
            </div>
          ) : (
            <div className="max-h-[65vh] space-y-4 overflow-y-auto pr-1">
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

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setReportOpen(false)} disabled={reporting}>
              {reportReference ? "Close" : "Cancel"}
            </Button>
            {!reportReference ? (
              <Button type="button" onClick={handleSubmitReport} disabled={reporting} className="bg-rose-700 text-white hover:bg-rose-800">
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
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

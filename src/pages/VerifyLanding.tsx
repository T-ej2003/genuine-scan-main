import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Camera, Keyboard, Loader2, QrCode, ScanLine, ShieldCheck } from "lucide-react";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { MotionPanel } from "@/components/mscqr/motion";
import { StatusBadge } from "@/components/mscqr/status";
import { PublicShell } from "@/components/public/PublicShell";

type NavigatorWithConnection = Navigator & {
  connection?: {
    effectiveType?: string;
  };
};

type BarcodeScanResult = {
  rawValue?: string | null;
};

type BarcodeDetectorCtor = new (options: { formats: string[] }) => {
  detect: (image: ImageBitmapSource) => Promise<BarcodeScanResult[]>;
};

type WindowWithBarcodeDetector = Window & {
  BarcodeDetector?: BarcodeDetectorCtor;
};

export default function VerifyLanding() {
  const [code, setCode] = useState("");
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [scanStage, setScanStage] = useState<0 | 1>(0);
  const [cameraDecoding, setCameraDecoding] = useState(false);
  const [cameraError, setCameraError] = useState("");
  const navigate = useNavigate();
  const { toast } = useToast();
  const timersRef = useRef<number[]>([]);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const cleaned = useMemo(() => code.trim(), [code]);
  const browserWindow = typeof window !== "undefined" ? (window as WindowWithBarcodeDetector) : undefined;
  const navWithConnection = navigator as NavigatorWithConnection;
  const cameraAssistSupported = typeof browserWindow?.BarcodeDetector !== "undefined";

  useEffect(() => {
    const timers = timersRef.current;
    return () => {
      for (const timer of timers) window.clearTimeout(timer);
      timers.length = 0;
    };
  }, []);

  const go = () => {
    if (!cleaned || isRedirecting) return;

    for (const timer of timersRef.current) window.clearTimeout(timer);
    timersRef.current.length = 0;

    setIsRedirecting(true);
    setScanStage(0);

    apiClient
      .captureRouteTransition({
        routeFrom: "/verify",
        routeTo: `/verify/${encodeURIComponent(cleaned)}`,
        source: "verify_redirect",
        transitionMs: 1250,
        verifyCodePresent: true,
        deviceType: /mobile/i.test(navigator.userAgent) ? "mobile" : "desktop",
        networkType: String(navWithConnection.connection?.effectiveType || "unknown"),
        online: navigator.onLine,
      })
      .catch(() => {
        // best effort telemetry
      });

    const stageTimer = window.setTimeout(() => setScanStage(1), 700);
    const navTimer = window.setTimeout(() => {
      navigate(`/verify/${encodeURIComponent(cleaned)}`);
    }, 1250);

    timersRef.current.push(stageTimer, navTimer);
  };

  const handleCameraCapture = async (file: File) => {
    if (!file) return;
    if (!cameraAssistSupported) {
      setCameraError("Camera code scanning is not supported in this browser. Enter the code manually.");
      return;
    }

    setCameraDecoding(true);
    setCameraError("");
    try {
      const Detector = browserWindow?.BarcodeDetector;
      if (!Detector) {
        setCameraError("Camera code scanning is not supported in this browser. Enter the code manually.");
        return;
      }
      const detector = new Detector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const [result] = await detector.detect(bitmap);
      const rawValue = String(result?.rawValue || "").trim();
      if (!rawValue) {
        setCameraError("No code was detected in the captured image. Try again with better lighting.");
        return;
      }

      setCode(rawValue);
      toast({ title: "Code captured", description: "Code detected successfully. Starting verification." });
      apiClient
        .captureRouteTransition({
          routeFrom: "/verify",
          routeTo: `/verify/${encodeURIComponent(rawValue)}`,
          source: "mobile_camera_scan",
          transitionMs: 400,
          verifyCodePresent: true,
          deviceType: /mobile/i.test(navigator.userAgent) ? "mobile" : "desktop",
          networkType: String(navWithConnection.connection?.effectiveType || "unknown"),
          online: navigator.onLine,
        })
        .catch(() => {
          // best effort telemetry
        });
      const settleTimer = window.setTimeout(() => {
        setCode(rawValue);
        setCameraDecoding(false);
        setCameraError("");
        setIsRedirecting(false);
        setScanStage(0);
        const navTimer = window.setTimeout(() => navigate(`/verify/${encodeURIComponent(rawValue)}`), 200);
        timersRef.current.push(navTimer);
      }, 100);
      timersRef.current.push(settleTimer);
    } catch (error: unknown) {
      setCameraError(error instanceof Error ? error.message : "Camera decode failed. Use manual entry if this continues.");
    } finally {
      setCameraDecoding(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <PublicShell>
      {isRedirecting ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-[#05080c]/82 backdrop-blur-md">
          <div className="rounded-[1.75rem] border border-cyan-200/20 bg-mscqr-surface-elevated/95 p-6 text-mscqr-primary shadow-[0_30px_120px_rgba(0,0,0,0.45)]">
            <div className="flex items-center gap-4">
              <span className="relative flex size-12 items-center justify-center rounded-2xl border border-cyan-200/25 bg-cyan-200/10 text-cyan-100">
                <span className="absolute inline-flex size-full animate-ping rounded-2xl bg-cyan-200/20 motion-reduce:animate-none" />
                <ScanLine className="relative size-5" />
              </span>
              <div>
                <p className="text-sm font-semibold text-white">{scanStage === 0 ? "Scanning code" : "Preparing verification"}</p>
                <p className="mt-1 text-xs text-slate-400">Opening the governed verification lifecycle.</p>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      <main className="relative isolate overflow-hidden">
        <div className="pointer-events-none absolute inset-0 -z-10">
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_18%_10%,rgba(34,211,238,0.14),transparent_28%),radial-gradient(circle_at_88%_20%,rgba(251,191,36,0.08),transparent_22%)]" />
          <div className="absolute inset-0 mscqr-public-grid opacity-70" />
        </div>

        <div className="mx-auto grid min-h-[calc(100svh-145px)] w-full max-w-7xl gap-10 px-4 py-14 lg:min-h-[calc(100svh-81px)] lg:grid-cols-[0.9fr_1.1fr] lg:items-center lg:py-20">
          <MotionPanel className="max-w-3xl">
            <StatusBadge tone="issued">Public verification</StatusBadge>
            <h1 className="mt-7 text-balance text-5xl font-semibold leading-[0.98] tracking-[-0.055em] text-white sm:text-6xl">
              Check a product without losing the evidence trail.
            </h1>
            <p className="mt-6 max-w-2xl text-base leading-8 text-slate-300">
              Scan a signed MSCQR label or enter the printed code manually. The result is checked against governed
              issuance, print state, scan history, and review policy.
            </p>
            <div className="mt-8 grid gap-3 sm:grid-cols-3">
              <VerificationPromise icon={ShieldCheck} label="Lifecycle checked" />
              <VerificationPromise icon={QrCode} label="Manual fallback" />
              <VerificationPromise icon={ScanLine} label="Duplicate-aware" />
            </div>
          </MotionPanel>

          <MotionPanel>
            <div className="relative overflow-hidden rounded-[2rem] border border-white/12 bg-mscqr-surface/92 shadow-[0_40px_140px_rgba(0,0,0,0.48)]">
              <div className="border-b border-white/10 bg-white/[0.035] px-5 py-4 sm:px-6">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-xs uppercase tracking-[0.26em] text-slate-500">MSCQR verification entry</p>
                    <h2 className="mt-1 text-2xl font-semibold text-white">Verify a product</h2>
                  </div>
                  <span className="relative flex size-11 items-center justify-center rounded-2xl border border-cyan-200/25 bg-cyan-200/10 text-cyan-100">
                    <span className="absolute inline-flex size-full animate-ping rounded-2xl bg-cyan-200/20 motion-reduce:animate-none" />
                    <QrCode className="relative size-5" />
                  </span>
                </div>
              </div>

              <div className="grid gap-6 p-5 sm:p-6">
                <div className="grid gap-2">
                  <label htmlFor="verify-code" className="text-sm font-medium text-slate-200">
                    Label code
                  </label>
                  <Input
                    id="verify-code"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="e.g. MSCQR-7F42-91C8"
                    disabled={isRedirecting}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") go();
                    }}
                    className="h-12 border-white/10 bg-[#05080c] font-mono text-base text-white placeholder:text-slate-600 focus-visible:ring-cyan-200/60"
                  />
                  <p className="text-xs leading-5 text-slate-500">Manual lookup remains available if scanning is not possible.</p>
                </div>

                <div className="grid gap-3 sm:grid-cols-2">
                  <Button
                    className="h-12 bg-none bg-cyan-200 text-slate-950 hover:bg-cyan-100"
                    onClick={go}
                    disabled={!cleaned || isRedirecting}
                  >
                    {isRedirecting ? (
                      <>
                        <Loader2 data-icon="inline-start" className="animate-spin" />
                        <span>{scanStage === 0 ? "Scanning" : "Preparing"}</span>
                      </>
                    ) : (
                      <>
                        <Keyboard data-icon="inline-start" />
                        Verify code
                      </>
                    )}
                  </Button>

                  <input
                    ref={fileInputRef}
                    type="file"
                    accept="image/*"
                    capture="environment"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleCameraCapture(file);
                    }}
                  />

                  <Button
                    type="button"
                    variant="outline"
                    className="h-12 border-white/10 bg-white/[0.04] text-slate-100 hover:bg-white/[0.08]"
                    disabled={isRedirecting || cameraDecoding}
                    onClick={() => fileInputRef.current?.click()}
                  >
                    {cameraDecoding ? (
                      <>
                        <Loader2 data-icon="inline-start" className="animate-spin" />
                        Decoding
                      </>
                    ) : (
                      <>
                        <Camera data-icon="inline-start" />
                        Camera capture
                      </>
                    )}
                  </Button>
                </div>

                {cameraError ? (
                  <div className="rounded-2xl border border-rose-300/25 bg-rose-300/10 px-4 py-3 text-sm leading-6 text-rose-100">
                    {cameraError}
                  </div>
                ) : null}
                {!cameraAssistSupported ? (
                  <div className="rounded-2xl border border-white/10 bg-white/[0.035] px-4 py-3 text-sm leading-6 text-slate-400">
                    Camera decode depends on browser support. Manual code entry is always available.
                  </div>
                ) : null}

                <div className="rounded-[1.5rem] border border-white/10 bg-[#05080c] p-4">
                  <p className="text-xs uppercase tracking-[0.22em] text-slate-500">What happens next</p>
                  <div className="mt-4 grid gap-3 text-sm text-slate-300">
                    <div className="flex items-center gap-3">
                      <span className="size-2 rounded-full bg-cyan-200" />
                      MSCQR checks the governed registry record.
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="size-2 rounded-full bg-emerald-300" />
                      The result is separated from any purchase answers you later provide.
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="size-2 rounded-full bg-amber-300" />
                      Duplicate or risky behavior can be escalated for review.
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </MotionPanel>
        </div>
      </main>
    </PublicShell>
  );
}

function VerificationPromise({ icon: Icon, label }: { icon: React.ElementType; label: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.035] p-4">
      <Icon className="size-4 text-cyan-200" />
      <p className="mt-3 text-sm font-medium text-slate-100">{label}</p>
    </div>
  );
}

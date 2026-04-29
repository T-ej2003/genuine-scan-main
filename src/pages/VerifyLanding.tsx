import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Camera, Keyboard, Loader2, QrCode, ScanLine, ShieldCheck, Shirt } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PublicShell } from "@/components/public/PublicShell";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";

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
  const manualInputRef = useRef<HTMLInputElement | null>(null);

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
        transitionMs: 900,
        verifyCodePresent: true,
        deviceType: /mobile/i.test(navigator.userAgent) ? "mobile" : "desktop",
        networkType: String(navWithConnection.connection?.effectiveType || "unknown"),
        online: navigator.onLine,
      })
      .catch(() => {
        // Best effort telemetry only.
      });

    const stageTimer = window.setTimeout(() => setScanStage(1), 450);
    const navTimer = window.setTimeout(() => {
      navigate(`/verify/${encodeURIComponent(cleaned)}`);
    }, 900);

    timersRef.current.push(stageTimer, navTimer);
  };

  const handleCameraCapture = async (file: File) => {
    if (!file) return;
    if (!cameraAssistSupported) {
      setCameraError("This browser cannot scan a QR label from the camera. Enter the code manually instead.");
      return;
    }

    setCameraDecoding(true);
    setCameraError("");
    try {
      const Detector = browserWindow?.BarcodeDetector;
      if (!Detector) {
        setCameraError("This browser cannot scan a QR label from the camera. Enter the code manually instead.");
        return;
      }
      const detector = new Detector({ formats: ["qr_code"] });
      const bitmap = await createImageBitmap(file);
      const [result] = await detector.detect(bitmap);
      const rawValue = String(result?.rawValue || "").trim();
      if (!rawValue) {
        setCameraError("No QR label was detected. Try again with better lighting, or enter the code manually.");
        return;
      }

      setCode(rawValue);
      toast({ title: "QR label captured", description: "Starting garment verification." });
      apiClient
        .captureRouteTransition({
          routeFrom: "/verify",
          routeTo: `/verify/${encodeURIComponent(rawValue)}`,
          source: "mobile_camera_scan",
          transitionMs: 350,
          verifyCodePresent: true,
          deviceType: /mobile/i.test(navigator.userAgent) ? "mobile" : "desktop",
          networkType: String(navWithConnection.connection?.effectiveType || "unknown"),
          online: navigator.onLine,
        })
        .catch(() => {
          // Best effort telemetry only.
        });
      const navTimer = window.setTimeout(() => navigate(`/verify/${encodeURIComponent(rawValue)}`), 200);
      timersRef.current.push(navTimer);
    } catch (error: unknown) {
      setCameraError(error instanceof Error ? error.message : "Camera scan failed. Enter the code manually if this continues.");
    } finally {
      setCameraDecoding(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <PublicShell>
      {isRedirecting ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-white/82 backdrop-blur-md">
          <div className="rounded-3xl border border-border bg-white p-6 text-foreground shadow-xl">
            <div className="flex items-center gap-4">
              <span className="relative flex size-12 items-center justify-center rounded-2xl border border-moonlight-300 bg-moonlight-100 text-primary">
                <ScanLine className="relative size-5" />
              </span>
              <div>
                <p className="text-sm font-semibold">{scanStage === 0 ? "Checking QR label" : "Opening result"}</p>
                <p className="mt-1 text-sm text-muted-foreground">Preparing your garment verification.</p>
              </div>
            </div>
          </div>
        </div>
      ) : null}

      <main className="bg-mscqr-background">
        <section className="border-b border-border bg-white">
          <div className="mx-auto grid w-full max-w-7xl gap-10 px-4 py-16 lg:grid-cols-[0.58fr_0.42fr] lg:items-center lg:py-20">
            <div>
              <h1 className="text-balance text-5xl font-semibold leading-tight text-foreground sm:text-6xl">
                Verify a garment
              </h1>
              <p className="mt-6 max-w-2xl text-lg leading-8 text-muted-foreground">
                Scan the QR label on your garment or enter the code to check if it was verified by MSCQR.
              </p>
              <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:flex-wrap">
                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  capture="environment"
                  className="hidden"
                  onChange={(event) => {
                    const file = event.target.files?.[0];
                    if (file) handleCameraCapture(file);
                  }}
                />
                <Button type="button" size="lg" onClick={() => fileInputRef.current?.click()} disabled={isRedirecting || cameraDecoding}>
                  {cameraDecoding ? <Loader2 data-icon="inline-start" className="animate-spin" /> : <Camera data-icon="inline-start" />}
                  Scan QR label
                </Button>
                <Button type="button" size="lg" variant="outline" onClick={() => manualInputRef.current?.focus()}>
                  <Keyboard data-icon="inline-start" />
                  Enter code manually
                </Button>
              </div>
              {cameraError ? (
                <div className="mt-5 rounded-2xl border border-destructive/20 bg-destructive/10 px-4 py-3 text-sm leading-6 text-destructive">
                  {cameraError}
                </div>
              ) : null}
              {!cameraAssistSupported ? (
                <p className="mt-4 text-sm leading-6 text-muted-foreground">
                  Camera scanning depends on your browser. Manual code entry works on every device.
                </p>
              ) : null}
            </div>

            <div className="rounded-3xl border border-moonlight-300 bg-white p-5 shadow-xl shadow-moonlight-900/10">
              <div className="rounded-2xl border border-border bg-mscqr-background p-5">
                <div className="flex items-center gap-3">
                  <div className="flex size-12 items-center justify-center rounded-2xl bg-accent text-accent-foreground">
                    <Shirt className="size-6" />
                  </div>
                  <div>
                    <h2 className="text-xl font-semibold text-foreground">Garment QR label</h2>
                    <p className="mt-1 text-sm text-muted-foreground">Use the code printed on the garment tag.</p>
                  </div>
                </div>

                <div className="mt-6 grid gap-3">
                  <label htmlFor="verify-code" className="text-sm font-medium text-foreground">
                    QR label code
                  </label>
                  <Input
                    ref={manualInputRef}
                    id="verify-code"
                    value={code}
                    onChange={(event) => setCode(event.target.value)}
                    placeholder="Example: MSCQR-7F42-91C8"
                    disabled={isRedirecting}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") go();
                    }}
                    className="h-12 font-mono"
                  />
                  <Button className="h-12" onClick={go} disabled={!cleaned || isRedirecting}>
                    {isRedirecting ? (
                      <>
                        <Loader2 data-icon="inline-start" className="animate-spin" />
                        Checking
                      </>
                    ) : (
                      <>
                        <ScanLine data-icon="inline-start" />
                        Check garment
                      </>
                    )}
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="border-b border-border">
          <div className="mx-auto w-full max-w-7xl px-4 py-12">
            <div className="rounded-3xl border border-border bg-white p-6">
              <div className="grid gap-6 lg:grid-cols-[0.4fr_0.6fr] lg:items-center">
                <div>
                  <h2 className="text-2xl font-semibold text-foreground">What MSCQR checks</h2>
                  <p className="mt-3 text-sm leading-7 text-muted-foreground">
                    MSCQR checks the QR label, brand record, print status, and unusual scan patterns.
                  </p>
                </div>
                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  {[
                    ["QR label", QrCode],
                    ["Brand record", ShieldCheck],
                    ["Print status", Shirt],
                    ["Scan patterns", ScanLine],
                  ].map(([label, Icon]) => (
                    <div key={String(label)} className="rounded-2xl border border-border bg-mscqr-background p-4">
                      {React.createElement(Icon as typeof QrCode, { className: "size-5 text-primary" })}
                      <p className="mt-3 text-sm font-semibold text-foreground">{String(label)}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="mt-6 flex flex-wrap gap-3 text-sm">
              <Link to="/how-scanning-works" className="font-medium text-primary underline-offset-4 hover:underline">
                See how scanning works
              </Link>
              <Link to="/trust" className="font-medium text-primary underline-offset-4 hover:underline">
                Trust & Security
              </Link>
            </div>
          </div>
        </section>
      </main>
    </PublicShell>
  );
}

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Camera, Loader2, QrCode } from "lucide-react";
import apiClient from "@/lib/api-client";
import { useToast } from "@/hooks/use-toast";
import { PremiumScanLoader } from "@/components/premium/PremiumScanLoader";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

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
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{
        background:
          "radial-gradient(circle at 10% 10%, rgba(141,157,182,0.34), transparent 40%), radial-gradient(circle at 90% 20%, rgba(241,227,221,0.72), transparent 38%), linear-gradient(155deg, #f6f9fc 0%, #eef4f9 45%, #f1e3dd 100%)",
      }}
    >
      {isRedirecting ? (
        <div className="fixed inset-0 z-40 flex items-center justify-center bg-[#66729230] backdrop-blur-[3px]">
          <PremiumScanLoader compact />
        </div>
      ) : null}

      <Card
        className="relative w-full max-w-md overflow-hidden border shadow-[0_20px_40px_rgba(102,114,146,0.2)] premium-surface-in"
        style={{ borderColor: `${PREMIUM_PALETTE.steel}88` }}
      >
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[#4f5b75]">
            <QrCode className="h-5 w-5" /> Verify a Product
          </CardTitle>
          <CardDescription>Paste a code value to start MSCQR’s secure verification journey.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="e.g. A0000000001"
            disabled={isRedirecting}
            onKeyDown={(e) => {
              if (e.key === "Enter") go();
            }}
          />
          <Button
            className="w-full bg-[#667292] text-white hover:bg-[#5a6482]"
            onClick={go}
            disabled={!cleaned || isRedirecting}
          >
            {isRedirecting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                <span className="sr-only">{scanStage === 0 ? "Scanning code" : "Preparing verification"}</span>
              </>
            ) : (
              "Verify"
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
            className="w-full"
            disabled={isRedirecting || cameraDecoding}
            onClick={() => fileInputRef.current?.click()}
          >
            {cameraDecoding ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Decoding code image...
              </>
            ) : (
              <>
                <Camera className="mr-2 h-4 w-4" />
                Use mobile camera capture
              </>
            )}
          </Button>

          {cameraError ? <p className="text-xs text-rose-700">{cameraError}</p> : null}
          {!cameraAssistSupported ? (
            <p className="text-xs text-slate-500">Camera decode is browser-dependent. Manual code entry is always available.</p>
          ) : null}
        </CardContent>

        {isRedirecting ? (
          <div className="absolute inset-0 z-30 flex items-center justify-center rounded-xl bg-white/82 backdrop-blur-[2px]">
            <PremiumScanLoader compact />
          </div>
        ) : null}
      </Card>
    </div>
  );
}

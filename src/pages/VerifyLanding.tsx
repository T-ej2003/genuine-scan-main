import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Loader2, QrCode, ScanLine } from "lucide-react";

export default function VerifyLanding() {
  const [code, setCode] = useState("");
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [scanStage, setScanStage] = useState<0 | 1>(0);
  const navigate = useNavigate();
  const timersRef = useRef<number[]>([]);

  const cleaned = useMemo(() => code.trim(), [code]);

  useEffect(() => {
    return () => {
      for (const timer of timersRef.current) window.clearTimeout(timer);
    };
  }, []);

  const go = () => {
    if (!cleaned || isRedirecting) return;

    setIsRedirecting(true);
    setScanStage(0);

    const stageTimer = window.setTimeout(() => setScanStage(1), 700);
    const navTimer = window.setTimeout(() => {
      navigate(`/verify/${encodeURIComponent(cleaned)}`);
    }, 1250);

    timersRef.current.push(stageTimer, navTimer);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[radial-gradient(circle_at_top,_#e8eef8_0%,_#f4f7fb_45%,_#f8fafc_100%)] p-4">
      {isRedirecting ? (
        <div className="fixed top-4 left-1/2 z-40 w-[92%] max-w-md -translate-x-1/2 rounded-full border border-slate-300 bg-white/95 px-4 py-2 shadow-lg backdrop-blur">
          <div className="flex items-center justify-center gap-2 text-sm font-medium text-slate-900">
            <ScanLine className="h-4 w-4 text-slate-700" />
            <span>{scanStage === 0 ? "Scanning QR..." : "Opening secure verification..."}</span>
          </div>
        </div>
      ) : null}

      <Card className="relative w-full max-w-md border-slate-300/80 shadow-[0_10px_30px_rgba(15,23,42,0.08)]">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <QrCode className="h-5 w-5" /> Verify a Product
          </CardTitle>
          <CardDescription>Paste a QR code value (or scan to open the verify URL directly).</CardDescription>
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
          <Button className="w-full bg-slate-900 text-white hover:bg-slate-800" onClick={go} disabled={!cleaned || isRedirecting}>
            {isRedirecting ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Scanning QR...
              </>
            ) : (
              "Verify"
            )}
          </Button>
        </CardContent>

        {isRedirecting ? (
          <div className="absolute inset-0 z-30 flex items-center justify-center rounded-xl bg-white/85 backdrop-blur-[1px]">
            <div className="w-[90%] max-w-xs rounded-xl border border-slate-200 bg-white p-4 text-center shadow-lg">
              <Loader2 className="mx-auto h-5 w-5 animate-spin text-slate-800" />
              <p className="mt-2 text-sm font-medium text-slate-900">
                {scanStage === 0 ? "Scanning QR..." : "Preparing secure verification..."}
              </p>
              <div className="mt-3 grid grid-cols-12 gap-1">
                {Array.from({ length: 12 }).map((_, idx) => (
                  <span
                    key={idx}
                    className="h-7 rounded-sm bg-slate-300/70 animate-pulse"
                    style={{ animationDelay: `${idx * 90}ms` }}
                  />
                ))}
              </div>
            </div>
          </div>
        ) : null}
      </Card>
    </div>
  );
}

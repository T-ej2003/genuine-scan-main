import React, { useEffect, useState } from "react";
import QRCode from "qrcode";
import { AlertTriangle, KeyRound, ShieldCheck } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export type MfaEnrollmentData = {
  secret: string;
  otpauthUri: string;
  backupCodes: string[];
};

type Props = {
  title: string;
  description: string;
  setup: MfaEnrollmentData;
  code: string;
  onCodeChange: (value: string) => void;
  confirming?: boolean;
  error?: string | null;
};

export function MfaEnrollmentPanel({
  title,
  description,
  setup,
  code,
  onCodeChange,
  confirming = false,
  error,
}: Props) {
  const [qrDataUrl, setQrDataUrl] = useState("");

  useEffect(() => {
    let cancelled = false;
    QRCode.toDataURL(setup.otpauthUri, {
      width: 192,
      margin: 1,
      errorCorrectionLevel: "M",
    })
      .then((url) => {
        if (!cancelled) setQrDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl("");
      });

    return () => {
      cancelled = true;
    };
  }, [setup.otpauthUri]);

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <Badge className="bg-slate-900 text-white hover:bg-slate-900">Required MFA</Badge>
          <Badge variant="outline">Authenticator app</Badge>
        </div>
        <h3 className="text-lg font-semibold text-slate-950">{title}</h3>
        <p className="text-sm text-slate-600">{description}</p>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="grid gap-4 md:grid-cols-[220px_1fr]">
        <div className="rounded-2xl border border-slate-200 bg-white p-4">
          <div className="mb-3 text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Scan QR</div>
          {qrDataUrl ? (
            <img src={qrDataUrl} alt="MFA authenticator QR code" className="mx-auto h-48 w-48 rounded-xl border border-slate-200 bg-white p-2" />
          ) : (
            <div className="flex h-48 w-48 items-center justify-center rounded-xl border border-dashed border-slate-300 text-xs text-slate-500">
              QR preview unavailable
            </div>
          )}
        </div>

        <div className="space-y-4 rounded-2xl border border-slate-200 bg-slate-50/80 p-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Manual secret</div>
            <div className="mt-2 rounded-xl border border-slate-200 bg-white px-3 py-2 font-mono text-sm break-all text-slate-900">
              {setup.secret}
            </div>
          </div>

          <Alert className="border-amber-200 bg-amber-50 text-amber-950">
            <KeyRound className="h-4 w-4 text-amber-700" />
            <AlertTitle>Save your backup codes now</AlertTitle>
            <AlertDescription>
              These one-time recovery codes are shown only during setup or reset. Keep them somewhere safe.
            </AlertDescription>
          </Alert>

          <div className="grid gap-2 sm:grid-cols-2">
            {setup.backupCodes.map((backupCode) => (
              <div key={backupCode} className="rounded-xl border border-slate-200 bg-white px-3 py-2 font-mono text-sm text-slate-900">
                {backupCode}
              </div>
            ))}
          </div>
        </div>
      </div>

      <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950">
        <ShieldCheck className="h-4 w-4 text-emerald-700" />
        <AlertDescription>
          After scanning the QR, enter the current 6-digit code from your authenticator app to finish enrollment.
        </AlertDescription>
      </Alert>

      <div className="space-y-2">
        <Label htmlFor="mfaEnrollmentCode">Authenticator code</Label>
        <Input
          id="mfaEnrollmentCode"
          type="text"
          inputMode="numeric"
          autoComplete="one-time-code"
          placeholder="123456"
          value={code}
          onChange={(event) => onCodeChange(event.target.value)}
          disabled={confirming}
          className="h-11"
        />
      </div>
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import { useParams, Link, useSearchParams } from "react-router-dom";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Shield,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ExternalLink,
  MapPin,
  Building2,
  Factory,
  ScanEye,
  CalendarClock,
  Mail,
  Phone,
  Globe2,
  Loader2,
} from "lucide-react";
import apiClient from "@/lib/api-client";

type VerifyPayload = {
  isAuthentic: boolean;
  message?: string;
  code?: string;
  status?: string;
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
  batchName?: string | null;
  printedAt?: string | null;
  firstScanned?: string | null;
  scanCount?: number;
  isFirstScan?: boolean;
  scanOutcome?: string;
  redeemedAt?: string | null;
  warningMessage?: string | null;
};

export default function Verify() {
  const { code } = useParams<{ code: string }>();
  const [searchParams] = useSearchParams();
  const [isLoading, setIsLoading] = useState(true);
  const [result, setResult] = useState<VerifyPayload | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const token = searchParams.get("t");
        if (!code && !token) {
          setResult({ isAuthentic: false, message: "Missing code" });
          return;
        }
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

        const res = token
          ? await apiClient.scanToken(token, {
              device,
              lat: geo.lat,
              lon: geo.lon,
              acc: geo.acc,
            })
          : await apiClient.verifyQRCode(code as string, {
              device,
              lat: geo.lat,
              lon: geo.lon,
              acc: geo.acc,
            });
        if (!res.success) {
          setError(res.error || "Verification failed");
          setResult(null);
          return;
        }
        setResult(res.data as VerifyPayload);
      } finally {
        if (active) setIsLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [code, searchParams]);

  const statusKind = useMemo(() => {
    if (result?.scanOutcome === "VALID") return "genuine";
    if (result?.scanOutcome === "ALREADY_REDEEMED") return "fraud";
    if (result?.scanOutcome === "SUSPICIOUS" || result?.status === "ACTIVATED") return "unprinted";
    if (result?.status === "ALLOCATED") return "unprinted";
    if (result?.status === "DORMANT" || result?.status === "ACTIVE") return "unassigned";
    if (result?.status === "BLOCKED") return "invalid";
    return result?.isAuthentic ? "genuine" : "invalid";
  }, [result?.isAuthentic, result?.status, result?.scanOutcome]);

  const manufacturer = result?.batch?.manufacturer || null;

  const productName = result?.batch?.name || "—";
  const productLabel = "Batch";
  const serialNumber = result?.code || code || "—";

  const headline =
    statusKind === "genuine"
      ? "Genuine Product"
      : statusKind === "fraud"
      ? "Already Redeemed"
      : statusKind === "unprinted"
      ? "Not Yet Printed"
      : statusKind === "unassigned"
      ? "Not Assigned"
      : "Verification Failed";

  const subtitle =
    statusKind === "genuine"
      ? "This item matches our official records"
      : statusKind === "fraud"
      ? "This code was already redeemed. Possible counterfeit."
      : statusKind === "unprinted"
      ? "This code exists but was not confirmed as printed"
      : statusKind === "unassigned"
      ? "This code exists but is not assigned to a product"
      : "This code could not be verified";

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_20%_20%,#134e4a_0%,transparent_40%),radial-gradient(circle_at_80%_10%,#1e3a8a_0%,transparent_40%),linear-gradient(135deg,#0f172a_0%,#0b1220_60%,#0a0f1d_100%)] flex items-center justify-center p-4">
      <div className="w-full max-w-2xl">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-white mb-3">
            <Shield className="h-10 w-10 text-emerald-400" />
            <span className="text-2xl font-bold tracking-wide">AuthenticQR</span>
          </Link>
          <p className="text-slate-300">Product Verification</p>
        </div>

        <Card className="border-0 shadow-2xl overflow-hidden animate-fade-in">
          {isLoading ? (
            <CardContent className="py-16 text-center">
              <Loader2 className="h-12 w-12 animate-spin text-emerald-400 mx-auto mb-4" />
              <p className="text-lg font-medium">Verifying authenticity...</p>
              <p className="text-sm text-muted-foreground mt-1">Please wait</p>
            </CardContent>
          ) : error ? (
            <CardContent className="py-12 text-center space-y-3">
              <XCircle className="h-10 w-10 text-destructive mx-auto" />
              <p className="text-lg font-semibold">{error}</p>
              <Button variant="outline" asChild className="w-full">
                <Link to="/">Return to Home</Link>
              </Button>
            </CardContent>
          ) : (
            <>
              <div
                className={
                  statusKind === "genuine"
                    ? "bg-emerald-500"
                    : statusKind === "fraud"
                    ? "bg-rose-600"
                    : statusKind === "unprinted"
                    ? "bg-amber-500"
                    : statusKind === "unassigned"
                    ? "bg-slate-600"
                    : "bg-destructive"
                }
              >
                <div className="p-6 text-center text-white">
                  <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-white/20 mb-4">
                    {statusKind === "genuine" ? (
                      <CheckCircle2 className="h-10 w-10 text-white" />
                    ) : statusKind === "invalid" ? (
                      <XCircle className="h-10 w-10 text-white" />
                    ) : (
                      <AlertTriangle className="h-10 w-10 text-white" />
                    )}
                  </div>
                  <h1 className="text-2xl font-bold">{headline}</h1>
                  <p className="text-white/80 mt-1">{subtitle}</p>
                </div>
              </div>

              <CardContent className="p-6 space-y-6">
                <div className="text-center p-4 bg-muted rounded-lg">
                  <p className="text-sm text-muted-foreground mb-1">Verified Code</p>
                  <p className="font-mono text-lg font-bold">{result?.code || code}</p>
                </div>

                <div className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-lg border p-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-emerald-500/10 rounded-lg">
                        <Building2 className="h-5 w-5 text-emerald-500" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs text-muted-foreground">Licensed By</p>
                        <p className="font-semibold">
                          {result?.licensee?.brandName || result?.licensee?.name || "—"}
                        </p>
                        {result?.licensee?.location && (
                          <div className="text-xs text-muted-foreground flex items-center gap-1">
                            <MapPin className="h-3 w-3" />
                            {result.licensee.location}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  <div className="rounded-lg border p-4">
                    <div className="flex items-start gap-3">
                      <div className="p-2 bg-blue-500/10 rounded-lg">
                        <Factory className="h-5 w-5 text-blue-500" />
                      </div>
                      <div className="space-y-1">
                        <p className="text-xs text-muted-foreground">Manufacturer</p>
                        <p className="font-semibold">
                          {manufacturer?.name || "—"}
                        </p>
                        {manufacturer?.location && (
                          <div className="text-xs text-muted-foreground flex items-center gap-1">
                            <MapPin className="h-3 w-3" />
                            {manufacturer.location}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-lg border p-4 space-y-2">
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">{productLabel}</Badge>
                    <span className="text-sm font-medium">
                      {productName}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    Serial Number: <span className="font-mono">{serialNumber}</span>
                  </div>
                </div>

                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <ScanEye className="h-4 w-4" />
                      Scan Count
                    </div>
                    <p className="text-lg font-semibold">{result?.scanCount ?? 0}</p>
                  </div>
                  <div className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <CalendarClock className="h-4 w-4" />
                      First Scan
                    </div>
                    <p className="text-sm font-medium">
                      {result?.firstScanned ? new Date(result.firstScanned).toLocaleString() : "—"}
                    </p>
                  </div>
                  <div className="rounded-lg border p-3">
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <CalendarClock className="h-4 w-4" />
                      Printed
                    </div>
                    <p className="text-sm font-medium">
                      {result?.printedAt ? new Date(result.printedAt).toLocaleDateString() : "—"}
                    </p>
                  </div>
                </div>

                {result?.warningMessage && (
                  <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    {result.warningMessage}
                  </div>
                )}

                <div className="grid gap-3 md:grid-cols-2">
                  {result?.licensee?.supportEmail && (
                    <div className="flex items-center gap-2 text-sm">
                      <Mail className="h-4 w-4 text-muted-foreground" />
                      <span>{result.licensee.supportEmail}</span>
                    </div>
                  )}
                  {result?.licensee?.supportPhone && (
                    <div className="flex items-center gap-2 text-sm">
                      <Phone className="h-4 w-4 text-muted-foreground" />
                      <span>{result.licensee.supportPhone}</span>
                    </div>
                  )}
                  {result?.licensee?.website && (
                    <div className="flex items-center gap-2 text-sm">
                      <Globe2 className="h-4 w-4 text-muted-foreground" />
                      <span>{result.licensee.website}</span>
                    </div>
                  )}
                  {manufacturer?.website && (
                    <div className="flex items-center gap-2 text-sm">
                      <Globe2 className="h-4 w-4 text-muted-foreground" />
                      <span>{manufacturer.website}</span>
                    </div>
                  )}
                </div>

                {result?.licensee?.website && (
                  <Button asChild className="w-full" size="lg">
                    <a href={result.licensee.website} target="_blank" rel="noopener noreferrer">
                      Visit Official Website
                      <ExternalLink className="ml-2 h-4 w-4" />
                    </a>
                  </Button>
                )}
              </CardContent>
            </>
          )}
        </Card>

        <p className="text-center text-slate-400 text-sm mt-6">
          Secure verification powered by AuthenticQR
        </p>
      </div>
    </div>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AlertCircle,
  Apple,
  CheckCircle2,
  Download,
  Laptop,
  Loader2,
  MonitorSmartphone,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import { AuthShell } from "@/components/auth/AuthShell";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import apiClient from "@/lib/api-client";

type ConnectorPlatformRelease = {
  platform: "macos" | "windows";
  label: string;
  installerKind: "pkg" | "zip" | "exe";
  filename: string;
  architecture: string;
  bytes: number;
  sha256: string;
  notes: string[];
  contentType: string;
  downloadPath: string;
  downloadUrl: string;
};

type LatestConnectorRelease = {
  productName: string;
  latestVersion: string;
  supportPath: string;
  helpPath: string;
  setupGuidePath: string;
  release: {
    version: string;
    publishedAt: string;
    summary: string;
    notes: string[];
    platforms: {
      macos: ConnectorPlatformRelease | null;
      windows: ConnectorPlatformRelease | null;
    };
  };
};

const formatBytes = (value: number) => {
  if (!Number.isFinite(value) || value <= 0) return "Download available";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
};

const detectPlatform = () => {
  if (typeof navigator === "undefined") return "unknown";
  const ua = `${navigator.userAgent || ""} ${(navigator as any).userAgentData?.platform || ""}`.toLowerCase();
  if (ua.includes("mac")) return "macos";
  if (ua.includes("win")) return "windows";
  return "unknown";
};

const platformCopy = {
  macos: {
    title: "Mac installer",
    description: "One install. The connector starts automatically whenever that Mac user signs in.",
    action: "Download for Mac",
    icon: Apple,
    helper: "Signed package target with LaunchAgent auto-start.",
  },
  windows: {
    title: "Windows installer",
    description: "Download the Windows package, open it, then run Install Connector once on the printing PC.",
    action: "Download for Windows",
    icon: MonitorSmartphone,
    helper: "Scheduled Task auto-start after installation.",
  },
} as const;

export default function ConnectorDownload() {
  const [params] = useSearchParams();
  const inviteToken = useMemo(() => String(params.get("inviteToken") || "").trim(), [params]);

  const [release, setRelease] = useState<LatestConnectorRelease | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<null | {
    email: string;
    role: string;
    expiresAt: string;
    licenseeName: string | null;
    requiresConnector: boolean;
  }>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);

  const detectedPlatform = useMemo(() => detectPlatform(), []);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);

      const [releaseRes, previewRes] = await Promise.all([
        apiClient.getLatestConnectorRelease(),
        inviteToken ? apiClient.getInvitePreview(inviteToken) : Promise.resolve(null as any),
      ]);

      if (cancelled) return;

      if (!releaseRes?.success || !releaseRes.data) {
        setError(releaseRes?.error || "Connector downloads are not available right now.");
      } else {
        setRelease(releaseRes.data as LatestConnectorRelease);
      }

      if (inviteToken) {
        if (previewRes?.success && previewRes.data) {
          setPreview(previewRes.data);
          setPreviewError(null);
        } else {
          setPreview(null);
          setPreviewError(previewRes?.error || "Invite details are not available.");
        }
      } else {
        setPreview(null);
        setPreviewError(null);
      }

      setLoading(false);
    };

    void load();

    return () => {
      cancelled = true;
    };
  }, [inviteToken]);

  const downloadCards = useMemo(() => {
    if (!release) return [];
    return (["macos", "windows"] as const)
      .map((platformKey) => {
        const item = release.release.platforms[platformKey];
        if (!item) return null;
        return {
          ...item,
          ...platformCopy[platformKey],
          recommended: detectedPlatform === platformKey,
        };
      })
      .filter(Boolean) as Array<ConnectorPlatformRelease & (typeof platformCopy)[keyof typeof platformCopy] & { recommended: boolean }>;
  }, [detectedPlatform, release]);

  return (
    <AuthShell
      title="Install MSCQR Connector"
      description="Download the connector for the computer that will physically print. Install once, then it starts automatically in the background."
      sideTitle="Printing setup for manufacturer workstations"
      sideDescription="MSCQR uses a native connector for workstation printers because web browsers cannot securely manage local printers on their own. The connector bridges that operating-system printer access while keeping the print workflow approved and audited."
    >
      <div className="space-y-6">
        {loading ? (
          <div className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
            <Loader2 className="h-4 w-4 animate-spin" />
            Checking the latest connector release...
          </div>
        ) : null}

        {error ? (
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Connector download unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}

        {preview ? (
          <Alert className="border-emerald-200 bg-emerald-50 text-emerald-950">
            <ShieldCheck className="h-4 w-4 text-emerald-700" />
            <AlertTitle>Onboarding for {preview.licenseeName || "your factory team"}</AlertTitle>
            <AlertDescription className="space-y-2">
              <div>
                Your invite is ready for <strong>{preview.email}</strong>. Install the connector on the computer that will
                print, then return to the activation email to set the password.
              </div>
              <div className="flex flex-wrap gap-2">
                <Button asChild size="sm">
                  <Link to={`/accept-invite?token=${encodeURIComponent(inviteToken)}`}>Open activation link</Link>
                </Button>
                <Button asChild size="sm" variant="outline">
                  <Link to={release?.setupGuidePath || "/help/manufacturer"}>View setup guide</Link>
                </Button>
              </div>
            </AlertDescription>
          </Alert>
        ) : null}

        {!preview && previewError ? (
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{previewError}</AlertDescription>
          </Alert>
        ) : null}

        {release ? (
          <Card className="border-slate-200/80 bg-slate-50/70">
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="secondary" className="bg-emerald-100 text-emerald-800 hover:bg-emerald-100">
                  Latest connector {release.latestVersion}
                </Badge>
                <Badge variant="outline">
                  Published {new Date(release.release.publishedAt).toLocaleDateString()}
                </Badge>
              </div>
              <CardTitle className="text-xl">{release.productName}</CardTitle>
              <CardDescription>{release.release.summary}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 lg:grid-cols-2">
                {downloadCards.map((item) => {
                  const Icon = item.icon;
                  return (
                    <Card key={item.platform} className={item.recommended ? "border-emerald-300 shadow-sm" : ""}>
                      <CardHeader className="space-y-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-3">
                            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-emerald-100 text-emerald-800">
                              <Icon className="h-5 w-5" />
                            </div>
                            <div>
                              <CardTitle className="text-lg">{item.title}</CardTitle>
                              <CardDescription>{item.description}</CardDescription>
                            </div>
                          </div>
                          {item.recommended ? (
                            <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">Recommended</Badge>
                          ) : null}
                        </div>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                          <Badge variant="outline">{item.architecture}</Badge>
                          <Badge variant="outline">{item.installerKind.toUpperCase()}</Badge>
                          <Badge variant="outline">{formatBytes(item.bytes)}</Badge>
                        </div>
                      </CardHeader>
                      <CardContent className="space-y-4 text-sm text-muted-foreground">
                        <p>{item.helper}</p>
                        <ul className="list-disc pl-5 space-y-1">
                          {item.notes.map((note) => (
                            <li key={note}>{note}</li>
                          ))}
                        </ul>
                        <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-xs text-slate-600">
                          File: <span className="font-medium text-slate-900">{item.filename}</span>
                        </div>
                        <Button asChild className="w-full">
                          <a href={item.downloadUrl}>
                            <Download className="mr-2 h-4 w-4" />
                            {item.action}
                          </a>
                        </Button>
                      </CardContent>
                    </Card>
                  );
                })}
              </div>

              <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Simple setup steps for factory teams</CardTitle>
                    <CardDescription>Share these steps with the workstation user who will print labels.</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm text-muted-foreground">
                    <div className="flex gap-3">
                      <Badge className="h-fit bg-slate-900 text-white hover:bg-slate-900">1</Badge>
                      <div>Open this page on the computer that is already connected to the printer.</div>
                    </div>
                    <div className="flex gap-3">
                      <Badge className="h-fit bg-slate-900 text-white hover:bg-slate-900">2</Badge>
                      <div>Download the Mac or Windows installer that matches that computer.</div>
                    </div>
                    <div className="flex gap-3">
                      <Badge className="h-fit bg-slate-900 text-white hover:bg-slate-900">3</Badge>
                      <div>Run the installer once. The connector will then start automatically at sign-in.</div>
                    </div>
                    <div className="flex gap-3">
                      <Badge className="h-fit bg-slate-900 text-white hover:bg-slate-900">4</Badge>
                      <div>Open MSCQR, go to <strong>Printer Setup</strong>, and confirm the printer status is ready.</div>
                    </div>
                    <div className="flex gap-3">
                      <Badge className="h-fit bg-slate-900 text-white hover:bg-slate-900">5</Badge>
                      <div>Return to <strong>Batches</strong> and create the print job.</div>
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-slate-950 text-slate-100">
                  <CardHeader>
                    <div className="flex items-center gap-2 text-emerald-300">
                      <Sparkles className="h-4 w-4" />
                      <CardTitle className="text-base text-white">What stays automatic after install</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3 text-sm text-slate-300">
                    <div className="flex items-start gap-3">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-300" />
                      <div>The connector starts automatically when that workstation user signs in.</div>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-300" />
                      <div>MSCQR reads the operating-system printer list and shows business-safe readiness states.</div>
                    </div>
                    <div className="flex items-start gap-3">
                      <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-300" />
                      <div>Manufacturers stay inside the normal batch workflow instead of running commands or local tools.</div>
                    </div>
                    <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3 text-xs leading-6 text-slate-300">
                      If your printer is a shared office AirPrint / IPP printer, your admin can also save it as a managed
                      network printer. Use the connector when printing depends on the workstation’s local printer setup.
                    </div>
                  </CardContent>
                </Card>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <Button asChild variant="outline">
                  <Link to={release.setupGuidePath}>Open setup guide</Link>
                </Button>
                <Button asChild variant="ghost">
                  <Link to={release.supportPath}>
                    <Laptop className="mr-2 h-4 w-4" />
                    Printer setup help
                  </Link>
                </Button>
              </div>
            </CardContent>
          </Card>
        ) : null}
      </div>
    </AuthShell>
  );
}

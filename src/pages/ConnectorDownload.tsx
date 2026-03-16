import React, { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import {
  AlertCircle,
  Apple,
  ArrowRight,
  CheckCircle2,
  Clock3,
  Download,
  type LucideIcon,
  Laptop,
  Loader2,
  MonitorSmartphone,
  Printer,
  ShieldCheck,
  Sparkles,
  Workflow,
} from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
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

type DownloadCard = ConnectorPlatformRelease & {
  title: string;
  description: string;
  action: string;
  helper: string;
  icon: LucideIcon;
  recommended: boolean;
  href: string;
  iconSurfaceClass: string;
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

const formatPublishedDate = (value: string) => {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Latest release";

  return new Intl.DateTimeFormat(undefined, {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(date);
};

const detectPlatform = () => {
  if (typeof navigator === "undefined") return "unknown";

  const ua = `${navigator.userAgent || ""} ${(navigator as any).userAgentData?.platform || ""}`.toLowerCase();

  if (ua.includes("mac")) return "macos";
  if (ua.includes("win")) return "windows";
  return "unknown";
};

const ensureApiDownloadPath = (value: string) => {
  const normalized = value.startsWith("public/") ? `/${value}` : value;
  if (normalized.startsWith("/public/connector/download/")) {
    return `/api${normalized}`;
  }
  return normalized;
};

const normalizeDownloadHref = (downloadUrl: string, downloadPath: string) => {
  const candidate = String(downloadUrl || downloadPath || "").trim();
  if (!candidate) return "#";

  const origin = typeof window !== "undefined" ? window.location.origin : "https://mscqr.local";
  const absolute = /^[a-z][a-z\d+\-.]*:\/\//i.test(candidate);

  try {
    const url = new URL(candidate, origin);
    if (url.pathname.startsWith("/public/connector/download/")) {
      url.pathname = `/api${url.pathname}`;
    }

    if (!absolute) {
      return `${url.pathname}${url.search}${url.hash}`;
    }

    return url.toString();
  } catch {
    return ensureApiDownloadPath(candidate);
  }
};

const shortenChecksum = (value: string) => {
  const checksum = String(value || "").trim();
  if (checksum.length <= 18) return checksum || "Unavailable";
  return `${checksum.slice(0, 12)}...${checksum.slice(-8)}`;
};

const platformCopy: Record<
  "macos" | "windows",
  {
    title: string;
    description: string;
    action: string;
    icon: LucideIcon;
    helper: string;
    iconSurfaceClass: string;
  }
> = {
  macos: {
    title: "Mac installer",
    description: "One install. The connector starts automatically whenever that Mac user signs in.",
    action: "Download for Mac",
    icon: Apple,
    helper: "Signed package target with LaunchAgent auto-start.",
    iconSurfaceClass: "bg-emerald-100 text-emerald-700",
  },
  windows: {
    title: "Windows installer",
    description: "Download the Windows ZIP, extract it to a normal folder, then run Install Connector once on the printing PC.",
    action: "Download for Windows",
    icon: MonitorSmartphone,
    helper: "Extract first, then install. The connector uses a per-user Startup entry and verifies local printer readiness before claiming success.",
    iconSurfaceClass: "bg-sky-100 text-sky-700",
  },
};

const workspaceHighlights = [
  {
    icon: ShieldCheck,
    title: "Approved printer access",
    detail: "Keep printing on the workstation that already sees the device instead of forcing the browser to manage local printers.",
  },
  {
    icon: Sparkles,
    title: "Single install",
    detail: "Run the package once and the connector keeps starting automatically in the background after sign-in, then verifies whether Windows or macOS can actually use the printer.",
  },
  {
    icon: Printer,
    title: "Cleaner rollout",
    detail: "Mac and Windows installers, setup help, and the live version number all stay on one page without the cramped split-screen shell.",
  },
];

const setupSteps = [
  "Open this page on the same computer that is already connected to the printer.",
  "Choose the Mac or Windows installer that matches that computer.",
  "Run the installer once. The connector will start automatically at sign-in after that.",
  "The installer verifies local printer readiness before it tells you setup is complete.",
  "If the printer still needs OS-side attention, MSCQR opens Printer Setup and keeps the connector installed.",
  "Return to Batches and create the print job.",
];

const automaticBehaviors = [
  "The connector starts automatically whenever that workstation user signs in.",
  "MSCQR keeps reading the operating-system printer list and surfaces business-safe readiness states.",
  "Manufacturers stay inside the normal batch workflow instead of launching scripts or extra local tools.",
];

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
    if (!release) return [] as DownloadCard[];

    return (["macos", "windows"] as const)
      .map((platformKey) => {
        const item = release.release.platforms[platformKey];
        if (!item) return null;

        return {
          ...item,
          ...platformCopy[platformKey],
          recommended: detectedPlatform === platformKey,
          href: normalizeDownloadHref(item.downloadUrl, item.downloadPath),
        };
      })
      .filter(Boolean) as DownloadCard[];
  }, [detectedPlatform, release]);

  const recommendedCard = useMemo(
    () => downloadCards.find((item) => item.recommended) || downloadCards[0] || null,
    [downloadCards],
  );

  const detectedPlatformLabel =
    detectedPlatform === "macos"
      ? "This computer looks like a Mac."
      : detectedPlatform === "windows"
        ? "This computer looks like Windows."
        : "Choose the installer that matches the computer connected to the printer.";

  return (
    <div className="relative min-h-screen overflow-hidden bg-[radial-gradient(circle_at_top_left,rgba(16,185,129,0.16),transparent_26%),radial-gradient(circle_at_top_right,rgba(15,23,42,0.12),transparent_30%),linear-gradient(180deg,#eef8f4_0%,#f8fafc_46%,#ffffff_100%)] text-slate-950">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-[-8rem] top-[-6rem] h-72 w-72 rounded-full bg-emerald-300/30 blur-3xl" />
        <div className="absolute right-[-6rem] top-32 h-80 w-80 rounded-full bg-sky-200/35 blur-3xl" />
        <div className="absolute bottom-[-8rem] left-1/3 h-80 w-80 rounded-full bg-amber-200/30 blur-3xl" />
      </div>

      <div className="relative mx-auto flex min-h-screen w-full max-w-[1580px] flex-col px-4 py-4 sm:px-6 sm:py-6 lg:px-10 lg:py-8">
        <div className="overflow-hidden rounded-[34px] border border-white/70 bg-white/70 shadow-[0_40px_120px_-70px_rgba(15,23,42,0.4)] backdrop-blur-xl">
          <div className="border-b border-slate-200/80 px-5 py-5 sm:px-8 sm:py-6">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex items-center gap-4">
                <div className="flex h-14 w-14 items-center justify-center rounded-[20px] bg-slate-950 shadow-[0_20px_35px_-25px_rgba(15,23,42,0.8)]">
                  <img src="/brand/mscqr-mark.svg" alt="MSCQR logo" className="h-8 w-8" />
                </div>
                <div>
                  <div className="text-2xl font-semibold tracking-tight text-slate-950">MSCQR</div>
                  <div className="text-xs uppercase tracking-[0.26em] text-slate-500">Secure QR Operations</div>
                </div>
              </div>

              <div className="flex flex-wrap gap-3">
                <Button asChild size="sm" variant="outline">
                  <Link to={release?.setupGuidePath || "/help/manufacturer"}>
                    <Workflow className="h-4 w-4" />
                    Setup guide
                  </Link>
                </Button>
                <Button asChild size="sm" variant="ghost">
                  <Link to={release?.supportPath || "/help/manufacturer"}>
                    <Laptop className="h-4 w-4" />
                    Printer setup help
                  </Link>
                </Button>
              </div>
            </div>
          </div>

          <div className="space-y-6 px-5 py-5 sm:px-8 sm:py-8 lg:space-y-8">
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
                <AlertDescription className="space-y-3">
                  <div>
                    Your invite is ready for <strong>{preview.email}</strong>. Install the connector on the computer that
                    will print, then return to the activation email to set the password.
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

            <div className="grid gap-6 xl:grid-cols-[1.08fr_0.92fr]">
              <section className="relative overflow-hidden rounded-[32px] bg-slate-950 px-6 py-7 text-white sm:px-8 sm:py-8 lg:px-10">
                <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(52,211,153,0.25),transparent_34%),linear-gradient(135deg,rgba(15,23,42,0.98),rgba(15,23,42,0.92))]" />
                <div className="relative space-y-8">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="border border-emerald-300/20 bg-emerald-400/15 text-emerald-100 hover:bg-emerald-400/15">
                      Workstation printing
                    </Badge>
                    {release ? (
                      <Badge className="border border-white/10 bg-white/10 text-slate-100 hover:bg-white/10">
                        Latest connector {release.latestVersion}
                      </Badge>
                    ) : null}
                  </div>

                  <div className="space-y-4">
                    <h1 className="max-w-3xl text-4xl font-semibold leading-[1.05] tracking-tight sm:text-5xl">
                      Install the MSCQR Connector on the workstation that actually prints.
                    </h1>
                    <p className="max-w-2xl text-base leading-7 text-slate-300 sm:text-lg">
                      This page is now dedicated to installation only: more room, less congestion, and a direct download
                      flow for the live Mac and Windows packages. Open it on the printer computer, install once, and keep
                      the rest of the workflow inside MSCQR.
                    </p>
                  </div>

                  <div className="grid gap-3 md:grid-cols-3">
                    {workspaceHighlights.map((item) => (
                      <div
                        key={item.title}
                        className="rounded-[24px] border border-white/10 bg-white/5 p-4 backdrop-blur-sm"
                      >
                        <div className="mb-4 inline-flex rounded-2xl bg-white/10 p-3 text-emerald-200">
                          <item.icon className="h-5 w-5" />
                        </div>
                        <div className="space-y-2">
                          <div className="text-sm font-semibold text-white">{item.title}</div>
                          <div className="text-sm leading-6 text-slate-300">{item.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="rounded-[32px] border border-emerald-200/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.96),rgba(238,248,244,0.88))] p-6 shadow-[0_30px_80px_-60px_rgba(15,23,42,0.45)] sm:p-8">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge className="bg-emerald-100 text-emerald-800 hover:bg-emerald-100">
                    {recommendedCard ? `${recommendedCard.title} available` : "Choose Mac or Windows"}
                  </Badge>
                  {release ? <Badge variant="outline">Published {formatPublishedDate(release.release.publishedAt)}</Badge> : null}
                </div>

                <div className="mt-5 space-y-4">
                  <h2 className="text-3xl font-semibold tracking-tight text-slate-950">
                    Install once on the printer computer.
                  </h2>
                  <p className="text-base leading-7 text-slate-600">
                    Open this page on the same Mac or Windows computer that is already connected to the printer. Choose
                    the installer below, run it once, and the connector starts automatically every time that user signs
                    in after that. Windows setup now verifies the local printer before it claims the workstation is ready.
                  </p>
                </div>

                <div className="mt-6 grid gap-3 sm:grid-cols-2">
                  <div className="rounded-[24px] border border-slate-200 bg-white/80 p-4">
                    <div className="flex items-center gap-3">
                      <div className="rounded-2xl bg-emerald-100 p-3 text-emerald-700">
                        <MonitorSmartphone className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-slate-950">Detected device</div>
                        <div className="text-sm leading-6 text-slate-600">{detectedPlatformLabel}</div>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-[24px] border border-slate-200 bg-white/80 p-4">
                    <div className="flex items-center gap-3">
                      <div className="rounded-2xl bg-slate-950 p-3 text-white">
                        <Clock3 className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-slate-950">After install</div>
                        <div className="text-sm leading-6 text-slate-600">
                          The connector keeps starting in the background automatically at sign-in.
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="mt-6 flex flex-wrap gap-3">
                  {recommendedCard ? (
                    <Button asChild size="lg" className="sm:min-w-[240px]">
                      <a href={recommendedCard.href}>
                        <Download className="h-4 w-4" />
                        Get installer for this device
                      </a>
                    </Button>
                  ) : null}
                  <Button asChild size="lg" variant="outline">
                    <Link to={release?.setupGuidePath || "/help/manufacturer"}>
                      Open setup guide
                      <ArrowRight className="h-4 w-4" />
                    </Link>
                  </Button>
                </div>
              </section>
            </div>

            {release ? (
              <section className="rounded-[32px] border border-slate-200/80 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.92))] p-6 sm:p-8 lg:p-10">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                  <div className="space-y-3">
                    <Badge className="bg-emerald-100 text-emerald-800 hover:bg-emerald-100">Install MSCQR Connector</Badge>
                    <h2 className="text-3xl font-semibold tracking-tight text-slate-950 sm:text-[2.2rem]">
                      Choose the installer for the production workstation
                    </h2>
                    <p className="max-w-3xl text-base leading-7 text-slate-600">
                      {release.release.summary} Download the package that matches that computer and keep everything else
                      inside the normal MSCQR workflow.
                    </p>
                  </div>

                  <div className="rounded-[24px] border border-slate-200 bg-white px-4 py-3 text-sm text-slate-600">
                    <div className="font-semibold text-slate-950">{release.productName}</div>
                    <div>Version {release.latestVersion}</div>
                  </div>
                </div>

                <div className="mt-8 grid gap-5 xl:grid-cols-2">
                  {downloadCards.map((item) => {
                    const Icon = item.icon;

                    return (
                      <article
                        key={item.platform}
                        className={cn(
                          "relative overflow-hidden rounded-[30px] border bg-white p-6 shadow-[0_28px_60px_-48px_rgba(15,23,42,0.5)]",
                          item.recommended ? "border-emerald-300" : "border-slate-200",
                        )}
                      >
                        <div className="flex flex-col gap-6">
                          <div className="flex flex-wrap items-start justify-between gap-4">
                            <div className="flex items-center gap-4">
                              <div className={cn("flex h-14 w-14 items-center justify-center rounded-[20px]", item.iconSurfaceClass)}>
                                <Icon className="h-7 w-7" />
                              </div>

                              <div className="space-y-2">
                                <div className="flex flex-wrap items-center gap-2">
                                  <h3 className="text-2xl font-semibold text-slate-950">{item.title}</h3>
                                  {item.recommended ? (
                                    <Badge className="bg-slate-950 text-white hover:bg-slate-950">Best match for this device</Badge>
                                  ) : null}
                                </div>
                                <p className="max-w-xl text-sm leading-6 text-slate-600">{item.description}</p>
                              </div>
                            </div>

                            <div className="flex flex-wrap gap-2">
                              <Badge variant="outline">{item.architecture}</Badge>
                              <Badge variant="outline">{item.installerKind.toUpperCase()}</Badge>
                              <Badge variant="outline">{formatBytes(item.bytes)}</Badge>
                            </div>
                          </div>

                          <div className="grid gap-4 lg:grid-cols-[minmax(0,0.9fr)_minmax(220px,0.58fr)]">
                            <div className="space-y-4">
                              <p className="text-sm leading-6 text-slate-600">{item.helper}</p>

                              {item.platform === "windows" && item.installerKind === "zip" ? (
                                <Alert className="border-amber-200 bg-amber-50 text-amber-950">
                                  <AlertCircle className="h-4 w-4 text-amber-700" />
                                  <AlertTitle>Important for Windows</AlertTitle>
                                  <AlertDescription>
                                    Extract the ZIP fully before running <strong>Install Connector.cmd</strong>. Do not run it from the ZIP preview in File Explorer. The installer will tell you whether the connector is ready, needs printer attention, or failed.
                                  </AlertDescription>
                                </Alert>
                              ) : null}

                              <ul className="space-y-3">
                                {item.notes.map((note) => (
                                  <li key={note} className="flex items-start gap-3 text-sm leading-6 text-slate-600">
                                    <CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-emerald-600" />
                                    <span>{note}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>

                            <div className="rounded-[24px] border border-slate-200 bg-slate-50/90 p-4">
                              <div className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">
                                Package details
                              </div>
                              <div className="mt-3 space-y-3 text-sm text-slate-600">
                                <div>
                                  <div className="text-xs uppercase tracking-[0.16em] text-slate-400">File</div>
                                  <div className="mt-1 break-all font-medium text-slate-900">{item.filename}</div>
                                </div>

                                <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-1">
                                  <div className="rounded-2xl bg-white px-3 py-2">
                                    <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Type</div>
                                    <div className="mt-1 font-medium text-slate-900">{item.installerKind.toUpperCase()}</div>
                                  </div>
                                  <div className="rounded-2xl bg-white px-3 py-2">
                                    <div className="text-xs uppercase tracking-[0.16em] text-slate-400">Size</div>
                                    <div className="mt-1 font-medium text-slate-900">{formatBytes(item.bytes)}</div>
                                  </div>
                                </div>

                                <div>
                                  <div className="text-xs uppercase tracking-[0.16em] text-slate-400">SHA-256</div>
                                  <code className="mt-1 block rounded-xl bg-white px-3 py-2 text-xs text-slate-700">
                                    {shortenChecksum(item.sha256)}
                                  </code>
                                </div>
                              </div>
                            </div>
                          </div>

                          <div className="flex flex-col gap-3 sm:flex-row">
                            <Button asChild size="lg" className="sm:min-w-[230px]">
                              <a href={item.href}>
                                <Download className="h-4 w-4" />
                                {item.action}
                              </a>
                            </Button>
                            <Button asChild size="lg" variant="outline">
                              <Link to={release.setupGuidePath}>
                                View setup guide
                                <ArrowRight className="h-4 w-4" />
                              </Link>
                            </Button>
                          </div>
                        </div>
                      </article>
                    );
                  })}
                </div>
              </section>
            ) : null}

            {release ? (
              <div className="grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
                <section className="rounded-[32px] border border-slate-200 bg-white/90 p-6 sm:p-8">
                  <div className="flex items-center gap-3">
                    <div className="rounded-2xl bg-slate-950 p-3 text-white">
                      <Workflow className="h-5 w-5" />
                    </div>
                    <div>
                      <h3 className="text-2xl font-semibold tracking-tight text-slate-950">Simple setup steps for factory teams</h3>
                      <p className="mt-1 text-sm leading-6 text-slate-600">
                        Share these steps with the workstation user who will print labels.
                      </p>
                    </div>
                  </div>

                  <div className="mt-6 grid gap-4">
                    {setupSteps.map((step, index) => (
                      <div key={step} className="flex gap-4 rounded-[24px] border border-slate-200 bg-slate-50/75 p-4">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-950 text-sm font-semibold text-white">
                          {index + 1}
                        </div>
                        <div className="pt-1 text-sm leading-6 text-slate-700">{step}</div>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="rounded-[32px] bg-slate-950 p-6 text-white sm:p-8">
                  <div className="flex items-center gap-3 text-emerald-300">
                    <Sparkles className="h-5 w-5" />
                    <h3 className="text-2xl font-semibold tracking-tight text-white">What stays automatic after install</h3>
                  </div>

                  <div className="mt-6 space-y-4">
                    {automaticBehaviors.map((item) => (
                      <div key={item} className="flex items-start gap-3 rounded-[24px] border border-white/10 bg-white/5 p-4">
                        <CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-emerald-300" />
                        <div className="text-sm leading-6 text-slate-200">{item}</div>
                      </div>
                    ))}
                  </div>

                  <div className="mt-6 rounded-[24px] border border-white/10 bg-white/5 p-4 text-sm leading-6 text-slate-300">
                    If your printer is a shared office AirPrint or IPP printer, your admin can also save it as a managed
                    network printer. Use the connector when printing depends on the workstation's local printer setup.
                  </div>
                </section>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  );
}

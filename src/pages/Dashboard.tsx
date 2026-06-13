import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { APP_PATHS, getRoleDisplayLabel } from "@/app/route-metadata";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { ErrorState, LoadingState } from "@/components/mscqr/feedback-state";
import { MotionPanel } from "@/components/mscqr/motion";
import { PrintStateIndicator } from "@/components/mscqr/status";
import { DashboardPagePattern } from "@/components/page-patterns/PagePatterns";
import { QRStatusChart } from "@/components/dashboard/QRStatusChart";
import { RecentActivityCard } from "@/components/dashboard/RecentActivityCard";
import { QrCode, Building2, Factory, FileText, RefreshCw, ArrowRight, Boxes } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";
import { useDashboardAuditLogs, useDashboardStats } from "@/features/dashboard/hooks";
import { buildOverviewLifecycleSteps } from "@/features/dashboard/presentation";
import apiClient from "@/lib/api-client";
import { useActivePrintSessionSuppression } from "@/lib/active-print-session";
import { ApiResponseError } from "@/lib/api/query-utils";
import { clearDashboardReadCache } from "@/lib/api/internal-client-dashboard-request-control";
import { canPollVisibleDocument, pollingPolicy } from "@/lib/query-polling-policy";

import type { AuditLogDTO, DashboardStatsDTO, QrStatsDTO } from "../../shared/contracts/runtime/dashboard.ts";

const STATS_POLL_MS = pollingPolicy.dashboardFallbackMs;
type StatusFocus = "all" | "dormant" | "allocated" | "printed" | "scanned";
type QrStatsDashboardExtras = QrStatsDTO & {
  suspiciousScans?: number;
  suspicious?: number;
  scansToday?: number;
  todayScans?: number;
};
type LegacyPublicCodeReport = {
  totalLegacyCodes: number;
  knownUnsafeLegacyCodes: number;
  potentiallyRotatableLegacyCodes: number;
  note?: string;
  groups: Array<{
    brandName: string | null;
    brandPrefix: string | null;
    batchName: string | null;
    batchLifecycleState: string | null;
    batchReleasedAt: string | null;
    status: string;
    count: number;
    knownUnsafeCount: number;
    potentiallyRotatableCount: number;
    batchPrintedAt: string | null;
    batchPrintPackDownloadedAt: string | null;
  }>;
};

const normalizeLegacyPublicCodeReport = (value: unknown): LegacyPublicCodeReport | null => {
  if (!value || typeof value !== "object") return null;
  const raw = value as Partial<LegacyPublicCodeReport>;
  return {
    totalLegacyCodes: Number(raw.totalLegacyCodes || 0),
    knownUnsafeLegacyCodes: Number(raw.knownUnsafeLegacyCodes || 0),
    potentiallyRotatableLegacyCodes: Number(raw.potentiallyRotatableLegacyCodes || 0),
    note: typeof raw.note === "string" ? raw.note : undefined,
    groups: Array.isArray(raw.groups) ? raw.groups : [],
  };
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const activePrintSuppressed = useActivePrintSessionSuppression();
  const scopedLicenseeId = user?.role === "manufacturer" ? undefined : user?.licenseeId;
  const canReadAuditFeed = user?.role === "super_admin" || user?.role === "licensee_admin";
  const dashboardQuery = useDashboardStats(scopedLicenseeId);
  const auditLogsQuery = useDashboardAuditLogs(canReadAuditFeed, 5);
  const dashboardRefetch = dashboardQuery.refetch;
  const auditLogsRefetch = auditLogsQuery.refetch;

  const [liveSummary, setLiveSummary] = useState<DashboardStatsDTO | null>(null);
  const [liveQrStats, setLiveQrStats] = useState<QrStatsDTO | null>(null);
  const [liveLogs, setLiveLogs] = useState<AuditLogDTO[] | null>(null);
  const [liveUpdates, setLiveUpdates] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [statusFocus, setStatusFocus] = useState<StatusFocus>("all");
  const [scopeDialogOpen, setScopeDialogOpen] = useState(false);
  const [legacyReport, setLegacyReport] = useState<LegacyPublicCodeReport | null>(null);
  const [legacyReportLoading, setLegacyReportLoading] = useState(false);
  const [legacyRotationBusy, setLegacyRotationBusy] = useState(false);
  const [legacyRotationSummary, setLegacyRotationSummary] = useState<string | null>(null);

  const pollRef = useRef<number | null>(null);
  const stopSseRef = useRef<(() => void) | null>(null);
  const sseConnectedRef = useRef(false);
  const refreshTimerRef = useRef<number | null>(null);
  const refreshInFlightRef = useRef<Promise<void> | null>(null);
  const latestAuditLogsRef = useRef<AuditLogDTO[]>([]);

  useEffect(() => {
    latestAuditLogsRef.current = (auditLogsQuery.data?.logs || []) as AuditLogDTO[];
  }, [auditLogsQuery.data]);

  const refreshDashboard = useCallback(async (options?: { bypassCache?: boolean }) => {
    if (activePrintSuppressed && !options?.bypassCache) return;
    if (refreshInFlightRef.current) return refreshInFlightRef.current;
    if (options?.bypassCache) {
      clearDashboardReadCache(["dashboard:stats", "qr:stats", "audit:logs"]);
    }

    refreshInFlightRef.current = (async () => {
      await dashboardRefetch();
      if (canReadAuditFeed) {
        await auditLogsRefetch();
      }
    })().finally(() => {
      refreshInFlightRef.current = null;
    });

    return refreshInFlightRef.current;
  }, [activePrintSuppressed, auditLogsRefetch, canReadAuditFeed, dashboardRefetch]);

  useEffect(() => {
    const closeRealtime = () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
      if (refreshTimerRef.current) window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
      if (stopSseRef.current) {
        stopSseRef.current();
        stopSseRef.current = null;
      }
      sseConnectedRef.current = false;
      setSseConnected(false);
    };

    if (!liveUpdates || activePrintSuppressed) {
      setLiveSummary(null);
      setLiveQrStats(null);
      setLiveLogs(null);
      closeRealtime();
      return () => {
        closeRealtime();
      };
    }

    // start polling stats (fallback when SSE disconnects)
    closeRealtime();
    pollRef.current = window.setInterval(() => {
      if (!canPollVisibleDocument()) return;
      if (sseConnectedRef.current) return;
      void refreshDashboard();
    }, STATS_POLL_MS);

    const scheduleSummaryRefresh = () => {
      if (refreshTimerRef.current) return;
      refreshTimerRef.current = window.setTimeout(() => {
        refreshTimerRef.current = null;
        void refreshDashboard();
      }, 350);
    };

    stopSseRef.current = apiClient.streamDashboardEvents(
      (envelope) => {
        if (envelope?.type === "snapshot") {
          const payload = envelope?.payload || {};
          const summary = payload.summary && typeof payload.summary === "object" ? (payload.summary as Record<string, unknown>) : {};
          setLiveSummary({
            totalQRCodes: Number(summary.totalQRCodes ?? 0),
            activeLicensees: Number(summary.activeLicensees ?? 0),
            manufacturers: Number(summary.manufacturers ?? 0),
            totalBatches: Number(summary.totalBatches ?? 0),
          });
          setLiveQrStats((payload.qrStats || {}) as QrStatsDTO);
          setLastUpdated(new Date());
          return;
        }
        if (envelope?.type === "audit.delta") {
          const payload = envelope?.payload || {};
          const log = payload.log as AuditLogDTO | undefined;
          if (log) {
            setLiveLogs((prev) => [log, ...(prev || latestAuditLogsRef.current)].slice(0, 10));
          }
          return;
        }
        if (envelope?.type === "summary.refresh") {
          scheduleSummaryRefresh();
        }
      },
      () => {
        sseConnectedRef.current = false;
        setSseConnected(false);
      },
      () => {
        sseConnectedRef.current = true;
        setSseConnected(true);
      }
    );

    return () => {
      closeRealtime();
    };
  }, [activePrintSuppressed, canReadAuditFeed, liveUpdates, refreshDashboard, scopedLicenseeId, user?.role]);

  useEffect(() => {
    if (dashboardQuery.dataUpdatedAt) {
      setLastUpdated(new Date(dashboardQuery.dataUpdatedAt));
    }
  }, [dashboardQuery.dataUpdatedAt]);

  const summary = liveSummary ?? dashboardQuery.data?.summary ?? null;
  const qrStats = liveQrStats ?? dashboardQuery.data?.qrStats ?? null;
  const logs = liveLogs ?? auditLogsQuery.data?.logs ?? [];
  const loading = dashboardQuery.isLoading && !dashboardQuery.data && !liveSummary;
  const rawError = dashboardQuery.error instanceof Error ? dashboardQuery.error.message : null;
  const error =
    rawError && /no token provided/i.test(rawError)
      ? "Your secure session could not be refreshed. Please sign in again."
      : rawError;
  const activityRateLimited =
    auditLogsQuery.error instanceof ApiResponseError &&
    String(auditLogsQuery.error.code || "").toUpperCase() === "RATE_LIMITED";
  const activityRefreshPaused = Boolean(auditLogsQuery.data?.refreshPaused || dashboardQuery.data?.refreshPaused);
  const activityUnavailableMessage = activityRateLimited
    ? "Recent activity is temporarily unavailable. We're refreshing activity too often. Try again shortly."
    : activityRefreshPaused
      ? "Activity refresh is temporarily paused. Dashboard work can continue."
      : undefined;

  // totals (support multiple backend shapes)
  const activeLicenseesCount = summary?.activeLicensees ?? 0;

  // chart: support both { dormant: n } OR { byStatus: { DORMANT: n } }
  const qrStatusData = useMemo(() => {
    const by = qrStats?.byStatus || qrStats?.statusCounts || {};
    return {
      dormant: qrStats?.dormant ?? (by.DORMANT ?? 0) + (by.ACTIVE ?? 0),
      allocated: qrStats?.allocated ?? (by.ALLOCATED ?? 0) + (by.ACTIVATED ?? 0),
      printed: qrStats?.printed ?? by.PRINTED ?? 0,
      scanned: (qrStats?.scanned ?? by.SCANNED ?? 0) + (by.REDEEMED ?? 0),
    };
  }, [qrStats]);

  const statusRows = useMemo(() => {
    const total = qrStatusData.dormant + qrStatusData.allocated + qrStatusData.printed + qrStatusData.scanned;
    return [
      {
        key: "dormant" as const,
        label: "Not used yet",
        value: qrStatusData.dormant,
        description: "Ready to assign to a batch",
        href: "/batches",
        pct: total > 0 ? Math.round((qrStatusData.dormant / total) * 100) : 0,
      },
      {
        key: "allocated" as const,
        label: "Assigned",
        value: qrStatusData.allocated,
        description: "Assigned to batches or manufacturers",
        href: "/batches",
        pct: total > 0 ? Math.round((qrStatusData.allocated / total) * 100) : 0,
      },
      {
        key: "printed" as const,
        label: "Printed",
        value: qrStatusData.printed,
        description: "Printed and ready for customer scan",
        href: "/batches",
        pct: total > 0 ? Math.round((qrStatusData.printed / total) * 100) : 0,
      },
      {
        key: "scanned" as const,
        label: "First scan completed",
        value: qrStatusData.scanned,
        description: "Customer verifications completed",
        href: APP_PATHS.scanActivity,
        pct: total > 0 ? Math.round((qrStatusData.scanned / total) * 100) : 0,
      },
    ];
  }, [qrStatusData]);

  const focusedRow = statusFocus === "all" ? null : statusRows.find((row) => row.key === statusFocus) || null;
  const totalTracked = statusRows.reduce((acc, row) => acc + row.value, 0);
  const fulfilled = qrStatusData.printed + qrStatusData.scanned;
  const fulfillmentPct = totalTracked > 0 ? Math.round((fulfilled / totalTracked) * 100) : 0;
  const redemptionPct = fulfilled > 0 ? Math.round((qrStatusData.scanned / fulfilled) * 100) : 0;
  const qrStatsExtras = qrStats as QrStatsDashboardExtras | null;
  const scansToday = qrStatsExtras?.scansToday ?? qrStatsExtras?.todayScans ?? null;
  const qrLabelsAvailable = qrStatusData.dormant + qrStatusData.allocated;

  const roleLabel = useMemo(() => getRoleDisplayLabel(user?.role), [user?.role]);
  const normalizedRole = String(user?.role || "").toLowerCase();
  const isPlatformAdmin = normalizedRole === "super_admin" || normalizedRole === "platform_super_admin";

  const loadLegacyReport = useCallback(async () => {
    if (!isPlatformAdmin) return;
    setLegacyReportLoading(true);
    try {
      const response = await apiClient.getLegacyPublicCodeReport();
      if (response.success && response.data) {
        setLegacyReport(normalizeLegacyPublicCodeReport(response.data));
      }
    } finally {
      setLegacyReportLoading(false);
    }
  }, [isPlatformAdmin]);

  useEffect(() => {
    void loadLegacyReport();
  }, [loadLegacyReport]);

  const runLegacyRotation = async (dryRun: boolean) => {
    if (!isPlatformAdmin) return;
    setLegacyRotationBusy(true);
    setLegacyRotationSummary(null);
    try {
      const response = await apiClient.rotateLegacyPublicCodes({ dryRun, limit: 250 });
      if (!response.success || !response.data) {
        setLegacyRotationSummary(response.error || "Legacy code rotation could not complete.");
        return;
      }
      const result = response.data;
      setLegacyRotationSummary(
        dryRun
          ? `Dry run checked ${result.scanned} rows: ${result.rotated.length} eligible, ${result.skipped.length} protected.`
          : `Rotated ${result.rotated.length} safe rows; ${result.skipped.length} protected rows were left unchanged.`
      );
      await loadLegacyReport();
    } finally {
      setLegacyRotationBusy(false);
    }
  };

  const downloadLegacyReportCsv = async () => {
    if (!isPlatformAdmin) return;
    const response = await apiClient.getLegacyPublicCodeReportCsv();
    if (!response.success || !response.data) {
      setLegacyRotationSummary(response.error || "Legacy report export could not complete.");
      return;
    }
    const blob = new Blob([response.data], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "mscqr-legacy-public-code-report.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const quickActions = useMemo(() => {
    if (user?.role === "super_admin") {
      return [
        { label: "Brands", description: "Onboard and manage brand workspaces", href: APP_PATHS.licensees },
        { label: "QR Requests", description: "Review pending QR label requests", href: APP_PATHS.codeRequests },
        { label: "View scans", description: "Review scan patterns and items needing attention", href: APP_PATHS.scanActivity },
        { label: "History", description: "Review recent workspace activity", href: APP_PATHS.auditHistory },
      ];
    }
    if (user?.role === "licensee_admin") {
      return [
        { label: "View batches", description: "Assign and monitor garment production", href: APP_PATHS.batches },
        { label: "Manufacturers", description: "Manage factory users", href: APP_PATHS.manufacturers },
        { label: "Request QR labels", description: "Ask for more labels for an upcoming garment batch", href: APP_PATHS.codeRequests },
        { label: "View scans", description: "Monitor scans and items needing attention", href: APP_PATHS.scanActivity },
      ];
    }
    return [
      { label: "View batches", description: "Open assigned garment batches and print labels", href: APP_PATHS.batches },
      { label: "Setup printer", description: "Check the printer before printing QR labels", href: APP_PATHS.printerSetup },
      { label: "View scans", description: "Track scans for your assigned batches", href: APP_PATHS.scanActivity },
      { label: "Verify Product", description: "Open customer verification", href: APP_PATHS.verify },
    ];
  }, [user?.role]);

  const cards = useMemo(() => {
    const totalQrHref = APP_PATHS.scanActivity;
    const totalQrCta = "View scans";
    const scopeCard =
      user?.role === "manufacturer"
        ? {
            title: "Linked brands",
            value: user?.linkedLicensees?.length || (user?.licenseeId ? 1 : 0),
            icon: Building2,
            variant: "info" as const,
            subtitle: "Brand workspaces you can print for",
            href: "/dashboard",
            ctaLabel: "Open scope details",
            action: "scope" as const,
          }
        : user?.role === "licensee_admin"
          ? {
              title: "Ready for batches",
              value: qrStatusData.dormant,
              icon: Boxes,
              variant: "info" as const,
              subtitle: "Labels waiting for a garment batch",
              href: "/batches",
              ctaLabel: "View batches",
              action: "navigate" as const,
            }
          : {
              title: "Brands",
              value: activeLicenseesCount,
              icon: Building2,
              variant: "info" as const,
              subtitle: "Active brand workspaces",
              href: "/licensees",
              ctaLabel: "Manage brands",
              action: "navigate" as const,
            };

    const items = [
      {
        title: "QR labels available",
        value: qrLabelsAvailable,
        icon: QrCode,
        variant: "default" as const,
        subtitle: `${qrStatusData.dormant.toLocaleString()} not used yet • ${qrStatusData.allocated.toLocaleString()} assigned`,
        href: totalQrHref,
        ctaLabel: totalQrCta,
      },
      scopeCard,
      {
        title: "Labels printed",
        value: qrStatusData.printed,
        icon: Factory,
        variant: "warning" as const,
        subtitle: "QR labels confirmed as printed",
        href: user?.role === "manufacturer" ? APP_PATHS.printerSetup : APP_PATHS.batches,
        ctaLabel: user?.role === "manufacturer" ? "Setup printer" : "View batches",
      },
      {
        title: "Scans today",
        value: scansToday ?? qrStatusData.scanned,
        icon: FileText,
        variant: "success" as const,
        subtitle: scansToday == null ? "Today count unavailable; showing all scans" : "Customer scans recorded today",
        href: APP_PATHS.scanActivity,
        ctaLabel: "View scans",
      },
    ];
    return items;
  }, [
    activeLicenseesCount,
    qrStatusData.dormant,
    qrStatusData.allocated,
    qrStatusData.printed,
    qrStatusData.scanned,
    qrLabelsAvailable,
    scansToday,
    user?.licenseeId,
    user?.linkedLicensees,
    user?.role,
  ]);

  const canViewAudit = user?.role === "super_admin" || user?.role === "licensee_admin" || user?.role === "manufacturer";
  const overviewLifecycleSteps = useMemo(() => buildOverviewLifecycleSteps(qrStatusData), [qrStatusData]);

  if (loading) {
    return (
      <DashboardLayout>
        <LoadingState
          title="Loading workspace overview"
          description="MSCQR is loading QR labels, printing status, scans, and recent workspace activity for your role."
        />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <DashboardPagePattern
        eyebrow="Workspace"
        title="Overview"
        description={`A simple view of QR labels, batches, printing, scans, and next actions for your ${roleLabel.toLowerCase()} workspace.`}
        actions={
          <>
            <span className="text-xs text-mscqr-secondary">
              {lastUpdated ? `Updated ${formatDistanceToNow(lastUpdated, { addSuffix: true })}` : "Not updated yet"}
              {liveUpdates ? (sseConnected ? " · live" : " · auto-refresh on") : " · auto-refresh paused"}
            </span>
            <div className="flex items-center gap-2 rounded-2xl border border-mscqr-border bg-mscqr-surface px-3 py-1.5">
              <span className="text-xs text-mscqr-secondary">Live</span>
              <Switch checked={liveUpdates} onCheckedChange={setLiveUpdates} />
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void refreshDashboard({ bypassCache: true })}
              className="gap-2"
              disabled={dashboardQuery.isFetching || auditLogsQuery.isFetching}
            >
              <RefreshCw className={cn("h-4 w-4", dashboardQuery.isFetching ? "animate-spin" : "")} />
              {dashboardQuery.isFetching || auditLogsQuery.isFetching ? "Refreshing..." : "Refresh"}
            </Button>
          </>
        }
      >

        {error && (
          <ErrorState
            title="Operations overview unavailable"
            description={error}
            action={{ label: "Retry overview", onClick: () => void refreshDashboard({ bypassCache: true }) }}
          />
        )}

        <div className="grid items-stretch gap-4 md:grid-cols-2 xl:grid-cols-4" data-testid="dashboard-kpi-grid">
          {cards.map((item) => (
            <MotionPanel
              key={item.title}
              className="h-full min-w-0"
            >
              <button
                type="button"
                onClick={() => (("action" in item && item.action === "scope") ? setScopeDialogOpen(true) : navigate(item.href))}
                className="group flex h-full min-h-[15.5rem] w-full min-w-0 flex-col rounded-[1.55rem] border border-mscqr-border bg-mscqr-surface/92 p-5 text-left shadow-[0_18px_46px_-38px_rgba(15,23,42,0.55)] transition hover:-translate-y-0.5 hover:border-mscqr-accent/45 hover:bg-mscqr-surface-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent motion-reduce:hover:translate-y-0"
                data-testid="dashboard-kpi-card"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="min-w-0">
                    <p className="break-words font-mono text-[11px] uppercase tracking-[0.2em] text-mscqr-muted">{item.title}</p>
                    <p className="mt-3 break-words text-3xl font-semibold tracking-tight text-mscqr-primary">{item.value.toLocaleString()}</p>
                  </div>
                  <div className="flex size-11 shrink-0 items-center justify-center rounded-2xl border border-mscqr-border bg-mscqr-surface-muted text-mscqr-accent transition group-hover:border-mscqr-accent/35">
                    <item.icon className="size-5" />
                  </div>
                </div>
                <p className="mt-4 min-h-12 text-sm leading-6 text-mscqr-secondary">{item.subtitle}</p>
                <div className="mt-auto flex items-center justify-between gap-3 pt-4 text-sm font-medium text-mscqr-accent">
                  <span className="min-w-0 break-words">{item.ctaLabel}</span>
                  <ArrowRight className="size-4 transition group-hover:translate-x-1" />
                </div>
              </button>
            </MotionPanel>
          ))}
        </div>

        <MotionPanel className="rounded-[1.75rem] border border-mscqr-border bg-mscqr-surface/92 p-5">
          <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium text-mscqr-accent">QR label progress</p>
              <h2 className="mt-2 text-xl font-semibold text-mscqr-primary">From request to customer scan</h2>
            </div>
            <PrintStateIndicator value={qrStatusData.printed > 0 ? "PRINT_CONFIRMED" : "PENDING"} label="print check" />
          </div>
          <div className="grid gap-3 md:grid-cols-5">
            {overviewLifecycleSteps.map((step, index) => (
              <div key={step.label} className="rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="flex size-8 items-center justify-center rounded-full bg-mscqr-accent-soft text-sm font-semibold text-mscqr-accent">
                    {index + 1}
                  </span>
                  <Badge variant={step.state === "complete" ? "default" : step.state === "current" ? "secondary" : "outline"}>
                    {step.state === "complete" ? "Ready" : step.state === "current" ? "In progress" : "Waiting"}
                  </Badge>
                </div>
                <h3 className="mt-4 text-sm font-semibold text-mscqr-primary">{step.title}</h3>
                <p className="mt-2 text-sm leading-6 text-mscqr-secondary">{step.body}</p>
              </div>
            ))}
          </div>
        </MotionPanel>

        <div className="grid items-start gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <Card className="self-start border-mscqr-border bg-mscqr-surface/92">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-mscqr-primary">Quick actions</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {quickActions.map((action) => (
                <button
                  key={action.href}
                  type="button"
                  onClick={() => navigate(action.href)}
                  className="rounded-2xl border border-mscqr-border bg-mscqr-surface-elevated p-4 text-left transition hover:border-mscqr-accent/45 hover:bg-mscqr-surface-muted"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-mscqr-primary">{action.label}</span>
                    <ArrowRight className="h-4 w-4 text-mscqr-accent" />
                  </div>
                  <p className="mt-2 text-xs leading-5 text-mscqr-secondary">{action.description}</p>
                </button>
              ))}
            </CardContent>
          </Card>

          {isPlatformAdmin ? (
            <Card className="border-mscqr-border bg-mscqr-surface/92">
              <CardHeader>
                <CardTitle className="text-lg font-semibold text-mscqr-primary">Legacy public code report</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-2xl font-semibold text-mscqr-primary">
                      {(legacyReport?.totalLegacyCodes || 0).toLocaleString()}
                    </div>
                    <div className="text-xs text-mscqr-secondary">Predictable public codes not starting with c_</div>
                    {legacyReport ? (
                      <div className="mt-1 text-xs text-mscqr-secondary">
                        {(legacyReport.potentiallyRotatableLegacyCodes || 0).toLocaleString()} potentially rotatable ·{" "}
                        {(legacyReport.knownUnsafeLegacyCodes || 0).toLocaleString()} protected by print/scan/release evidence
                      </div>
                    ) : null}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="outline" size="sm" onClick={() => void downloadLegacyReportCsv()} disabled={legacyReportLoading}>
                      Export CSV
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => void loadLegacyReport()} disabled={legacyReportLoading}>
                      Refresh
                    </Button>
                  </div>
                </div>
                <div className="max-h-60 space-y-2 overflow-y-auto pr-1">
                  {(legacyReport?.groups || []).slice(0, 8).map((row) => (
                    <div
                      key={`${row.brandPrefix || row.brandName}-${row.batchName || "unbatched"}-${row.status}`}
                      className="rounded-md border border-mscqr-border bg-mscqr-surface-elevated p-3 text-sm"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium text-mscqr-primary">
                          {row.brandName || row.brandPrefix || "Unknown brand"}
                        </span>
                        <Badge variant="outline">{row.count.toLocaleString()}</Badge>
                      </div>
                      <div className="mt-1 text-xs text-mscqr-secondary">
                        {row.batchName || "Unbatched"} · {row.status}
                        {row.batchLifecycleState ? ` · ${row.batchLifecycleState}` : ""}
                        {row.batchPrintedAt ? " · printed batch" : ""}
                        {row.batchPrintPackDownloadedAt ? " · pack downloaded" : ""}
                        {row.batchReleasedAt ? " · released" : ""}
                      </div>
                      <div className="mt-1 text-xs text-mscqr-secondary">
                        {row.potentiallyRotatableCount.toLocaleString()} potentially rotatable ·{" "}
                        {row.knownUnsafeCount.toLocaleString()} protected
                      </div>
                    </div>
                  ))}
                  {legacyReport && (legacyReport.groups || []).length === 0 ? (
                    <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
                      No legacy predictable public codes found.
                    </div>
                  ) : null}
                </div>
                <div className="flex flex-wrap justify-end gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void runLegacyRotation(true)}
                    disabled={legacyRotationBusy || legacyReportLoading}
                  >
                    Dry run rotation
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => void runLegacyRotation(false)}
                    disabled={legacyRotationBusy || legacyReportLoading || !legacyReport?.totalLegacyCodes}
                  >
                    Rotate safe rows
                  </Button>
                </div>
                {legacyRotationSummary ? (
                  <div className="rounded-md border border-mscqr-border bg-mscqr-surface-muted p-3 text-xs text-mscqr-secondary">
                    {legacyRotationSummary}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          ) : null}

          <Card className="border-mscqr-border bg-mscqr-surface/92">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-mscqr-primary">Workspace snapshot</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-mscqr-secondary">Labels assigned or printed</span>
                  <span className="font-medium text-mscqr-primary">{fulfillmentPct}%</span>
                </div>
                <Progress value={fulfillmentPct} />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-mscqr-secondary">Printed labels with scans</span>
                  <span className="font-medium text-mscqr-primary">{redemptionPct}%</span>
                </div>
                <Progress value={redemptionPct} />
              </div>

              <div className="space-y-2">
                {statusRows.map((row) => (
                  <button
                    key={row.key}
                    type="button"
                    onClick={() => setStatusFocus((prev) => (prev === row.key ? "all" : row.key))}
                    className={cn(
                      "w-full rounded-md border px-3 py-2 text-left transition-colors",
                      statusFocus === row.key ? "border-mscqr-accent/40 bg-mscqr-accent/10" : "border-mscqr-border hover:bg-mscqr-surface-muted/70"
                    )}
                  >
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium text-mscqr-primary">{row.label}</span>
                      <span className="text-mscqr-secondary">{row.value.toLocaleString()} ({row.pct}%)</span>
                    </div>
                    <p className="text-xs text-mscqr-secondary">{row.description}</p>
                  </button>
                ))}
              </div>

              {focusedRow && (
                <div className="rounded-2xl border border-mscqr-accent/30 bg-mscqr-accent-soft/40 p-3">
                  <div className="font-medium text-mscqr-primary">{focusedRow.label} focus</div>
                  <p className="text-xs text-mscqr-secondary">
                    {focusedRow.value.toLocaleString()} QR labels currently {focusedRow.description.toLowerCase()}.
                  </p>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="mt-2 px-0 text-mscqr-accent"
                    onClick={() => navigate(focusedRow.href)}
                  >
                    Open related view
                  </Button>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="grid gap-6 md:grid-cols-2 mt-6">
          <Card className="border-mscqr-border bg-mscqr-surface/92">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-mscqr-primary">Label status distribution</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-mscqr-secondary">
                See how QR labels are moving through inventory, production, printing, and customer scans.
              </p>
              <QRStatusChart data={qrStatusData} selectedStatus={statusFocus} onStatusSelect={setStatusFocus} />
            </CardContent>
          </Card>
          <RecentActivityCard
            logs={logs.map((log) => ({
              ...log,
              action: log.action || "Activity",
              entityType: log.entityType || "System",
              entityId: log.entityId || log.id,
            }))}
            emptyMessage={
              activityUnavailableMessage ||
              (canViewAudit
                ? "No recent activity yet. Actions in batches, users, and requests will appear here."
                : "Activity feed is available for admin roles. Use Batches for your print operations.")
            }
            notice={logs.length > 0 ? activityUnavailableMessage : undefined}
            onViewAll={canViewAudit ? () => navigate(APP_PATHS.auditHistory) : undefined}
          />
        </div>

        <Dialog open={scopeDialogOpen} onOpenChange={setScopeDialogOpen}>
          <DialogContent className="sm:max-w-[620px]">
            <DialogHeader>
              <DialogTitle>Manufacturer workspace details</DialogTitle>
              <DialogDescription>
                This shows the brand workspaces connected to your manufacturer account.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="rounded-xl border bg-slate-50 p-4">
                <p className="text-sm font-medium text-slate-500">Linked brands</p>
                <div className="mt-2 space-y-2">
                  {(user?.linkedLicensees?.length ? user.linkedLicensees : user?.licensee ? [user.licensee] : []).map((entry) => (
                    <div key={entry.id} className="rounded-lg border bg-white px-3 py-2">
                      <p className="text-sm font-semibold text-slate-900">{entry.brandName || entry.name}</p>
                      <p className="text-xs text-slate-600">
                        Prefix: <span className="font-mono">{entry.prefix || "—"}</span>
                      </p>
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-sm text-slate-600">
                  Manufacturer access is limited to batches, printing, scans, and issues inside these linked brand workspaces only.
                </p>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate("/batches")}
                >
                  <p className="font-medium text-slate-900">Batches</p>
                  <p className="mt-1 text-xs text-slate-600">Print assigned labels and review batch progress.</p>
                </button>
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate(APP_PATHS.scanActivity)}
                >
                  <p className="font-medium text-slate-900">Scans</p>
                  <p className="mt-1 text-xs text-slate-600">Review scans within your production scope.</p>
                </button>
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate("/help/manufacturer")}
                >
                  <p className="font-medium text-slate-900">Help</p>
                  <p className="mt-1 text-xs text-slate-600">See help for manufacturer workspaces.</p>
                </button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </DashboardPagePattern>
    </DashboardLayout>
  );
}

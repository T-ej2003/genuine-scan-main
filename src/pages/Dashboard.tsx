import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { APP_PATHS, getRoleDisplayLabel } from "@/app/route-metadata";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { ErrorState, LoadingState } from "@/components/mscqr/feedback-state";
import { MotionPanel } from "@/components/mscqr/motion";
import { PrintStateIndicator, StatusBadge } from "@/components/mscqr/status";
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

import type { AuditLogDTO, DashboardStatsDTO, QrStatsDTO } from "../../shared/contracts/runtime/dashboard.ts";

const STATS_POLL_MS = 5000;
const API_BASE = (import.meta.env.VITE_API_URL || "/api").replace(/\/$/, "");
type StatusFocus = "all" | "dormant" | "allocated" | "printed" | "scanned";
type DashboardGraphView = "scans" | "confidence" | "printed" | "batches";
type QrStatsDashboardExtras = QrStatsDTO & {
  suspiciousScans?: number;
  suspicious?: number;
  scansToday?: number;
  todayScans?: number;
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const scopedLicenseeId = user?.role === "manufacturer" ? undefined : user?.licenseeId;
  const canReadAuditFeed = user?.role === "super_admin" || user?.role === "licensee_admin";
  const dashboardQuery = useDashboardStats(scopedLicenseeId);
  const auditLogsQuery = useDashboardAuditLogs(canReadAuditFeed, 5);

  const [liveSummary, setLiveSummary] = useState<DashboardStatsDTO | null>(null);
  const [liveQrStats, setLiveQrStats] = useState<QrStatsDTO | null>(null);
  const [liveLogs, setLiveLogs] = useState<AuditLogDTO[] | null>(null);
  const [liveUpdates, setLiveUpdates] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [statusFocus, setStatusFocus] = useState<StatusFocus>("all");
  const [graphView, setGraphView] = useState<DashboardGraphView>("scans");
  const [scopeDialogOpen, setScopeDialogOpen] = useState(false);

  const pollRef = useRef<number | null>(null);
  const sseRef = useRef<EventSource | null>(null);
  const refreshTimerRef = useRef<number | null>(null);

  const refreshDashboard = async () => {
    await dashboardQuery.refetch();
    if (canReadAuditFeed) {
      await auditLogsQuery.refetch();
    }
  };

  useEffect(() => {
    const closeRealtime = () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
      if (refreshTimerRef.current) window.clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = null;
      if (sseRef.current) {
        sseRef.current.close();
        sseRef.current = null;
      }
      setSseConnected(false);
    };

    void refreshDashboard();

    if (!liveUpdates) {
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
      if (document.visibilityState !== "visible") return;
      if (sseRef.current) return;
      void refreshDashboard();
    }, STATS_POLL_MS);

    // setup SSE for realtime (cookie-auth; do not put tokens in URLs)
    {
      let es: EventSource;
      try {
        es = new EventSource(`${API_BASE}/events/dashboard`, { withCredentials: true });
      } catch {
        es = new EventSource(`${API_BASE}/events/dashboard`);
      }
      sseRef.current = es;
      setSseConnected(true);

      const scheduleSummaryRefresh = () => {
        if (refreshTimerRef.current) return;
        refreshTimerRef.current = window.setTimeout(() => {
          refreshTimerRef.current = null;
          void refreshDashboard();
        }, 350);
      };

      es.addEventListener("realtime", (e: MessageEvent) => {
        try {
          const envelope = JSON.parse(e.data || "{}");
          if (envelope?.channel !== "dashboard") return;
          if (envelope?.type === "snapshot") {
            const payload = envelope?.payload || {};
            setLiveSummary({
              totalQRCodes: payload?.summary?.totalQRCodes ?? 0,
              activeLicensees: payload?.summary?.activeLicensees ?? 0,
              manufacturers: payload?.summary?.manufacturers ?? 0,
              totalBatches: payload?.summary?.totalBatches ?? 0,
            });
            setLiveQrStats(payload?.qrStats || {});
            setLastUpdated(new Date());
            return;
          }
          if (envelope?.type === "audit.delta") {
            const log = envelope?.payload?.log;
            if (log) {
              setLiveLogs((prev) => [log, ...((prev || auditLogsQuery.data || []) as AuditLogDTO[])].slice(0, 10));
            }
            return;
          }
          if (envelope?.type === "summary.refresh") {
            scheduleSummaryRefresh();
          }
        } catch {
          // ignore
        }
      });

      es.onerror = () => {
        es.close();
        sseRef.current = null;
        setSseConnected(false);
      };
      es.onopen = () => setSseConnected(true);
    }

    return () => {
      closeRealtime();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [auditLogsQuery.data, canReadAuditFeed, liveUpdates, scopedLicenseeId, user?.role]);

  useEffect(() => {
    if (dashboardQuery.dataUpdatedAt) {
      setLastUpdated(new Date(dashboardQuery.dataUpdatedAt));
    }
  }, [dashboardQuery.dataUpdatedAt]);

  const summary = liveSummary ?? dashboardQuery.data?.summary ?? null;
  const qrStats = liveQrStats ?? dashboardQuery.data?.qrStats ?? null;
  const logs = liveLogs ?? auditLogsQuery.data ?? [];
  const loading = dashboardQuery.isLoading && !dashboardQuery.data && !liveSummary;
  const rawError =
    (dashboardQuery.error instanceof Error ? dashboardQuery.error.message : null) ||
    (auditLogsQuery.error instanceof Error ? auditLogsQuery.error.message : null);
  const error =
    rawError && /no token provided/i.test(rawError)
      ? "Your secure session could not be refreshed. Please sign in again."
      : rawError;

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
  const rawStatusCounts = qrStats?.byStatus || qrStats?.statusCounts || {};
  const qrStatsExtras = qrStats as QrStatsDashboardExtras | null;
  const suspiciousScanCount =
    qrStatsExtras?.suspiciousScans ??
    qrStatsExtras?.suspicious ??
    (rawStatusCounts.SUSPICIOUS ?? 0) + (rawStatusCounts.BLOCKED ?? 0);
  const scansToday = qrStatsExtras?.scansToday ?? qrStatsExtras?.todayScans ?? null;
  const qrLabelsAvailable = qrStatusData.dormant + qrStatusData.allocated;
  const graphOptions: Array<{ id: DashboardGraphView; label: string; description: string }> = [
    { id: "scans", label: "Scans over time", description: "Shows customer scan activity when the data is available." },
    { id: "confidence", label: "Genuine vs suspicious", description: "Compares verified scans with scans that need review." },
    { id: "printed", label: "Labels printed", description: "Tracks labels that have been confirmed as printed." },
    { id: "batches", label: "Top scanned batches", description: "Highlights the batches customers scan most often." },
  ];

  const roleLabel = useMemo(() => getRoleDisplayLabel(user?.role), [user?.role]);

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
              title: "QR labels available",
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
  const overviewLifecycleSteps = [
    {
      label: "Issue",
      title: "QR labels ready",
      body: `${qrStatusData.dormant.toLocaleString()} waiting for allocation.`,
      state: qrStatusData.dormant > 0 ? ("current" as const) : ("complete" as const),
    },
    {
      label: "Assign",
      title: "Batch assignment",
      body: `${qrStatusData.allocated.toLocaleString()} assigned to production.`,
      state: qrStatusData.allocated > 0 ? ("complete" as const) : ("pending" as const),
    },
    {
      label: "Print",
      title: "Print labels",
      body: `${qrStatusData.printed.toLocaleString()} labels confirmed as printed.`,
      state: qrStatusData.printed > 0 ? ("complete" as const) : ("pending" as const),
    },
    {
      label: "Verify",
      title: "Public checks",
      body: `${qrStatusData.scanned.toLocaleString()} customer verification events.`,
      state: qrStatusData.scanned > 0 ? ("complete" as const) : ("pending" as const),
    },
    {
      label: "Review",
      title: "Review issues",
      body: "Scan results and workspace history remain reviewable.",
      state: "current" as const,
    },
  ];

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
            <StatusBadge tone={liveUpdates && sseConnected ? "verified" : liveUpdates ? "degraded" : "neutral"}>
              {liveUpdates && sseConnected ? "Updated just now" : liveUpdates ? "Refreshes automatically" : "Auto-refresh paused"}
            </StatusBadge>
            <StatusBadge tone="audit">
              {lastUpdated ? `Updated ${formatDistanceToNow(lastUpdated, { addSuffix: true })}` : "Not updated yet"}
            </StatusBadge>
            <div className="flex items-center gap-2 rounded-2xl border border-mscqr-border bg-mscqr-surface px-3 py-1.5">
              <span className="text-xs text-mscqr-secondary">Live</span>
              <Switch checked={liveUpdates} onCheckedChange={setLiveUpdates} />
            </div>
            <Button variant="outline" size="sm" onClick={() => void refreshDashboard()} className="gap-2">
              <RefreshCw className={cn("h-4 w-4", dashboardQuery.isFetching ? "animate-spin" : "")} />
              Refresh
            </Button>
          </>
        }
      >

        {error && (
          <ErrorState
            title="Operations overview unavailable"
            description={error}
            action={{ label: "Retry overview", onClick: () => void refreshDashboard() }}
          />
        )}

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          {cards.map((item) => (
            <MotionPanel
              key={item.title}
              className="h-full"
            >
              <button
                type="button"
                onClick={() => (("action" in item && item.action === "scope") ? setScopeDialogOpen(true) : navigate(item.href))}
                className="group rounded-[1.55rem] border border-mscqr-border bg-mscqr-surface/92 p-5 text-left shadow-[0_18px_46px_-38px_rgba(15,23,42,0.55)] transition hover:-translate-y-0.5 hover:border-mscqr-accent/45 hover:bg-mscqr-surface-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-mscqr-accent motion-reduce:hover:translate-y-0"
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-mscqr-muted">{item.title}</p>
                    <p className="mt-3 text-3xl font-semibold tracking-tight text-mscqr-primary">{item.value.toLocaleString()}</p>
                  </div>
                  <div className="flex size-11 items-center justify-center rounded-2xl border border-mscqr-border bg-mscqr-surface-muted text-mscqr-accent transition group-hover:border-mscqr-accent/35">
                    <item.icon className="size-5" />
                  </div>
                </div>
                <p className="mt-4 min-h-10 text-sm leading-6 text-mscqr-secondary">{item.subtitle}</p>
                <div className="mt-4 flex items-center justify-between text-sm font-medium text-mscqr-accent">
                  <span>{item.ctaLabel}</span>
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
              <CardTitle className="text-lg font-semibold text-mscqr-primary">Scan trend graph</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-wrap gap-2">
                {graphOptions.map((option) => (
                  <Button
                    key={option.id}
                    type="button"
                    size="sm"
                    variant={graphView === option.id ? "default" : "outline"}
                    onClick={() => setGraphView(option.id)}
                  >
                    {option.label}
                  </Button>
                ))}
              </div>
              {graphView === "scans" ? (
                <QRStatusChart data={qrStatusData} selectedStatus={statusFocus} onStatusSelect={setStatusFocus} />
              ) : (
                <div className="rounded-2xl border border-dashed border-mscqr-border bg-mscqr-surface-muted/40 p-6">
                  <p className="text-sm font-semibold text-mscqr-primary">
                    {graphOptions.find((option) => option.id === graphView)?.label}
                  </p>
                  <p className="mt-2 text-sm leading-6 text-mscqr-secondary">
                    {graphOptions.find((option) => option.id === graphView)?.description} This workspace will show the graph here once matching data is available.
                  </p>
                  {graphView === "confidence" ? (
                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                      <div className="rounded-2xl border bg-white p-4">
                        <p className="text-sm text-mscqr-secondary">Genuine scans</p>
                        <p className="mt-2 text-2xl font-semibold text-mscqr-primary">{Math.max(qrStatusData.scanned - suspiciousScanCount, 0).toLocaleString()}</p>
                      </div>
                      <div className="rounded-2xl border bg-white p-4">
                        <p className="text-sm text-mscqr-secondary">Suspicious scans</p>
                        <p className="mt-2 text-2xl font-semibold text-mscqr-primary">{suspiciousScanCount.toLocaleString()}</p>
                      </div>
                    </div>
                  ) : null}
                </div>
              )}
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
              canViewAudit
                ? "No recent activity yet. Actions in batches, users, and requests will appear here."
                : "Activity feed is available for admin roles. Use Batches for your print operations."
            }
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

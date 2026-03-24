import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { APP_PATHS, getRoleDisplayLabel } from "@/app/route-metadata";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { DashboardPagePattern } from "@/components/page-patterns/PagePatterns";
import { StatsCard } from "@/components/dashboard/StatsCard";
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
  const [scopeDialogOpen, setScopeDialogOpen] = useState(false);

  const pollRef = useRef<number | null>(null);
  const sseRef = useRef<EventSource | null>(null);

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
      const es = new EventSource(`${API_BASE}/events/dashboard`);
      sseRef.current = es;
      setSseConnected(true);

      es.addEventListener("stats", (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          setLiveSummary({
            totalQRCodes: payload?.totalQRCodes ?? 0,
            activeLicensees: payload?.activeLicensees ?? 0,
            manufacturers: payload?.manufacturers ?? 0,
            totalBatches: payload?.totalBatches ?? 0,
          });
          setLiveQrStats(payload?.qr || {});
          setLastUpdated(new Date());
        } catch {
          // ignore parse errors
        }
      });

      es.addEventListener("audit", (e: MessageEvent) => {
        try {
          const log = JSON.parse(e.data);
          setLiveLogs((prev) => [log, ...((prev || auditLogsQuery.data || []) as AuditLogDTO[])].slice(0, 10));
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
  const error =
    (dashboardQuery.error instanceof Error ? dashboardQuery.error.message : null) ||
    (auditLogsQuery.error instanceof Error ? auditLogsQuery.error.message : null);

  // totals (support multiple backend shapes)
  const totalQRCodes = summary?.totalQRCodes ?? 0;
  const activeLicenseesCount = summary?.activeLicensees ?? 0;
  const manufacturersCount = summary?.manufacturers ?? 0;
  const batchesCount = summary?.totalBatches ?? 0;

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
        label: "Dormant",
        value: qrStatusData.dormant,
        description: "Commissioned but not allocated",
        href: "/batches",
        pct: total > 0 ? Math.round((qrStatusData.dormant / total) * 100) : 0,
      },
      {
        key: "allocated" as const,
        label: "Allocated",
        value: qrStatusData.allocated,
        description: "Assigned to batches/manufacturers",
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
        label: "Redeemed",
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

  const roleLabel = useMemo(() => getRoleDisplayLabel(user?.role), [user?.role]);

  const quickActions = useMemo(() => {
    if (user?.role === "super_admin") {
      return [
        { label: "Licensees", description: "Onboard and manage tenants", href: APP_PATHS.licensees },
        { label: "Code Requests", description: "Review pending allocations", href: APP_PATHS.codeRequests },
        { label: "Scan Activity", description: "Inspect scans and risk", href: APP_PATHS.scanActivity },
        { label: "Audit History", description: "Review recent operations", href: APP_PATHS.auditHistory },
      ];
    }
    if (user?.role === "licensee_admin") {
      return [
        { label: "Batches", description: "Assign and monitor production", href: APP_PATHS.batches },
        { label: "Manufacturers", description: "Manage factory users", href: APP_PATHS.manufacturers },
        { label: "Code Requests", description: "Request more codes", href: APP_PATHS.codeRequests },
        { label: "Scan Activity", description: "Monitor scans and alerts", href: APP_PATHS.scanActivity },
      ];
    }
    return [
      { label: "My Batches", description: "Create and print jobs", href: APP_PATHS.batches },
      { label: "Printer Setup", description: "Check printer readiness", href: APP_PATHS.printerSetup },
      { label: "Scan Activity", description: "Track scans for your assigned batches", href: APP_PATHS.scanActivity },
      { label: "Verify Product", description: "Open customer verification", href: APP_PATHS.verify },
    ];
  }, [user?.role]);

  const cards = useMemo(() => {
    const totalQrHref = APP_PATHS.scanActivity;
    const totalQrCta =
      user?.role === "super_admin" ? "Inspect master inventory" : "Inspect tenant inventory";
    const manufacturersHref = user?.role === "manufacturer" ? APP_PATHS.scanActivity : APP_PATHS.manufacturers;
    const manufacturersCta =
      user?.role === "manufacturer" ? "View manufacturer telemetry" : "Manage manufacturers";
    const scopeCard =
      user?.role === "manufacturer"
        ? {
            title: "Linked Licensees",
            value: user?.linkedLicensees?.length || (user?.licenseeId ? 1 : 0),
            icon: Building2,
            variant: "info" as const,
            subtitle: "Authorized operating scope",
            href: "/dashboard",
            ctaLabel: "Open scope details",
            action: "scope" as const,
          }
        : user?.role === "licensee_admin"
          ? {
              title: "Unassigned Inventory",
              value: qrStatusData.dormant,
              icon: Boxes,
              variant: "info" as const,
              subtitle: "Codes still waiting for manufacturer allocation",
              href: "/batches",
              ctaLabel: "Review source batches",
              action: "navigate" as const,
            }
          : {
              title: "Active Licensees",
              value: activeLicenseesCount,
              icon: Building2,
              variant: "info" as const,
              subtitle: "Currently enabled tenants",
              href: "/licensees",
              ctaLabel: "Manage licensees",
              action: "navigate" as const,
            };

    const items = [
      {
        title: "Total Codes",
        value: totalQRCodes,
        icon: QrCode,
        variant: "default" as const,
        subtitle: `Dormant ${qrStatusData.dormant.toLocaleString()} • Redeemed ${qrStatusData.scanned.toLocaleString()}`,
        href: totalQrHref,
        ctaLabel: totalQrCta,
      },
      scopeCard,
      {
        title: "Manufacturers",
        value: manufacturersCount,
        icon: Factory,
        variant: "warning" as const,
        subtitle: user?.role === "manufacturer" ? "Your production footprint" : "Operational manufacturing users",
        href: manufacturersHref,
        ctaLabel: manufacturersCta,
      },
      {
        title: "Batches",
        value: batchesCount,
        icon: FileText,
        variant: "success" as const,
        subtitle: "Batch planning, assignment, and print operations",
        href: "/batches",
        ctaLabel: "Open batch operations",
      },
    ];
    return items;
  }, [
    activeLicenseesCount,
    batchesCount,
    manufacturersCount,
    qrStatusData.dormant,
    qrStatusData.scanned,
    totalQRCodes,
    user?.licenseeId,
    user?.linkedLicensees,
    user?.role,
  ]);

  const canViewAudit = user?.role === "super_admin" || user?.role === "licensee_admin" || user?.role === "manufacturer";

  if (loading) return <div className="p-6">Loading…</div>;

  return (
    <DashboardLayout>
      <DashboardPagePattern
        title="Dashboard"
        description={`Welcome back, ${user?.name}. Review the activity, queues, and next actions for your ${roleLabel.toLowerCase()} workspace.`}
        actions={
          <>
            <Badge variant={liveUpdates && sseConnected ? "default" : "secondary"}>
              {liveUpdates && sseConnected ? "Live Connected" : liveUpdates ? "Live Polling" : "Live Paused"}
            </Badge>
            <Badge variant="outline">
              {lastUpdated ? `Updated ${formatDistanceToNow(lastUpdated, { addSuffix: true })}` : "Not updated yet"}
            </Badge>
            <div className="flex items-center gap-2 rounded-md border px-3 py-1.5">
              <span className="text-xs text-muted-foreground">Live</span>
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
          <div className="rounded-md border border-destructive/40 bg-destructive/5 px-4 py-3 text-sm text-destructive">
            {error}
          </div>
        )}

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {cards.map((item) => (
            <StatsCard
              key={item.title}
              title={item.title}
              value={item.value}
              icon={item.icon}
              subtitle={item.subtitle}
              variant={item.variant}
              onClick={() => (("action" in item && item.action === "scope") ? setScopeDialogOpen(true) : navigate(item.href))}
              ctaLabel={item.ctaLabel}
            />
          ))}
        </div>

        <div className="grid items-start gap-6 lg:grid-cols-2">
          <Card className="animate-fade-in self-start">
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              {quickActions.map((action) => (
                <button
                  key={action.href}
                  type="button"
                  onClick={() => navigate(action.href)}
                  className="rounded-lg border p-3 text-left transition-colors hover:bg-muted/60"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{action.label}</span>
                    <ArrowRight className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{action.description}</p>
                </button>
              ))}
            </CardContent>
          </Card>

          <Card className="animate-fade-in">
            <CardHeader>
              <CardTitle className="text-lg font-semibold">Operational Snapshot</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Lifecycle completion</span>
                  <span className="font-medium">{fulfillmentPct}%</span>
                </div>
                <Progress value={fulfillmentPct} />
              </div>
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Printed to redeemed conversion</span>
                  <span className="font-medium">{redemptionPct}%</span>
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
                      statusFocus === row.key ? "border-primary/40 bg-primary/5" : "hover:bg-muted/60"
                    )}
                  >
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">{row.label}</span>
                      <span>{row.value.toLocaleString()} ({row.pct}%)</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{row.description}</p>
                  </button>
                ))}
              </div>

              {focusedRow && (
                <div className="rounded-md border bg-muted/40 p-3">
                  <div className="font-medium">{focusedRow.label} focus</div>
                  <p className="text-xs text-muted-foreground">
                    {focusedRow.value.toLocaleString()} codes currently {focusedRow.description.toLowerCase()}.
                  </p>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="mt-2 px-0 text-primary"
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
          <QRStatusChart data={qrStatusData} selectedStatus={statusFocus} onStatusSelect={setStatusFocus} />
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
              <DialogTitle>Manufacturer Scope Details</DialogTitle>
              <DialogDescription>
                This shows the tenant boundary applied to your manufacturer account and where to operate within it.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="rounded-xl border bg-slate-50 p-4">
                <p className="text-[11px] uppercase tracking-wide text-slate-500">Linked Licensees</p>
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
                  Manufacturer access is limited to batches, tracking, printing, and incidents inside these linked licensee scopes only.
                </p>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate("/batches")}
                >
                  <p className="font-medium text-slate-900">Batches</p>
                  <p className="mt-1 text-xs text-slate-600">Print assigned inventory and inspect allocation results.</p>
                </button>
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate(APP_PATHS.scanActivity)}
                >
                  <p className="font-medium text-slate-900">Scan Activity</p>
                  <p className="mt-1 text-xs text-slate-600">Review scan analytics within your production scope.</p>
                </button>
                <button
                  type="button"
                  className="rounded-xl border p-4 text-left hover:bg-slate-50"
                  onClick={() => navigate("/help/licensee-admin")}
                >
                  <p className="font-medium text-slate-900">Help</p>
                  <p className="mt-1 text-xs text-slate-600">See the exact navigation path used by licensee operators.</p>
                </button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </DashboardPagePattern>
    </DashboardLayout>
  );
}

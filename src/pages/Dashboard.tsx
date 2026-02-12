import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { StatsCard } from "@/components/dashboard/StatsCard";
import { QRStatusChart } from "@/components/dashboard/QRStatusChart";
import { RecentActivityCard } from "@/components/dashboard/RecentActivityCard";
import { QrCode, Building2, Factory, FileText, RefreshCw, ArrowRight } from "lucide-react";
import apiClient from "@/lib/api-client";
import { onMutationEvent } from "@/lib/mutation-events";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { formatDistanceToNow } from "date-fns";

const STATS_POLL_MS = 5000;
const API_BASE = (import.meta.env.VITE_API_URL || "/api").replace(/\/$/, "");
type StatusFocus = "all" | "dormant" | "allocated" | "printed" | "scanned";

export default function Dashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [summary, setSummary] = useState<any>(null);
  const [qrStats, setQrStats] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [liveUpdates, setLiveUpdates] = useState(true);
  const [sseConnected, setSseConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [statusFocus, setStatusFocus] = useState<StatusFocus>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<number | null>(null);
  const sseRef = useRef<EventSource | null>(null);

  const load = async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    try {
      const [summaryRes, qrRes] = await Promise.all([
        apiClient.getDashboardStats(user?.licenseeId),
        apiClient.getQRStats(user?.licenseeId),
      ]);

      if (!summaryRes.success) throw new Error(summaryRes.error || "Failed to load dashboard stats");
      if (!qrRes.success) throw new Error(qrRes.error || "Failed to load QR stats");

      setSummary(summaryRes.data || {});
      setQrStats(qrRes.data || {});
      setLastUpdated(new Date());

      if (user?.role === "super_admin" || user?.role === "licensee_admin") {
        const logsRes = await apiClient.getAuditLogs({ limit: 5 });
        if (logsRes.success) {
          const payload: any = logsRes.data;
          const list = Array.isArray(payload) ? payload : Array.isArray(payload?.logs) ? payload.logs : [];
          setLogs(list);
        } else {
          setLogs([]);
        }
      } else {
        setLogs([]);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load dashboard");
      setSummary(null);
      setQrStats(null);
      setLogs([]);
    } finally {
      if (!opts?.silent) setLoading(false);
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

    // initial load
    load();

    if (!liveUpdates) {
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
      load({ silent: true });
    }, STATS_POLL_MS);

    // setup SSE for realtime
    const token = apiClient.getToken();
    if (token) {
      const es = new EventSource(`${API_BASE}/events/dashboard?token=${encodeURIComponent(token)}`);
      sseRef.current = es;
      setSseConnected(true);

      es.addEventListener("stats", (e: MessageEvent) => {
        try {
          const payload = JSON.parse(e.data);
          setSummary({
            totalQRCodes: payload?.totalQRCodes ?? 0,
            activeLicensees: payload?.activeLicensees ?? 0,
            manufacturers: payload?.manufacturers ?? 0,
            totalBatches: payload?.totalBatches ?? 0,
          });
          setQrStats(payload?.qr || {});
          setLastUpdated(new Date());
        } catch {
          // ignore parse errors
        }
      });

      es.addEventListener("audit", (e: MessageEvent) => {
        try {
          const log = JSON.parse(e.data);
          setLogs((prev) => [log, ...(prev || [])].slice(0, 10));
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
  }, [user?.licenseeId, user?.role, liveUpdates]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      load({ silent: true });
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // totals (support multiple backend shapes)
  const totalQRCodes = summary?.totalQRCodes ?? 0;
  const activeLicenseesCount = summary?.activeLicensees ?? 0;
  const manufacturersCount = summary?.manufacturers ?? 0;
  const batchesCount = summary?.totalBatches ?? 0;

  // chart: support both { dormant: n } OR { byStatus: { DORMANT: n } }
  const qrStatusData = useMemo(() => {
    const by = qrStats?.byStatus || qrStats?.statusCounts || {};
    return {
      dormant: qrStats?.dormant ?? by.DORMANT ?? 0,
      allocated: (qrStats?.allocated ?? by.ALLOCATED ?? 0) + (by.ACTIVE ?? 0) + (by.ACTIVATED ?? 0),
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
        href: "/qr-tracking",
        pct: total > 0 ? Math.round((qrStatusData.scanned / total) * 100) : 0,
      },
    ];
  }, [qrStatusData]);

  const focusedRow = statusFocus === "all" ? null : statusRows.find((row) => row.key === statusFocus) || null;
  const totalTracked = statusRows.reduce((acc, row) => acc + row.value, 0);
  const fulfilled = qrStatusData.printed + qrStatusData.scanned;
  const fulfillmentPct = totalTracked > 0 ? Math.round((fulfilled / totalTracked) * 100) : 0;
  const redemptionPct = fulfilled > 0 ? Math.round((qrStatusData.scanned / fulfilled) * 100) : 0;

  const roleLabel = useMemo(() => {
    if (user?.role === "super_admin") return "Super Admin";
    if (user?.role === "licensee_admin") return "Licensee Admin";
    if (user?.role === "manufacturer") return "Manufacturer";
    return "User";
  }, [user?.role]);

  const quickActions = useMemo(() => {
    if (user?.role === "super_admin") {
      return [
        { label: "Licensees", description: "Onboard and manage tenants", href: "/licensees" },
        { label: "QR Requests", description: "Review pending allocations", href: "/qr-requests" },
        { label: "Tracking", description: "Inspect scans and risk", href: "/qr-tracking" },
        { label: "Audit Logs", description: "Review recent operations", href: "/audit-logs" },
      ];
    }
    if (user?.role === "licensee_admin") {
      return [
        { label: "Batches", description: "Assign and monitor production", href: "/batches" },
        { label: "Manufacturers", description: "Manage factory users", href: "/manufacturers" },
        { label: "QR Requests", description: "Raise range requests", href: "/qr-requests" },
        { label: "Tracking", description: "Monitor scans and alerts", href: "/qr-tracking" },
      ];
    }
    return [
      { label: "My Batches", description: "Create and print jobs", href: "/batches" },
      { label: "QR Tracking", description: "Track scans for your assigned batches", href: "/qr-tracking" },
      { label: "Verify Page", description: "Open customer verification", href: "/verify" },
      { label: "Account", description: "Manage account settings", href: "/account" },
    ];
  }, [user?.role]);

  const cards = useMemo(() => {
    const totalQrHref =
      user?.role === "super_admin" ? "/qr-codes" : "/qr-tracking";
    const totalQrCta =
      user?.role === "super_admin" ? "Inspect master inventory" : "Inspect tenant inventory";
    const scopeHref = user?.role === "super_admin" ? "/licensees" : "/dashboard";
    const scopeCta = user?.role === "super_admin" ? "Manage licensees" : "View scope";
    const manufacturersHref = user?.role === "manufacturer" ? "/qr-tracking" : "/manufacturers";
    const manufacturersCta =
      user?.role === "manufacturer" ? "View manufacturer telemetry" : "Manage manufacturers";

    const items = [
      {
        title: "Total QR Codes",
        value: totalQRCodes,
        icon: QrCode,
        variant: "default" as const,
        subtitle: `Dormant ${qrStatusData.dormant.toLocaleString()} • Redeemed ${qrStatusData.scanned.toLocaleString()}`,
        href: totalQrHref,
        ctaLabel: totalQrCta,
      },
      {
        title: user?.role === "manufacturer" ? "My Licensee Scope" : "Active Licensees",
        value: user?.role === "manufacturer" ? (user?.licenseeId ? 1 : 0) : activeLicenseesCount,
        icon: Building2,
        variant: "info" as const,
        subtitle:
          user?.role === "manufacturer" ? "Current assigned tenant" : "Currently enabled tenants",
        href: scopeHref,
        ctaLabel: scopeCta,
      },
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
        title: "QR Batches",
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
    user?.role,
  ]);

  const canViewAudit = user?.role === "super_admin" || user?.role === "licensee_admin";

  if (loading) return <div className="p-6">Loading…</div>;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <h1 className="text-3xl font-bold">Dashboard</h1>
            <p className="text-muted-foreground">
              Welcome back, {user?.name}. {roleLabel} overview with live operational signals.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
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
            <Button variant="outline" size="sm" onClick={() => load()} className="gap-2">
              <RefreshCw className="h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

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
              onClick={() => navigate(item.href)}
              ctaLabel={item.ctaLabel}
            />
          ))}
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          <Card className="animate-fade-in">
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
                    {focusedRow.value.toLocaleString()} QR codes currently {focusedRow.description.toLowerCase()}.
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
            logs={logs}
            emptyMessage={
              canViewAudit
                ? "No recent activity yet. Actions in batches, users, and requests will appear here."
                : "Activity feed is available for admin roles. Use Batches for your print operations."
            }
            onViewAll={canViewAudit ? () => navigate("/audit-logs") : undefined}
          />
        </div>
      </div>
    </DashboardLayout>
  );
}

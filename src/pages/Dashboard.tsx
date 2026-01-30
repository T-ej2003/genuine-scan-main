import React, { useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { StatsCard } from "@/components/dashboard/StatsCard";
import { QRStatusChart } from "@/components/dashboard/QRStatusChart";
import { RecentActivityCard } from "@/components/dashboard/RecentActivityCard";
import { QrCode, Building2, Factory, FileText } from "lucide-react";
import apiClient from "@/lib/api-client";

const STATS_POLL_MS = 5000;

export default function Dashboard() {
  const { user } = useAuth();

  const [stats, setStats] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<number | null>(null);

  const load = async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    try {
      // Stats: use your existing endpoint (qr/stats). This is what drives the chart.
      const statsRes = await apiClient.getQRStats(user?.licenseeId);

      if (!statsRes.success) throw new Error(statsRes.error || "Failed to load stats");
      setStats(statsRes.data || {});

      // Logs: only super_admin (route is protected in your backend)
      if (user?.role === "super_admin") {
        const logsRes = await apiClient.getAuditLogs({ limit: 5 });
        if (logsRes.success) setLogs(Array.isArray(logsRes.data) ? logsRes.data : []);
        else setLogs([]);
      } else {
        setLogs([]);
      }
    } catch (e: any) {
      setError(e?.message || "Failed to load dashboard");
      setStats(null);
      setLogs([]);
    } finally {
      if (!opts?.silent) setLoading(false);
    }
  };

  useEffect(() => {
    // initial load
    load();

    // start polling stats
    if (pollRef.current) window.clearInterval(pollRef.current);

    pollRef.current = window.setInterval(() => {
      // avoid polling when tab is hidden
      if (document.visibilityState !== "visible") return;

      // "silent" refresh = don't show loading screen, just update numbers/chart
      load({ silent: true });
    }, STATS_POLL_MS);

    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.licenseeId, user?.role]);

  // totals (support multiple backend shapes)
  const totalQRCodes = stats?.totalQRCodes ?? stats?.total ?? 0;
  const activeLicenseesCount = stats?.activeLicensees ?? stats?.licenseesActive ?? 0;
  const manufacturersCount = stats?.manufacturers ?? stats?.manufacturersCount ?? 0;
  const batchesCount = stats?.batches ?? stats?.batchesCount ?? 0;

  // chart: support both { dormant: n } OR { byStatus: { DORMANT: n } }
  const qrStatusData = useMemo(() => {
    const by = stats?.byStatus || stats?.statusCounts || {};
    return {
      dormant: stats?.dormant ?? by.DORMANT ?? 0,
      allocated: stats?.allocated ?? by.ALLOCATED ?? 0,
      printed: stats?.printed ?? by.PRINTED ?? 0,
      scanned: stats?.scanned ?? by.SCANNED ?? 0,
    };
  }, [stats]);

  if (loading) return <div className="p-6">Loading…</div>;
  if (error) return <div className="p-6 text-red-500">{error}</div>;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">Welcome back, {user?.name}</p>
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatsCard
            title="Total QR Codes"
            value={totalQRCodes}
            icon={QrCode}
            trend={{ value: 12, label: "vs last month" }}
          />
          <StatsCard title="Active Licensees" value={activeLicenseesCount} icon={Building2} variant="info" />
          <StatsCard title="Manufacturers" value={manufacturersCount} icon={Factory} variant="warning" />
          <StatsCard title="Total Batches" value={batchesCount} icon={FileText} variant="success" />
        </div>

        <div className="grid gap-6 md:grid-cols-2 mt-6">
          <QRStatusChart data={qrStatusData} />
          <RecentActivityCard logs={logs} />
        </div>
      </div>
    </DashboardLayout>
  );
}


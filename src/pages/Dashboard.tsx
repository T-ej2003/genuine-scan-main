import React, { useEffect, useMemo, useRef, useState } from "react";
import { useAuth } from "@/contexts/AuthContext";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { StatsCard } from "@/components/dashboard/StatsCard";
import { QRStatusChart } from "@/components/dashboard/QRStatusChart";
import { RecentActivityCard } from "@/components/dashboard/RecentActivityCard";
import { QrCode, Building2, Factory, FileText } from "lucide-react";
import apiClient from "@/lib/api-client";
import { onMutationEvent } from "@/lib/mutation-events";

const STATS_POLL_MS = 5000;
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:4000/api";

export default function Dashboard() {
  const { user } = useAuth();

  const [summary, setSummary] = useState<any>(null);
  const [qrStats, setQrStats] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
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
    // initial load
    load();

    // start polling stats (fallback)
    if (pollRef.current) window.clearInterval(pollRef.current);
    pollRef.current = window.setInterval(() => {
      if (document.visibilityState !== "visible") return;
      if (sseRef.current) return;
      load({ silent: true });
    }, STATS_POLL_MS);

    // setup SSE for realtime
    if (sseRef.current) {
      sseRef.current.close();
      sseRef.current = null;
    }
    const token = apiClient.getToken();
    if (token) {
      const es = new EventSource(`${API_BASE}/events/dashboard?token=${encodeURIComponent(token)}`);
      sseRef.current = es;

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
      };
    }

    return () => {
      if (pollRef.current) window.clearInterval(pollRef.current);
      pollRef.current = null;
      if (sseRef.current) {
        sseRef.current.close();
        sseRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.licenseeId, user?.role]);

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
          />
          <StatsCard title="Active Licensees" value={activeLicenseesCount} icon={Building2} variant="info" />
          <StatsCard title="Manufacturers" value={manufacturersCount} icon={Factory} variant="warning" />
          <StatsCard title="QR Batches" value={batchesCount} icon={FileText} variant="success" />
        </div>

        <div className="grid gap-6 md:grid-cols-2 mt-6">
          <QRStatusChart data={qrStatusData} />
          <RecentActivityCard logs={logs} />
        </div>
      </div>
    </DashboardLayout>
  );
}

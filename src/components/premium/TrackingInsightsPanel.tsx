import React, { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AlertTriangle, CheckCircle2, PackageCheck, QrCode } from "lucide-react";
import { cn } from "@/lib/utils";
import { PREMIUM_PALETTE } from "@/components/premium/palette";
import { PremiumChartSkeleton } from "@/components/premium/PremiumLoadingBlocks";

export type TrackingTotals = {
  total: number;
  scanEvents?: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  created: number;
};

export type TrackingTrendPoint = {
  label: string;
  total: number;
  scanEvents?: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
};

type TrackingInsightsPanelProps = {
  totals: TrackingTotals;
  trend: TrackingTrendPoint[];
  loading?: boolean;
  className?: string;
};

const legendEntries = [
  { key: "dormant", label: "Ready for production", color: "#475569" },
  { key: "allocated", label: "Assigned", color: "#d97706" },
  { key: "printed", label: "Printed", color: "#0891b2" },
  { key: "redeemed", label: "Scanned", color: "#059669" },
  { key: "blocked", label: "Needs attention", color: "#dc2626" },
] as const;

export function TrackingInsightsPanel({ totals, trend, loading, className }: TrackingInsightsPanelProps) {
  const distributionData = useMemo(
    () =>
      [
        { name: "Ready for production", value: totals.dormant, color: "#475569" },
        { name: "Assigned", value: totals.allocated, color: "#d97706" },
        { name: "Printed", value: totals.printed, color: "#0891b2" },
        { name: "Scanned", value: totals.redeemed, color: "#059669" },
        { name: "Needs attention", value: totals.blocked, color: "#dc2626" },
      ].filter((entry) => entry.value > 0),
    [totals]
  );

  const statusBars = useMemo(
    () => [
      { label: "Ready", value: totals.dormant },
      { label: "Assigned", value: totals.allocated },
      { label: "Printed", value: totals.printed },
      { label: "Scanned", value: totals.redeemed },
      { label: "Attention", value: totals.blocked },
    ],
    [totals]
  );
  const hasGraphData = distributionData.length > 0;
  const hasTrendData = trend.length > 0;
  const readyForProduction = totals.dormant + totals.allocated;
  const needsAttention = totals.blocked;
  const scannedLabels = totals.redeemed || totals.scanEvents || 0;
  const kpis = [
    { label: "Total labels", value: totals.total, detail: "Labels in this view", icon: QrCode, tone: "text-slate-900" },
    { label: "Scanned labels", value: scannedLabels, detail: "Customer scan activity", icon: CheckCircle2, tone: "text-emerald-700" },
    { label: "Ready for production", value: readyForProduction, detail: "Ready or assigned", icon: PackageCheck, tone: "text-sky-700" },
    { label: "Needs attention", value: needsAttention, detail: "Blocked or review needed", icon: AlertTriangle, tone: "text-red-700" },
  ];

  if (loading) return <PremiumChartSkeleton />;

  return (
    <section className={cn("rounded-2xl border bg-white/95 p-5 shadow-[0_14px_30px_rgba(102,114,146,0.13)]", className)} style={{ borderColor: `${PREMIUM_PALETTE.steel}66` }}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-[#4f5b75]">Label activity overview</p>
          <h2 className="mt-1 text-xl font-semibold text-slate-950">Production labels and customer scans</h2>
          <p className="mt-1 text-sm text-slate-600">Metrics reflect the current filters and show which statuses need attention.</p>
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {kpis.map((entry) => (
          <article key={entry.label} className="min-h-28 rounded-xl border border-[#8d9db63d] bg-gradient-to-br from-white to-[#f6f9fb] p-4 premium-pop-in">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-[11px] uppercase tracking-[0.1em] text-slate-500">{entry.label}</p>
                <p className={cn("mt-2 text-2xl font-semibold", entry.tone)}>{Math.max(0, Number(entry.value || 0)).toLocaleString()}</p>
              </div>
              <entry.icon className={cn("h-5 w-5", entry.tone)} />
            </div>
            <p className="mt-2 text-xs text-slate-500">{entry.detail}</p>
          </article>
        ))}
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {legendEntries.map((entry) => (
          <div key={entry.key} className="inline-flex items-center gap-2 rounded-full border bg-white px-3 py-1 text-xs text-slate-700">
            <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
            {entry.label}
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[1fr_0.85fr]">
      <div className="rounded-2xl border border-[#8d9db63f] bg-white p-4">
        <div className="mb-3">
          <p className="text-sm font-semibold text-slate-950">Label status distribution</p>
          <p className="text-xs text-slate-500">Shows how labels are moving from inventory to production and customer scans.</p>
        </div>
        {!hasGraphData ? (
          <div className="flex h-60 items-center justify-center rounded-xl border border-dashed border-[#8d9db66f] bg-[#bccad61c] px-6 text-center text-sm text-slate-600">
            No scans yet. Once customers begin scanning products, activity will appear here.
          </div>
        ) : (
          <div className="grid gap-4 lg:grid-cols-[0.75fr_1fr]">
            <div className="h-56 w-full premium-surface-in">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={distributionData} dataKey="value" nameKey="name" innerRadius={58} outerRadius={92} paddingAngle={2}>
                    {distributionData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="h-56 w-full premium-surface-in">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={statusBars} layout="vertical" margin={{ left: 8, right: 8, top: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#667292", fontSize: 11 }} />
                  <YAxis type="category" dataKey="label" width={72} tick={{ fill: "#475569", fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="value" name="Labels" fill="#0891b2" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </div>

      <div className="rounded-2xl border border-[#8d9db63f] bg-white p-4">
        <p className="text-sm font-semibold text-slate-950">Scan activity over time</p>
        <p className="mt-1 text-xs text-slate-500">Displayed when time-series scan data is available for the current filters.</p>
        {hasTrendData ? (
          <div className="mt-4 h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trend} margin={{ left: 4, right: 8, top: 8, bottom: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="label" tick={{ fill: "#667292", fontSize: 11 }} />
                <YAxis tick={{ fill: "#667292", fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="scanEvents" name="Scan events" fill="#1d4ed8" radius={[6, 6, 0, 0]} />
                <Bar dataKey="blocked" name="Needs attention" fill="#dc2626" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="mt-4 flex h-56 items-center justify-center rounded-xl border border-dashed border-[#8d9db66f] bg-[#bccad61c] px-6 text-center text-sm text-slate-600">
            No scan timeline is available yet for this view.
          </div>
        )}
      </div>
      </div>
    </section>
  );
}

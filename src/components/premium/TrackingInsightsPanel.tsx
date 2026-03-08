import React, { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { BarChart3, ChartSpline, Donut, Layers3 } from "lucide-react";
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

type ChartMode = "bar" | "line" | "area" | "donut";

type TrackingInsightsPanelProps = {
  totals: TrackingTotals;
  trend: TrackingTrendPoint[];
  loading?: boolean;
  className?: string;
};

const metricConfig: Array<{ key: keyof TrackingTotals; label: string; color: string }> = [
  { key: "total", label: "Distinct codes", color: "#0f172a" },
  { key: "scanEvents", label: "Scan events", color: "#1d4ed8" },
  { key: "dormant", label: "Dormant", color: "#475569" },
  { key: "allocated", label: "Allocated", color: "#d97706" },
  { key: "printed", label: "Printed", color: "#0891b2" },
  { key: "redeemed", label: "Redeemed", color: "#059669" },
  { key: "blocked", label: "Blocked", color: "#dc2626" },
  { key: "created", label: "Batches", color: "#7c3aed" },
];

const legendEntries = [
  { key: "total", label: "Distinct codes", color: "#0f172a" },
  { key: "scanEvents", label: "Scan events", color: "#1d4ed8" },
  { key: "dormant", label: "Dormant", color: "#475569" },
  { key: "allocated", label: "Allocated", color: "#d97706" },
  { key: "printed", label: "Printed", color: "#0891b2" },
  { key: "redeemed", label: "Redeemed", color: "#059669" },
  { key: "blocked", label: "Blocked", color: "#dc2626" },
] as const;

const chartModes: Array<{ key: ChartMode; label: string; icon: React.ReactNode }> = [
  { key: "bar", label: "Bar", icon: <BarChart3 className="h-3.5 w-3.5" /> },
  { key: "line", label: "Line", icon: <ChartSpline className="h-3.5 w-3.5" /> },
  { key: "area", label: "Area", icon: <Layers3 className="h-3.5 w-3.5" /> },
  { key: "donut", label: "Donut", icon: <Donut className="h-3.5 w-3.5" /> },
];

export function TrackingInsightsPanel({ totals, trend, loading, className }: TrackingInsightsPanelProps) {
  const [mode, setMode] = useState<ChartMode>("bar");

  const distributionData = useMemo(
    () =>
      [
        { name: "Dormant", value: totals.dormant, color: "#475569" },
        { name: "Allocated", value: totals.allocated, color: "#d97706" },
        { name: "Printed", value: totals.printed, color: "#0891b2" },
        { name: "Redeemed", value: totals.redeemed, color: "#059669" },
        { name: "Blocked", value: totals.blocked, color: "#dc2626" },
      ].filter((entry) => entry.value > 0),
    [totals]
  );

  const hasGraphData = trend.length > 0 || distributionData.length > 0;

  if (loading) return <PremiumChartSkeleton />;

  return (
    <section className={cn("rounded-2xl border bg-white/90 p-4 shadow-[0_14px_30px_rgba(102,114,146,0.13)]", className)} style={{ borderColor: `${PREMIUM_PALETTE.steel}66` }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-[#4f5b75]">Tracking Analytics</p>
          <p className="text-xs text-slate-500">Metrics reflect the current data scope and applied filters.</p>
        </div>
        <div className="inline-flex rounded-xl border border-[#8d9db65e] bg-[#bccad622] p-1">
          {chartModes.map((entry) => (
            <button
              key={entry.key}
              type="button"
              onClick={() => setMode(entry.key)}
              className={cn(
                "inline-flex items-center gap-1 rounded-lg px-2.5 py-1.5 text-xs font-medium transition-colors",
                mode === entry.key ? "bg-white text-[#4f5b75] shadow-sm" : "text-slate-600 hover:bg-white/70"
              )}
            >
              {entry.icon}
              {entry.label}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-4 grid gap-2 sm:grid-cols-3 lg:grid-cols-7">
        {metricConfig.map((entry) => (
          <article key={entry.key} className="rounded-xl border border-[#8d9db63d] bg-gradient-to-br from-white to-[#f6f9fb] px-3 py-2.5 premium-pop-in">
            <p className="text-[11px] uppercase tracking-[0.1em] text-slate-500">{entry.label}</p>
            <p className="mt-1 text-lg font-semibold" style={{ color: entry.color }}>
              {Math.max(0, Number(totals[entry.key] || 0)).toLocaleString()}
            </p>
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

      <div className="mt-4 rounded-2xl border border-[#8d9db63f] bg-gradient-to-br from-white via-white to-[#f1e3dd54] p-2 sm:p-4">
        {!hasGraphData ? (
          <div className="flex h-60 items-center justify-center rounded-xl border border-dashed border-[#8d9db66f] bg-[#bccad61c] text-sm text-slate-600">
            No chart data available for this filter scope.
          </div>
        ) : (
          <div className="h-64 w-full premium-surface-in">
            {mode === "bar" ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trend} margin={{ left: 4, right: 8, top: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#bccad6" />
                  <XAxis dataKey="label" tick={{ fill: "#667292", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#667292", fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="total" name="Distinct codes" fill="#0f172a" radius={[6, 6, 0, 0]} />
                  <Bar dataKey="scanEvents" name="Scan events" fill="#1d4ed8" radius={[6, 6, 0, 0]} />
                  <Bar dataKey="redeemed" name="Redeemed" fill="#059669" radius={[6, 6, 0, 0]} />
                  <Bar dataKey="blocked" name="Blocked" fill="#dc2626" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : null}

            {mode === "line" ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trend} margin={{ left: 4, right: 8, top: 8, bottom: 8 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#bccad6" />
                  <XAxis dataKey="label" tick={{ fill: "#667292", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#667292", fontSize: 11 }} />
                  <Tooltip />
                  <Line type="monotone" dataKey="total" stroke="#0f172a" strokeWidth={2.5} dot={false} />
                  <Line type="monotone" dataKey="scanEvents" stroke="#1d4ed8" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="redeemed" stroke="#059669" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="blocked" stroke="#dc2626" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : null}

            {mode === "area" ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend} margin={{ left: 4, right: 8, top: 8, bottom: 8 }}>
                  <defs>
                    <linearGradient id="trackingAreaTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#0f172a" stopOpacity={0.45} />
                      <stop offset="95%" stopColor="#0f172a" stopOpacity={0.05} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#bccad6" />
                  <XAxis dataKey="label" tick={{ fill: "#667292", fontSize: 11 }} />
                  <YAxis tick={{ fill: "#667292", fontSize: 11 }} />
                  <Tooltip />
                  <Area type="monotone" dataKey="total" stroke="#0f172a" fill="url(#trackingAreaTotal)" strokeWidth={2.5} />
                  <Area type="monotone" dataKey="scanEvents" stroke="#1d4ed8" fill="#1d4ed820" strokeWidth={1.6} />
                  <Area type="monotone" dataKey="blocked" stroke="#dc2626" fill="#dc262620" strokeWidth={1.6} />
                </AreaChart>
              </ResponsiveContainer>
            ) : null}

            {mode === "donut" ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={distributionData} dataKey="value" nameKey="name" innerRadius={54} outerRadius={90} paddingAngle={2}>
                    {distributionData.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : null}
          </div>
        )}
      </div>
    </section>
  );
}

import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import { AlertTriangle, Ban, CheckCircle2, RefreshCw, ScanEye, Search, ShieldAlert } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useAuth } from "@/contexts/AuthContext";
import { onMutationEvent } from "@/lib/mutation-events";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PremiumSectionAccordion } from "@/components/premium/PremiumSectionAccordion";
import { TrackingInsightsPanel, type TrackingTotals, type TrackingTrendPoint } from "@/components/premium/TrackingInsightsPanel";
import { PremiumTableSkeleton } from "@/components/premium/PremiumLoadingBlocks";
import { PREMIUM_PALETTE } from "@/components/premium/palette";

type BatchSummaryRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  createdAt: string;
  counts?: Record<string, number>;
};

type ScanLogRow = {
  id: string;
  code: string;
  status?: string | null;
  scanCount?: number | null;
  scannedAt: string;
  batchId?: string | null;
  device?: string | null;
  userAgent?: string | null;
  ipAddress?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
  locationName?: string | null;
  deviceLabel?: string | null;
  isFirstScan?: boolean | null;
  licensee?: { id: string; name: string; prefix: string };
  qrCode?: { id: string; code: string; status: string };
};

type TrackingFilterState = {
  code: string;
  batchId: string;
  batchName: string;
  status: string;
  firstScan: string;
  fromDate: string;
  toDate: string;
  licenseeId: string;
};

const toCount = (counts: Record<string, number> | undefined, key: string) => counts?.[key] ?? 0;

const STATUS_TONE: Record<string, string> = {
  DORMANT: "border-slate-300 bg-slate-100 text-slate-700",
  ACTIVE: "border-slate-300 bg-slate-100 text-slate-700",
  ALLOCATED: "border-amber-200 bg-amber-50 text-amber-700",
  ACTIVATED: "border-amber-200 bg-amber-50 text-amber-700",
  PRINTED: "border-cyan-200 bg-cyan-50 text-cyan-700",
  REDEEMED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  SCANNED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  BLOCKED: "border-red-200 bg-red-50 text-red-700",
};

const statusTone = (status?: string | null) => STATUS_TONE[String(status || "").toUpperCase()] || "border-slate-300 bg-slate-100 text-slate-700";

const asIsoStart = (dateValue?: string) => (dateValue ? new Date(`${dateValue}T00:00:00`).toISOString() : undefined);
const asIsoEnd = (dateValue?: string) => (dateValue ? new Date(`${dateValue}T23:59:59.999`).toISOString() : undefined);

export default function QRTracking() {
  const { user } = useAuth();

  const [summary, setSummary] = useState<BatchSummaryRow[]>([]);
  const [logs, setLogs] = useState<ScanLogRow[]>([]);
  const [licensees, setLicensees] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [filters, setFilters] = useState<TrackingFilterState>({
    code: "",
    batchId: "",
    batchName: "",
    status: "all",
    firstScan: "all",
    fromDate: "",
    toDate: "",
    licenseeId: "all",
  });

  const isSuperAdmin = user?.role === "super_admin";
  const scopedLicenseeId = isSuperAdmin && filters.licenseeId !== "all" ? filters.licenseeId : undefined;

  const load = async (opts?: { silent?: boolean; override?: Partial<TrackingFilterState> }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    const current = { ...filters, ...(opts?.override || {}) };

    try {
      const [summaryRes, logsRes] = await Promise.all([
        apiClient.getBatchSummary({ licenseeId: isSuperAdmin && current.licenseeId !== "all" ? current.licenseeId : undefined }),
        apiClient.getScanLogs({
          licenseeId: isSuperAdmin && current.licenseeId !== "all" ? current.licenseeId : undefined,
          code: current.code.trim() || undefined,
          batchId: current.batchId.trim() || undefined,
          status: current.status !== "all" ? (current.status as any) : undefined,
          onlyFirstScan:
            current.firstScan === "yes"
              ? true
              : current.firstScan === "no"
              ? false
              : undefined,
          from: asIsoStart(current.fromDate),
          to: asIsoEnd(current.toDate),
          limit: 200,
        }),
      ]);

      if (!summaryRes.success) throw new Error(summaryRes.error || "Failed to load batch summary");
      if (!logsRes.success) throw new Error(logsRes.error || "Failed to load scan logs");

      setSummary((summaryRes.data as any[]) || []);
      const payload: any = logsRes.data;
      const list = Array.isArray(payload)
        ? payload
        : Array.isArray(payload?.logs)
        ? payload.logs
        : [];
      setLogs(list);
    } catch (e: any) {
      setError(e?.message || "Failed to load tracking data");
      setSummary([]);
      setLogs([]);
    } finally {
      if (!opts?.silent) setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!isSuperAdmin) return;
    apiClient.getLicensees().then((res) => {
      if (!res.success) return;
      setLicensees((res.data as any[]) || []);
    });
  }, [isSuperAdmin]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      load({ silent: true });
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters, isSuperAdmin]);

  const batchNameById = useMemo(() => {
    const map = new Map<string, string>();
    summary.forEach((b) => map.set(b.id, b.name || b.id));
    return map;
  }, [summary]);

  const filteredSummary = useMemo(() => {
    const q = filters.batchName.trim().toLowerCase();
    if (!q) return summary;
    return summary.filter((b) => {
      return (
        String(b.name || "").toLowerCase().includes(q) ||
        String(b.id || "").toLowerCase().includes(q) ||
        String(b.startCode || "").toLowerCase().includes(q) ||
        String(b.endCode || "").toLowerCase().includes(q)
      );
    });
  }, [summary, filters.batchName]);

  const friendlyError = useMemo(() => {
    const msg = String(error || "").toLowerCase();
    if (!msg) return "";
    if (msg.includes("internal server error") || msg.includes("http 500")) {
      return "Tracking data is temporarily unavailable. Please refresh in a moment.";
    }
    if (msg.includes("network") || msg.includes("timeout") || msg.includes("offline")) {
      return "Network connection issue while loading tracking data. Check connectivity and retry.";
    }
    return "We could not load tracking data. Please retry.";
  }, [error]);

  const formatLocation = (log: ScanLogRow) => log.locationName || "Location unavailable";

  const blockedLogCount = logs.filter((l) => String(l.qrCode?.status || l.status || "").toUpperCase() === "BLOCKED").length;
  const firstScanCount = logs.filter((l) => Boolean(l.isFirstScan)).length;
  const summaryInScope = useMemo(() => {
    const batchQuery = filters.batchId.trim().toLowerCase();
    if (!batchQuery) return filteredSummary;
    return filteredSummary.filter((b) => {
      const id = String(b.id || "").toLowerCase();
      const name = String(b.name || "").toLowerCase();
      return id.includes(batchQuery) || name.includes(batchQuery);
    });
  }, [filteredSummary, filters.batchId]);
  const hasScanScopedFilters = useMemo(
    () =>
      Boolean(filters.code.trim()) ||
      filters.status !== "all" ||
      filters.firstScan !== "all" ||
      Boolean(filters.fromDate) ||
      Boolean(filters.toDate),
    [filters.code, filters.status, filters.firstScan, filters.fromDate, filters.toDate]
  );

  const analyticsTotals = useMemo<TrackingTotals>(() => {
    const totals: TrackingTotals = {
      total: 0,
      dormant: 0,
      allocated: 0,
      printed: 0,
      redeemed: 0,
      blocked: 0,
      created: summaryInScope.length,
    };

    if (hasScanScopedFilters && logs.length) {
      const uniqueCodes = new Set<string>();
      logs.forEach((entry) => {
        uniqueCodes.add(String(entry.code || entry.id || ""));
        const status = String(entry.qrCode?.status || entry.status || "").toUpperCase();
        if (status === "BLOCKED") totals.blocked += 1;
        else if (status === "PRINTED") totals.printed += 1;
        else if (status === "REDEEMED" || status === "SCANNED") totals.redeemed += 1;
        else if (status === "ALLOCATED" || status === "ACTIVE" || status === "ACTIVATED") totals.allocated += 1;
        else totals.dormant += 1;
      });
      totals.total = uniqueCodes.size || logs.length;
      return totals;
    }

    summaryInScope.forEach((row) => {
      const counts = row.counts || {};
      totals.total += Number(row.totalCodes || 0);
      totals.dormant += toCount(counts, "DORMANT");
      totals.allocated += toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVE") + toCount(counts, "ACTIVATED");
      totals.printed += toCount(counts, "PRINTED");
      totals.redeemed += toCount(counts, "REDEEMED") + toCount(counts, "SCANNED");
      totals.blocked += toCount(counts, "BLOCKED");
    });

    return totals;
  }, [summaryInScope, hasScanScopedFilters, logs]);

  const analyticsTrend = useMemo<TrackingTrendPoint[]>(() => {
    const byDay = new Map<string, TrackingTrendPoint>();
    const formatDay = (value: string) => format(new Date(value), "MMM d");
    const seedPoint = (label: string): TrackingTrendPoint => ({
      label,
      total: 0,
      dormant: 0,
      allocated: 0,
      printed: 0,
      redeemed: 0,
      blocked: 0,
    });

    if (logs.length) {
      logs.forEach((entry) => {
        const day = entry.scannedAt ? formatDay(entry.scannedAt) : "Unknown";
        const current = byDay.get(day) || seedPoint(day);
        const status = String(entry.qrCode?.status || entry.status || "").toUpperCase();
        current.total += 1;
        if (status === "BLOCKED") current.blocked += 1;
        else if (status === "PRINTED") current.printed += 1;
        else if (status === "REDEEMED" || status === "SCANNED") current.redeemed += 1;
        else if (status === "ALLOCATED" || status === "ACTIVE" || status === "ACTIVATED") current.allocated += 1;
        else current.dormant += 1;
        byDay.set(day, current);
      });
      return Array.from(byDay.values()).slice(-10);
    }

    summaryInScope.forEach((row) => {
      const day = row.createdAt ? formatDay(row.createdAt) : "Unknown";
      const current = byDay.get(day) || seedPoint(day);
      const counts = row.counts || {};
      current.total += Number(row.totalCodes || 0);
      current.dormant += toCount(counts, "DORMANT");
      current.allocated += toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVE") + toCount(counts, "ACTIVATED");
      current.printed += toCount(counts, "PRINTED");
      current.redeemed += toCount(counts, "REDEEMED") + toCount(counts, "SCANNED");
      current.blocked += toCount(counts, "BLOCKED");
      byDay.set(day, current);
    });

    return Array.from(byDay.values()).slice(-10);
  }, [logs, summaryInScope]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div
          className="flex flex-col gap-3 rounded-2xl border p-4 shadow-[0_16px_32px_rgba(102,114,146,0.14)] sm:flex-row sm:items-center sm:justify-between premium-surface-in"
          style={{
            borderColor: `${PREMIUM_PALETTE.steel}66`,
            background:
              "linear-gradient(135deg, rgba(255,255,255,0.98) 0%, rgba(241,227,221,0.68) 52%, rgba(188,202,214,0.48) 100%)",
          }}
        >
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-[#8d9db668] bg-white/70">
              <ScanEye className="h-5 w-5 text-[#667292]" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-[#4f5b75]">QR Tracking</h1>
              <p className="text-sm text-slate-600">
                {user?.role === "manufacturer"
                  ? "Track scans and lifecycle states for your production scope."
                  : "Monitor scans, warnings, and blocked events in your authorized scope."}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="border-red-200 bg-red-50 text-red-700">{blockedLogCount} blocked events</Badge>
            <Badge className="border-emerald-200 bg-emerald-50 text-emerald-700">{firstScanCount} first scans</Badge>
            <Button variant="outline" onClick={() => load()} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
        </div>

        {error && (
          <div className="rounded-xl border border-red-300 bg-red-50 px-4 py-3 text-sm text-red-700">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4" />
              {friendlyError}
            </div>
            <details className="mt-2 text-xs text-red-700/80">
              <summary className="cursor-pointer">Technical details</summary>
              <p className="mt-1 break-all">{error}</p>
            </details>
          </div>
        )}

        <TrackingInsightsPanel totals={analyticsTotals} trend={analyticsTrend} loading={loading && !logs.length && !summary.length} />

        <PremiumSectionAccordion
          defaultOpen={["tracking-filters"]}
          items={[
            {
              value: "tracking-filters",
              title: "Tracking Filters",
              subtitle: "Scope scan logs and batch inventory without leaving this page",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">Live scope</Badge>,
              content: (
                <div className="space-y-3">
                  <div className="flex flex-wrap gap-2">
                    <Button onClick={() => load()} disabled={loading} className="bg-[#667292] text-white hover:bg-[#596380]">
                      Apply filters
                    </Button>
                    <Button
                      variant="outline"
                      disabled={loading}
                      onClick={() => {
                        const reset: TrackingFilterState = {
                          code: "",
                          batchId: "",
                          batchName: "",
                          status: "all",
                          firstScan: "all",
                          fromDate: "",
                          toDate: "",
                          licenseeId: "all",
                        };
                        setFilters(reset);
                        load({ override: reset });
                      }}
                    >
                      Clear
                    </Button>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                    {isSuperAdmin && (
                      <Select
                        value={filters.licenseeId}
                        onValueChange={(value) => setFilters((prev) => ({ ...prev, licenseeId: value }))}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Licensee scope" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="all">All licensees</SelectItem>
                          {licensees.map((l) => (
                            <SelectItem key={l.id} value={l.id}>
                              {l.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    )}

                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                      <Input
                        placeholder="Search QR code"
                        value={filters.code}
                        onChange={(e) => setFilters((prev) => ({ ...prev, code: e.target.value }))}
                        className="pl-9"
                      />
                    </div>

                    <Input
                      placeholder="Filter by batch ID"
                      value={filters.batchId}
                      onChange={(e) => setFilters((prev) => ({ ...prev, batchId: e.target.value }))}
                    />

                    <Input
                      placeholder="Filter summary by batch name"
                      value={filters.batchName}
                      onChange={(e) => setFilters((prev) => ({ ...prev, batchName: e.target.value }))}
                    />

                    <Select value={filters.status} onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All statuses</SelectItem>
                        <SelectItem value="DORMANT">Dormant</SelectItem>
                        <SelectItem value="ACTIVE">Active</SelectItem>
                        <SelectItem value="ALLOCATED">Allocated</SelectItem>
                        <SelectItem value="ACTIVATED">Activated</SelectItem>
                        <SelectItem value="PRINTED">Printed</SelectItem>
                        <SelectItem value="REDEEMED">Redeemed</SelectItem>
                        <SelectItem value="SCANNED">Scanned</SelectItem>
                        <SelectItem value="BLOCKED">Blocked</SelectItem>
                      </SelectContent>
                    </Select>

                    <Select value={filters.firstScan} onValueChange={(value) => setFilters((prev) => ({ ...prev, firstScan: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="First scan" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All scans</SelectItem>
                        <SelectItem value="yes">First scans only</SelectItem>
                        <SelectItem value="no">Repeat scans only</SelectItem>
                      </SelectContent>
                    </Select>

                    <div className="space-y-1">
                      <Label className="text-xs font-medium text-slate-600">From date</Label>
                      <Input
                        type="date"
                        value={filters.fromDate}
                        onChange={(e) => setFilters((prev) => ({ ...prev, fromDate: e.target.value }))}
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs font-medium text-slate-600">To date</Label>
                      <Input
                        type="date"
                        value={filters.toDate}
                        onChange={(e) => setFilters((prev) => ({ ...prev, toDate: e.target.value }))}
                      />
                    </div>
                  </div>
                </div>
              ),
            },
          ]}
        />

        <PremiumSectionAccordion
          defaultOpen={["batch-summary", "scan-logs"]}
          items={[
            {
              value: "batch-summary",
              title: "Batch Summary",
              subtitle: "Inventory state by batch and lifecycle status",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">{filteredSummary.length} batches</Badge>,
              content:
                loading && !filteredSummary.length ? (
                  <PremiumTableSkeleton rows={6} />
                ) : (
                  <div className="overflow-hidden rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-slate-50">
                          <TableHead>Batch</TableHead>
                          <TableHead>Range</TableHead>
                          <TableHead>Total</TableHead>
                          <TableHead>Dormant</TableHead>
                          <TableHead>Allocated</TableHead>
                          <TableHead>Printed</TableHead>
                          <TableHead>Redeemed</TableHead>
                          <TableHead>Blocked</TableHead>
                          <TableHead>Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {filteredSummary.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={9} className="text-slate-500">
                              No batches found for current filters.
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredSummary.map((b) => {
                            const counts = b.counts || {};
                            const allocated =
                              toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVE") + toCount(counts, "ACTIVATED");
                            const redeemed = toCount(counts, "REDEEMED") + toCount(counts, "SCANNED");
                            const blocked = toCount(counts, "BLOCKED");

                            return (
                              <TableRow key={b.id}>
                                <TableCell className="font-medium text-slate-900">{b.name}</TableCell>
                                <TableCell className="font-mono text-xs text-slate-600">
                                  <div>{b.startCode}</div>
                                  <div>{b.endCode}</div>
                                </TableCell>
                                <TableCell>{b.totalCodes}</TableCell>
                                <TableCell>
                                  <Badge className={statusTone("DORMANT")}>{toCount(counts, "DORMANT")}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("ALLOCATED")}>{allocated}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("PRINTED")}>{toCount(counts, "PRINTED")}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("REDEEMED")}>{redeemed}</Badge>
                                </TableCell>
                                <TableCell>
                                  <Badge className={statusTone("BLOCKED")}>{blocked}</Badge>
                                </TableCell>
                                <TableCell className="text-slate-500">
                                  {b.createdAt ? format(new Date(b.createdAt), "MMM d, yyyy") : "—"}
                                </TableCell>
                              </TableRow>
                            );
                          })
                        )}
                      </TableBody>
                    </Table>
                  </div>
                ),
            },
            {
              value: "scan-logs",
              title: "Scan Logs",
              subtitle: "Real-time observations and suspicious scan signals",
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">{logs.length} entries</Badge>,
              content:
                loading && !logs.length ? (
                  <PremiumTableSkeleton rows={8} />
                ) : (
                  <>
                    <div className="overflow-hidden rounded-lg border">
                      <Table>
                        <TableHeader>
                          <TableRow className="bg-slate-50">
                            <TableHead>Code</TableHead>
                            <TableHead>Batch</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Scan #</TableHead>
                            <TableHead>Location</TableHead>
                            <TableHead>Device</TableHead>
                            <TableHead>IP</TableHead>
                            <TableHead>Scanned At</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {logs.length === 0 ? (
                            <TableRow>
                              <TableCell colSpan={8} className="text-slate-500">
                                No scan logs found.
                              </TableCell>
                            </TableRow>
                          ) : (
                            logs.map((log) => {
                              const status = log.qrCode?.status || log.status || "—";
                              const tone = statusTone(status);
                              const isBlocked = String(status).toUpperCase() === "BLOCKED";
                              return (
                                <TableRow key={log.id} className={isBlocked ? "bg-red-50/40" : undefined}>
                                  <TableCell className="font-mono text-xs">
                                    <div className="font-semibold text-slate-900">{log.code}</div>
                                    {log.licensee?.name && <div className="text-slate-500">{log.licensee.name}</div>}
                                  </TableCell>
                                  <TableCell className="text-sm text-slate-700">
                                    {log.batchId ? batchNameById.get(log.batchId) || log.batchId : "—"}
                                  </TableCell>
                                  <TableCell>
                                    <Badge className={tone}>
                                      {isBlocked ? <Ban className="mr-1 h-3 w-3" /> : <CheckCircle2 className="mr-1 h-3 w-3" />}
                                      {status}
                                    </Badge>
                                  </TableCell>
                                  <TableCell>
                                    <div className="font-medium text-slate-900">{log.scanCount ?? 0}</div>
                                    {log.isFirstScan ? (
                                      <Badge className="mt-1 border-emerald-200 bg-emerald-50 text-emerald-700">First scan</Badge>
                                    ) : (
                                      <Badge className="mt-1 border-amber-200 bg-amber-50 text-amber-700">
                                        <AlertTriangle className="mr-1 h-3 w-3" />
                                        Repeat
                                      </Badge>
                                    )}
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-700">{formatLocation(log)}</TableCell>
                                  <TableCell className="max-w-[220px] text-xs text-slate-600">
                                    {log.deviceLabel || "Browser device"}
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-600">{log.ipAddress || "—"}</TableCell>
                                  <TableCell className="text-xs text-slate-600">
                                    {log.scannedAt ? format(new Date(log.scannedAt), "PPp") : "—"}
                                  </TableCell>
                                </TableRow>
                              );
                            })
                          )}
                        </TableBody>
                      </Table>
                    </div>

                    <div className="mt-3 text-sm text-slate-500">
                      Scope: {isSuperAdmin ? (scopedLicenseeId ? "Selected licensee" : "All licensees") : "Your assigned tenant only"}
                    </div>
                  </>
                ),
            },
          ]}
        />
      </div>
    </DashboardLayout>
  );
}

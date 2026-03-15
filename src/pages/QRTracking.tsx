import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import { AlertTriangle, Ban, CheckCircle2, Copy, RefreshCw, ScanEye, Search, ShieldAlert } from "lucide-react";

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
import { BatchAllocationMapDialog } from "@/components/batches/BatchAllocationMapDialog";

type BatchSummaryRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  batchInventoryTotal: number;
  scopeCodeCount: number;
  scanEventCount: number;
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
  customerUserId?: string | null;
  ownershipId?: string | null;
  ownershipMatchMethod?: string | null;
  isTrustedOwnerContext?: boolean | null;
  licensee?: { id: string; name: string; prefix: string };
  qrCode?: { id: string; code: string; status: string };
};

type TrackingEventSummary = {
  totalScanEvents: number;
  firstScanEvents: number;
  repeatScanEvents: number;
  blockedEvents: number;
  trustedOwnerEvents: number;
  externalEvents: number;
  namedLocationEvents: number;
  knownDeviceEvents: number;
};

type TrackingFilterState = {
  code: string;
  batchQuery: string;
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
  const [scopeMeta, setScopeMeta] = useState<{
    mode: "inventory" | "activity";
    title: string;
    description: string;
    quantities: { distinctCodes: number; scanEvents: number; matchedBatches: number };
  } | null>(null);
  const [analyticsTotals, setAnalyticsTotals] = useState<TrackingTotals>({
    total: 0,
    dormant: 0,
    allocated: 0,
    printed: 0,
    redeemed: 0,
    blocked: 0,
    created: 0,
    scanEvents: 0,
  });
  const [analyticsTrend, setAnalyticsTrend] = useState<TrackingTrendPoint[]>([]);
  const [eventSummary, setEventSummary] = useState<TrackingEventSummary>({
    totalScanEvents: 0,
    firstScanEvents: 0,
    repeatScanEvents: 0,
    blockedEvents: 0,
    trustedOwnerEvents: 0,
    externalEvents: 0,
    namedLocationEvents: 0,
    knownDeviceEvents: 0,
  });
  const [licensees, setLicensees] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [allocationMapOpen, setAllocationMapOpen] = useState(false);
  const [allocationMapLoading, setAllocationMapLoading] = useState(false);
  const [allocationMap, setAllocationMap] = useState<any | null>(null);

  const [filters, setFilters] = useState<TrackingFilterState>({
    code: "",
    batchQuery: "",
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
      const response = await apiClient.getQrTrackingAnalytics({
        licenseeId: isSuperAdmin && current.licenseeId !== "all" ? current.licenseeId : undefined,
        code: current.code.trim() || undefined,
        batchQuery: current.batchQuery.trim() || undefined,
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
      });

      if (!response.success || !response.data) {
        throw new Error(response.error || "Failed to load tracking analytics");
      }

      const payload: any = response.data;
      setSummary(Array.isArray(payload.batches) ? payload.batches : []);
      setLogs(Array.isArray(payload.logs) ? payload.logs : []);
      setAnalyticsTotals({
        total: Number(payload.totals?.total || 0),
        dormant: Number(payload.totals?.dormant || 0),
        allocated: Number(payload.totals?.allocated || 0),
        printed: Number(payload.totals?.printed || 0),
        redeemed: Number(payload.totals?.redeemed || 0),
        blocked: Number(payload.totals?.blocked || 0),
        created: Number(payload.totals?.created || 0),
        scanEvents: Number(payload.eventSummary?.totalScanEvents || payload.scope?.quantities?.scanEvents || 0),
      });
      setAnalyticsTrend(Array.isArray(payload.trend) ? payload.trend : []);
      setScopeMeta(payload.scope || null);
      setEventSummary({
        totalScanEvents: Number(payload.eventSummary?.totalScanEvents || 0),
        firstScanEvents: Number(payload.eventSummary?.firstScanEvents || 0),
        repeatScanEvents: Number(payload.eventSummary?.repeatScanEvents || 0),
        blockedEvents: Number(payload.eventSummary?.blockedEvents || 0),
        trustedOwnerEvents: Number(payload.eventSummary?.trustedOwnerEvents || 0),
        externalEvents: Number(payload.eventSummary?.externalEvents || 0),
        namedLocationEvents: Number(payload.eventSummary?.namedLocationEvents || 0),
        knownDeviceEvents: Number(payload.eventSummary?.knownDeviceEvents || 0),
      });
    } catch (e: any) {
      setError(e?.message || "Failed to load tracking data");
      setSummary([]);
      setLogs([]);
      setAnalyticsTrend([]);
      setScopeMeta(null);
      setEventSummary({
        totalScanEvents: 0,
        firstScanEvents: 0,
        repeatScanEvents: 0,
        blockedEvents: 0,
        trustedOwnerEvents: 0,
        externalEvents: 0,
        namedLocationEvents: 0,
        knownDeviceEvents: 0,
      });
      setAnalyticsTotals({
        total: 0,
        dormant: 0,
        allocated: 0,
        printed: 0,
        redeemed: 0,
        blocked: 0,
        created: 0,
        scanEvents: 0,
      });
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

  const formatLocation = (log: ScanLogRow) => {
    if (log.locationName) return log.locationName;
    if (typeof log.latitude === "number" && typeof log.longitude === "number") {
      const accuracyText = typeof log.accuracy === "number" && Number.isFinite(log.accuracy) ? ` (~${Math.round(log.accuracy)}m)` : "";
      return `GPS ${log.latitude.toFixed(3)}, ${log.longitude.toFixed(3)}${accuracyText}`;
    }
    return "Location unavailable";
  };

  const describeScanContext = (log: ScanLogRow) => {
    if (log.isTrustedOwnerContext) {
      if (log.ownershipMatchMethod === "user") return "Trusted owner account";
      if (log.ownershipMatchMethod === "device_token") return "Trusted claimed device";
      if (log.ownershipMatchMethod === "ip_fallback") return "Trusted network fallback";
      return "Trusted owner context";
    }
    return "External / anonymous context";
  };

  const blockedLogCount = eventSummary.blockedEvents;
  const firstScanCount = eventSummary.firstScanEvents;
  const openAllocationMap = async (batchId: string) => {
    setAllocationMapOpen(true);
    setAllocationMapLoading(true);
    setAllocationMap(null);
    try {
      const response = await apiClient.getBatchAllocationMap(batchId);
      if (!response.success || !response.data) {
        throw new Error(response.error || "Could not load allocation details.");
      }
      setAllocationMap(response.data);
    } catch (e: any) {
      setAllocationMapOpen(false);
      setError(e?.message || "Could not load allocation details.");
    } finally {
      setAllocationMapLoading(false);
    }
  };

  const copyBatchId = async (batchId: string) => {
    try {
      await navigator.clipboard.writeText(batchId);
    } catch {
      // non-blocking convenience action
    }
  };

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
            <Badge className="border-amber-200 bg-amber-50 text-amber-700">{eventSummary.externalEvents} external scans</Badge>
            <Badge className="border-sky-200 bg-sky-50 text-sky-700">{eventSummary.trustedOwnerEvents} owner-linked scans</Badge>
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

        {scopeMeta ? (
          <div className="grid gap-3 md:grid-cols-6">
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Scope mode</p>
              <p className="mt-1 text-lg font-semibold text-slate-900">{scopeMeta.title}</p>
              <p className="mt-1 text-xs text-slate-600">{scopeMeta.description}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Distinct QR codes</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.distinctCodes.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Scan events</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.scanEvents.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Matched batches</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{scopeMeta.quantities.matchedBatches.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Named locations</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{eventSummary.namedLocationEvents.toLocaleString()}</p>
            </div>
            <div className="rounded-xl border bg-white p-4 shadow-sm">
              <p className="text-[11px] uppercase tracking-wide text-slate-500">Known devices</p>
              <p className="mt-1 text-2xl font-semibold text-slate-900">{eventSummary.knownDeviceEvents.toLocaleString()}</p>
            </div>
          </div>
        ) : null}

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
                          batchQuery: "",
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
                      placeholder="Batch ID / batch name"
                      value={filters.batchQuery}
                      onChange={(e) => setFilters((prev) => ({ ...prev, batchQuery: e.target.value }))}
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
              badge: <Badge className="border-[#8d9db664] bg-[#bccad630] text-[#4f5b75]">{summary.length} batches</Badge>,
              content:
                loading && !summary.length ? (
                  <PremiumTableSkeleton rows={6} />
                ) : (
                  <div className="overflow-hidden rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-slate-50">
                          <TableHead>Batch</TableHead>
                          <TableHead>Batch ID</TableHead>
                          <TableHead>Range</TableHead>
                          <TableHead>In Scope</TableHead>
                          <TableHead>Inventory Total</TableHead>
                          <TableHead>Events</TableHead>
                          <TableHead>Dormant</TableHead>
                          <TableHead>Allocated</TableHead>
                          <TableHead>Printed</TableHead>
                          <TableHead>Redeemed</TableHead>
                          <TableHead>Blocked</TableHead>
                          <TableHead>Created</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {summary.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={12} className="text-slate-500">
                              No batches found for current filters.
                            </TableCell>
                          </TableRow>
                        ) : (
                          summary.map((b) => {
                            const counts = b.counts || {};
                            const dormant = toCount(counts, "DORMANT") + toCount(counts, "ACTIVE");
                            const allocated = toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVATED");
                            const redeemed = toCount(counts, "REDEEMED") + toCount(counts, "SCANNED");
                            const blocked = toCount(counts, "BLOCKED");

                            return (
                              <TableRow key={b.id}>
                                <TableCell className="font-medium text-slate-900">{b.name}</TableCell>
                                <TableCell className="font-mono text-xs text-slate-600">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="break-all">{b.id}</span>
                                    <Button
                                      type="button"
                                      variant="outline"
                                      size="sm"
                                      className="h-9 gap-2 whitespace-nowrap px-3 text-xs font-medium"
                                      onClick={() => copyBatchId(b.id)}
                                    >
                                      <Copy className="h-3.5 w-3.5" />
                                      Copy ID
                                    </Button>
                                  </div>
                                  <Button type="button" variant="link" className="h-auto px-0 text-xs" onClick={() => openAllocationMap(b.id)}>
                                    Open allocation map
                                  </Button>
                                </TableCell>
                                <TableCell className="font-mono text-xs text-slate-600">
                                  <div>{b.startCode}</div>
                                  <div>{b.endCode}</div>
                                </TableCell>
                                <TableCell>{Number(b.scopeCodeCount || 0).toLocaleString()}</TableCell>
                                <TableCell>{Number(b.batchInventoryTotal || b.totalCodes || 0).toLocaleString()}</TableCell>
                                <TableCell>{Number(b.scanEventCount || 0).toLocaleString()}</TableCell>
                                <TableCell>
                                  <Badge className={statusTone("DORMANT")}>{dormant}</Badge>
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
                            <TableHead>Context</TableHead>
                            <TableHead>Location</TableHead>
                            <TableHead>Device</TableHead>
                            <TableHead>IP</TableHead>
                            <TableHead>Scanned At</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {logs.length === 0 ? (
                            <TableRow>
                              <TableCell colSpan={9} className="text-slate-500">
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
                                  <TableCell className="text-xs text-slate-700">
                                    <Badge className={log.isTrustedOwnerContext ? "border-sky-200 bg-sky-50 text-sky-700" : "border-amber-200 bg-amber-50 text-amber-700"}>
                                      {log.isTrustedOwnerContext ? "Trusted owner" : "External"}
                                    </Badge>
                                    <div className="mt-1 text-[11px] text-slate-500">{describeScanContext(log)}</div>
                                  </TableCell>
                                  <TableCell className="text-xs text-slate-700">{formatLocation(log)}</TableCell>
                                  <TableCell className="max-w-[220px] text-xs text-slate-600">
                                    <div>{log.deviceLabel || "Browser device"}</div>
                                    <div className="mt-1 text-[11px] text-slate-500">
                                      {log.userAgent ? "User agent captured" : "Browser fingerprint only"}
                                    </div>
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

        <BatchAllocationMapDialog
          open={allocationMapOpen}
          onOpenChange={(open) => {
            setAllocationMapOpen(open);
            if (!open) {
              setAllocationMap(null);
              setAllocationMapLoading(false);
            }
          }}
          loading={allocationMapLoading}
          payload={allocationMap}
        />
      </div>
    </DashboardLayout>
  );
}

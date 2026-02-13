import React, { useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import { AlertTriangle, Ban, CheckCircle2, Filter, Layers, RefreshCw, ScanEye, Search, ShieldAlert } from "lucide-react";

import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
import { useAuth } from "@/contexts/AuthContext";
import { onMutationEvent } from "@/lib/mutation-events";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

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

  const formatLocation = (log: ScanLogRow) => log.locationName || "Location unavailable";

  const blockedLogCount = logs.filter((l) => String(l.qrCode?.status || l.status || "").toUpperCase() === "BLOCKED").length;
  const firstScanCount = logs.filter((l) => Boolean(l.isFirstScan)).length;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-gradient-to-r from-slate-50 via-white to-cyan-50 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-cyan-200 bg-cyan-50">
              <ScanEye className="h-5 w-5 text-cyan-700" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-slate-900">QR Tracking</h1>
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
              {error}
            </div>
          </div>
        )}

        <Card className="border-slate-200">
          <CardHeader className="flex flex-col gap-3 border-b bg-slate-50/60 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-slate-500" />
              <span className="font-semibold text-slate-900">Tracking Filters</span>
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() => load()}
                disabled={loading}
                className="bg-slate-900 text-white hover:bg-slate-800"
              >
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
          </CardHeader>
          <CardContent className="grid gap-3 pt-4 md:grid-cols-2 xl:grid-cols-4">
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

            <Select
              value={filters.status}
              onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}
            >
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

            <Select
              value={filters.firstScan}
              onValueChange={(value) => setFilters((prev) => ({ ...prev, firstScan: value }))}
            >
              <SelectTrigger>
                <SelectValue placeholder="First scan" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All scans</SelectItem>
                <SelectItem value="yes">First scans only</SelectItem>
                <SelectItem value="no">Repeat scans only</SelectItem>
              </SelectContent>
            </Select>

            <Input
              type="date"
              value={filters.fromDate}
              onChange={(e) => setFilters((prev) => ({ ...prev, fromDate: e.target.value }))}
            />
            <Input
              type="date"
              value={filters.toDate}
              onChange={(e) => setFilters((prev) => ({ ...prev, toDate: e.target.value }))}
            />
          </CardContent>
        </Card>

        <Card className="border-slate-200">
          <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/60">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-slate-500" />
              <span className="font-semibold text-slate-900">Batch Summary</span>
            </div>
            <Badge className="border-slate-200 bg-white text-slate-700">{filteredSummary.length} batches</Badge>
          </CardHeader>
          <CardContent className="pt-4">
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
          </CardContent>
        </Card>

        <Card className="border-slate-200">
          <CardHeader className="flex flex-row items-center justify-between border-b bg-slate-50/60">
            <div className="flex items-center gap-2">
              <ScanEye className="h-4 w-4 text-slate-500" />
              <span className="font-semibold text-slate-900">Scan Logs</span>
            </div>
            <Badge className="border-slate-200 bg-white text-slate-700">{logs.length} entries</Badge>
          </CardHeader>
          <CardContent className="pt-4">
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
                            {log.licensee?.name && (
                              <div className="text-slate-500">{log.licensee.name}</div>
                            )}
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
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}

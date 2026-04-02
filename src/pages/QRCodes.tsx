// src/pages/QRCodes.tsx

import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { useAuth } from "@/contexts/AuthContext";

import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { Search, QrCode, Filter, Download } from "lucide-react";
import { format } from "date-fns";

import apiClient from "@/lib/api-client";
import { saveAs } from "file-saver";
import { onMutationEvent } from "@/lib/mutation-events";

type UIStatus = "dormant" | "allocated" | "printed" | "scanned" | "blocked";
type ApiStatus =
  | "DORMANT"
  | "ACTIVE"
  | "ALLOCATED"
  | "ACTIVATED"
  | "PRINTED"
  | "REDEEMED"
  | "SCANNED"
  | "BLOCKED";

const statusColors: Record<UIStatus, string> = {
  dormant: "bg-muted text-muted-foreground",
  allocated: "bg-info/10 text-info",
  printed: "bg-warning/10 text-warning",
  scanned: "bg-success/10 text-success",
  blocked: "bg-rose-100 text-rose-700",
};

const toUIStatus = (s: string): UIStatus => {
  const v = String(s || "").toUpperCase();
  if (v === "BLOCKED") return "blocked";
  if (v === "ALLOCATED" || v === "ACTIVE" || v === "ACTIVATED") return "allocated";
  if (v === "PRINTED") return "printed";
  if (v === "SCANNED" || v === "REDEEMED") return "scanned";
  return "dormant";
};

const toApiStatus = (s: string): ApiStatus | undefined => {
  if (!s || s === "all") return undefined;
  return String(s).toUpperCase() as ApiStatus;
};

type Licensee = { id: string; name: string; prefix: string };
type BatchRow = { id: string; name: string; licenseeId: string; printedAt?: string | null };

type QrRow = {
  id?: string;
  code: string;
  status: string;
  batchId?: string | null;
  scanCount?: number | null;
  createdAt?: string | Date | null;
  scannedAt?: string | Date | null;
  batch?: { id: string; name: string; printedAt?: string | Date | null } | null;
};

function safeDate(d: any): Date | null {
  if (!d) return null;
  const dt = new Date(d);
  return isNaN(dt.getTime()) ? null : dt;
}

export default function QRCodes() {
  const { user } = useAuth();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const [selectedLicensee, setSelectedLicensee] = useState<string>(
    user?.role === "super_admin" ? "all" : user?.licenseeId || "all"
  );

  const [licensees, setLicensees] = useState<Licensee[]>([]);
  const [batches, setBatches] = useState<BatchRow[]>([]);
  const [selectedBatchId, setSelectedBatchId] = useState<string>("all");

  const [qrCodes, setQRCodes] = useState<QrRow[]>([]);
  const [total, setTotal] = useState(0);

  const [stats, setStats] = useState<{ total: number; byStatus: Record<string, number> } | null>(null);

  const [loading, setLoading] = useState(false);
  const [uiError, setUiError] = useState<string | null>(null);

  const filteredLicenseeId =
    user?.role === "super_admin"
      ? selectedLicensee === "all"
        ? undefined
        : selectedLicensee
      : user?.role === "licensee_admin"
        ? user?.licenseeId
        : undefined;

  const uiStats = useMemo(() => {
    const by = stats?.byStatus || {};
    const dormant = by.DORMANT || 0;
    const allocated = (by.ALLOCATED || 0) + (by.ACTIVE || 0) + (by.ACTIVATED || 0);
    const printed = by.PRINTED || 0;
    const scanned = (by.SCANNED || 0) + (by.REDEEMED || 0);
    const blocked = by.BLOCKED || 0;
    const total = stats?.total ?? dormant + allocated + printed + scanned + blocked;
    return { total, dormant, allocated, printed, scanned };
  }, [stats]);

  // multi-select rows for bulk zip/delete
  const [selectedCodes, setSelectedCodes] = useState<Record<string, boolean>>({});
  const selectedCount = useMemo(() => Object.values(selectedCodes).filter(Boolean).length, [selectedCodes]);

  const toggleSelect = (code: string) => {
    setSelectedCodes((prev) => ({ ...prev, [code]: !prev[code] }));
  };

  const toggleSelectAllDisplayed = () => {
    const allSelected = qrCodes.length > 0 && qrCodes.every((r) => selectedCodes[r.code]);
    const next: Record<string, boolean> = { ...selectedCodes };
    qrCodes.forEach((r) => (next[r.code] = !allSelected));
    setSelectedCodes(next);
  };

  const fetchLicensees = async () => {
    if (user?.role !== "super_admin") return;
    const res = await apiClient.getLicensees();
    if (res.success) setLicensees((res.data as any) || []);
  };

  const fetchBatches = async () => {
    const res = await apiClient.getBatches();
    if (!res.success) return setBatches([]);
    const list = (res.data || []) as any[];
    setBatches(
      list.map((b) => ({
        id: b.id,
        name: b.name,
        licenseeId: b.licenseeId,
        printedAt: b.printedAt || null,
      }))
    );
  };

  const fetchStats = async () => {
    const res = await apiClient.getQRStats(filteredLicenseeId || undefined);
    if (res.success) setStats((res.data as any) || null);
    else setStats(null);
  };

  const fetchCodes = async () => {
    setLoading(true);
    setUiError(null);
    try {
      const res = await apiClient.getQRCodes({
        licenseeId: filteredLicenseeId || undefined,
        status: toApiStatus(statusFilter),
        q: search.trim() || undefined,
        limit: 1000,
        offset: 0,
      } as any);

      if (!res.success) {
        setQRCodes([]);
        setTotal(0);
        setSelectedCodes({});
        setUiError(res.error || "Failed to load QR codes");
        return;
      }

      const payload: any = res.data;

      let list: QrRow[] = [];
      let total = 0;

      if (payload?.qrCodes) {
        list = payload.qrCodes;
        total = payload.total || payload.qrCodes.length || 0;
      } else if (Array.isArray(payload)) {
        list = payload;
        total = payload.length;
      }

      // batch filter (UI)
      if (selectedBatchId !== "all") {
        list = list.filter((r) => (r.batch?.id || r.batchId) === selectedBatchId);
      }

      setQRCodes(list);
      setTotal(total);
      setSelectedCodes({});
    } finally {
      setLoading(false);
    }
  };

  const refreshAll = async () => {
    setUiError(null);
    if (user?.role === "super_admin") await fetchLicensees();
    await Promise.all([fetchBatches(), fetchStats()]);
    await fetchCodes();
  };

  useEffect(() => {
    refreshAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedLicensee, statusFilter, selectedBatchId]);

  useEffect(() => {
    const off = onMutationEvent(() => {
      refreshAll();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // export CSV (uses api-client)
  const handleExportCsv = async () => {
    try {
      setUiError(null);
      const blob = await apiClient.exportQRCodesCsv({
        licenseeId: filteredLicenseeId || undefined,
        status: toApiStatus(statusFilter),
        q: search.trim() || undefined,
      } as any);
      saveAs(blob, "qr-codes.csv");
    } catch (e: any) {
      setUiError(`Export failed: ${e?.message || "Unknown error"}`);
    }
  };

  const deleteSelectedQRCodes = async () => {
    const codes = Object.entries(selectedCodes).filter(([, v]) => v).map(([k]) => k);

    if (codes.length === 0) {
      setUiError("Select at least 1 QR code to delete.");
      return;
    }

    const ok = window.confirm(`Hard delete ${codes.length} QR code(s)?\nThis cannot be undone.`);
    if (!ok) return;

    setLoading(true);
    try {
      const res = await apiClient.deleteQRCodes({ codes });
      if (!res.success) {
        setUiError(res.error || "Delete failed");
        return;
      }

      setQRCodes((prev) => prev.filter((r) => !codes.includes(r.code)));
      setSelectedCodes({});
      await fetchStats();
    } finally {
      setLoading(false);
    }
  };

  // batch options respect selected licensee for super_admin
  const visibleBatches = useMemo(() => {
    if (user?.role !== "super_admin") return batches;
    if (selectedLicensee === "all") return batches;
    return batches.filter((b) => b.licenseeId === selectedLicensee);
  }, [batches, selectedLicensee, user?.role]);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">QR Codes</h1>
            <p className="text-muted-foreground">
              View QR inventory and export reports. Production labels now ship only through managed MSCQR print jobs.
            </p>
          </div>

          <div className="flex gap-2 flex-wrap">
            {(user?.role === "super_admin" || user?.role === "licensee_admin") && (
              <Button
                variant="destructive"
                onClick={deleteSelectedQRCodes}
                disabled={loading || selectedCount === 0}
              >
                Delete selected ({selectedCount})
              </Button>
            )}

            <Button variant="outline" onClick={refreshAll} disabled={loading}>
              Refresh
            </Button>

            <Button variant="outline" onClick={handleExportCsv} disabled={loading}>
              <Download className="mr-2 h-4 w-4" />
              Export CSV
            </Button>
          </div>
        </div>

        {uiError && (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {uiError}
          </div>
        )}

        <div className="rounded-xl border border-border/70 bg-muted/40 px-4 py-3 text-sm text-muted-foreground">
          Printable signed labels are now issued only through MSCQR print jobs and printer confirmations. Inventory
          export remains available here for audit and reconciliation.
        </div>

        {/* Stats */}
        <div className="grid gap-4 md:grid-cols-4">
          {(["dormant", "allocated", "printed", "scanned"] as UIStatus[]).map((status) => {
            const count =
              status === "dormant"
                ? uiStats.dormant
                : status === "allocated"
                ? uiStats.allocated
                : status === "printed"
                ? uiStats.printed
                : uiStats.scanned;

            const pct = uiStats.total ? Math.round((count / uiStats.total) * 100) : 0;

            return (
              <Card key={status}>
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground capitalize">{status}</p>
                      <p className="text-2xl font-bold">{count}</p>
                    </div>
                    <Badge className={statusColors[status]}>{pct}%</Badge>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Filters + Table */}
        <Card>
          <CardHeader className="pb-4">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search QR codes..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                  onKeyDown={(e) => {
                    if (e.key === "Enter") fetchCodes();
                  }}
                />
              </div>

              {user?.role === "super_admin" && (
                <Select value={selectedLicensee} onValueChange={setSelectedLicensee}>
                  <SelectTrigger className="w-[220px]">
                    <SelectValue placeholder="Select licensee" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Licensees</SelectItem>
                    {licensees.map((l) => (
                      <SelectItem key={l.id} value={l.id}>
                        {l.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              <Select value={selectedBatchId} onValueChange={setSelectedBatchId}>
                <SelectTrigger className="w-[220px]">
                  <SelectValue placeholder="Batch" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Batches</SelectItem>
                  {visibleBatches.map((b) => (
                    <SelectItem key={b.id} value={b.id}>
                      {b.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[160px]">
                  <Filter className="mr-2 h-4 w-4" />
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="dormant">Dormant</SelectItem>
                  <SelectItem value="allocated">Allocated</SelectItem>
                  <SelectItem value="printed">Printed</SelectItem>
                  <SelectItem value="scanned">Scanned</SelectItem>
                </SelectContent>
              </Select>

              <Button variant="outline" onClick={fetchCodes} disabled={loading}>
                Apply
              </Button>
            </div>
          </CardHeader>

          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[40px]">
                      <input
                        type="checkbox"
                        aria-label="Select all"
                        checked={qrCodes.length > 0 && qrCodes.every((r) => !!selectedCodes[r.code])}
                        onChange={toggleSelectAllDisplayed}
                      />
                    </TableHead>
                    <TableHead>QR Code</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Batch</TableHead>
                    <TableHead>Scan</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Scanned</TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : qrCodes.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">
                        No QR codes found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    qrCodes.map((qr) => {
                      const uiStatus = toUIStatus(qr.status);
                      const created = safeDate(qr.createdAt);
                      const scanned = safeDate(qr.scannedAt);

                      return (
                        <TableRow key={qr.id || qr.code}>
                          <TableCell>
                            <input
                              type="checkbox"
                              checked={!!selectedCodes[qr.code]}
                              onChange={() => toggleSelect(qr.code)}
                              aria-label={`Select ${qr.code}`}
                            />
                          </TableCell>

                          <TableCell>
                            <div className="flex items-center gap-3">
                              <div className="h-10 w-10 rounded-lg bg-muted flex items-center justify-center">
                                <QrCode className="h-5 w-5 text-muted-foreground" />
                              </div>
                              <span className="font-mono font-medium">{qr.code}</span>
                            </div>
                          </TableCell>

                          <TableCell>
                            <Badge className={statusColors[uiStatus]}>{uiStatus}</Badge>
                          </TableCell>

                          <TableCell>
                            {qr.batch?.name ? (
                              <span className="text-sm">{qr.batch.name}</span>
                            ) : qr.batchId ? (
                              <span className="text-sm">{qr.batchId}</span>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          <TableCell>
                            {Number(qr.scanCount || 0) > 0 ? (
                              <span className="font-medium">{qr.scanCount}</span>
                            ) : (
                              <span className="text-muted-foreground">0</span>
                            )}
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {created ? format(created, "MMM d, yyyy") : "—"}
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {scanned ? format(scanned, "MMM d, yyyy") : "—"}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>

            <div className="mt-3 text-sm text-muted-foreground">
              Showing {qrCodes.length} of {total}
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}

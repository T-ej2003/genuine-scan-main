import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import apiClient from "@/lib/api-client";
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
import { RefreshCw, Search, ScanEye, Layers } from "lucide-react";
import { format } from "date-fns";

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
  productBatchId?: string | null;
  device?: string | null;
  userAgent?: string | null;
  ipAddress?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  accuracy?: number | null;
  isFirstScan?: boolean | null;
  licensee?: { id: string; name: string; prefix: string };
  qrCode?: { id: string; code: string; status: string };
};

const toCount = (counts: Record<string, number> | undefined, key: string) => counts?.[key] ?? 0;

export default function QRTracking() {
  const [summary, setSummary] = useState<BatchSummaryRow[]>([]);
  const [logs, setLogs] = useState<ScanLogRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [codeQuery, setCodeQuery] = useState("");
  const [batchId, setBatchId] = useState("");
  const [productBatchId, setProductBatchId] = useState("");

  const load = async (opts?: { silent?: boolean; override?: { code?: string; batchId?: string; productBatchId?: string } }) => {
    if (!opts?.silent) {
      setLoading(true);
      setError(null);
    }

    try {
      const codeFilter = opts?.override?.code ?? codeQuery;
      const batchFilter = opts?.override?.batchId ?? batchId;
      const productFilter = opts?.override?.productBatchId ?? productBatchId;

      const [summaryRes, logsRes] = await Promise.all([
        apiClient.getBatchSummary(),
        apiClient.getScanLogs({
          code: codeFilter.trim() || undefined,
          batchId: batchFilter.trim() || undefined,
          productBatchId: productFilter.trim() || undefined,
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

  const batchNameById = useMemo(() => {
    const map = new Map<string, string>();
    summary.forEach((b) => map.set(b.id, b.name || b.id));
    return map;
  }, [summary]);

  const formatLocation = (log: ScanLogRow) => {
    if (log.latitude == null || log.longitude == null) return "—";
    const acc = log.accuracy ? ` (±${Math.round(log.accuracy)}m)` : "";
    return `${log.latitude.toFixed(4)}, ${log.longitude.toFixed(4)}${acc}`;
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-emerald-500/10 flex items-center justify-center">
              <ScanEye className="h-5 w-5 text-emerald-600" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">QR Tracking</h1>
              <p className="text-muted-foreground">Batch status + scan activity across all QR codes</p>
            </div>
          </div>
          <Button variant="outline" onClick={() => load()} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </div>

        {error && (
          <div className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">
            {error}
          </div>
        )}

        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-muted-foreground" />
              <span className="font-semibold">Batch Summary</span>
            </div>
            <Badge variant="secondary">{summary.length} batches</Badge>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Batch</TableHead>
                    <TableHead>Range</TableHead>
                    <TableHead>Total</TableHead>
                    <TableHead>Dormant</TableHead>
                    <TableHead>Allocated</TableHead>
                    <TableHead>Printed</TableHead>
                    <TableHead>Scanned</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-muted-foreground">
                        No batches found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    summary.map((b) => {
                      const counts = b.counts || {};
                      const allocated = toCount(counts, "ALLOCATED") + toCount(counts, "ACTIVE");
                      return (
                        <TableRow key={b.id}>
                          <TableCell className="font-medium">{b.name}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <div>{b.startCode}</div>
                            <div>{b.endCode}</div>
                          </TableCell>
                          <TableCell>{b.totalCodes}</TableCell>
                          <TableCell>{toCount(counts, "DORMANT")}</TableCell>
                          <TableCell>{allocated}</TableCell>
                          <TableCell>{toCount(counts, "PRINTED")}</TableCell>
                          <TableCell>{toCount(counts, "SCANNED")}</TableCell>
                          <TableCell className="text-muted-foreground">
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

        <Card>
          <CardHeader className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-2">
              <ScanEye className="h-4 w-4 text-muted-foreground" />
              <span className="font-semibold">Scan Logs</span>
            </div>
            <div className="flex flex-col gap-2 sm:flex-row">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search code..."
                  value={codeQuery}
                  onChange={(e) => setCodeQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Input
                placeholder="Batch ID (optional)"
                value={batchId}
                onChange={(e) => setBatchId(e.target.value)}
              />
              <Input
                placeholder="Product Batch ID (optional)"
                value={productBatchId}
                onChange={(e) => setProductBatchId(e.target.value)}
              />
              <div className="flex gap-2">
                <Button onClick={() => load()} disabled={loading}>
                  Apply
                </Button>
                <Button
                  variant="outline"
                  onClick={() => {
                    setCodeQuery("");
                    setBatchId("");
                    setProductBatchId("");
                    load({ override: { code: "", batchId: "", productBatchId: "" } });
                  }}
                  disabled={loading}
                >
                  Clear
                </Button>
              </div>
            </div>
          </CardHeader>

          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Code</TableHead>
                    <TableHead>Batch</TableHead>
                    <TableHead>Product Batch</TableHead>
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
                      <TableCell colSpan={9} className="text-muted-foreground">
                        No scan logs found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    logs.map((log) => (
                      <TableRow key={log.id}>
                        <TableCell className="font-mono text-xs">
                          <div className="font-semibold">{log.code}</div>
                          {log.licensee?.name && (
                            <div className="text-muted-foreground">{log.licensee.name}</div>
                          )}
                        </TableCell>
                        <TableCell className="text-sm">
                          {log.batchId ? batchNameById.get(log.batchId) || log.batchId : "—"}
                        </TableCell>
                        <TableCell className="text-sm">{log.productBatchId || "—"}</TableCell>
                        <TableCell>
                          <Badge variant="secondary">{log.qrCode?.status || log.status || "—"}</Badge>
                        </TableCell>
                        <TableCell>{log.scanCount ?? 0}</TableCell>
                        <TableCell className="text-xs">{formatLocation(log)}</TableCell>
                        <TableCell className="text-xs">
                          {log.device || log.userAgent || "—"}
                          {log.isFirstScan ? (
                            <div>
                              <Badge variant="outline" className="mt-1">
                                First scan
                              </Badge>
                            </div>
                          ) : null}
                        </TableCell>
                        <TableCell className="text-xs">{log.ipAddress || "—"}</TableCell>
                        <TableCell className="text-xs">
                          {log.scannedAt ? format(new Date(log.scannedAt), "PPp") : "—"}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>

            <div className="mt-3 text-sm text-muted-foreground">
              Showing {logs.length} scan log entries
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}

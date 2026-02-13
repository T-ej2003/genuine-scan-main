// src/pages/Batches.tsx

import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { useAuth } from "@/contexts/AuthContext";
import { useOperationProgress } from "@/hooks/useOperationProgress";
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

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { onMutationEvent } from "@/lib/mutation-events";

import { format } from "date-fns";
import { Search, Trash2, RefreshCw, MoreHorizontal, Download, UserCog, Activity } from "lucide-react";

import { saveAs } from "file-saver";

type BatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  createdAt: string;
  licensee?: { id: string; name: string; prefix: string };
  manufacturer?: { id: string; name: string; email: string };
  _count?: { qrCodes: number };
  availableCodes?: number;
  remainingStartCode?: string | null;
  remainingEndCode?: string | null;
};

type ManufacturerRow = { id: string; name: string; email: string; isActive: boolean };

type QrRow = {
  code: string;
  batchId?: string | null;
  batch?: { id: string } | null;
};

type TraceEventType = "COMMISSIONED" | "ASSIGNED" | "PRINTED" | "REDEEMED" | "BLOCKED";

type TraceEventRow = {
  id: string;
  eventType?: TraceEventType;
  action?: string;
  sourceAction?: string | null;
  createdAt: string;
  details?: any;
  user?: { id: string; name?: string | null; email?: string | null } | null;
  manufacturer?: { id: string; name?: string | null; email?: string | null } | null;
  qrCode?: { id: string; code?: string | null } | null;
  userId?: string | null;
};

const LARGE_ALLOCATION_THRESHOLD = 25_000;
const LARGE_DOWNLOAD_THRESHOLD = 10_000;
const bytesToMb = (value: number) => `${(value / (1024 * 1024)).toFixed(value >= 10 * 1024 * 1024 ? 0 : 1)} MB`;

export default function Batches() {
  const { toast } = useToast();
  const { user } = useAuth();
  const progress = useOperationProgress();

  const role = user?.role;

  const canDelete = role === "super_admin" || role === "licensee_admin";
  const canAssignManufacturer = role === "licensee_admin";
  const isManufacturer = role === "manufacturer";

  const [loading, setLoading] = useState(false);
  const [rows, setRows] = useState<BatchRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [assignmentFilter, setAssignmentFilter] = useState<"all" | "assigned" | "unassigned">("all");
  const [printFilter, setPrintFilter] = useState<"all" | "printed" | "unprinted">("all");

  // manufacturers for assign dropdown (licensee_admin)
  const [manufacturers, setManufacturers] = useState<ManufacturerRow[]>([]);
  const [assignOpen, setAssignOpen] = useState(false);
  const [assignBatch, setAssignBatch] = useState<BatchRow | null>(null);
  const [assignManufacturerId, setAssignManufacturerId] = useState<string>("");
  const [assignQuantity, setAssignQuantity] = useState<string>("");
  const [assignBatchName, setAssignBatchName] = useState<string>("");

  // print pack dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printBatch, setPrintBatch] = useState<BatchRow | null>(null);
  const [printing, setPrinting] = useState(false);

  const [printQuantity, setPrintQuantity] = useState<string>("");
  const [printJobId, setPrintJobId] = useState<string>("");
  const [printLockToken, setPrintLockToken] = useState<string>("");
  const [printJobTokensCount, setPrintJobTokensCount] = useState<number>(0);
  const [exportingBatchId, setExportingBatchId] = useState<string | null>(null);

  // allocation history
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyBatch, setHistoryBatch] = useState<BatchRow | null>(null);
  const [historyLogs, setHistoryLogs] = useState<TraceEventRow[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const fetchBatches = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getBatches();
      if (!res.success) {
        setRows([]);
        setError(res.error || "Failed to load batches");
        return;
      }
      setRows((Array.isArray(res.data) ? res.data : []) as BatchRow[]);
    } catch (e: any) {
      setRows([]);
      setError(e?.message || "Failed to load batches");
    } finally {
      setLoading(false);
    }
  };

  const fetchManufacturersForAssign = async () => {
    if (!canAssignManufacturer) return;
    const licenseeId = user?.licenseeId;
    const res = await apiClient.getManufacturers({
      licenseeId: licenseeId || undefined,
      includeInactive: false,
    });
    if (res.success) {
      setManufacturers(((res.data as any) || []) as ManufacturerRow[]);
    } else {
      setManufacturers([]);
    }
  };

  useEffect(() => {
    fetchBatches();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const off = onMutationEvent(() => {
      fetchBatches();
      fetchManufacturersForAssign();
    });
    return off;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    fetchManufacturersForAssign();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.licenseeId, role]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    return rows.filter((b) => {
      if (isManufacturer) {
        if (printFilter === "printed" && !b.printedAt) return false;
        if (printFilter === "unprinted" && b.printedAt) return false;
      } else {
        if (assignmentFilter === "assigned" && !b.manufacturer) return false;
        if (assignmentFilter === "unassigned" && b.manufacturer) return false;
      }
      if (!s) return true;
      const hay = [
        b.name,
        b.startCode,
        b.endCode,
        b.licensee?.name,
        b.licensee?.prefix,
        b.manufacturer?.name,
        b.manufacturer?.email,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return hay.includes(s);
    });
  }, [rows, q, assignmentFilter, isManufacturer, printFilter]);

  // -------- DELETE (admins) --------
  const handleDelete = async (batch: BatchRow) => {
    if (!canDelete) return;

    const ok = window.confirm(
      `Delete batch "${batch.name}"?\n\nThis will:\n- Delete the batch\n- Unassign ALL QR codes from this batch (back to DORMANT)\n\nContinue?`
    );
    if (!ok) return;

    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.deleteBatch(batch.id);
      if (!res.success) {
        setError(res.error || "Delete failed");
        return;
      }
      toast({ title: "Deleted", description: `Batch "${batch.name}" deleted.` });
      await fetchBatches();
    } catch (e: any) {
      setError(e?.message || "Delete failed");
    } finally {
      setLoading(false);
    }
  };

  // -------- ASSIGN MANUFACTURER (licensee_admin) --------
  const openAssign = (b: BatchRow) => {
    setAssignBatch(b);
    setAssignManufacturerId(b.manufacturer?.id || "");
    setAssignQuantity("");
    setAssignBatchName("");
    setAssignOpen(true);
  };

  const submitAssign = async () => {
    if (!assignBatch) return;
    if (!assignManufacturerId) {
      toast({ title: "Select a manufacturer", variant: "destructive" });
      return;
    }
    const qty = parseInt(assignQuantity, 10);
    if (!Number.isFinite(qty) || qty <= 0) {
      toast({ title: "Enter a valid quantity", variant: "destructive" });
      return;
    }
    if (assignBatch.availableCodes != null && qty > assignBatch.availableCodes) {
      toast({
        title: "Quantity too large",
        description: `Available: ${assignBatch.availableCodes}.`,
        variant: "destructive",
      });
      return;
    }

    const showLargeAllocationProgress = qty >= LARGE_ALLOCATION_THRESHOLD;
    if (showLargeAllocationProgress) {
      progress.start({
        title: "Allocating QR batch",
        description: "Validating availability, assigning manufacturer, and creating child batch.",
        phaseLabel: "Allocation",
        detail: `Allocating ${qty.toLocaleString()} QR codes to selected manufacturer.`,
        mode: "simulated",
        initialValue: 12,
      });
    }

    setLoading(true);
    try {
      const res = await apiClient.assignBatchManufacturer({
        batchId: assignBatch.id,
        manufacturerId: assignManufacturerId,
        quantity: qty,
        name: assignBatchName.trim() || undefined,
      });

      if (!res.success) {
        if (showLargeAllocationProgress) progress.close();
        const raw = (res.error || "Error").toLowerCase();
        const isBusy = raw.includes("busy") || raw.includes("retry") || raw.includes("conflict");
        toast({
          title: isBusy ? "Batch busy" : "Assign failed",
          description: isBusy
            ? "These codes were just allocated by another action. Please retry."
            : res.error || "Error",
          variant: "destructive",
        });
        return;
      }

      const data: any = res.data || {};
      const createdName = data.newBatchName || assignBatchName.trim() || "Auto";
      if (showLargeAllocationProgress) {
        await progress.complete(
          `Allocated ${qty.toLocaleString()} codes. Child batch ${data.newBatchId || "(id pending)"} is ready for print.`
        );
      }
      toast({
        title: "Assigned",
        description: `Created child batch ${data.newBatchId || "(id pending)"}: ${createdName}`,
      });
      setAssignOpen(false);
      setAssignBatch(null);
      setAssignManufacturerId("");
      setAssignQuantity("");
      setAssignBatchName("");
      await fetchBatches();
    } catch (e: any) {
      if (showLargeAllocationProgress) progress.close();
      toast({ title: "Assign failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  // -------- PRINT JOB (MANUFACTURER) --------
  const openPrintPack = (b: BatchRow) => {
    setPrintBatch(b);
    setPrintQuantity("");
    setPrintJobId("");
    setPrintLockToken("");
    setPrintJobTokensCount(0);
    setPrintOpen(true);
  };

  const createPrintJob = async () => {
    if (!printBatch) return;
    const qty = parseInt(printQuantity, 10);
    if (!Number.isFinite(qty) || qty <= 0) {
      toast({ title: "Enter a valid quantity", variant: "destructive" });
      return;
    }
    if (printBatch.availableCodes != null && qty > printBatch.availableCodes) {
      toast({
        title: "Quantity too large",
        description: `Available: ${printBatch.availableCodes}.`,
        variant: "destructive",
      });
      return;
    }

    setPrinting(true);
    try {
      const res = await apiClient.createPrintJob({ batchId: printBatch.id, quantity: qty });
      if (!res.success) {
        const raw = (res.error || "Error").toLowerCase();
        const isBusy = raw.includes("conflict") || raw.includes("busy") || raw.includes("retry");
        toast({
          title: isBusy ? "Batch busy" : "Print job failed",
          description: isBusy
            ? "These codes were just allocated by another job. Please retry."
            : res.error || "Error",
          variant: "destructive",
        });
        return;
      }
      const data: any = res.data || {};
      setPrintJobId(data.printJobId || "");
      setPrintLockToken(data.printLockToken || "");
      setPrintJobTokensCount(
        typeof data.tokenCount === "number" ? data.tokenCount : Array.isArray(data.tokens) ? data.tokens.length : 0
      );
      toast({ title: "Print job created", description: "Download your QR pack. Printing will auto-confirm on download." });
    } finally {
      setPrinting(false);
    }
  };

  const downloadPrintPack = async () => {
    if (!printJobId || !printLockToken) return;
    const showLargeDownloadProgress = (printJobTokensCount || 0) >= LARGE_DOWNLOAD_THRESHOLD || printJobTokensCount === 0;
    if (showLargeDownloadProgress) {
      progress.start({
        title: "Preparing secure download",
        description: "Generating PNGs, compressing ZIP, and streaming to your browser.",
        phaseLabel: "Download",
        detail:
          printJobTokensCount > 0
            ? `Preparing approximately ${printJobTokensCount.toLocaleString()} QR files.`
            : "Preparing QR package...",
        mode: "simulated",
        initialValue: 8,
      });
    }

    setPrinting(true);
    try {
      const blob = await apiClient.downloadPrintJobPack(printJobId, printLockToken, (snapshot) => {
        if (!showLargeDownloadProgress) return;
        const hasKnownTotal = snapshot.totalBytes != null && snapshot.totalBytes > 0;
        const progressValue = hasKnownTotal
          ? Math.max(8, Math.min(98, snapshot.percent || 0))
          : Math.max(12, Math.min(94, 12 + Math.floor(snapshot.loadedBytes / (1024 * 1024 * 20))));
        const speedMbps = snapshot.elapsedMs > 0 ? (snapshot.loadedBytes * 8) / (snapshot.elapsedMs / 1000) / 1_000_000 : 0;

        progress.update({
          value: progressValue,
          indeterminate: !hasKnownTotal,
          detail: hasKnownTotal
            ? `Downloaded ${bytesToMb(snapshot.loadedBytes)} of ${bytesToMb(snapshot.totalBytes!)}`
            : `Downloaded ${bytesToMb(snapshot.loadedBytes)} (estimating total size...)`,
          speedLabel: speedMbps > 0 ? `${speedMbps.toFixed(1)} Mbps` : "",
          phaseLabel: "Downloading",
        });
      });
      if (showLargeDownloadProgress) {
        await progress.complete("Download complete. Saving ZIP to your device.");
      }
      saveAs(blob, `print-job-${printJobId}.zip`);
      toast({ title: "Downloaded", description: "Print pack downloaded and confirmed." });
      setPrintOpen(false);
      setPrintBatch(null);
      setPrintJobId("");
      setPrintLockToken("");
      setPrintJobTokensCount(0);
      await fetchBatches();
    } catch (e: any) {
      if (showLargeDownloadProgress) progress.close();
      toast({ title: "Download failed", description: e?.message || "Error", variant: "destructive" });
    } finally {
      setPrinting(false);
    }
  };

  const openHistory = async (b: BatchRow) => {
    setHistoryBatch(b);
    setHistoryOpen(true);
    setHistoryLoading(true);
    try {
      const traceRes = await apiClient.getTraceTimeline({ batchId: b.id, limit: 100 });
      if (traceRes.success) {
        const payload: any = traceRes.data;
        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.events)
          ? payload.events
          : Array.isArray(payload?.logs)
          ? payload.logs
          : [];
        setHistoryLogs((list as TraceEventRow[]) || []);
      } else {
        setHistoryLogs([]);
      }
    } finally {
      setHistoryLoading(false);
    }
  };

  const eventBadgeClass = (eventType?: string) => {
    if (eventType === "COMMISSIONED") return "bg-sky-500/10 text-sky-700";
    if (eventType === "ASSIGNED") return "bg-indigo-500/10 text-indigo-700";
    if (eventType === "PRINTED") return "bg-amber-500/10 text-amber-700";
    if (eventType === "REDEEMED") return "bg-emerald-500/10 text-emerald-700";
    if (eventType === "BLOCKED") return "bg-red-500/10 text-red-700";
    return "bg-muted text-muted-foreground";
  };

  const historySummary = (log: TraceEventRow) => {
    const d = log?.details || {};
    const eventType = log?.eventType || "";
    if (eventType === "COMMISSIONED") {
      const qty = d.quantity ?? d.created ?? d.totalCodes;
      const range = d.startCode && d.endCode ? ` (${d.startCode} → ${d.endCode})` : "";
      return `Commissioned ${qty ?? "—"} codes${range}.`;
    }
    if (eventType === "ASSIGNED") {
      return `Assigned ${d.quantity ?? "—"} codes to manufacturer ${d.manufacturerId || "—"}.`;
    }
    if (eventType === "PRINTED") {
      return `Printed ${d.printedCodes ?? d.codes ?? "—"} codes.`;
    }
    if (eventType === "REDEEMED") {
      return `Redeemed on scan${d.scanCount != null ? ` (scan #${d.scanCount})` : ""}.`;
    }
    if (eventType === "BLOCKED") {
      return `Blocked${d.reason ? `: ${d.reason}` : ""}${d.blockedCodes ? ` (${d.blockedCodes} codes)` : ""}.`;
    }

    const ctx = d.context || "";
    if (ctx === "ASSIGN_MANUFACTURER_QUANTITY_CHILD") {
      return `Allocated ${d.quantity ?? "—"} to manufacturer ${d.manufacturerId || "—"} (${d.startCode || "?"} → ${d.endCode || "?"})`;
    }
    return log?.sourceAction || log?.action || "Activity";
  };

  const historyUser = (log: TraceEventRow) => {
    if (log?.user?.name) return `${log.user.name} (${log.user.email || log.user.id || "id"})`;
    if (log?.manufacturer?.name) {
      return `${log.manufacturer.name} (${log.manufacturer.email || log.manufacturer.id || "id"})`;
    }
    if (log?.user?.email) return log.user.email;
    if (log?.userId) return log.userId;
    return "System";
  };

  const downloadAuditPackage = async (batch: BatchRow) => {
    if (exportingBatchId) return;
    setExportingBatchId(batch.id);
    try {
      const blob = await apiClient.exportBatchAuditPackage(batch.id);
      saveAs(blob, `batch-${batch.id}-audit-package.zip`);
      toast({
        title: "Audit package downloaded",
        description: "Immutable package contains manifest, event chain, and signatures.",
      });
    } catch (e: any) {
      toast({
        title: "Audit package failed",
        description: e?.message || "Could not download package.",
        variant: "destructive",
      });
    } finally {
      setExportingBatchId(null);
    }
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold">Batches</h1>
            <p className="text-muted-foreground">
              {isManufacturer
                ? "Your assigned QR batches (create print jobs, download pack, then confirm printing)"
                : "Manage received QR batches (assign by quantity / delete / review printing)"}
            </p>
          </div>

          <Button variant="outline" onClick={fetchBatches} disabled={loading}>
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
          <CardHeader className="pb-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search batches..."
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  className="pl-9"
                />
              </div>
              {role !== "manufacturer" ? (
                <Select value={assignmentFilter} onValueChange={(v) => setAssignmentFilter(v as any)}>
                  <SelectTrigger className="w-[220px]">
                    <SelectValue placeholder="Assignment filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All batches</SelectItem>
                    <SelectItem value="assigned">Assigned batches</SelectItem>
                    <SelectItem value="unassigned">Unassigned batches</SelectItem>
                  </SelectContent>
                </Select>
              ) : (
                <Select value={printFilter} onValueChange={(v) => setPrintFilter(v as any)}>
                  <SelectTrigger className="w-[220px]">
                    <SelectValue placeholder="Printed filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All batches</SelectItem>
                    <SelectItem value="printed">Printed</SelectItem>
                    <SelectItem value="unprinted">Not printed</SelectItem>
                  </SelectContent>
                </Select>
              )}
            </div>
          </CardHeader>

          <CardContent>
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Batch</TableHead>
                    <TableHead>Licensee</TableHead>
                  <TableHead>Range</TableHead>
                  <TableHead>Total</TableHead>
                  <TableHead>Remaining</TableHead>
                  <TableHead>Assigned QR</TableHead>
                  <TableHead>Manufacturer</TableHead>
                  <TableHead>Printed</TableHead>
                  <TableHead>Created</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={10} className="text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={10} className="text-muted-foreground">
                        No batches found.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((b) => {
                      const assignedCount = b._count?.qrCodes ?? 0;
                      const printed = !!b.printedAt;

                      return (
                        <TableRow key={b.id}>
                          <TableCell>
                            <div className="space-y-1">
                              <div className="font-medium">{b.name}</div>
                              <div className="text-[11px] text-muted-foreground font-mono">{b.id}</div>
                            </div>
                          </TableCell>

                          <TableCell>
                            {b.licensee?.name ? (
                              <div className="space-y-1">
                                <div>{b.licensee.name}</div>
                                <div className="text-xs text-muted-foreground">
                                  Prefix: {b.licensee.prefix}
                                </div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">{b.licenseeId}</span>
                            )}
                          </TableCell>

                          <TableCell className="font-mono text-xs">
                            <div>{b.startCode}</div>
                            <div>{b.endCode}</div>
                          </TableCell>

                          <TableCell>{b.totalCodes}</TableCell>

                          <TableCell>
                            <div className="space-y-1">
                              <Badge variant={b.availableCodes ? "default" : "secondary"}>
                                {b.availableCodes ?? 0}
                              </Badge>
                              <div className="text-[11px] text-muted-foreground font-mono">
                                {b.remainingStartCode && b.remainingEndCode
                                  ? `${b.remainingStartCode} → ${b.remainingEndCode}`
                                  : "—"}
                              </div>
                            </div>
                          </TableCell>

                          <TableCell>
                            <Badge variant={assignedCount > 0 ? "default" : "secondary"}>{assignedCount}</Badge>
                          </TableCell>

                          <TableCell>
                            {b.manufacturer ? (
                              <div className="space-y-1">
                                <div>{b.manufacturer.name}</div>
                                <div className="text-xs text-muted-foreground">{b.manufacturer.email}</div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>

                          <TableCell>
                            {printed ? (
                              <Badge className="bg-success/10 text-success">
                                {format(new Date(b.printedAt as string), "MMM d, yyyy")}
                              </Badge>
                            ) : (
                              <Badge className="bg-muted text-muted-foreground">Not printed</Badge>
                            )}
                          </TableCell>

                          <TableCell className="text-muted-foreground">
                            {b.createdAt ? format(new Date(b.createdAt), "MMM d, yyyy") : "—"}
                          </TableCell>

                          <TableCell className="text-right">
                            {/* Manufacturer: print pack download (one-time) */}
                            {isManufacturer ? (
                              <div className="flex justify-end gap-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={loading || (b.availableCodes ?? 0) <= 0}
                                  onClick={() => openPrintPack(b)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  {"Create Print Job"}
                                </Button>
                              </div>
                            ) : (
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="outline" size="sm">
                                    <MoreHorizontal className="mr-2 h-4 w-4" />
                                    Actions
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  <DropdownMenuItem onClick={() => openHistory(b)}>
                                    <Activity className="mr-2 h-4 w-4" />
                                    View history
                                  </DropdownMenuItem>
                                  <DropdownMenuItem
                                    onClick={() => downloadAuditPackage(b)}
                                    disabled={exportingBatchId === b.id}
                                  >
                                    <Download className="mr-2 h-4 w-4" />
                                    {exportingBatchId === b.id ? "Preparing package..." : "Download audit package"}
                                  </DropdownMenuItem>
                                  {canAssignManufacturer && (
                                    <DropdownMenuItem onClick={() => openAssign(b)} disabled={!!b.manufacturer || !!b.printedAt}>
                                      <UserCog className="mr-2 h-4 w-4" />
                                      Assign manufacturer
                                    </DropdownMenuItem>
                                  )}

                                  {canDelete && (
                                    <DropdownMenuItem className="text-destructive" onClick={() => handleDelete(b)}>
                                      <Trash2 className="mr-2 h-4 w-4" />
                                      Delete
                                    </DropdownMenuItem>
                                  )}
                                </DropdownMenuContent>
                              </DropdownMenu>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>

            <div className="mt-3 text-sm text-muted-foreground">
              Showing {filtered.length} of {rows.length}
            </div>
          </CardContent>
        </Card>

        {/* Assign Manufacturer Dialog */}
        <Dialog
          open={assignOpen}
          onOpenChange={(v) => {
            setAssignOpen(v);
            if (!v) {
              setAssignBatch(null);
              setAssignManufacturerId("");
              setAssignQuantity("");
              setAssignBatchName("");
            }
          }}
        >
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Assign Manufacturer</DialogTitle>
              <DialogDescription>
                Split this received batch by quantity and assign the new batch to a manufacturer.
              </DialogDescription>
            </DialogHeader>

            {!assignBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{assignBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">{assignBatch.id}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {assignBatch.startCode} → {assignBatch.endCode}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Manufacturer</Label>
                  <Select value={assignManufacturerId} onValueChange={setAssignManufacturerId}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select manufacturer" />
                    </SelectTrigger>
                    <SelectContent>
                      {manufacturers.length === 0 ? (
                        <SelectItem value="__none__" disabled>
                          No manufacturers found
                        </SelectItem>
                      ) : (
                        manufacturers.map((m) => (
                          <SelectItem key={m.id} value={m.id}>
                            {m.name} ({m.email})
                          </SelectItem>
                        ))
                      )}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Quantity to allocate</Label>
                  <Input
                    type="number"
                    min={1}
                    value={assignQuantity}
                    onChange={(e) => setAssignQuantity(e.target.value)}
                    placeholder="Enter quantity"
                  />
                  <div className="text-xs text-muted-foreground">
                    Available in this batch: {assignBatch.availableCodes ?? assignBatch.totalCodes}
                  </div>
                  {assignBatch.availableCodes != null && Number(assignQuantity) > 0 && (
                    <div className="text-xs text-muted-foreground">
                      Remaining after split:{" "}
                      {Math.max(assignBatch.availableCodes - Number(assignQuantity), 0)}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <Label>New Child Batch Name (optional)</Label>
                  <Input
                    value={assignBatchName}
                    onChange={(e) => setAssignBatchName(e.target.value)}
                    placeholder="e.g. Factory-A PO-1234"
                  />
                  <div className="text-xs text-muted-foreground">
                    If empty, a default name is generated automatically.
                  </div>
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setAssignOpen(false)} disabled={loading}>
                    Cancel
                  </Button>
                  <Button onClick={submitAssign} disabled={loading}>
                    Save
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Print Job Dialog */}
        <Dialog open={printOpen} onOpenChange={(v) => { setPrintOpen(v); if (!v) setPrintBatch(null); }}>
          <DialogContent className="sm:max-w-[640px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Print Job</DialogTitle>
              <DialogDescription>
                Select quantity, generate signed QR tokens, download the pack. Printing is auto-confirmed after download.
              </DialogDescription>
            </DialogHeader>

            {!printBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{printBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">
                    {printBatch.startCode} → {printBatch.endCode}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Quantity to print</Label>
                  <Input
                    type="number"
                    min={1}
                    value={printQuantity}
                    onChange={(e) => setPrintQuantity(e.target.value)}
                    placeholder="Enter quantity"
                  />
                  <div className="text-xs text-muted-foreground">
                    Available: {printBatch.availableCodes ?? printBatch.totalCodes}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button onClick={createPrintJob} disabled={printing}>
                    {printing ? "Creating..." : "Create Print Job"}
                  </Button>
                  {printJobId && (
                    <Badge variant="secondary">Job: {printJobId.slice(0, 8)}…</Badge>
                  )}
                </div>

                {printJobId && printLockToken && (
                  <div className="rounded-md border p-3 text-sm space-y-2">
                    <div className="text-xs text-muted-foreground">Print Lock Token</div>
                    <div className="font-mono text-xs break-all">{printLockToken}</div>
                    <div className="text-xs text-muted-foreground">
                      Tokens generated: {printJobTokensCount}
                    </div>
                  </div>
                )}

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setPrintOpen(false)} disabled={printing}>
                    Close
                  </Button>
                  <Button onClick={downloadPrintPack} disabled={printing || !printJobId}>
                    {printing ? "Generating..." : "Download ZIP"}
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Allocation History Dialog */}
        <Dialog open={historyOpen} onOpenChange={(v) => { setHistoryOpen(v); if (!v) { setHistoryBatch(null); setHistoryLogs([]); } }}>
          <DialogContent className="sm:max-w-[700px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Batch History</DialogTitle>
              <DialogDescription>
                {historyBatch ? historyBatch.name : "Selected batch"} — lifecycle timeline (COMMISSIONED → ASSIGNED → PRINTED → REDEEMED/BLOCKED)
              </DialogDescription>
            </DialogHeader>

            {historyLoading ? (
              <div className="text-sm text-muted-foreground">Loading history…</div>
            ) : historyLogs.length === 0 ? (
              <div className="text-sm text-muted-foreground">No history found.</div>
            ) : (
              <div className="space-y-2">
                {historyLogs.map((log, idx) => (
                  <div key={log.id || `${log.createdAt}-${idx}`} className="rounded-md border p-3 text-sm">
                    <div className="flex items-center justify-between gap-2">
                      <div className="space-y-1">
                        {log.eventType && (
                          <Badge className={eventBadgeClass(log.eventType)}>{log.eventType}</Badge>
                        )}
                        <div className="font-medium">{historySummary(log)}</div>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {log.createdAt ? format(new Date(log.createdAt), "PPp") : "—"}
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      By {historyUser(log)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </DialogContent>
        </Dialog>

        <OperationProgressDialog
          open={progress.state.open}
          title={progress.state.title}
          description={progress.state.description}
          phaseLabel={progress.state.phaseLabel}
          detail={progress.state.detail}
          speedLabel={progress.state.speedLabel}
          value={progress.state.value}
          indeterminate={progress.state.indeterminate}
        />
      </div>
    </DashboardLayout>
  );
}

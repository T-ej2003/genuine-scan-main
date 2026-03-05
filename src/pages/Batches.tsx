// src/pages/Batches.tsx

import React, { useEffect, useMemo, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { useAuth } from "@/contexts/AuthContext";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";

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
import { Search, Trash2, RefreshCw, Download, UserCog, Activity, PencilLine } from "lucide-react";

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

type PrinterConnectionStatus = {
  connected: boolean;
  stale: boolean;
  requiredForPrinting: boolean;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  printerName?: string | null;
  printerId?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  error?: string | null;
};

const LARGE_ALLOCATION_THRESHOLD = 25_000;
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

  const [renameOpen, setRenameOpen] = useState(false);
  const [renameBatch, setRenameBatch] = useState<BatchRow | null>(null);
  const [renameValue, setRenameValue] = useState("");

  // direct-print dialog
  const [printOpen, setPrintOpen] = useState(false);
  const [printBatch, setPrintBatch] = useState<BatchRow | null>(null);
  const [printing, setPrinting] = useState(false);

  const [printQuantity, setPrintQuantity] = useState<string>("");
  const [printJobId, setPrintJobId] = useState<string>("");
  const [printLockToken, setPrintLockToken] = useState<string>("");
  const [printJobTokensCount, setPrintJobTokensCount] = useState<number>(0);
  const [directTokenBatchSize, setDirectTokenBatchSize] = useState<string>("1");
  const [directRemainingToPrint, setDirectRemainingToPrint] = useState<number | null>(null);
  const [directPrintTokens, setDirectPrintTokens] = useState<
    Array<{ qrId: string; code: string; renderToken: string; expiresAt: string }>
  >([]);
  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatus>({
    connected: false,
    stale: true,
    requiredForPrinting: true,
    lastHeartbeatAt: null,
    ageSeconds: null,
    printerName: null,
    printerId: null,
    deviceName: null,
    agentVersion: null,
    error: "No printer heartbeat yet",
  });
  const [exportingBatchId, setExportingBatchId] = useState<string | null>(null);

  // allocation history
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyBatch, setHistoryBatch] = useState<BatchRow | null>(null);
  const [historyLogs, setHistoryLogs] = useState<TraceEventRow[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyLastUpdatedAt, setHistoryLastUpdatedAt] = useState<Date | null>(null);

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

  const loadPrinterStatus = async () => {
    if (!isManufacturer) return;
    const res = await apiClient.getPrinterConnectionStatus();
    if (!res.success || !res.data) {
      setPrinterStatus({
        connected: false,
        stale: true,
        requiredForPrinting: true,
        lastHeartbeatAt: null,
        ageSeconds: null,
        printerName: null,
        printerId: null,
        deviceName: null,
        agentVersion: null,
        error: res.error || "Printer status unavailable",
      });
      return;
    }
    setPrinterStatus(res.data as PrinterConnectionStatus);
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

  useEffect(() => {
    if (!isManufacturer) return;
    loadPrinterStatus();
    const timer = window.setInterval(() => {
      loadPrinterStatus();
    }, 6000);
    return () => window.clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isManufacturer, user?.id]);

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
    setAssignOpen(true);
  };

  const openRename = (b: BatchRow) => {
    setRenameBatch(b);
    setRenameValue(b.name || "");
    setRenameOpen(true);
  };

  const submitRename = async () => {
    if (!renameBatch) return;
    const nextName = renameValue.trim();
    if (nextName.length < 2) {
      toast({ title: "Batch name too short", description: "Enter at least 2 characters.", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const res = await apiClient.renameBatch(renameBatch.id, nextName);
      if (!res.success) {
        toast({ title: "Rename failed", description: res.error || "Error", variant: "destructive" });
        return;
      }
      toast({ title: "Batch renamed", description: `Updated to "${nextName}".` });
      setRenameOpen(false);
      setRenameBatch(null);
      setRenameValue("");
      await fetchBatches();
    } finally {
      setLoading(false);
    }
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
      const createdName = data.newBatchName || "Auto";
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
    setDirectTokenBatchSize("1");
    setDirectRemainingToPrint(null);
    setDirectPrintTokens([]);
    setPrintOpen(true);
    loadPrinterStatus();
  };

  const runAutoDirectPrint = async (jobId: string, lockToken: string, requestedQty: number) => {
    let printedCount = 0;
    let remainingToPrint = Math.max(0, requestedQty);
    let guard = 0;

    while (remainingToPrint > 0 && guard < 600) {
      guard += 1;
      const nextBatchSize = Math.max(1, Math.min(25, remainingToPrint));
      const issueRes = await apiClient.requestDirectPrintTokens(jobId, lockToken, nextBatchSize);
      if (!issueRes.success) {
        return {
          success: false,
          printedCount,
          remainingToPrint,
          error: issueRes.error || "Failed to issue direct-print tokens.",
        };
      }

      const issueData: any = issueRes.data || {};
      const items = Array.isArray(issueData.items) ? issueData.items : [];
      setDirectPrintTokens(items);

      if (typeof issueData.remainingToPrint === "number") {
        remainingToPrint = issueData.remainingToPrint;
        setDirectRemainingToPrint(issueData.remainingToPrint);
      }

      if (items.length === 0) {
        if (issueData.jobConfirmed || remainingToPrint === 0) {
          return { success: true, printedCount, remainingToPrint: 0 };
        }
        return {
          success: false,
          printedCount,
          remainingToPrint,
          error: "Print agent received no render tokens while codes remain pending.",
        };
      }

      for (const item of items) {
        const resolveRes = await apiClient.resolveDirectPrintToken(jobId, {
          printLockToken: lockToken,
          renderToken: item.renderToken,
        });
        if (!resolveRes.success) {
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
          };
        }

        const resolvedData: any = resolveRes.data || {};
        const scanUrl = String(resolvedData.scanUrl || "").trim();
        if (!scanUrl) {
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: `Resolved token missing scan URL for ${item.code}.`,
          };
        }

        const localPrintRes = await apiClient.printWithLocalAgent({
          printJobId: jobId,
          qrId: item.qrId,
          code: item.code,
          scanUrl,
          copies: 1,
        });

        if (!localPrintRes.success) {
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: localPrintRes.error || `Local print failed for ${item.code}.`,
          };
        }

        printedCount += 1;
        if (typeof resolvedData.remainingToPrint === "number") {
          remainingToPrint = resolvedData.remainingToPrint;
          setDirectRemainingToPrint(resolvedData.remainingToPrint);
        }
      }
    }

    return {
      success: remainingToPrint === 0,
      printedCount,
      remainingToPrint,
      error:
        remainingToPrint === 0
          ? null
          : "Auto print stopped before all labels completed. Retry remaining labels.",
    };
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

    const livePrinterStatus = await apiClient.getPrinterConnectionStatus();
    if (!livePrinterStatus.success || !livePrinterStatus.data || !(livePrinterStatus.data as any).connected) {
      setPrinterStatus({
        connected: false,
        stale: true,
        requiredForPrinting: true,
        lastHeartbeatAt: null,
        ageSeconds: null,
        printerName: null,
        printerId: null,
        deviceName: null,
        agentVersion: null,
        error: livePrinterStatus.error || "Printer disconnected",
      });
      toast({
        title: "Printer not connected",
        description: "Connect your authenticated print agent and printer before creating a print job.",
        variant: "destructive",
      });
      return;
    }
    setPrinterStatus(livePrinterStatus.data as PrinterConnectionStatus);

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
        typeof data.tokenCount === "number" ? data.tokenCount : 0
      );
      setDirectRemainingToPrint(typeof data.tokenCount === "number" ? data.tokenCount : null);
      setDirectPrintTokens([]);
      const createdJobId = String(data.printJobId || "").trim();
      const createdLockToken = String(data.printLockToken || "").trim();
      if (!createdJobId || !createdLockToken) {
        toast({
          title: "Print job setup incomplete",
          description: "Missing secure print session data. Please retry.",
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Direct-print job created",
        description: "Auto print pipeline started with your connected printer.",
      });

      const autoResult = await runAutoDirectPrint(
        createdJobId,
        createdLockToken,
        typeof data.tokenCount === "number" ? data.tokenCount : qty
      );

      if (autoResult.success) {
        toast({
          title: "Auto print complete",
          description: `${autoResult.printedCount} labels printed through the secure direct-print pipeline.`,
        });
      } else {
        toast({
          title: "Auto print needs attention",
          description:
            autoResult.error ||
            `Printed ${autoResult.printedCount}. Remaining: ${autoResult.remainingToPrint}.`,
          variant: "destructive",
        });
      }
      await fetchBatches();
    } finally {
      setPrinting(false);
    }
  };

  const requestDirectPrintTokens = async () => {
    if (!printJobId || !printLockToken) return;
    const count = Math.max(1, Math.min(100, Number.parseInt(directTokenBatchSize, 10) || 1));

    setPrinting(true);
    try {
      const res = await apiClient.requestDirectPrintTokens(printJobId, printLockToken, count);
      if (!res.success) {
        toast({
          title: "Token request failed",
          description: res.error || "Could not issue direct-print tokens.",
          variant: "destructive",
        });
        return;
      }
      const data: any = res.data || {};
      const items = Array.isArray(data.items) ? data.items : [];
      setDirectPrintTokens(items);
      if (typeof data.remainingToPrint === "number") {
        setDirectRemainingToPrint(data.remainingToPrint);
      }

      if (items.length === 0) {
        toast({
          title: data.jobConfirmed ? "Job confirmed" : "No active tokens",
          description: data.jobConfirmed
            ? "All QR codes in this direct-print job are completed."
            : "No unprinted QR codes are currently available for this job.",
        });
      } else {
        toast({
          title: "Direct-print tokens issued",
          description: `${items.length} one-time render token(s) generated.`,
        });
      }
    } finally {
      setPrinting(false);
    }
  };

  const fetchHistory = async (batch: BatchRow, opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setHistoryLoading(true);
    }
    try {
      const traceRes = await apiClient.getTraceTimeline({ batchId: batch.id, limit: 100 });
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
        setHistoryLastUpdatedAt(new Date());
      } else {
        setHistoryLogs([]);
      }
    } finally {
      setHistoryLoading(false);
    }
  };

  const openHistory = async (b: BatchRow) => {
    setHistoryBatch(b);
    setHistoryOpen(true);
    await fetchHistory(b);
  };

  useEffect(() => {
    if (!historyOpen || !historyBatch) return;
    const timer = window.setInterval(() => {
      fetchHistory(historyBatch, { silent: true });
    }, 8_000);
    return () => window.clearInterval(timer);
  }, [historyOpen, historyBatch]);

  const eventBadgeClass = (eventType?: string) => {
    if (eventType === "COMMISSIONED") return "bg-sky-500/10 text-sky-700";
    if (eventType === "ASSIGNED") return "bg-cyan-500/10 text-cyan-700";
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
                ? "Your assigned QR batches (create direct-print jobs, issue one-time render tokens, then confirm printing)"
                : "Manage received QR batches (assign by quantity / delete / review printing)"}
            </p>
          </div>

          <div className="flex items-center gap-2">
            {isManufacturer && (
              <Button
                variant="outline"
                onClick={loadPrinterStatus}
                className={
                  printerStatus.connected
                    ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
                    : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100"
                }
                title={
                  printerStatus.connected
                    ? `${printerStatus.printerName || "Printer connected"}`
                    : printerStatus.error || "Printer disconnected"
                }
              >
                {printerStatus.connected ? "Printer Connected" : "Printer Offline"}
              </Button>
            )}

            <Button variant="outline" onClick={fetchBatches} disabled={loading}>
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh
            </Button>
          </div>
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
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead>Batch</TableHead>
                    <TableHead>Range</TableHead>
                    <TableHead>Availability</TableHead>
                    <TableHead>Manufacturer</TableHead>
                    <TableHead>Printed</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Controls</TableHead>
                  </TableRow>
                </TableHeader>

                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">
                        Loading...
                      </TableCell>
                    </TableRow>
                  ) : filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-muted-foreground">
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
                              <div className="font-medium break-words">{b.name}</div>
                              <div className="text-[11px] text-muted-foreground font-mono break-all">{b.id}</div>
                              {b.licensee?.name ? (
                                <div className="text-xs text-muted-foreground">
                                  {b.licensee.name} ({b.licensee.prefix})
                                </div>
                              ) : (
                                <div className="text-xs text-muted-foreground">{b.licenseeId}</div>
                              )}
                              <div className="flex items-center gap-2 text-xs">
                                <Badge variant={assignedCount > 0 ? "default" : "secondary"}>{assignedCount} assigned</Badge>
                                <Badge variant={b.totalCodes > 0 ? "outline" : "secondary"}>{b.totalCodes} total</Badge>
                              </div>
                            </div>
                          </TableCell>

                          <TableCell className="font-mono text-xs">
                            <div className="break-all">{b.startCode}</div>
                            <div className="break-all">{b.endCode}</div>
                          </TableCell>

                          <TableCell>
                            <div className="space-y-1">
                              <Badge variant={b.availableCodes ? "default" : "secondary"}>{b.availableCodes ?? 0} remaining</Badge>
                              <div className="text-[11px] text-muted-foreground font-mono break-all">
                                {b.remainingStartCode && b.remainingEndCode
                                  ? `${b.remainingStartCode} → ${b.remainingEndCode}`
                                  : "—"}
                              </div>
                            </div>
                          </TableCell>

                          <TableCell>
                            {b.manufacturer ? (
                              <div className="space-y-1">
                                <div>{b.manufacturer.name}</div>
                                <div className="text-xs text-muted-foreground break-all">{b.manufacturer.email}</div>
                              </div>
                            ) : (
                              <span className="text-muted-foreground">Unassigned</span>
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

                          <TableCell>
                            {/* Manufacturer: direct-print controls */}
                            {isManufacturer ? (
                              <div className="flex flex-wrap gap-2">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  disabled={loading || (b.availableCodes ?? 0) <= 0 || !printerStatus.connected}
                                  onClick={() => openPrintPack(b)}
                                >
                                  <Download className="mr-2 h-4 w-4" />
                                  {"Create Print Job"}
                                </Button>
                              </div>
                            ) : (
                              <div className="rounded-lg border bg-muted/20 p-2">
                                <div className="mb-2 text-[11px] font-medium text-muted-foreground">Control Panel</div>
                                <div className="flex flex-wrap gap-2">
                                  <Button size="sm" variant="outline" onClick={() => openHistory(b)}>
                                    <Activity className="mr-2 h-4 w-4" />
                                    History
                                  </Button>
                                  <Button size="sm" variant="outline" onClick={() => openRename(b)} disabled={!!b.printedAt}>
                                    <PencilLine className="mr-2 h-4 w-4" />
                                    Rename
                                  </Button>
                                  {canAssignManufacturer && (
                                    <Button size="sm" variant="outline" onClick={() => openAssign(b)} disabled={!!b.manufacturer || !!b.printedAt}>
                                      <UserCog className="mr-2 h-4 w-4" />
                                      Assign
                                    </Button>
                                  )}
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => downloadAuditPackage(b)}
                                    disabled={exportingBatchId === b.id}
                                  >
                                    <Download className="mr-2 h-4 w-4" />
                                    {exportingBatchId === b.id ? "Preparing..." : "Audit"}
                                  </Button>
                                  {canDelete && (
                                    <Button size="sm" variant="outline" className="text-destructive" onClick={() => handleDelete(b)}>
                                      <Trash2 className="mr-2 h-4 w-4" />
                                      Delete
                                    </Button>
                                  )}
                                </div>
                              </div>
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

        {/* Rename Batch Dialog */}
        <Dialog
          open={renameOpen}
          onOpenChange={(v) => {
            setRenameOpen(v);
            if (!v) {
              setRenameBatch(null);
              setRenameValue("");
            }
          }}
        >
          <DialogContent className="sm:max-w-[520px]">
            <DialogHeader>
              <DialogTitle>Rename Batch</DialogTitle>
              <DialogDescription>Update the batch label for easier operations tracking.</DialogDescription>
            </DialogHeader>

            {!renameBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div className="rounded-md border p-3 text-sm">
                  <div className="font-medium">{renameBatch.name}</div>
                  <div className="text-muted-foreground font-mono text-xs">{renameBatch.id}</div>
                </div>

                <div className="space-y-2">
                  <Label>Batch name</Label>
                  <Input
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    maxLength={120}
                    placeholder="Enter batch name"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setRenameOpen(false)} disabled={loading}>
                    Cancel
                  </Button>
                  <Button onClick={submitRename} disabled={loading}>
                    Save
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Print Job Dialog */}
        <Dialog
          open={printOpen}
          onOpenChange={(v) => {
            setPrintOpen(v);
            if (!v) {
              setPrintBatch(null);
              setDirectPrintTokens([]);
              setDirectRemainingToPrint(null);
            }
          }}
        >
          <DialogContent className="sm:max-w-[640px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Print Job</DialogTitle>
              <DialogDescription>
                Select quantity, create a direct-print job, and issue one-time short-lived render tokens for your authenticated
                print agent.
              </DialogDescription>
            </DialogHeader>

            {!printBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div
                  className={
                    printerStatus.connected
                      ? "rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800"
                      : "rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
                  }
                >
                  <div className="font-medium">
                    {printerStatus.connected ? "Printer connected" : "Printer offline"}
                  </div>
                  <div className="text-xs">
                    {printerStatus.connected
                      ? `${printerStatus.printerName || "Authenticated print agent"} is ready. Create print job will auto-print labels.`
                      : printerStatus.error || "Connect authenticated print agent and printer to continue."}
                  </div>
                </div>

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
                  <Button onClick={createPrintJob} disabled={printing || !printerStatus.connected}>
                    {printing ? "Auto printing..." : "Create Print Job & Auto Print"}
                  </Button>
                  {printJobId && (
                    <Badge variant="secondary" title={printJobId}>
                      {friendlyReferenceLabel(printJobId, "Job")} · #{shortRawReference(printJobId, 8)}
                    </Badge>
                  )}
                </div>

                {printJobId && printLockToken && (
                  <div className="rounded-md border p-3 text-sm space-y-2">
                    <div className="text-xs text-muted-foreground">Print Lock Token</div>
                    <div className="font-mono text-xs break-all">{printLockToken}</div>
                    <div className="text-xs text-muted-foreground">
                      Secured QRs in this job: {printJobTokensCount}
                    </div>
                    {directRemainingToPrint != null && (
                      <div className="text-xs text-muted-foreground">Remaining to print: {directRemainingToPrint}</div>
                    )}
                  </div>
                )}

                {printJobId && printLockToken && (
                  <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm space-y-3">
                    <div className="font-medium text-emerald-900">Direct-print pipeline active</div>
                    <div className="text-xs text-emerald-900">
                      ZIP/PNG distribution is disabled for manufacturer security hardening. Use authenticated print-agent calls
                      to request one-time render tokens per QR.
                    </div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-[1fr_auto] sm:items-end">
                      <div className="space-y-1">
                        <Label className="text-xs">Tokens per request</Label>
                        <Input
                          type="number"
                          min={1}
                          max={100}
                          value={directTokenBatchSize}
                          onChange={(e) => setDirectTokenBatchSize(e.target.value)}
                        />
                      </div>
                      <Button variant="outline" onClick={requestDirectPrintTokens} disabled={printing || !printJobId}>
                        Issue one-time tokens
                      </Button>
                    </div>

                    {directPrintTokens.length > 0 && (
                      <div className="space-y-2">
                        <div className="text-xs font-medium">Issued Token Set</div>
                        <div className="max-h-48 overflow-auto rounded-md border bg-background p-2 space-y-2">
                          {directPrintTokens.map((item) => (
                            <div key={item.qrId} className="rounded border p-2">
                              <div className="text-xs text-muted-foreground">{item.code}</div>
                              <div className="font-mono text-[11px] break-all">{item.renderToken}</div>
                              <div className="text-[11px] text-muted-foreground">Expires: {item.expiresAt}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex justify-end gap-3 pt-2">
                  <Button variant="outline" onClick={() => setPrintOpen(false)} disabled={printing}>
                    Close
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>

        {/* Allocation History Dialog */}
        <Dialog
          open={historyOpen}
          onOpenChange={(v) => {
            setHistoryOpen(v);
            if (!v) {
              setHistoryBatch(null);
              setHistoryLogs([]);
              setHistoryLastUpdatedAt(null);
            }
          }}
        >
          <DialogContent className="sm:max-w-[700px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Batch History</DialogTitle>
              <DialogDescription>
                {historyBatch ? historyBatch.name : "Selected batch"} — lifecycle timeline (COMMISSIONED → ASSIGNED → PRINTED → REDEEMED/BLOCKED)
              </DialogDescription>
            </DialogHeader>

            <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border bg-muted/20 px-3 py-2 text-xs">
              <div className="flex items-center gap-2">
                <Badge className="bg-emerald-500/10 text-emerald-700">Live</Badge>
                <span className="text-muted-foreground">
                  {historyLastUpdatedAt ? `Updated ${format(historyLastUpdatedAt, "PPp")}` : "Waiting for first snapshot..."}
                </span>
              </div>
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  if (!historyBatch) return;
                  fetchHistory(historyBatch);
                }}
                disabled={!historyBatch || historyLoading}
              >
                <RefreshCw className="mr-2 h-4 w-4" />
                Refresh now
              </Button>
            </div>

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

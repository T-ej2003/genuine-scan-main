// src/pages/Batches.tsx

import React, { useEffect, useMemo, useRef, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { useAuth } from "@/contexts/AuthContext";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import apiClient from "@/lib/api-client";
import { friendlyReferenceLabel, shortRawReference } from "@/lib/friendly-reference";
import { getPrinterDiagnosticSummary, type LocalPrinterAgentSnapshot } from "@/lib/printer-diagnostics";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { BatchAllocationMapDialog } from "@/components/batches/BatchAllocationMapDialog";

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
import QRCode from "qrcode";
import { useNavigate, useSearchParams } from "react-router-dom";

import { saveAs } from "file-saver";

type BatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  manufacturerId?: string | null;
  batchKind?: "RECEIVED_PARENT" | "MANUFACTURER_CHILD";
  parentBatchId?: string | null;
  rootBatchId?: string | null;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: string | null;
  createdAt: string;
  licensee?: { id: string; name: string; prefix: string };
  manufacturer?: { id: string; name: string; email: string };
  _count?: { qrCodes: number };
  availableCodes?: number;
  unassignedRemainingCodes?: number;
  assignedCodes?: number;
  printableCodes?: number;
  printedCodes?: number;
  redeemedCodes?: number;
  blockedCodes?: number;
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
  trusted: boolean;
  compatibilityMode: boolean;
  compatibilityReason?: string | null;
  eligibleForPrinting: boolean;
  connectionClass?: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
  stale: boolean;
  requiredForPrinting: boolean;
  trustStatus?: string;
  trustReason?: string | null;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  registrationId?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  mtlsFingerprint?: string | null;
  printerName?: string | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  capabilitySummary?: {
    transports: string[];
    protocols: string[];
    languages: string[];
    supportsRaster: boolean;
    supportsPdf: boolean;
    dpiOptions: number[];
    mediaSizes: string[];
  } | null;
  printers?: Array<{
    printerId: string;
    printerName: string;
    model?: string | null;
    connection?: string | null;
    online?: boolean;
    isDefault?: boolean;
    protocols?: string[];
    languages?: string[];
    mediaSizes?: string[];
    dpi?: number | null;
  }>;
  calibrationProfile?: Record<string, unknown> | null;
  error?: string | null;
};

type LocalPrinterRow = {
  printerId: string;
  printerName: string;
  model?: string | null;
  connection?: string | null;
  online?: boolean;
  isDefault?: boolean;
  protocols?: string[];
  languages?: string[];
  mediaSizes?: string[];
  dpi?: number | null;
};

const LARGE_ALLOCATION_THRESHOLD = 25_000;
const PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS = 3 * 60 * 1000;
export default function Batches() {
  const { toast } = useToast();
  const { user } = useAuth();
  const progress = useOperationProgress();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

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
    Array<{ printItemId: string; qrId: string; code: string; renderToken: string; expiresAt: string }>
  >([]);
  const [detectedPrinters, setDetectedPrinters] = useState<LocalPrinterRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState<string>("");
  const [switchingPrinter, setSwitchingPrinter] = useState(false);
  const [printPath, setPrintPath] = useState<"auto" | "spooler" | "raw-9100" | "label-language" | "pdf-raster">("auto");
  const [labelLanguage, setLabelLanguage] = useState<"AUTO" | "ZPL" | "EPL" | "CPCL" | "TSPL" | "ESC_POS">("AUTO");
  const [calibrationProfile, setCalibrationProfile] = useState({
    dpi: "",
    labelWidthMm: "50",
    labelHeightMm: "50",
    offsetXmm: "0",
    offsetYmm: "0",
    darkness: "",
    speed: "",
  });
  const [printProgressOpen, setPrintProgressOpen] = useState(false);
  const [printProgressPhase, setPrintProgressPhase] = useState("Preparing print pipeline");
  const [printProgressTotal, setPrintProgressTotal] = useState(0);
  const [printProgressPrinted, setPrintProgressPrinted] = useState(0);
  const [printProgressRemaining, setPrintProgressRemaining] = useState(0);
  const [printProgressCurrentCode, setPrintProgressCurrentCode] = useState<string | null>(null);
  const [printProgressError, setPrintProgressError] = useState<string | null>(null);
  const printerFailureReportRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });
  const printerFailureInFlightRef = useRef(false);
  const [localPrinterAgent, setLocalPrinterAgent] = useState<LocalPrinterAgentSnapshot>({
    reachable: false,
    connected: false,
    error: "Local print agent has not been checked yet.",
    checkedAt: null,
  });
  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatus>({
    connected: false,
    trusted: false,
    compatibilityMode: false,
    compatibilityReason: null,
    eligibleForPrinting: false,
    connectionClass: "BLOCKED",
    stale: true,
    requiredForPrinting: true,
    trustStatus: "UNREGISTERED",
    trustReason: "No trusted printer registration",
    lastHeartbeatAt: null,
    ageSeconds: null,
    registrationId: null,
    agentId: null,
    deviceFingerprint: null,
    mtlsFingerprint: null,
    printerName: null,
    printerId: null,
    selectedPrinterId: null,
    selectedPrinterName: null,
    deviceName: null,
    agentVersion: null,
    capabilitySummary: null,
    printers: [],
    calibrationProfile: null,
    error: "No trusted printer heartbeat yet",
  });
  const [exportingBatchId, setExportingBatchId] = useState<string | null>(null);
  const [allocationMapOpen, setAllocationMapOpen] = useState(false);
  const [allocationMapLoading, setAllocationMapLoading] = useState(false);
  const [allocationMap, setAllocationMap] = useState<any | null>(null);
  const [allocationHint, setAllocationHint] = useState<{ title: string; body: string } | null>(null);

  // allocation history
  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyBatch, setHistoryBatch] = useState<BatchRow | null>(null);
  const [historyLogs, setHistoryLogs] = useState<TraceEventRow[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyLastUpdatedAt, setHistoryLastUpdatedAt] = useState<Date | null>(null);
  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
  const printerHasInventory =
    detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId);
  const printerUnavailable = !printerReady && !printerHasInventory;
  const printerDiagnostics = useMemo(
    () =>
      getPrinterDiagnosticSummary({
        localAgent: localPrinterAgent,
        remoteStatus: printerStatus,
        printers: detectedPrinters,
        selectedPrinterId,
      }),
    [detectedPrinters, localPrinterAgent, printerStatus, selectedPrinterId]
  );

  const normalizePrinterRows = (rows: unknown): LocalPrinterRow[] => {
    if (!Array.isArray(rows)) return [];
    const result: LocalPrinterRow[] = [];
    for (const row of rows) {
      if (!row || typeof row !== "object") continue;
      const printerId = String((row as any).printerId || (row as any).id || "").trim();
      const printerName = String((row as any).printerName || (row as any).name || "").trim();
      if (!printerId || !printerName) continue;
      result.push({
        printerId,
        printerName,
        model: String((row as any).model || "").trim() || null,
        connection: String((row as any).connection || (row as any).transport || "").trim() || null,
        online: Boolean((row as any).online ?? true),
        isDefault: Boolean((row as any).isDefault),
        protocols: Array.isArray((row as any).protocols) ? (row as any).protocols : [],
        languages: Array.isArray((row as any).languages) ? (row as any).languages : [],
        mediaSizes: Array.isArray((row as any).mediaSizes) ? (row as any).mediaSizes : [],
        dpi: Number.isFinite(Number((row as any).dpi)) ? Number((row as any).dpi) : null,
      });
      if (result.length >= 40) break;
    }
    return result;
  };

  const buildCalibrationPayload = () => ({
    dpi: Number(calibrationProfile.dpi || 0) || undefined,
    labelWidthMm: Number(calibrationProfile.labelWidthMm || 0) || undefined,
    labelHeightMm: Number(calibrationProfile.labelHeightMm || 0) || undefined,
    offsetXmm: Number(calibrationProfile.offsetXmm || 0) || 0,
    offsetYmm: Number(calibrationProfile.offsetYmm || 0) || 0,
    darkness: Number(calibrationProfile.darkness || 0) || undefined,
    speed: Number(calibrationProfile.speed || 0) || undefined,
  });

  const printWithBrowserFallback = async (params: { code: string; scanUrl: string; copies?: number }) => {
    const dataUrl = await QRCode.toDataURL(params.scanUrl, {
      margin: 1,
      width: 420,
      errorCorrectionLevel: "M",
    });
    const popup = window.open("", "_blank", "width=560,height=760");
    if (!popup) {
      throw new Error("Browser print popup blocked");
    }
    popup.document.write(`
      <!doctype html>
      <html>
      <head>
        <title>MSCQR Print ${params.code}</title>
        <style>
          body { margin: 0; padding: 18px; font-family: Arial, sans-serif; }
          .label { width: 52mm; min-height: 52mm; border: 1px dashed #ccc; padding: 8px; box-sizing: border-box; }
          .code { font-size: 11px; margin-bottom: 6px; }
          img { width: 100%; height: auto; display: block; }
          .url { margin-top: 6px; font-size: 9px; word-break: break-all; color: #444; }
        </style>
      </head>
      <body>
        <div class="label">
          <div class="code">${params.code}</div>
          <img src="${dataUrl}" alt="QR ${params.code}" />
          <div class="url">${params.scanUrl}</div>
        </div>
      </body>
      </html>
    `);
    popup.document.close();
    popup.focus();
    popup.print();
    popup.close();
    return {
      success: true,
      data: {
        queued: true,
        printerName: "Browser print dialog",
        jobRef: `browser-${Date.now()}`,
      },
    };
  };

  const autoReportPrinterFailure = async (params: {
    context: string;
    reason: string;
    diagnostics?: Record<string, unknown>;
  }) => {
    const now = Date.now();
    const signature = `${params.context}|${params.reason}|${selectedPrinterId || printerStatus.selectedPrinterId || printerStatus.printerId || ""}`;
    if (
      printerFailureReportRef.current.signature === signature &&
      now - printerFailureReportRef.current.at < PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS
    ) {
      return;
    }
    if (printerFailureInFlightRef.current) return;

    printerFailureInFlightRef.current = true;
    printerFailureReportRef.current = { signature, at: now };
    try {
      const screenshot = await captureSupportScreenshot();
      const form = new FormData();
      form.append(
        "title",
        `Auto printer failure (${params.context}): ${printerStatus.selectedPrinterName || printerStatus.printerName || "Unknown printer"}`
      );
      form.append("description", params.reason);
      form.append("sourcePath", `${window.location.pathname}${window.location.search}`);
      form.append("pageUrl", window.location.href);
      form.append("autoDetected", "true");
      form.append(
        "diagnostics",
        JSON.stringify({
          ...buildSupportDiagnosticsPayload(),
          printerStatus,
          selectedPrinterId,
          detectedPrinters,
          printPath,
          labelLanguage,
          context: params.context,
          details: params.diagnostics || null,
        })
      );
      if (screenshot) form.append("screenshot", screenshot);
      await apiClient.createSupportIssueReport(form);
    } catch {
      // avoid interrupting print flow for auto-report failure
    } finally {
      printerFailureInFlightRef.current = false;
    }
  };

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
    const [remote, local] = await Promise.all([
      apiClient.getPrinterConnectionStatus(),
      apiClient.getLocalPrintAgentStatus(),
    ]);
    const localPrinters = normalizePrinterRows((local as any)?.data?.printers || []);
    setLocalPrinterAgent({
      reachable: Boolean(local.success),
      connected: Boolean((local as any)?.data?.connected),
      error: local.success ? String((local as any)?.data?.error || "").trim() || null : String(local.error || "Local print agent is unavailable"),
      checkedAt: new Date().toISOString(),
    });

    if (!remote.success || !remote.data) {
      setPrinterStatus({
        connected: false,
        trusted: false,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        requiredForPrinting: true,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        registrationId: null,
        agentId: null,
        deviceFingerprint: null,
        mtlsFingerprint: null,
        printerName: null,
        printerId: null,
        selectedPrinterId: null,
        selectedPrinterName: null,
        deviceName: null,
        agentVersion: null,
        capabilitySummary: null,
        printers: localPrinters,
        calibrationProfile: null,
        error: remote.error || local.error || "Printer status unavailable",
      });
      setDetectedPrinters(localPrinters);
      return;
    }

    const mergedPrinters =
      normalizePrinterRows((remote.data as PrinterConnectionStatus).printers || []).length > 0
        ? normalizePrinterRows((remote.data as PrinterConnectionStatus).printers || [])
        : localPrinters;

    setPrinterStatus({
      ...(remote.data as PrinterConnectionStatus),
      printers: mergedPrinters,
    });
    setDetectedPrinters(mergedPrinters);

    const preferredPrinterId =
      String(
        (remote.data as any).selectedPrinterId ||
          (local as any)?.data?.selectedPrinterId ||
          mergedPrinters.find((row) => row.isDefault)?.printerId ||
          mergedPrinters[0]?.printerId ||
          ""
      ).trim();
    if (preferredPrinterId) {
      setSelectedPrinterId(preferredPrinterId);
    }
  };

  useEffect(() => {
    fetchBatches();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const manufacturerName = String(searchParams.get("manufacturerName") || "").trim();
    const printState = String(searchParams.get("printState") || "").trim().toLowerCase();
    if (manufacturerName) {
      setQ(manufacturerName);
      setAssignmentFilter("assigned");
    }
    if (printState === "printed" || printState === "pending") {
      setPrintFilter(printState === "printed" ? "printed" : "unprinted");
    }
  }, [searchParams]);

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

  useEffect(() => {
    if (!selectedPrinterId) return;
    const key = `printer-calibration:${selectedPrinterId}`;
    try {
      const raw = window.localStorage.getItem(key);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== "object") return;
      setCalibrationProfile((prev) => ({
        dpi: parsed.dpi ? String(parsed.dpi) : prev.dpi,
        labelWidthMm: parsed.labelWidthMm ? String(parsed.labelWidthMm) : prev.labelWidthMm,
        labelHeightMm: parsed.labelHeightMm ? String(parsed.labelHeightMm) : prev.labelHeightMm,
        offsetXmm: parsed.offsetXmm != null ? String(parsed.offsetXmm) : prev.offsetXmm,
        offsetYmm: parsed.offsetYmm != null ? String(parsed.offsetYmm) : prev.offsetYmm,
        darkness: parsed.darkness ? String(parsed.darkness) : prev.darkness,
        speed: parsed.speed ? String(parsed.speed) : prev.speed,
      }));
    } catch {
      // ignore malformed local calibration profile
    }
  }, [selectedPrinterId]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    const manufacturerIdFilter = String(searchParams.get("manufacturerId") || "").trim();
    return rows.filter((b) => {
      if (manufacturerIdFilter && String(b.manufacturer?.id || b.manufacturerId || "").trim() !== manufacturerIdFilter) {
        return false;
      }
      if (isManufacturer) {
        if (printFilter === "printed" && !b.printedAt) return false;
        if (printFilter === "unprinted" && b.printedAt) return false;
      } else {
        const isAssignedRow = b.batchKind === "MANUFACTURER_CHILD" || Boolean(b.manufacturer);
        if (assignmentFilter === "assigned" && !isAssignedRow) return false;
        if (assignmentFilter === "unassigned" && isAssignedRow) return false;
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
  }, [rows, q, assignmentFilter, isManufacturer, printFilter, searchParams]);

  const getAvailableInventory = (batch: BatchRow) =>
    batch.batchKind === "MANUFACTURER_CHILD"
      ? Number(batch.printableCodes ?? batch.availableCodes ?? 0)
      : Number(batch.unassignedRemainingCodes ?? batch.availableCodes ?? 0);

  const getAvailabilityTitle = (batch: BatchRow) =>
    batch.batchKind === "MANUFACTURER_CHILD" ? "Ready to print" : "Unassigned remaining";

  const getAvailabilityTone = (value: number) => (value > 0 ? "default" : "secondary");

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
    const availableInventory = getAvailableInventory(assignBatch);
    if (availableInventory > 0 && qty > availableInventory) {
      toast({
        title: "Quantity too large",
        description: `Unassigned remaining: ${availableInventory}.`,
        variant: "destructive",
      });
      return;
    }

    const showLargeAllocationProgress = qty >= LARGE_ALLOCATION_THRESHOLD;
    if (showLargeAllocationProgress) {
      progress.start({
        title: "Allocating QR batch",
        description: "Validating remainder, assigning manufacturer, and creating allocated batch.",
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
          `Allocated ${qty.toLocaleString()} codes. Batch ${data.newBatchId || "(id pending)"} is ready for print.`
        );
      }
      if (data.message?.title || data.message?.body) {
        setAllocationHint({
          title: data.message?.title || "Allocation complete",
          body: data.message?.body || "The source batch retains the remainder and the allocated batch is ready for print.",
        });
      }
      toast({
        title: "Assigned",
        description: `Created allocated batch ${data.newBatchId || "(id pending)"}: ${createdName}`,
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
    setPrintProgressOpen(false);
    setPrintProgressPhase("Preparing print pipeline");
    setPrintProgressTotal(0);
    setPrintProgressPrinted(0);
    setPrintProgressRemaining(0);
    setPrintProgressCurrentCode(null);
    setPrintProgressError(null);
    setPrintOpen(true);
    void loadPrinterStatus();
  };

  const switchSelectedPrinter = async () => {
    if (!selectedPrinterId) return;
    setSwitchingPrinter(true);
    try {
      const response = await apiClient.selectLocalPrinter(selectedPrinterId);
      if (!response.success) {
        toast({
          title: "Switch failed",
          description: response.error || "Could not switch local printer.",
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Printer switched", description: "Local print agent updated active printer." });
      await loadPrinterStatus();
    } finally {
      setSwitchingPrinter(false);
    }
  };

  const applyCalibration = async () => {
    if (!selectedPrinterId) return;
    setSwitchingPrinter(true);
    try {
      const calibrationPayload = {
        printerId: selectedPrinterId,
        ...buildCalibrationPayload(),
      };
      const response = await apiClient.applyLocalPrinterCalibration(calibrationPayload);
      if (!response.success) {
        toast({
          title: "Calibration failed",
          description: response.error || "Could not apply calibration profile.",
          variant: "destructive",
        });
        return;
      }
      try {
        window.localStorage.setItem(`printer-calibration:${selectedPrinterId}`, JSON.stringify(calibrationPayload));
      } catch {
        // non-blocking local persistence
      }
      toast({ title: "Calibration saved", description: "Alignment profile applied to local printer." });
      await loadPrinterStatus();
    } finally {
      setSwitchingPrinter(false);
    }
  };

  const runAutoDirectPrint = async (jobId: string, lockToken: string, requestedQty: number) => {
    let printedCount = 0;
    let remainingToPrint = Math.max(0, requestedQty);
    let guard = 0;
    let usedBrowserFallback = false;

    setPrintProgressOpen(true);
    setPrintProgressTotal(requestedQty);
    setPrintProgressPrinted(0);
    setPrintProgressRemaining(remainingToPrint);
    setPrintProgressCurrentCode(null);
    setPrintProgressError(null);
    setPrintProgressPhase("Issuing one-time render tokens");

    while (remainingToPrint > 0 && guard < 600) {
      guard += 1;
      const nextBatchSize = Math.max(1, Math.min(250, remainingToPrint));
      const issueRes = await apiClient.requestDirectPrintTokens(jobId, lockToken, nextBatchSize);
      if (!issueRes.success) {
        setPrintProgressError(issueRes.error || "Failed to issue direct-print tokens.");
        return {
          success: false,
          printedCount,
          remainingToPrint,
          usedBrowserFallback,
          error: issueRes.error || "Failed to issue direct-print tokens.",
        };
      }

      const issueData: any = issueRes.data || {};
      const items = Array.isArray(issueData.items) ? issueData.items : [];
      setDirectPrintTokens(items);

      if (typeof issueData.remainingToPrint === "number") {
        remainingToPrint = issueData.remainingToPrint;
        setDirectRemainingToPrint(issueData.remainingToPrint);
        setPrintProgressRemaining(issueData.remainingToPrint);
      }

      if (items.length === 0) {
        if (issueData.jobConfirmed || remainingToPrint === 0) {
          setPrintProgressPhase("Print session completed");
          return { success: true, printedCount, remainingToPrint: 0, usedBrowserFallback };
        }
        setPrintProgressError("Print agent received no render tokens while codes remain pending.");
        return {
          success: false,
          printedCount,
          remainingToPrint,
          usedBrowserFallback,
          error: "Print agent received no render tokens while codes remain pending.",
        };
      }

      for (const item of items) {
        setPrintProgressPhase("Resolving token and sending print command");
        setPrintProgressCurrentCode(item.code);
        const resolveRes = await apiClient.resolveDirectPrintToken(jobId, {
          printLockToken: lockToken,
          renderToken: item.renderToken,
        });
        if (!resolveRes.success) {
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
            printItemId: item.printItemId,
            retries: 0,
          });
          setPrintProgressError(resolveRes.error || `Failed to resolve render token for ${item.code}.`);
          void autoReportPrinterFailure({
            context: "resolve_direct_print_token",
            reason: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
            diagnostics: { jobId, printItemId: item.printItemId, code: item.code },
          });
          return {
            success: false,
            printedCount,
            remainingToPrint,
            usedBrowserFallback,
            error: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
          };
        }

        const resolvedData: any = resolveRes.data || {};
        const printItemId = String(resolvedData.printItemId || item.printItemId || "").trim();
        const scanUrl = String(resolvedData.scanUrl || "").trim();
        if (!scanUrl || !printItemId) {
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: `Resolved token missing print session metadata for ${item.code}.`,
            printItemId: printItemId || item.printItemId,
            retries: 0,
          });
          setPrintProgressError(`Resolved token missing scan URL or print item id for ${item.code}.`);
          return {
            success: false,
            printedCount,
            remainingToPrint,
            usedBrowserFallback,
            error: `Resolved token missing scan URL or print item id for ${item.code}.`,
          };
        }

        let localPrintRes = await apiClient.printWithLocalAgent({
          printJobId: jobId,
          qrId: item.qrId,
          code: item.code,
          scanUrl,
          copies: 1,
          printerId: selectedPrinterId || printerStatus.selectedPrinterId || undefined,
          printPath,
          labelLanguage,
          mediaSize:
            (printerStatus.capabilitySummary?.mediaSizes && printerStatus.capabilitySummary.mediaSizes[0]) ||
            undefined,
          calibrationProfile: buildCalibrationPayload(),
        });

        if (!localPrintRes.success) {
          const canFallbackToBrowser =
            printerStatus.compatibilityMode ||
            String(localPrintRes.error || "").toLowerCase().includes("unavailable") ||
            String(localPrintRes.error || "").toLowerCase().includes("timed out");
          if (canFallbackToBrowser) {
            try {
              setPrintProgressPhase("Falling back to browser print dialog");
              localPrintRes = await printWithBrowserFallback({
                code: item.code,
                scanUrl,
                copies: 1,
              });
              usedBrowserFallback = true;
            } catch (fallbackError: any) {
              localPrintRes = {
                success: false,
                error: fallbackError?.message || "Browser print fallback failed",
              } as any;
            }
          }
        }

        if (!localPrintRes.success) {
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: localPrintRes.error || `Local print failed for ${item.code}.`,
            printItemId,
            retries: 0,
            agentMetadata: {
              selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
              printPath,
              labelLanguage,
              calibrationProfile: buildCalibrationPayload(),
            },
          });
          setPrintProgressError(localPrintRes.error || `Local print failed for ${item.code}.`);
          void autoReportPrinterFailure({
            context: "local_print",
            reason: localPrintRes.error || `Local print failed for ${item.code}.`,
            diagnostics: {
              jobId,
              printItemId,
              code: item.code,
              selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
              printPath,
              labelLanguage,
            },
          });
          return {
            success: false,
            printedCount,
            remainingToPrint,
            usedBrowserFallback,
            error: localPrintRes.error || `Local print failed for ${item.code}.`,
          };
        }

        setPrintProgressPhase("Confirming printed label with server");
        const confirmRes = await apiClient.confirmDirectPrintItem(jobId, {
          printLockToken: lockToken,
          printItemId,
          agentMetadata: {
            localPrintSuccess: true,
            localAgentVersion: (localPrintRes as any)?.data?.agentVersion || null,
            selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
            selectedPrinterName: printerStatus.selectedPrinterName || printerStatus.printerName || null,
            printPath,
            labelLanguage,
            usedBrowserFallback,
            calibrationProfile: buildCalibrationPayload(),
          },
        });
        if (!confirmRes.success) {
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: confirmRes.error || `Failed to confirm print item ${item.code}.`,
            printItemId,
            retries: 0,
          });
          setPrintProgressError(confirmRes.error || `Failed to confirm print item ${item.code}.`);
          return {
            success: false,
            printedCount,
            remainingToPrint,
            usedBrowserFallback,
            error: confirmRes.error || `Failed to confirm print item ${item.code}.`,
          };
        }

        const confirmData: any = confirmRes.data || {};
        printedCount += 1;
        setPrintProgressPrinted(printedCount);
        if (typeof confirmData.remainingToPrint === "number") {
          remainingToPrint = confirmData.remainingToPrint;
          setDirectRemainingToPrint(confirmData.remainingToPrint);
          setPrintProgressRemaining(confirmData.remainingToPrint);
        }
      }
    }

    setPrintProgressPhase(remainingToPrint === 0 ? "Print session completed" : "Print session paused");
    return {
      success: remainingToPrint === 0,
      printedCount,
      remainingToPrint,
      usedBrowserFallback,
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
    const availableInventory = getAvailableInventory(printBatch);
    if (availableInventory > 0 && qty > availableInventory) {
      toast({
        title: "Quantity too large",
        description: `Ready to print: ${availableInventory}.`,
        variant: "destructive",
      });
      return;
    }

    const livePrinterStatus = await apiClient.getPrinterConnectionStatus();
    if (
      !livePrinterStatus.success ||
      !livePrinterStatus.data ||
      !(livePrinterStatus.data as any).connected ||
      !(livePrinterStatus.data as any).eligibleForPrinting
    ) {
      setPrinterStatus({
        connected: false,
        trusted: false,
        compatibilityMode: false,
        compatibilityReason: null,
        eligibleForPrinting: false,
        connectionClass: "BLOCKED",
        stale: true,
        requiredForPrinting: true,
        trustStatus: "UNREGISTERED",
        trustReason: "No trusted printer registration",
        lastHeartbeatAt: null,
        ageSeconds: null,
        registrationId: null,
        agentId: null,
        deviceFingerprint: null,
        mtlsFingerprint: null,
        printerName: null,
        printerId: null,
        selectedPrinterId: null,
        selectedPrinterName: null,
        deviceName: null,
        agentVersion: null,
        capabilitySummary: null,
        printers: detectedPrinters,
        calibrationProfile: null,
        error: livePrinterStatus.error || (detectedPrinters.length > 0 ? "Printer connection requires attention" : "Printer unavailable"),
      });
      toast({
        title: "Printer unavailable",
        description: "Reconnect print agent or select a compatible local printer profile before creating a print job.",
        variant: "destructive",
      });
      void autoReportPrinterFailure({
        context: "create_print_job_printer_gate",
        reason: String(livePrinterStatus.error || "Printer not eligible for printing"),
      });
      return;
    }
    setPrinterStatus(livePrinterStatus.data as PrinterConnectionStatus);

    const selectedPrinter =
      detectedPrinters.find((row) => row.printerId === selectedPrinterId) ||
      detectedPrinters.find((row) => row.printerId === (livePrinterStatus.data as any).selectedPrinterId) ||
      null;
    if (selectedPrinter && selectedPrinter.online === false) {
      toast({
        title: "Selected printer offline",
        description: "Switch to an online printer and retry.",
        variant: "destructive",
      });
      return;
    }

    try {
      if (selectedPrinterId) {
        window.localStorage.setItem(
          `printer-calibration:${selectedPrinterId}`,
          JSON.stringify({
            printerId: selectedPrinterId,
            ...buildCalibrationPayload(),
          })
        );
      }
    } catch {
      // local persistence best-effort only
    }

    setPrinting(true);
    try {
      setPrintProgressOpen(true);
      setPrintProgressPhase("Creating secure print session");
      setPrintProgressError(null);
      setPrintProgressCurrentCode(null);
      setPrintProgressPrinted(0);
      setPrintProgressTotal(qty);
      setPrintProgressRemaining(qty);

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
        setPrintProgressError(res.error || "Print job setup failed.");
        void autoReportPrinterFailure({
          context: "create_print_job",
          reason: res.error || "Print job setup failed",
          diagnostics: { batchId: printBatch.id, quantity: qty },
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
      setPrintProgressTotal(typeof data.tokenCount === "number" ? data.tokenCount : qty);
      setPrintProgressRemaining(typeof data.tokenCount === "number" ? data.tokenCount : qty);
      const createdJobId = String(data.printJobId || "").trim();
      const createdLockToken = String(data.printLockToken || "").trim();
      if (!createdJobId || !createdLockToken) {
        toast({
          title: "Print job setup incomplete",
          description: "Missing secure print session data. Please retry.",
          variant: "destructive",
        });
        setPrintProgressError("Missing secure print session data.");
        return;
      }
      toast({
        title: "Direct-print job created",
        description: "Auto print pipeline started with your selected printer.",
      });

      const autoResult = await runAutoDirectPrint(
        createdJobId,
        createdLockToken,
        typeof data.tokenCount === "number" ? data.tokenCount : qty
      );

      if (autoResult.success) {
        toast({
          title: "Auto print complete",
          description: `${autoResult.printedCount} labels printed through the secure direct-print pipeline${autoResult.usedBrowserFallback ? " (browser fallback used)." : "."}`,
        });
        setPrintProgressPhase("Completed");
        setPrintProgressError(null);
      } else {
        toast({
          title: "Auto print needs attention",
          description:
            autoResult.error ||
            `Printed ${autoResult.printedCount}. Remaining: ${autoResult.remainingToPrint}.`,
          variant: "destructive",
        });
        setPrintProgressError(
          autoResult.error ||
            `Printed ${autoResult.printedCount}. Remaining: ${autoResult.remainingToPrint}.`
        );
        void autoReportPrinterFailure({
          context: "auto_print_flow",
          reason:
            autoResult.error ||
            `Printed ${autoResult.printedCount}. Remaining: ${autoResult.remainingToPrint}.`,
          diagnostics: {
            printJobId: createdJobId,
            tokenCount: data.tokenCount,
            printedCount: autoResult.printedCount,
            remainingToPrint: autoResult.remainingToPrint,
            usedBrowserFallback: autoResult.usedBrowserFallback,
          },
        });
      }
      await fetchBatches();
    } finally {
      setPrinting(false);
    }
  };

  const requestDirectPrintTokens = async () => {
    if (!printJobId || !printLockToken) return;
    const count = Math.max(1, Math.min(250, Number.parseInt(directTokenBatchSize, 10) || 1));

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

  const openAllocationMap = async (batch: BatchRow) => {
    setAllocationMapOpen(true);
    setAllocationMapLoading(true);
    setAllocationMap(null);
    try {
      const response = await apiClient.getBatchAllocationMap(batch.id);
      if (!response.success || !response.data) {
        toast({
          title: "Allocation map unavailable",
          description: response.error || "Could not load allocation details for this batch.",
          variant: "destructive",
        });
        setAllocationMapOpen(false);
        return;
      }
      setAllocationMap(response.data);
    } finally {
      setAllocationMapLoading(false);
    }
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
                  printerDiagnostics.tone === "success"
                    ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
                    : printerDiagnostics.tone === "warning"
                      ? "border-amber-300 bg-amber-50 text-amber-700 hover:bg-amber-100"
                      : printerDiagnostics.tone === "neutral"
                        ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
                        : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100"
                }
                title={printerDiagnostics.summary}
              >
                {`Printer ${printerDiagnostics.badgeLabel}`}
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

        {allocationHint ? (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-semibold">{allocationHint.title}</p>
                <p className="mt-1">{allocationHint.body}</p>
              </div>
              <Button type="button" variant="outline" size="sm" onClick={() => setAllocationHint(null)}>
                Dismiss
              </Button>
            </div>
          </div>
        ) : null}

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
                    <TableHead>Inventory State</TableHead>
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
                      const assignedCount = Number(b.assignedCodes ?? b._count?.qrCodes ?? 0);
                      const printed = !!b.printedAt;
                      const availableInventory = getAvailableInventory(b);
                      const isAllocatedBatch = b.batchKind === "MANUFACTURER_CHILD";
                      const canAssignThisBatch = canAssignManufacturer && !isAllocatedBatch && !printed && availableInventory > 0;

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
                                <Badge variant={isAllocatedBatch ? "default" : "secondary"}>
                                  {isAllocatedBatch ? "Allocated batch" : "Source batch"}
                                </Badge>
                                <Badge variant={assignedCount > 0 ? "default" : "secondary"}>
                                  {assignedCount.toLocaleString()} assigned
                                </Badge>
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
                              <Badge variant={getAvailabilityTone(availableInventory)}>
                                {getAvailabilityTitle(b)}: {availableInventory.toLocaleString()}
                              </Badge>
                              {isAllocatedBatch ? (
                                <div className="text-[11px] text-muted-foreground">
                                  Printed {Number(b.printedCodes || 0).toLocaleString()} · Redeemed {Number(b.redeemedCodes || 0).toLocaleString()}
                                </div>
                              ) : (
                                <div className="text-[11px] text-muted-foreground">
                                  Still available for later manufacturer allocation.
                                </div>
                              )}
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
                                  disabled={loading || (b.availableCodes ?? 0) <= 0 || !printerReady}
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
                                  <Button size="sm" variant="outline" onClick={() => openAllocationMap(b)}>
                                    <Activity className="mr-2 h-4 w-4" />
                                    Allocation map
                                  </Button>
                                  <Button size="sm" variant="outline" onClick={() => openRename(b)} disabled={!!b.printedAt}>
                                    <PencilLine className="mr-2 h-4 w-4" />
                                    Rename
                                  </Button>
                                  {canAssignManufacturer && (
                                    <Button size="sm" variant="outline" onClick={() => openAssign(b)} disabled={!canAssignThisBatch}>
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
                Split the current source batch by quantity. The unassigned remainder stays in the source batch and the allocated portion becomes a new manufacturer batch.
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
                    Unassigned remaining in this source batch: {getAvailableInventory(assignBatch)}
                  </div>
                  {getAvailableInventory(assignBatch) > 0 && Number(assignQuantity) > 0 && (
                    <div className="text-xs text-muted-foreground">
                      Remaining in source batch after allocation:{" "}
                      {Math.max(getAvailableInventory(assignBatch) - Number(assignQuantity), 0)}
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
              if (!printing) {
                setPrintProgressOpen(false);
              }
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
                    printerDiagnostics.tone === "success"
                      ? "rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800"
                      : printerDiagnostics.tone === "warning"
                        ? "rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800"
                      : printerDiagnostics.tone === "neutral"
                        ? "rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700"
                        : "rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
                  }
                >
                  <div className="font-medium">{printerDiagnostics.title}</div>
                  <div className="text-xs">
                    {printerReady
                      ? `${printerStatus.selectedPrinterName || printerStatus.printerName || "Authenticated print agent"} is ready. Create print job will auto-print labels.`
                      : printerDiagnostics.summary}
                  </div>
                  {!printerReady && <div className="mt-2 text-[11px]">{printerDiagnostics.detail}</div>}
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
                    Ready to print: {getAvailableInventory(printBatch)}
                  </div>
                </div>

                <div className="space-y-3 rounded-md border p-3">
                  <div className="text-sm font-medium">Printer and compatibility profile</div>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label className="text-xs">Active printer</Label>
                      <Select value={selectedPrinterId || "__none__"} onValueChange={(v) => setSelectedPrinterId(v === "__none__" ? "" : v)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select printer" />
                        </SelectTrigger>
                        <SelectContent>
                          {detectedPrinters.length === 0 ? (
                            <SelectItem value="__none__">No printers discovered</SelectItem>
                          ) : (
                            detectedPrinters.map((row) => (
                              <SelectItem key={row.printerId} value={row.printerId}>
                                {row.printerName}
                                {row.connection ? ` · ${row.connection}` : ""}
                                {row.online === false ? " · offline" : ""}
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Print path</Label>
                      <Select value={printPath} onValueChange={(value) => setPrintPath(value as any)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Print path" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="auto">Auto detect</SelectItem>
                          <SelectItem value="spooler">OS spooler (CUPS/Windows/macOS)</SelectItem>
                          <SelectItem value="raw-9100">Raw 9100 / JetDirect</SelectItem>
                          <SelectItem value="label-language">Label language mode</SelectItem>
                          <SelectItem value="pdf-raster">Raster/PDF fallback</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Label language</Label>
                      <Select value={labelLanguage} onValueChange={(value) => setLabelLanguage(value as any)}>
                        <SelectTrigger>
                          <SelectValue placeholder="Label language" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="AUTO">Auto</SelectItem>
                          <SelectItem value="ZPL">ZPL</SelectItem>
                          <SelectItem value="EPL">EPL</SelectItem>
                          <SelectItem value="CPCL">CPCL</SelectItem>
                          <SelectItem value="TSPL">TSPL</SelectItem>
                          <SelectItem value="ESC_POS">ESC/POS</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">DPI (optional)</Label>
                      <Input
                        value={calibrationProfile.dpi}
                        onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, dpi: e.target.value }))}
                        placeholder="300"
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    <Input value={calibrationProfile.labelWidthMm} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, labelWidthMm: e.target.value }))} placeholder="Width mm" />
                    <Input value={calibrationProfile.labelHeightMm} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, labelHeightMm: e.target.value }))} placeholder="Height mm" />
                    <Input value={calibrationProfile.offsetXmm} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, offsetXmm: e.target.value }))} placeholder="Offset X" />
                    <Input value={calibrationProfile.offsetYmm} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, offsetYmm: e.target.value }))} placeholder="Offset Y" />
                  </div>
                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    <Input value={calibrationProfile.darkness} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, darkness: e.target.value }))} placeholder="Darkness" />
                    <Input value={calibrationProfile.speed} onChange={(e) => setCalibrationProfile((prev) => ({ ...prev, speed: e.target.value }))} placeholder="Speed" />
                  </div>
                  <div className="flex flex-wrap justify-end gap-2">
                    <Button variant="outline" size="sm" disabled={switchingPrinter || !selectedPrinterId || detectedPrinters.length <= 1} onClick={switchSelectedPrinter}>
                      {switchingPrinter ? "Switching..." : "Switch printer"}
                    </Button>
                    <Button variant="outline" size="sm" disabled={switchingPrinter || !selectedPrinterId} onClick={applyCalibration}>
                      {switchingPrinter ? "Applying..." : "Apply calibration"}
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => navigate("/printer-diagnostics")}>
                      Open diagnostics
                    </Button>
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    Capabilities: {(printerStatus.capabilitySummary?.protocols || []).join(", ") || "auto"} ·{" "}
                    {(printerStatus.capabilitySummary?.languages || []).join(", ") || "AUTO"} ·{" "}
                    media {(printerStatus.capabilitySummary?.mediaSizes || []).join(", ") || "auto"}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button onClick={createPrintJob} disabled={printing || !printerReady}>
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
                          max={250}
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
          onOpenBatches={(batchId) => {
            const found = rows.find((row) => row.id === batchId);
            if (found) {
              setQ(found.name);
              setAllocationMapOpen(false);
            }
          }}
        />

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
        <PrintProgressDialog
          open={printProgressOpen}
          phase={printProgressPhase}
          total={printProgressTotal}
          printed={printProgressPrinted}
          remaining={printProgressRemaining}
          currentCode={printProgressCurrentCode}
          printerName={printerStatus.selectedPrinterName || printerStatus.printerName || null}
          modeLabel={printerStatus.trusted ? "Trusted mode" : printerStatus.compatibilityMode ? "Compatibility mode" : "Blocked"}
          error={printProgressError}
          onOpenChange={(open) => {
            if (!printing) setPrintProgressOpen(open);
          }}
        />
      </div>
    </DashboardLayout>
  );
}

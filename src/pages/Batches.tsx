// src/pages/Batches.tsx

import React, { useEffect, useMemo, useRef, useState } from "react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { OperationProgressDialog } from "@/components/feedback/OperationProgressDialog";
import { PrintProgressDialog } from "@/components/printing/PrintProgressDialog";
import { useAuth } from "@/contexts/AuthContext";
import { useOperationProgress } from "@/hooks/useOperationProgress";
import apiClient from "@/lib/api-client";
import { getPrinterDiagnosticSummary, type LocalPrinterAgentSnapshot } from "@/lib/printer-diagnostics";
import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import { BatchAllocationMapDialog } from "@/components/batches/BatchAllocationMapDialog";
import { LicenseeBatchWorkspaceDialog } from "@/components/batches/LicenseeBatchWorkspaceDialog";
import { buildStableBatchOverviewRows, type StableBatchOverviewRow } from "@/lib/batch-workspace";

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

import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";

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
import { Search, RefreshCw, Download } from "lucide-react";
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
  updatedAt?: string;
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

type AuditLogRow = {
  id: string;
  action?: string;
  entityType?: string | null;
  entityId?: string | null;
  createdAt: string;
  details?: any;
  user?: { id: string; name?: string | null; email?: string | null } | null;
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

type RegisteredPrinterRow = {
  id: string;
  name: string;
  vendor?: string | null;
  model?: string | null;
  connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  commandLanguage: "AUTO" | "ZPL" | "TSPL" | "SBPL" | "EPL" | "CPCL" | "ESC_POS" | "OTHER";
  ipAddress?: string | null;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY";
  nativePrinterId?: string | null;
  isActive: boolean;
  isDefault?: boolean;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
};

type PrinterNoticeTone = "success" | "warning" | "neutral" | "danger";

type PrinterSelectionNotice = {
  title: string;
  summary: string;
  detail: string;
  tone: PrinterNoticeTone;
};

type PrintJobRow = {
  id: string;
  jobNumber?: string | null;
  status: "PENDING" | "SENT" | "CONFIRMED" | "FAILED" | "CANCELLED";
  printMode: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
  quantity: number;
  itemCount?: number | null;
  failureReason?: string | null;
  createdAt: string;
  updatedAt?: string;
  sentAt?: string | null;
  confirmedAt?: string | null;
  completedAt?: string | null;
  printer?: {
    id: string;
    name: string;
    connectionType: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP";
    commandLanguage: string;
  } | null;
  session?: {
    id: string;
    status: string;
    totalItems?: number;
    confirmedItems?: number;
    frozenItems?: number;
    failedReason?: string | null;
    remainingToPrint?: number;
    counts?: Record<string, number>;
  } | null;
};

const LARGE_ALLOCATION_THRESHOLD = 25_000;
const PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS = 3 * 60 * 1000;

const formatDispatchModeLabel = (mode?: string | null) => {
  if (mode === "NETWORK_DIRECT") return "Factory label printer";
  if (mode === "NETWORK_IPP") return "Office / AirPrint printer";
  if (mode === "LOCAL_AGENT") return "Workstation printer";
  return "Printer";
};

const normalizePrintProgressPhase = (phase?: string | null) => String(phase || "").trim().toLowerCase();

const isCompletedPrintProgressPhase = (phase?: string | null) => {
  const normalized = normalizePrintProgressPhase(phase);
  return (
    normalized === "completed" ||
    normalized === "print job completed" ||
    normalized === "print session completed"
  );
};

const isTerminalPrintProgressPhase = (phase?: string | null) => {
  const normalized = normalizePrintProgressPhase(phase);
  return (
    isCompletedPrintProgressPhase(normalized) ||
    normalized === "print job failed" ||
    normalized === "print job cancelled"
  );
};

const buildManagedNetworkPrinterNotice = (
  printer: RegisteredPrinterRow | null
): PrinterSelectionNotice => {
  if (!printer) {
    return {
      title: "Select a saved printer",
      summary: "Choose a saved printer profile before starting this print job.",
      detail: "Only checked printer setups can receive managed network jobs.",
      tone: "neutral",
    };
  }

  const state = printer.registryStatus?.state || "ATTENTION";
  const profileLabel = getPrinterDispatchLabel(printer);

  if (state === "READY") {
    return {
      title: `${profileLabel} printer ready`,
      summary: `${printer.name} is validated and ready for server-side dispatch.`,
      detail:
        sanitizePrinterUiError(
          printer.registryStatus?.detail,
          printer.connectionType === "NETWORK_IPP"
            ? "This office printer is ready for standards-based printing."
            : "This factory label printer is ready for controlled dispatch."
        ),
      tone: "success",
    };
  }

  if (state === "OFFLINE") {
    return {
      title: "Network printer offline",
      summary: `${printer.name} is saved, but it is not reachable right now.`,
      detail:
        sanitizePrinterUiError(
          printer.registryStatus?.detail,
          "Bring the printer or site connector online and run the check again before printing."
        ),
      tone: "danger",
    };
  }

  if (state === "BLOCKED") {
    return {
      title: "Network printer blocked",
      summary: `${printer.name} cannot be used in its current configuration.`,
      detail:
        sanitizePrinterUiError(
          printer.registryStatus?.detail,
          "Update the saved setup and run the check again before printing."
        ),
      tone: "danger",
    };
  }

  return {
    title: "Network printer needs validation",
    summary: `${printer.name} is registered, but readiness has not been confirmed yet.`,
    detail:
      sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Open Printer Setup and run a check before printing."
      ),
    tone: "warning",
  };
};

const inferTraceEventTypeFromAudit = (log: AuditLogRow): TraceEventType | undefined => {
  const action = String(log.action || "").trim().toUpperCase();
  const context = String(log.details?.context || "").trim().toUpperCase();

  if (action === "ALLOCATED" || context.includes("ASSIGN_MANUFACTURER")) return "ASSIGNED";
  if (action.includes("PRINT")) return "PRINTED";
  if (action.includes("REDEEM") || action.includes("SCAN")) return "REDEEMED";
  if (action.includes("BLOCK")) return "BLOCKED";
  if (action.includes("COMMISSION")) return "COMMISSIONED";
  return undefined;
};

const normalizeAuditLogToTraceEvent = (log: AuditLogRow): TraceEventRow => ({
  id: String(log.id || `${log.createdAt}:${log.action || "AUDIT"}`).trim(),
  eventType: inferTraceEventTypeFromAudit(log),
  action: log.action,
  sourceAction: log.action || null,
  createdAt: String(log.createdAt || new Date().toISOString()),
  details: log.details || {},
  user: log.user || null,
  userId: log.userId || log.user?.id || null,
});

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
  const [directRemainingToPrint, setDirectRemainingToPrint] = useState<number | null>(null);
  const [detectedPrinters, setDetectedPrinters] = useState<LocalPrinterRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState<string>("");
  const [registeredPrinters, setRegisteredPrinters] = useState<RegisteredPrinterRow[]>([]);
  const [selectedPrinterProfileId, setSelectedPrinterProfileId] = useState<string>("");
  const [recentPrintJobs, setRecentPrintJobs] = useState<PrintJobRow[]>([]);
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
  const [printProgressPrinterName, setPrintProgressPrinterName] = useState<string | null>(null);
  const [printProgressDispatchMode, setPrintProgressDispatchMode] = useState<"LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | null>(null);
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
  const [workspaceOpen, setWorkspaceOpen] = useState(false);
  const [workspaceBatch, setWorkspaceBatch] = useState<StableBatchOverviewRow | null>(null);
  const [workspaceHistoryLogs, setWorkspaceHistoryLogs] = useState<TraceEventRow[]>([]);
  const [workspaceHistoryLoading, setWorkspaceHistoryLoading] = useState(false);
  const [workspaceHistoryLastUpdatedAt, setWorkspaceHistoryLastUpdatedAt] = useState<Date | null>(null);
  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
  const printerHasInventory =
    detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId);
  const printerUnavailable = !printerReady && !printerHasInventory;
  const activeLocalPrinterId = String(selectedPrinterId || printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
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
  const selectedPrinterProfile = useMemo(
    () => registeredPrinters.find((row) => row.id === selectedPrinterProfileId) || null,
    [registeredPrinters, selectedPrinterProfileId]
  );
  const selectedPrinterMode = selectedPrinterProfile?.connectionType || null;
  const selectedLocalProfileMatchesAgent =
    selectedPrinterProfile?.connectionType === "LOCAL_AGENT"
      ? !selectedPrinterProfile.nativePrinterId || selectedPrinterProfile.nativePrinterId === activeLocalPrinterId
      : false;
  const selectedPrinterCanPrint = Boolean(
    selectedPrinterProfile &&
      selectedPrinterProfile.isActive &&
      (selectedPrinterProfile.connectionType !== "LOCAL_AGENT"
        ? selectedPrinterProfile.registryStatus?.state === "READY"
        : printerReady && selectedLocalProfileMatchesAgent)
  );
  const selectedPrinterNotice = useMemo<PrinterSelectionNotice>(() => {
    if (selectedPrinterProfile?.connectionType !== "LOCAL_AGENT") {
      return buildManagedNetworkPrinterNotice(selectedPrinterProfile);
    }

    return {
      title: printerDiagnostics.title,
      summary: printerReady
        ? `${printerStatus.selectedPrinterName || printerStatus.printerName || "Workstation printer"} is ready.`
        : printerDiagnostics.summary,
      detail: !printerReady
        ? printerDiagnostics.detail
        : "The workstation printer is ready for approved MSCQR printing.",
      tone: printerDiagnostics.tone as PrinterNoticeTone,
    };
  }, [printerDiagnostics.detail, printerDiagnostics.summary, printerDiagnostics.title, printerDiagnostics.tone, printerReady, printerStatus.printerName, printerStatus.selectedPrinterName, selectedPrinterProfile]);

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

  const loadRegisteredPrinters = async (preferredLocalPrinterId?: string | null) => {
    if (!isManufacturer) return;
    const response = await apiClient.listRegisteredPrinters(true);
    if (!response.success) {
      setRegisteredPrinters([]);
      return;
    }

    const printers = (Array.isArray(response.data) ? response.data : []) as RegisteredPrinterRow[];
    setRegisteredPrinters(printers);
    setSelectedPrinterProfileId((prev) => {
      if (prev && printers.some((row) => row.id === prev && row.isActive)) return prev;

      const trimmedLocalId = String(preferredLocalPrinterId || "").trim();
      if (trimmedLocalId) {
        const matchingLocal = printers.find(
          (row) => row.connectionType === "LOCAL_AGENT" && row.nativePrinterId === trimmedLocalId && row.isActive
        );
        if (matchingLocal) return matchingLocal.id;
      }

      const preferred = printers.find((row) => row.isDefault && row.isActive) || printers.find((row) => row.isActive);
      return preferred?.id || "";
    });
  };

  const loadRecentPrintJobs = async (batchId?: string) => {
    if (!isManufacturer) return;
    const response = await apiClient.listPrintJobs({ batchId, limit: 8 });
    if (!response.success) {
      setRecentPrintJobs([]);
      return;
    }
    setRecentPrintJobs((Array.isArray(response.data) ? response.data : []) as PrintJobRow[]);
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
      await loadRegisteredPrinters(
        String((local as any)?.data?.selectedPrinterId || (local as any)?.data?.printerId || "").trim() || null
      );
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
    await loadRegisteredPrinters(preferredPrinterId || null);
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
    loadRecentPrintJobs();
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

  useEffect(() => {
    if (!selectedPrinterId) return;
    setSelectedPrinterProfileId((prev) => {
      const current = registeredPrinters.find((row) => row.id === prev) || null;
      if (current?.connectionType && current.connectionType !== "LOCAL_AGENT") return prev;
      const matchingLocal = registeredPrinters.find(
        (row) => row.connectionType === "LOCAL_AGENT" && row.nativePrinterId === selectedPrinterId && row.isActive
      );
      return matchingLocal?.id || prev;
    });
  }, [registeredPrinters, selectedPrinterId]);

  const filteredRows = useMemo(() => {
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

  const stableRows = useMemo(() => buildStableBatchOverviewRows(rows), [rows]);

  const filteredStableRows = useMemo(() => {
    const search = q.trim().toLowerCase();
    const manufacturerIdFilter = String(searchParams.get("manufacturerId") || "").trim();

    return stableRows.filter((row) => {
      if (manufacturerIdFilter) {
        const matchesManufacturer = row.manufacturerSummary.some(
          (allocation) => allocation.manufacturerId === manufacturerIdFilter
        );
        if (!matchesManufacturer) return false;
      }

      if (assignmentFilter === "assigned" && row.assignedCodes <= 0) return false;
      if (assignmentFilter === "unassigned" && row.remainingUnassignedCodes <= 0) return false;

      if (!search) return true;

      const haystack = [
        row.sourceBatchName,
        row.sourceBatchId,
        row.sourceOriginalRangeStart,
        row.sourceOriginalRangeEnd,
        row.licensee?.name,
        row.licensee?.prefix,
        ...row.manufacturerSummary.flatMap((allocation) => [
          allocation.manufacturerName,
          allocation.manufacturerEmail,
          allocation.batchName,
          allocation.batchId,
        ]),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(search);
    });
  }, [assignmentFilter, q, searchParams, stableRows]);

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
          `Allocated ${qty.toLocaleString()} codes. The new manufacturer batch is ready for print.`
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
        description: `${createdName} was created for controlled printing.`,
      });
      setAssignManufacturerId("");
      setAssignQuantity("");
      await fetchBatches();
      if (workspaceBatch) {
        await fetchWorkspaceHistory(workspaceBatch, { silent: true });
      }
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
    setDirectRemainingToPrint(null);
    setPrintProgressOpen(false);
    setPrintProgressPhase("Preparing print pipeline");
    setPrintProgressTotal(0);
    setPrintProgressPrinted(0);
    setPrintProgressRemaining(0);
    setPrintProgressCurrentCode(null);
    setPrintProgressError(null);
    setPrintProgressPrinterName(null);
    setPrintProgressDispatchMode(null);
    setPrintOpen(true);
    void loadPrinterStatus();
    void loadRecentPrintJobs(b.id);
  };

  useEffect(() => {
    if (!printProgressOpen || printing || printProgressError) return;
    if (!isCompletedPrintProgressPhase(printProgressPhase)) return;

    const timer = window.setTimeout(() => {
      setPrintProgressOpen(false);
    }, 900);

    return () => window.clearTimeout(timer);
  }, [printProgressError, printProgressOpen, printProgressPhase, printing]);

  const switchSelectedPrinter = async () => {
    if (!selectedPrinterId) return;
    setSwitchingPrinter(true);
    try {
      const response = await apiClient.selectLocalPrinter(selectedPrinterId);
      if (!response.success) {
        toast({
          title: "Switch failed",
          description: sanitizePrinterUiError(response.error, "Could not switch the workstation printer."),
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Printer switched", description: "The workstation printer has been updated." });
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
          title: "Printer setup update failed",
          description: sanitizePrinterUiError(response.error, "Could not save the printer setup changes."),
          variant: "destructive",
        });
        return;
      }
      try {
        window.localStorage.setItem(`printer-calibration:${selectedPrinterId}`, JSON.stringify(calibrationPayload));
      } catch {
        // non-blocking local persistence
      }
      toast({ title: "Printer setup saved", description: "The workstation printer setup has been updated." });
      await loadPrinterStatus();
    } finally {
      setSwitchingPrinter(false);
    }
  };

  const syncProgressFromPrintJob = (job: PrintJobRow | null) => {
    if (!job) return;
    const total = Number(job.itemCount || job.quantity || 0);
    const confirmed = Number(job.session?.confirmedItems || 0);
    const remaining =
      typeof job.session?.remainingToPrint === "number"
        ? job.session.remainingToPrint
        : Math.max(0, total - confirmed);

    if (total > 0) setPrintProgressTotal(total);
    setPrintProgressPrinted(confirmed);
    setPrintProgressRemaining(remaining);
    setDirectRemainingToPrint(remaining);
    setPrintProgressDispatchMode((prev) => job.printMode || prev || null);
    setPrintProgressPrinterName((prev) => {
      const resolvedName = String(job.printer?.name || "").trim();
      return resolvedName || prev || null;
    });

    if (job.status === "CONFIRMED") {
      setPrintProgressPhase("Print job completed");
      setPrintProgressError(null);
      return;
    }
    if (job.status === "FAILED") {
      setPrintProgressPhase("Print job failed");
      setPrintProgressError(
        sanitizePrinterUiError(job.failureReason || job.session?.failedReason, "This print job needs attention before it can continue.")
      );
      return;
    }
    if (job.status === "CANCELLED") {
      setPrintProgressPhase("Print job cancelled");
      setPrintProgressError(
        sanitizePrinterUiError(job.failureReason, "This print job was cancelled before completion.")
      );
      return;
    }
    if (job.printMode === "NETWORK_DIRECT" || job.printMode === "NETWORK_IPP") {
      setPrintProgressPhase(
        job.printMode === "NETWORK_IPP"
          ? job.status === "SENT"
            ? "Dispatching to registered IPP printer"
            : "Preparing network IPP dispatch"
          : job.status === "SENT"
            ? "Dispatching to registered network printer"
            : "Preparing network printer dispatch"
      );
    } else {
      setPrintProgressPhase("Local print session active");
    }
  };

  useEffect(() => {
    if (printing) return;
    if (!printJobId || (printProgressDispatchMode !== "NETWORK_DIRECT" && printProgressDispatchMode !== "NETWORK_IPP")) return;
    if (isTerminalPrintProgressPhase(printProgressPhase)) return;

    let cancelled = false;
    let inFlight = false;

    const syncLatest = async () => {
      if (cancelled || inFlight) return;
      inFlight = true;
      try {
        const response = await apiClient.getPrintJobStatus(printJobId);
        if (!response.success || !response.data || cancelled) return;

        const job = response.data as PrintJobRow;
        syncProgressFromPrintJob(job);
        if (
          job.status === "CONFIRMED" ||
          job.status === "FAILED" ||
          job.status === "CANCELLED"
        ) {
          void loadRecentPrintJobs(printBatch?.id);
          void fetchBatches();
        }
      } finally {
        inFlight = false;
      }
    };

    void syncLatest();
    const timer = window.setInterval(() => {
      void syncLatest();
    }, 3000);

    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [printBatch?.id, printJobId, printProgressDispatchMode, printProgressPhase, printing]);

  const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

  const pollPrintJobUntilSettled = async (jobId: string, timeoutMs = 90_000) => {
    const startedAt = Date.now();
    let latest: PrintJobRow | null = null;

    while (Date.now() - startedAt < timeoutMs) {
      const response = await apiClient.getPrintJobStatus(jobId);
      if (response.success && response.data) {
        latest = response.data as PrintJobRow;
        syncProgressFromPrintJob(latest);
        if (latest.status === "CONFIRMED" || latest.status === "FAILED" || latest.status === "CANCELLED") {
          return { settled: true as const, job: latest };
        }
      }
      await sleep(1200);
    }

    return { settled: false as const, job: latest };
  };

  const runAutoDirectPrint = async (jobId: string, lockToken: string, requestedQty: number) => {
    let printedCount = 0;
    let remainingToPrint = Math.max(0, requestedQty);
    let guard = 0;

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
        const safeError = sanitizePrinterUiError(issueRes.error, "Printing could not continue right now. Start a fresh print job and try again.");
        setPrintProgressError(safeError);
        return {
          success: false,
          printedCount,
          remainingToPrint,
          error: safeError,
        };
      }

      const issueData: any = issueRes.data || {};
      const items = Array.isArray(issueData.items) ? issueData.items : [];

      if (typeof issueData.remainingToPrint === "number") {
        remainingToPrint = issueData.remainingToPrint;
        setDirectRemainingToPrint(issueData.remainingToPrint);
        setPrintProgressRemaining(issueData.remainingToPrint);
      }

      if (items.length === 0) {
        if (issueData.jobConfirmed || remainingToPrint === 0) {
          setPrintProgressPhase("Print session completed");
          return { success: true, printedCount, remainingToPrint: 0 };
        }
        setPrintProgressError("Printing paused before all labels were confirmed. Retry the remaining labels.");
        return {
          success: false,
          printedCount,
          remainingToPrint,
          error: "Printing paused before all labels were confirmed. Retry the remaining labels.",
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
          const safeError = sanitizePrinterUiError(
            resolveRes.error,
            "Printing could not continue right now. Start a fresh print job and try again."
          );
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
            printItemId: item.printItemId,
            retries: 0,
          });
          setPrintProgressError(safeError);
          void autoReportPrinterFailure({
            context: "resolve_direct_print_token",
            reason: resolveRes.error || `Failed to resolve render token for ${item.code}.`,
            diagnostics: { jobId, printItemId: item.printItemId, code: item.code },
          });
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: safeError,
          };
        }

        const resolvedData: any = resolveRes.data || {};
        const printItemId = String(resolvedData.printItemId || item.printItemId || "").trim();
        const scanUrl = String(resolvedData.scanUrl || "").trim();
        const payloadContent = String(resolvedData.payloadContent || "");
        const payloadHash = String(resolvedData.payloadHash || "").trim();
        const payloadType = String(resolvedData.payloadType || "").trim();
        if (!scanUrl || !printItemId || !payloadContent || !payloadHash || !payloadType) {
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: `Resolved token missing print session metadata for ${item.code}.`,
            printItemId: printItemId || item.printItemId,
            retries: 0,
          });
          setPrintProgressError("Printing could not continue because this secure print session is incomplete. Start a fresh print job.");
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: "Printing could not continue because this secure print session is incomplete. Start a fresh print job.",
          };
        }

        const localPrintRes = await apiClient.printWithLocalAgent({
          printJobId: jobId,
          qrId: item.qrId,
          code: item.code,
          scanUrl,
          payloadType: resolvedData.payloadType,
          payloadContent,
          payloadHash,
          previewLabel: resolvedData.previewLabel || undefined,
          commandLanguage: resolvedData.commandLanguage || undefined,
          copies: 1,
          printerId:
            selectedPrinterId ||
            printerStatus.selectedPrinterId ||
            resolvedData?.printer?.nativePrinterId ||
            undefined,
          printPath,
          labelLanguage:
            resolvedData.commandLanguage && resolvedData.commandLanguage !== "OTHER"
              ? resolvedData.commandLanguage
              : labelLanguage,
          mediaSize:
            (printerStatus.capabilitySummary?.mediaSizes && printerStatus.capabilitySummary.mediaSizes[0]) ||
            undefined,
          calibrationProfile: buildCalibrationPayload(),
        });

        if (!localPrintRes.success) {
          const safeError = sanitizePrinterUiError(localPrintRes.error, "The workstation printer could not complete this label.");
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: localPrintRes.error || `Local print failed for ${item.code}.`,
            printItemId,
            retries: 0,
            agentMetadata: {
              selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
              printPath,
              labelLanguage,
              payloadType,
              payloadHash,
              calibrationProfile: buildCalibrationPayload(),
            },
          });
          setPrintProgressError(safeError);
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
              payloadType,
            },
          });
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: safeError,
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
            payloadType,
            payloadHash,
            calibrationProfile: buildCalibrationPayload(),
          },
        });
        if (!confirmRes.success) {
          const safeError = sanitizePrinterUiError(
            confirmRes.error,
            "MSCQR could not confirm the printed labels. Start a fresh print job for any remaining quantity."
          );
          await apiClient.reportDirectPrintFailure(jobId, {
            printLockToken: lockToken,
            reason: confirmRes.error || `Failed to confirm print item ${item.code}.`,
            printItemId,
            retries: 0,
          });
          setPrintProgressError(safeError);
          return {
            success: false,
            printedCount,
            remainingToPrint,
            error: safeError,
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

    if (!selectedPrinterProfile) {
      toast({
        title: "Select a printer profile",
        description: "Choose a saved printer before creating a job.",
        variant: "destructive",
      });
      return;
    }

    if (selectedPrinterProfile.connectionType === "LOCAL_AGENT") {
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
          description: sanitizePrinterUiError(
            livePrinterStatus.error,
            "Reconnect the workstation connector or choose a ready workstation printer before creating a job."
          ),
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
      if (selectedPrinterProfile.nativePrinterId && activeLocalPrinterId && selectedPrinterProfile.nativePrinterId !== activeLocalPrinterId) {
        toast({
          title: "Active workstation printer mismatch",
          description: "Switch the local agent to the registered printer profile you selected, then retry.",
          variant: "destructive",
        });
        return;
      }
    } else if (!selectedPrinterCanPrint) {
      toast({
        title: "Network printer needs attention",
        description: sanitizePrinterUiError(
          selectedPrinterProfile.registryStatus?.detail || selectedPrinterProfile.registryStatus?.summary,
          "Open Printer Setup and run a check before printing."
        ),
        variant: "destructive",
      });
      return;
    }

    try {
      if (selectedPrinterProfile.connectionType === "LOCAL_AGENT" && selectedPrinterId) {
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
    setPrintProgressPrinterName(selectedPrinterProfile.name);
    setPrintProgressDispatchMode(selectedPrinterProfile.connectionType);

      const res = await apiClient.createPrintJob({
        batchId: printBatch.id,
        printerId: selectedPrinterProfile.id,
        quantity: qty,
      });
      if (!res.success) {
        const raw = (res.error || "Error").toLowerCase();
        const isBusy = raw.includes("conflict") || raw.includes("busy") || raw.includes("retry");
        const safeError = sanitizePrinterUiError(res.error, "The print job could not be started right now.");
        toast({
          title: isBusy ? "Batch busy" : "Print job failed",
          description: isBusy
            ? "These codes were just allocated by another job. Please retry."
            : safeError,
          variant: "destructive",
        });
        setPrintProgressError(safeError);
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
      setPrintProgressTotal(typeof data.tokenCount === "number" ? data.tokenCount : qty);
      setPrintProgressRemaining(typeof data.tokenCount === "number" ? data.tokenCount : qty);
      const createdJobId = String(data.printJobId || "").trim();
      const createdLockToken = String(data.printLockToken || "").trim();
      const createdMode = String(data.mode || selectedPrinterProfile.connectionType).trim();
      const isServerDispatchedMode = createdMode === "NETWORK_DIRECT" || createdMode === "NETWORK_IPP";
      setPrintProgressPrinterName(String(data.printer?.name || selectedPrinterProfile.name || "").trim() || null);
      setPrintProgressDispatchMode(
        createdMode === "NETWORK_DIRECT" ? "NETWORK_DIRECT" : createdMode === "NETWORK_IPP" ? "NETWORK_IPP" : "LOCAL_AGENT"
      );
      if (!createdJobId) {
        toast({
          title: "Print job setup incomplete",
          description: "The print job could not be started correctly. Please try again.",
          variant: "destructive",
        });
        setPrintProgressError("The print job could not be started correctly. Please try again.");
        return;
      }

      if (isServerDispatchedMode) {
        toast({
          title: createdMode === "NETWORK_IPP" ? "Office printer job started" : "Factory printer job started",
          description:
            createdMode === "NETWORK_IPP"
              ? `Sending ${qty} label${qty === 1 ? "" : "s"} to ${selectedPrinterProfile.name} over ${selectedPrinterProfile.deliveryMode === "SITE_GATEWAY" ? "the site connector" : "the office printer route"}.`
              : `Dispatching ${qty} label${qty === 1 ? "" : "s"} to ${selectedPrinterProfile.name}.`,
        });
        setPrintProgressPhase(
          createdMode === "NETWORK_IPP"
            ? selectedPrinterProfile.deliveryMode === "SITE_GATEWAY"
              ? "Waiting for site connector dispatch"
              : "Sending to saved office printer"
            : "Sending to saved factory printer"
        );
        const pollResult = await pollPrintJobUntilSettled(createdJobId);
        if (pollResult.settled && pollResult.job?.status === "CONFIRMED") {
          toast({
            title: createdMode === "NETWORK_IPP" ? "Office printer job complete" : "Factory printer job complete",
            description: `${pollResult.job.session?.confirmedItems || qty} labels confirmed by the server.`,
          });
          setPrintProgressPhase("Completed");
          setPrintProgressError(null);
        } else if (pollResult.settled && pollResult.job?.status === "FAILED") {
          const message = sanitizePrinterUiError(
            pollResult.job.failureReason || pollResult.job.session?.failedReason,
            createdMode === "NETWORK_IPP"
              ? "The office printer could not complete this job."
              : "The factory printer could not complete this job."
          );
          toast({
            title: createdMode === "NETWORK_IPP" ? "Network IPP print failed" : "Network print failed",
            description: message,
            variant: "destructive",
          });
          setPrintProgressError(message);
          void autoReportPrinterFailure({
            context: createdMode === "NETWORK_IPP" ? "network_ipp_print" : "network_direct_print",
            reason: message,
            diagnostics: { printJobId: createdJobId, printerId: selectedPrinterProfile.id },
          });
        } else {
          toast({
            title: "Network print continues in background",
            description: "This print job is still running. Review the live status below or in Printer Setup.",
          });
        }
      } else {
        if (!createdLockToken) {
          toast({
            title: "Print job setup incomplete",
            description: "The workstation print session could not be started correctly. Please try again.",
            variant: "destructive",
          });
          setPrintProgressError("The workstation print session could not be started correctly. Please try again.");
          return;
        }
        toast({
          title: "Workstation print started",
          description: `MSCQR is sending approved labels to ${selectedPrinterProfile.name}.`,
        });

        const autoResult = await runAutoDirectPrint(
          createdJobId,
          createdLockToken,
          typeof data.tokenCount === "number" ? data.tokenCount : qty
        );

        if (autoResult.success) {
          toast({
            title: "Local print complete",
            description: `${autoResult.printedCount} labels printed through the controlled local-agent pipeline.`,
          });
          setPrintProgressPhase("Completed");
          setPrintProgressError(null);
        } else {
          const safeError = sanitizePrinterUiError(
            autoResult.error,
            `Printed ${autoResult.printedCount}. Remaining: ${autoResult.remainingToPrint}.`
          );
          toast({
            title: "Workstation print needs attention",
            description: safeError,
            variant: "destructive",
          });
          setPrintProgressError(safeError);
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
              printerId: selectedPrinterProfile.id,
            },
          });
        }
      }

      if (!isServerDispatchedMode && createdLockToken && directRemainingToPrint === 0) {
        toast({
          title: "Print session closed",
          description: "All remaining labels were processed.",
        });
      }
      await fetchBatches();
      await loadRecentPrintJobs(printBatch.id);
    } finally {
      setPrinting(false);
    }
  };

  const requestDirectPrintTokens = async () => {
    if (!printJobId || !printLockToken) return;

    setPrinting(true);
    try {
      const statusRes = await apiClient.getPrintJobStatus(printJobId);
      if (statusRes.success && statusRes.data) {
        syncProgressFromPrintJob(statusRes.data as PrintJobRow);
      }

      const remaining =
        ((statusRes.data as PrintJobRow | undefined)?.session?.remainingToPrint ??
          directRemainingToPrint ??
          printJobTokensCount ??
          1);
      const retryResult = await runAutoDirectPrint(printJobId, printLockToken, Math.max(1, remaining));
      if (!retryResult.success) {
        toast({
          title: "Retry needs attention",
          description:
            retryResult.error ||
            `Printed ${retryResult.printedCount}. Remaining: ${retryResult.remainingToPrint}.`,
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Retry completed",
        description: `${retryResult.printedCount} additional labels printed.`,
      });
      await loadRecentPrintJobs(printBatch?.id);
    } finally {
      setPrinting(false);
    }
  };

  const fetchWorkspaceHistory = async (workspace: StableBatchOverviewRow, opts?: { silent?: boolean }) => {
    if (!opts?.silent) {
      setWorkspaceHistoryLoading(true);
    }
    try {
      const batchIds = Array.from(
        new Set(
          [workspace.sourceBatchRow?.id || workspace.sourceBatchId, ...workspace.allocations.map((allocation) => allocation.batchId)]
            .map((value) => String(value || "").trim())
            .filter(Boolean)
        )
      );

      const [traceResponses, auditResponses] = await Promise.all([
        Promise.all(batchIds.map((batchId) => apiClient.getTraceTimeline({ batchId, limit: 60 }))),
        Promise.all(batchIds.map((batchId) => apiClient.getAuditLogs({ entityType: "Batch", entityId: batchId, limit: 60 }))),
      ]);
      const merged = new Map<string, TraceEventRow>();

      for (const response of traceResponses) {
        if (!response.success) continue;
        const payload: any = response.data;
        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.events)
            ? payload.events
            : Array.isArray(payload?.logs)
              ? payload.logs
              : [];

        for (const item of list as TraceEventRow[]) {
          const key = String(item.id || `${item.createdAt}:${item.action || item.sourceAction || item.eventType || "event"}`).trim();
          if (!merged.has(key)) {
            merged.set(key, item);
          }
        }
      }

      for (const response of auditResponses) {
        if (!response.success) continue;
        const payload: any = response.data;
        const list = Array.isArray(payload)
          ? payload
          : Array.isArray(payload?.logs)
            ? payload.logs
            : Array.isArray(payload?.data)
              ? payload.data
              : [];

        for (const item of list as AuditLogRow[]) {
          const normalized = normalizeAuditLogToTraceEvent(item);
          const key = String(
            normalized.id ||
              `${normalized.createdAt}:${normalized.action || normalized.sourceAction || normalized.eventType || "audit"}`
          ).trim();
          if (!merged.has(key)) {
            merged.set(key, normalized);
          }
        }
      }

      setWorkspaceHistoryLogs(
        Array.from(merged.values()).sort(
          (left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime()
        )
      );
      setWorkspaceHistoryLastUpdatedAt(new Date());
    } finally {
      setWorkspaceHistoryLoading(false);
    }
  };

  const openWorkspace = async (workspace: StableBatchOverviewRow) => {
    setWorkspaceBatch(workspace);
    setWorkspaceOpen(true);
    setAssignBatch(workspace.sourceBatchRow || null);
    setAssignManufacturerId("");
    setAssignQuantity("");
    await fetchWorkspaceHistory(workspace);
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

  const openBatchContextFromAllocationMap = async (batchId: string) => {
    const targetBatchId = String(batchId || "").trim();
    const mapSnapshot: any = allocationMap;
    const sourceBatchIdFromMap = String(mapSnapshot?.sourceBatchId || mapSnapshot?.sourceBatch?.id || "").trim();

    // Always close map first so navigation never happens behind a blocking overlay.
    setAllocationMapOpen(false);
    setAllocationMapLoading(false);

    if (!targetBatchId && !sourceBatchIdFromMap) return;

    const currentWorkspaceMatches =
      workspaceBatch &&
      (workspaceBatch.sourceBatchId === targetBatchId ||
        workspaceBatch.sourceBatchRow?.id === targetBatchId ||
        workspaceBatch.allocations.some((allocation) => allocation.batchId === targetBatchId));
    if (currentWorkspaceMatches) {
      return;
    }

    const matchWorkspaceByBatchId = (candidateId: string) =>
      stableRows.find(
        (row) =>
          row.sourceBatchId === candidateId ||
          row.sourceBatchRow?.id === candidateId ||
          row.allocations.some((allocation) => allocation.batchId === candidateId)
      ) || null;

    const matchedWorkspace =
      (targetBatchId ? matchWorkspaceByBatchId(targetBatchId) : null) ||
      (sourceBatchIdFromMap ? matchWorkspaceByBatchId(sourceBatchIdFromMap) : null);

    if (matchedWorkspace) {
      setAssignmentFilter("all");
      setQ(matchedWorkspace.sourceBatchName);
      await openWorkspace(matchedWorkspace);
      return;
    }

    const fallbackRow =
      (targetBatchId ? rows.find((row) => row.id === targetBatchId) : undefined) ||
      (sourceBatchIdFromMap ? rows.find((row) => row.id === sourceBatchIdFromMap) : undefined);

    setAssignmentFilter("all");
    if (fallbackRow?.name) {
      setQ(fallbackRow.name);
      return;
    }
    setQ(targetBatchId || sourceBatchIdFromMap);
  };

  useEffect(() => {
    if (!workspaceOpen || !workspaceBatch) return;
    const timer = window.setInterval(() => {
      fetchWorkspaceHistory(workspaceBatch, { silent: true });
    }, 8_000);
    return () => window.clearInterval(timer);
  }, [workspaceBatch, workspaceOpen]);

  useEffect(() => {
    if (!workspaceOpen || !workspaceBatch) return;
    const refreshed = stableRows.find((row) => row.sourceBatchId === workspaceBatch.sourceBatchId) || null;
    if (!refreshed) {
      setWorkspaceOpen(false);
      setWorkspaceBatch(null);
      setWorkspaceHistoryLogs([]);
      setWorkspaceHistoryLastUpdatedAt(null);
      return;
    }
    setWorkspaceBatch(refreshed);
    setAssignBatch(refreshed.sourceBatchRow || null);
    void fetchWorkspaceHistory(refreshed, { silent: true });
  }, [stableRows, workspaceBatch, workspaceOpen]);

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
                : "Manage received source batches through a stable workspace for allocation, printing review, and audit."}
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
                    <SelectItem value="all">All source batches</SelectItem>
                    <SelectItem value="assigned">With manufacturer assignments</SelectItem>
                    <SelectItem value="unassigned">With unassigned inventory</SelectItem>
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
            {isManufacturer ? (
              <>
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
                      ) : filteredRows.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={7} className="text-muted-foreground">
                            No batches found.
                          </TableCell>
                        </TableRow>
                      ) : (
                        filteredRows.map((b) => {
                          const printed = !!b.printedAt;

                          return (
                            <TableRow key={b.id}>
                              <TableCell>
                                <div className="space-y-1">
                                  <div className="font-medium break-words">{b.name}</div>
                                  {b.licensee?.name ? (
                                    <div className="text-xs text-muted-foreground">
                                      {b.licensee.name} ({b.licensee.prefix})
                                    </div>
                                  ) : (
                                    <div className="text-xs text-muted-foreground">Licensee scope</div>
                                  )}
                                  <div className="flex items-center gap-2 text-xs">
                                    <Badge variant="default">Allocated batch</Badge>
                                    <Badge variant={Number(b.totalCodes || 0) > 0 ? "outline" : "secondary"}>
                                      {Number(b.totalCodes || 0).toLocaleString()} total
                                    </Badge>
                                  </div>
                                </div>
                              </TableCell>

                              <TableCell className="font-mono text-xs">
                                <div className="break-all">{b.startCode}</div>
                                <div className="break-all">{b.endCode}</div>
                              </TableCell>

                              <TableCell>
                                <div className="space-y-1">
                                  <Badge variant={getAvailabilityTone(getAvailableInventory(b))}>
                                    {getAvailabilityTitle(b)}: {getAvailableInventory(b).toLocaleString()}
                                  </Badge>
                                  <div className="text-[11px] text-muted-foreground">
                                    Printed {Number(b.printedCodes || 0).toLocaleString()} · Redeemed {Number(b.redeemedCodes || 0).toLocaleString()}
                                  </div>
                                  <div className="text-[11px] text-muted-foreground font-mono break-all">
                                    {b.remainingStartCode && b.remainingEndCode
                                      ? `${b.remainingStartCode} -> ${b.remainingEndCode}`
                                      : "-"}
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
                                {b.createdAt ? format(new Date(b.createdAt), "MMM d, yyyy") : "-"}
                              </TableCell>

                              <TableCell>
                                <div className="flex flex-wrap gap-2">
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    disabled={loading || getAvailableInventory(b) <= 0}
                                    onClick={() => openPrintPack(b)}
                                  >
                                    <Download className="mr-2 h-4 w-4" />
                                    Create Print Job
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          );
                        })
                      )}
                    </TableBody>
                  </Table>
                </div>

                <div className="mt-3 text-sm text-muted-foreground">
                  Showing {filteredRows.length} of {rows.length}
                </div>
              </>
            ) : (
              <>
                <div className="mb-4 rounded-2xl border bg-muted/10 px-4 py-3 text-sm text-muted-foreground">
                  One stable row is shown for each source batch. Open the workspace to allocate more quantity, review manufacturer distribution, inspect print status, and download audit evidence without split-row confusion in the main list.
                </div>

                <div className="rounded-md border">
                  <Table className="table-fixed">
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-[24%]">Batch</TableHead>
                        <TableHead className="w-[16%]">Original range</TableHead>
                        <TableHead className="w-[19%]">Inventory</TableHead>
                        <TableHead className="w-[16%]">Manufacturers</TableHead>
                        <TableHead className="w-[14%]">Print status</TableHead>
                        <TableHead className="w-[11%]">Updated</TableHead>
                        <TableHead className="w-[120px] text-right">Workspace</TableHead>
                      </TableRow>
                    </TableHeader>

                    <TableBody>
                      {loading ? (
                        <TableRow>
                          <TableCell colSpan={7} className="text-muted-foreground">
                            Loading...
                          </TableCell>
                        </TableRow>
                      ) : filteredStableRows.length === 0 ? (
                        <TableRow>
                          <TableCell colSpan={7} className="text-muted-foreground">
                            No source batches found.
                          </TableCell>
                        </TableRow>
                      ) : (
                        filteredStableRows.map((row) => {
                          const topManufacturer = row.manufacturerSummary[0] || null;

                          return (
                            <TableRow
                              key={row.sourceBatchId}
                              className="cursor-pointer hover:bg-muted/20"
                              onClick={() => void openWorkspace(row)}
                            >
                              <TableCell>
                                <div className="space-y-2 pr-4">
                                  <div>
                                    <div className="font-medium break-words">{row.sourceBatchName}</div>
                                  </div>
                                  <div className="text-xs text-muted-foreground">
                                    {row.licensee?.name ? `${row.licensee.name} (${row.licensee.prefix})` : "Licensee scope"}
                                  </div>
                                  <div className="flex flex-wrap gap-2">
                                    <Badge variant="secondary">Source batch</Badge>
                                    <Badge variant="outline">{row.originalTotalCodes.toLocaleString()} total</Badge>
                                  </div>
                                </div>
                              </TableCell>

                              <TableCell className="font-mono text-[11px] leading-5">
                                <div className="break-all">{row.sourceOriginalRangeStart}</div>
                                <div className="break-all">{row.sourceOriginalRangeEnd}</div>
                              </TableCell>

                              <TableCell>
                                <div className="space-y-2 pr-4">
                                  <Badge variant={row.remainingUnassignedCodes > 0 ? "default" : "secondary"}>
                                    {row.remainingUnassignedCodes.toLocaleString()} unassigned remaining
                                  </Badge>
                                  <div className="flex flex-wrap gap-2 text-xs">
                                    <Badge variant={row.assignedCodes > 0 ? "secondary" : "outline"}>
                                      {row.assignedCodes.toLocaleString()} assigned
                                    </Badge>
                                    <Badge variant={row.pendingPrintableCodes > 0 ? "secondary" : "outline"}>
                                      {row.pendingPrintableCodes.toLocaleString()} ready to print
                                    </Badge>
                                  </div>
                                  <div className="text-[11px] text-muted-foreground font-mono break-all">
                                    {row.remainingRangeStart && row.remainingRangeEnd
                                      ? `${row.remainingRangeStart} -> ${row.remainingRangeEnd}`
                                      : "No unassigned range remains."}
                                  </div>
                                </div>
                              </TableCell>

                              <TableCell>
                                {topManufacturer ? (
                                  <div className="space-y-2">
                                    <div className="font-medium">{topManufacturer.manufacturerName}</div>
                                    <div className="text-xs text-muted-foreground">
                                      {row.manufacturerCount > 1
                                        ? `+${row.manufacturerCount - 1} more manufacturer accounts`
                                        : `${topManufacturer.allocatedCodes.toLocaleString()} assigned`}
                                    </div>
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground">Not assigned yet</span>
                                )}
                              </TableCell>

                              <TableCell>
                                <div className="space-y-2">
                                  <Badge variant={row.printedCodes > 0 ? "secondary" : "outline"}>
                                    {row.printedCodes.toLocaleString()} printed
                                  </Badge>
                                  <div className="text-xs text-muted-foreground">
                                    Ready {row.pendingPrintableCodes.toLocaleString()} · Redeemed {row.redeemedCodes.toLocaleString()}
                                  </div>
                                </div>
                              </TableCell>

                              <TableCell className="text-muted-foreground">
                                {row.sourceUpdatedAt ? format(new Date(row.sourceUpdatedAt), "MMM d, yyyy") : "-"}
                              </TableCell>

                              <TableCell className="text-right">
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={(event) => {
                                    event.stopPropagation();
                                    void openWorkspace(row);
                                  }}
                                >
                                  Open
                                </Button>
                              </TableCell>
                            </TableRow>
                          );
                        })
                      )}
                    </TableBody>
                  </Table>
                </div>

                <div className="mt-3 text-sm text-muted-foreground">
                  Showing {filteredStableRows.length} of {stableRows.length}
                </div>
              </>
            )}
          </CardContent>
        </Card>

        <LicenseeBatchWorkspaceDialog
          open={workspaceOpen}
          onOpenChange={(open) => {
            setWorkspaceOpen(open);
            if (!open) {
              setWorkspaceBatch(null);
              setAssignBatch(null);
              setAssignManufacturerId("");
              setAssignQuantity("");
              setWorkspaceHistoryLogs([]);
              setWorkspaceHistoryLastUpdatedAt(null);
            }
          }}
          workspace={workspaceBatch}
          manufacturers={manufacturers}
          assignManufacturerId={assignManufacturerId}
          assignQuantity={assignQuantity}
          assigning={loading}
          onAssignManufacturerChange={setAssignManufacturerId}
          onAssignQuantityChange={setAssignQuantity}
          onSubmitAssign={submitAssign}
          onOpenRename={() => {
            if (workspaceBatch?.sourceBatchRow) {
              openRename(workspaceBatch.sourceBatchRow);
            }
          }}
          onOpenAllocationMap={() => {
            if (workspaceBatch?.sourceBatchRow) {
              void openAllocationMap(workspaceBatch.sourceBatchRow);
            }
          }}
          onDownloadAudit={() => {
            if (workspaceBatch?.sourceBatchRow) {
              void downloadAuditPackage(workspaceBatch.sourceBatchRow);
            }
          }}
          onDelete={() => {
            if (workspaceBatch?.sourceBatchRow) {
              void handleDelete(workspaceBatch.sourceBatchRow);
            }
          }}
          canAssignManufacturer={canAssignManufacturer}
          canDelete={canDelete}
          exportingAudit={exportingBatchId === workspaceBatch?.sourceBatchRow?.id}
          historyLoading={workspaceHistoryLoading}
          historyLogs={workspaceHistoryLogs}
          historyLastUpdatedAt={workspaceHistoryLastUpdatedAt}
          onRefreshHistory={() => {
            if (workspaceBatch) {
              void fetchWorkspaceHistory(workspaceBatch);
            }
          }}
        />

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
              setDirectRemainingToPrint(null);
              const keepNetworkDispatchProgress =
                !printing &&
                (printProgressDispatchMode === "NETWORK_DIRECT" || printProgressDispatchMode === "NETWORK_IPP") &&
                !isTerminalPrintProgressPhase(printProgressPhase);
              if (!printing && !keepNetworkDispatchProgress) {
                setPrintProgressOpen(false);
                setPrintProgressPrinterName(null);
                setPrintProgressDispatchMode(null);
              }
            }
          }}
        >
          <DialogContent className="sm:max-w-[640px] max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Print Job</DialogTitle>
              <DialogDescription>
                Select quantity and a saved printer. MSCQR will use the approved printing path for that printer automatically.
              </DialogDescription>
            </DialogHeader>

            {!printBatch ? (
              <div className="text-sm text-muted-foreground">No batch selected.</div>
            ) : (
              <div className="space-y-4 mt-2">
                <div
                  className={
                    selectedPrinterNotice.tone === "success"
                      ? "rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800"
                      : selectedPrinterNotice.tone === "warning"
                        ? "rounded-md border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800"
                      : selectedPrinterNotice.tone === "neutral"
                        ? "rounded-md border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700"
                        : "rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-800"
                  }
                >
                  <div className="font-medium">{selectedPrinterNotice.title}</div>
                  <div className="text-xs">{selectedPrinterNotice.summary}</div>
                  <div className="mt-2 text-[11px]">
                    {selectedPrinterNotice.detail}
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
                    Ready to print: {getAvailableInventory(printBatch)}
                  </div>
                </div>

                <div className="space-y-3 rounded-md border p-3">
                  <div className="text-sm font-medium">Printer selection</div>
                  {registeredPrinters.length === 0 && (
                    <div className="rounded-md border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
                      No saved printer profiles are available yet. Open Printer Setup, add or check a printer, then return here and refresh this dialog.
                      <div className="mt-2 flex flex-wrap gap-2">
                        <Button size="sm" variant="outline" onClick={() => navigate("/printer-diagnostics")}>
                          Open Printer Setup
                        </Button>
                        <Button size="sm" variant="ghost" onClick={() => void loadPrinterStatus()}>
                          Refresh printers
                        </Button>
                      </div>
                    </div>
                  )}
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label className="text-xs">Registered printer profile</Label>
                      <Select
                        value={selectedPrinterProfileId || "__none__"}
                        onValueChange={(value) => setSelectedPrinterProfileId(value === "__none__" ? "" : value)}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select printer profile" />
                        </SelectTrigger>
                        <SelectContent>
                          {registeredPrinters.length === 0 ? (
                            <SelectItem value="__none__">No registered printers</SelectItem>
                          ) : (
                            registeredPrinters.map((row) => (
                              <SelectItem key={row.id} value={row.id}>
                                {row.name}
                                {` · ${getPrinterDispatchLabel(row)}`}
                                {!row.isActive ? " · inactive" : ""}
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  {selectedPrinterProfile && (
                    <div className="rounded-md border bg-muted/20 px-3 py-3 text-sm">
                      <div className="font-medium">{selectedPrinterProfile.name}</div>
                      <div className="mt-1 text-xs text-muted-foreground">{getPrinterDispatchLabel(selectedPrinterProfile)}</div>
                    </div>
                  )}

                  {selectedPrinterProfile?.connectionType === "LOCAL_AGENT" ? (
                    <>
                      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                        <div className="space-y-1">
                          <Label className="text-xs">Active workstation printer</Label>
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
                      </div>
                      <div className="rounded-md border bg-muted/20 p-3 text-xs text-muted-foreground">
                        Use <strong>Printer Setup</strong> if this workstation printer needs alignment or setup changes before the next run.
                      </div>
                      <div className="flex flex-wrap justify-end gap-2">
                        <Button variant="outline" size="sm" disabled={switchingPrinter || !selectedPrinterId || detectedPrinters.length <= 1} onClick={switchSelectedPrinter}>
                          {switchingPrinter ? "Switching..." : "Switch workstation printer"}
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => navigate("/printer-diagnostics")}>
                          Open Printer Setup
                        </Button>
                      </div>
                    </>
                  ) : (
                    <div className="rounded-md border bg-muted/20 p-3 text-sm">
                      <div className="font-medium">{selectedPrinterProfile?.name || "Network printer"}</div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {getPrinterDispatchLabel(selectedPrinterProfile)}
                      </div>
                      <div className="mt-2 text-xs text-muted-foreground">
                        {sanitizePrinterUiError(
                          selectedPrinterProfile?.registryStatus?.detail,
                          selectedPrinterProfile?.connectionType === "NETWORK_IPP"
                            ? "MSCQR will send the approved job to this office printer using its saved setup."
                            : "MSCQR will send the approved job to this factory label printer using its saved setup."
                        )}
                      </div>
                      <div className="mt-3 flex justify-end">
                        <Button variant="outline" size="sm" onClick={() => navigate("/printer-diagnostics")}>
                          Open Printer Setup
                        </Button>
                      </div>
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button onClick={createPrintJob} disabled={printing || !selectedPrinterProfile || !selectedPrinterCanPrint}>
                    {printing ? "Starting..." : "Start print"}
                  </Button>
                </div>

                {printJobId && (
                  <div className="rounded-md border p-3 text-sm space-y-2">
                    <div className="text-xs text-muted-foreground">Current print job</div>
                    <div className="font-medium">Printing in progress</div>
                    <div className="text-xs text-muted-foreground">
                      Target printer: {printProgressPrinterName || selectedPrinterProfile?.name || "—"} ·{" "}
                      {formatDispatchModeLabel(printProgressDispatchMode || selectedPrinterProfile?.connectionType || null)}
                    </div>
                    {directRemainingToPrint != null && (
                      <div className="text-xs text-muted-foreground">Remaining to print: {directRemainingToPrint}</div>
                    )}
                  </div>
                )}

                {printJobId && printLockToken && selectedPrinterProfile?.connectionType === "LOCAL_AGENT" && directRemainingToPrint !== 0 && (
                  <div className="rounded-md border border-emerald-200 bg-emerald-50 p-3 text-sm space-y-3">
                    <div className="font-medium text-emerald-900">Continue remaining labels</div>
                    <div className="text-xs text-emerald-900">
                      Retry only the labels that are still pending on this workstation.
                    </div>
                    <div className="flex justify-end">
                      <Button variant="outline" onClick={requestDirectPrintTokens} disabled={printing || !printJobId}>
                        Retry pending labels
                      </Button>
                    </div>
                  </div>
                )}

                {recentPrintJobs.length > 0 && (
                  <div className="rounded-md border p-3 text-sm space-y-3">
                    <div className="font-medium">Recent print jobs</div>
                    <div className="space-y-2">
                      {recentPrintJobs.map((job) => (
                        <div key={job.id} className="rounded-md border bg-muted/20 px-3 py-2">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="font-medium">
                              {job.jobNumber || "Print job"}
                            </div>
                            <Badge variant={job.status === "FAILED" ? "destructive" : "secondary"}>
                              {job.status}
                            </Badge>
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            {formatDispatchModeLabel(job.printMode)} ·{" "}
                            {job.printer?.name || "Unknown printer"} · {job.itemCount || job.quantity} labels
                          </div>
                          <div className="mt-1 text-xs text-muted-foreground">
                            Confirmed {job.session?.confirmedItems || 0}
                            {typeof job.session?.remainingToPrint === "number"
                              ? ` · Remaining ${job.session.remainingToPrint}`
                              : ""}
                            {job.failureReason ? ` · ${sanitizePrinterUiError(job.failureReason, "This print job needs attention.")}` : ""}
                          </div>
                        </div>
                      ))}
                    </div>
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
            void openBatchContextFromAllocationMap(batchId);
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
          printerName={printProgressPrinterName}
          modeLabel={formatDispatchModeLabel(printProgressDispatchMode)}
          error={printProgressError}
          onOpenChange={(open) => {
            if (!printing) setPrintProgressOpen(open);
          }}
        />
      </div>
    </DashboardLayout>
  );
}

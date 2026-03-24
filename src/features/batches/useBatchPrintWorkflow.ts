import { useEffect, useMemo, useRef, useState } from "react";

import apiClient from "@/lib/api-client";
import { getPrinterDiagnosticSummary, type LocalPrinterAgentSnapshot } from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import {
  useManufacturerPrinterRuntime,
  usePrintJobs,
  type ManufacturerPrinterRuntime,
} from "@/features/printing/hooks";

import {
  buildManagedNetworkPrinterNotice,
  defaultPrinterStatus,
  formatDispatchModeLabel,
  isCompletedPrintProgressPhase,
  isTerminalPrintProgressPhase,
  normalizePrinterRows,
  PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS,
} from "./print-workflow-utils";
import {
  createPrintJob as executeCreatePrintJob,
  retryPendingDirectPrint,
  syncProgressFromPrintJob as syncPrintJobProgress,
} from "./batch-print-operations";
import type {
  BatchRow,
  LocalPrinterRow,
  PrintJobRow,
  PrinterConnectionStatus,
  PrinterSelectionNotice,
  RegisteredPrinterRow,
} from "./types";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type UseBatchPrintWorkflowParams = {
  isManufacturer: boolean;
  userId?: string | null;
  toast: ToastLike;
  getAvailableInventory: (batch: BatchRow) => number;
  onBatchesChanged?: () => Promise<void> | void;
};

type CalibrationProfileState = {
  dpi: string;
  labelWidthMm: string;
  labelHeightMm: string;
  offsetXmm: string;
  offsetYmm: string;
  darkness: string;
  speed: string;
};

export function useBatchPrintWorkflow({
  isManufacturer,
  userId,
  toast,
  getAvailableInventory,
  onBatchesChanged,
}: UseBatchPrintWorkflowParams) {
  const [printOpen, setPrintOpen] = useState(false);
  const [printBatch, setPrintBatch] = useState<BatchRow | null>(null);
  const [printing, setPrinting] = useState(false);
  const [printQuantity, setPrintQuantity] = useState("");
  const [printJobId, setPrintJobId] = useState("");
  const [printLockToken, setPrintLockToken] = useState("");
  const [printJobTokensCount, setPrintJobTokensCount] = useState(0);
  const [directRemainingToPrint, setDirectRemainingToPrint] = useState<number | null>(null);
  const [detectedPrinters, setDetectedPrinters] = useState<LocalPrinterRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [registeredPrinters, setRegisteredPrinters] = useState<RegisteredPrinterRow[]>([]);
  const [selectedPrinterProfileId, setSelectedPrinterProfileId] = useState("");
  const [recentPrintJobs, setRecentPrintJobs] = useState<PrintJobRow[]>([]);
  const [switchingPrinter, setSwitchingPrinter] = useState(false);
  const [printPath] = useState<"auto" | "spooler" | "raw-9100" | "label-language" | "pdf-raster">("auto");
  const [labelLanguage] = useState<"AUTO" | "ZPL" | "EPL" | "CPCL" | "TSPL" | "ESC_POS">("AUTO");
  const [calibrationProfile, setCalibrationProfile] = useState<CalibrationProfileState>({
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
  const [printProgressDispatchMode, setPrintProgressDispatchMode] = useState<
    "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | null
  >(null);
  const [localPrinterAgent, setLocalPrinterAgent] = useState<LocalPrinterAgentSnapshot>({
    reachable: false,
    connected: false,
    error: "Local print agent has not been checked yet.",
    checkedAt: null,
  });
  const [printerStatus, setPrinterStatus] = useState<PrinterConnectionStatus>(defaultPrinterStatus);
  const printerFailureReportRef = useRef<{ signature: string; at: number }>({ signature: "", at: 0 });
  const printerFailureInFlightRef = useRef(false);

  const printJobsQuery = usePrintJobs(printBatch?.id, 8, false);
  const printerRuntimeQuery = useManufacturerPrinterRuntime(true, false);

  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
  const printerHasInventory =
    detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId);
  const activeLocalPrinterId = String(
    selectedPrinterId || printerStatus.selectedPrinterId || printerStatus.printerId || ""
  ).trim();
  const selectedDetectedPrinter = useMemo(
    () =>
      detectedPrinters.find((row) => row.printerId === activeLocalPrinterId) ||
      detectedPrinters.find((row) => row.isDefault) ||
      detectedPrinters[0] ||
      null,
    [activeLocalPrinterId, detectedPrinters]
  );
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
      tone: printerDiagnostics.tone,
    };
  }, [
    printerDiagnostics.detail,
    printerDiagnostics.summary,
    printerDiagnostics.title,
    printerDiagnostics.tone,
    printerReady,
    printerStatus.printerName,
    printerStatus.selectedPrinterName,
    selectedPrinterProfile,
  ]);

  const applyRegisteredPrintersSnapshot = (
    printers: RegisteredPrinterRow[],
    preferredLocalPrinterId?: string | null
  ) => {
    setRegisteredPrinters(printers);
    setSelectedPrinterProfileId((previous) => {
      if (previous && printers.some((row) => row.id === previous && row.isActive)) return previous;

      const trimmedLocalId = String(preferredLocalPrinterId || "").trim();
      if (trimmedLocalId) {
        const matchingLocal = printers.find(
          (row) => row.connectionType === "LOCAL_AGENT" && row.nativePrinterId === trimmedLocalId && row.isActive
        );
        if (matchingLocal) return matchingLocal.id;
      }

      const preferred =
        printers.find((row) => row.isDefault && row.isActive) || printers.find((row) => row.isActive);
      return preferred?.id || "";
    });
  };

  const buildCalibrationPayload = () => ({
    dpi:
      Number(calibrationProfile.dpi || 0) ||
      selectedDetectedPrinter?.dpi ||
      (Array.isArray(printerStatus.capabilitySummary?.dpiOptions)
        ? printerStatus.capabilitySummary?.dpiOptions[0]
        : undefined) ||
      undefined,
    labelWidthMm: Number(calibrationProfile.labelWidthMm || 0) || undefined,
    labelHeightMm: Number(calibrationProfile.labelHeightMm || 0) || undefined,
    offsetXmm: Number(calibrationProfile.offsetXmm || 0) || 0,
    offsetYmm: Number(calibrationProfile.offsetYmm || 0) || 0,
    darkness: Number(calibrationProfile.darkness || 0) || undefined,
    speed: Number(calibrationProfile.speed || 0) || undefined,
  });

  const applyPrinterRuntimeSnapshot = (
    snapshot: ManufacturerPrinterRuntime,
    preferredLocalPrinterId?: string | null
  ) => {
    setLocalPrinterAgent(snapshot.localAgent);
    setPrinterStatus({
      ...(snapshot.remoteStatus as PrinterConnectionStatus),
      printers: snapshot.detectedPrinters as LocalPrinterRow[],
    });
    setDetectedPrinters(snapshot.detectedPrinters as LocalPrinterRow[]);
    const nextPreferredPrinterId = String(preferredLocalPrinterId || snapshot.preferredPrinterId || "").trim();
    if (nextPreferredPrinterId) {
      setSelectedPrinterId((previous) => previous || nextPreferredPrinterId);
    }
    applyRegisteredPrintersSnapshot(
      snapshot.registeredPrinters as RegisteredPrinterRow[],
      nextPreferredPrinterId || snapshot.preferredPrinterId
    );
  };

  const autoReportPrinterFailure = async (params: {
    context: string;
    reason: string;
    diagnostics?: Record<string, unknown>;
  }) => {
    const now = Date.now();
    const signature = `${params.context}|${params.reason}|${
      selectedPrinterId || printerStatus.selectedPrinterId || printerStatus.printerId || ""
    }`;

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
      // Avoid interrupting print flow when auto-reporting fails.
    } finally {
      printerFailureInFlightRef.current = false;
    }
  };

  const loadRecentPrintJobs = async () => {
    if (!isManufacturer) return;
    const response = await printJobsQuery.refetch();
    if (!response.data) {
      setRecentPrintJobs([]);
      return;
    }
    setRecentPrintJobs(Array.isArray(response.data) ? (response.data as PrintJobRow[]) : []);
  };

  const loadPrinterStatus = async () => {
    if (!isManufacturer) return;
    const response = await printerRuntimeQuery.refetch();
    if (!response.data) {
      setRegisteredPrinters([]);
      setDetectedPrinters([]);
      return;
    }
    applyPrinterRuntimeSnapshot(response.data);
  };

  useEffect(() => {
    if (printJobsQuery.data) {
      setRecentPrintJobs(Array.isArray(printJobsQuery.data) ? (printJobsQuery.data as PrintJobRow[]) : []);
    }
  }, [printJobsQuery.data]);

  useEffect(() => {
    if (printerRuntimeQuery.data) {
      applyPrinterRuntimeSnapshot(printerRuntimeQuery.data);
    }
  }, [printerRuntimeQuery.data]);

  useEffect(() => {
    if (!isManufacturer) return;
    void loadPrinterStatus();
    void loadRecentPrintJobs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isManufacturer, userId]);

  useEffect(() => {
    if (!selectedPrinterId) return;
    const key = `printer-calibration:${selectedPrinterId}`;
    try {
      const raw = window.localStorage.getItem(key);
      if (!raw) return;
      const parsed = JSON.parse(raw) as Partial<CalibrationProfileState>;
      if (!parsed || typeof parsed !== "object") return;
      setCalibrationProfile((previous) => ({
        dpi: parsed.dpi ? String(parsed.dpi) : previous.dpi,
        labelWidthMm: parsed.labelWidthMm ? String(parsed.labelWidthMm) : previous.labelWidthMm,
        labelHeightMm: parsed.labelHeightMm ? String(parsed.labelHeightMm) : previous.labelHeightMm,
        offsetXmm: parsed.offsetXmm != null ? String(parsed.offsetXmm) : previous.offsetXmm,
        offsetYmm: parsed.offsetYmm != null ? String(parsed.offsetYmm) : previous.offsetYmm,
        darkness: parsed.darkness ? String(parsed.darkness) : previous.darkness,
        speed: parsed.speed ? String(parsed.speed) : previous.speed,
      }));
    } catch {
      // Ignore malformed local calibration state.
    }
  }, [selectedPrinterId]);

  useEffect(() => {
    if (!selectedPrinterId) return;
    setSelectedPrinterProfileId((previous) => {
      const current = registeredPrinters.find((row) => row.id === previous) || null;
      if (current?.connectionType && current.connectionType !== "LOCAL_AGENT") return previous;

      const matchingLocal = registeredPrinters.find(
        (row) => row.connectionType === "LOCAL_AGENT" && row.nativePrinterId === selectedPrinterId && row.isActive
      );
      return matchingLocal?.id || previous;
    });
  }, [registeredPrinters, selectedPrinterId]);

  const openPrintPack = (batch: BatchRow) => {
    setPrintBatch(batch);
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
    void loadRecentPrintJobs();
  };

  const handlePrintDialogOpenChange = (open: boolean) => {
    setPrintOpen(open);
    if (!open) {
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

  const progressStateSetters = useMemo(
    () => ({
      setPrintProgressOpen,
      setPrintProgressPhase,
      setPrintProgressTotal,
      setPrintProgressPrinted,
      setPrintProgressRemaining,
      setPrintProgressCurrentCode,
      setPrintProgressError,
      setPrintProgressPrinterName,
      setPrintProgressDispatchMode,
      setDirectRemainingToPrint,
    }),
    []
  );

  useEffect(() => {
    if (printing) return;
    if (!printJobId || (printProgressDispatchMode !== "NETWORK_DIRECT" && printProgressDispatchMode !== "NETWORK_IPP")) {
      return;
    }
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
        syncPrintJobProgress(job, progressStateSetters);
        if (job.status === "CONFIRMED" || job.status === "FAILED" || job.status === "CANCELLED") {
          void loadRecentPrintJobs();
          void onBatchesChanged?.();
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
  }, [
    onBatchesChanged,
    printJobId,
    printProgressDispatchMode,
    printProgressPhase,
    progressStateSetters,
    printing,
  ]);
  const createPrintJob = async () => {
    setPrinting(true);
    try {
      await executeCreatePrintJob({
        toast,
        printBatch,
        printQuantity,
        getAvailableInventory,
        selectedPrinterProfile,
        selectedPrinterId,
        detectedPrinters,
        printerStatus,
        activeLocalPrinterId,
        selectedPrinterCanPrint,
        setPrinterStatus,
        buildCalibrationPayload,
        autoReportPrinterFailure,
        onBatchesChanged,
        loadRecentPrintJobs,
        setPrintJobId,
        setPrintLockToken,
        setPrintJobTokensCount,
        printJobId,
        printLockToken,
        printJobTokensCount,
        directRemainingToPrint,
        ...progressStateSetters,
      });
    } finally {
      setPrinting(false);
    }
  };

  const requestDirectPrintTokens = async () => {
    if (!printJobId || !printLockToken) return;

    setPrinting(true);
    try {
      await retryPendingDirectPrint({
        toast,
        printBatch,
        printQuantity,
        getAvailableInventory,
        selectedPrinterProfile,
        selectedPrinterId,
        detectedPrinters,
        printerStatus,
        activeLocalPrinterId,
        selectedPrinterCanPrint,
        setPrinterStatus,
        buildCalibrationPayload,
        autoReportPrinterFailure,
        onBatchesChanged,
        loadRecentPrintJobs,
        setPrintJobId,
        setPrintLockToken,
        setPrintJobTokensCount,
        printJobId,
        printLockToken,
        printJobTokensCount,
        directRemainingToPrint,
        ...progressStateSetters,
      });
    } finally {
      setPrinting(false);
    }
  };

  const dialogProps = {
    open: printOpen,
    onOpenChange: handlePrintDialogOpenChange,
    printBatch,
    selectedPrinterNotice,
    printQuantity,
    onPrintQuantityChange: setPrintQuantity,
    readyToPrintCount: printBatch ? getAvailableInventory(printBatch) : 0,
    registeredPrinters,
    onRefreshPrinters: () => {
      void loadPrinterStatus();
    },
    selectedPrinterProfileId,
    onSelectedPrinterProfileIdChange: setSelectedPrinterProfileId,
    selectedPrinterProfile,
    detectedPrinters,
    selectedPrinterId,
    onSelectedPrinterIdChange: setSelectedPrinterId,
    switchingPrinter,
    onSwitchSelectedPrinter: switchSelectedPrinter,
    printing,
    onStartPrint: createPrintJob,
    selectedPrinterCanPrint,
    printJobId,
    printLockToken,
    printProgressPrinterName,
    printProgressDispatchMode,
    formatDispatchModeLabel,
    directRemainingToPrint,
    onRetryPendingLabels: requestDirectPrintTokens,
    recentPrintJobs,
    onClose: () => setPrintOpen(false),
  };

  const progressDialogProps = {
    open: printProgressOpen,
    phase: printProgressPhase,
    total: printProgressTotal,
    printed: printProgressPrinted,
    remaining: printProgressRemaining,
    currentCode: printProgressCurrentCode,
    printerName: printProgressPrinterName,
    modeLabel: formatDispatchModeLabel(printProgressDispatchMode),
    error: printProgressError,
    onOpenChange: (open: boolean) => {
      if (!printing) setPrintProgressOpen(open);
    },
  };

  return {
    printBatch,
    openPrintPack,
    dialogProps,
    progressDialogProps,
  };
}

export type BatchPrintWorkflow = ReturnType<typeof useBatchPrintWorkflow>;

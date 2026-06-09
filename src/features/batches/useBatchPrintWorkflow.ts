import { useEffect, useMemo, useRef, useState } from "react";

import apiClient from "@/lib/api-client";
import { getOptionalLocalStorageItem } from "@/lib/consent";
import {
  chooseStablePrinterSelection,
  getPrinterDiagnosticSummary,
  type LocalPrinterAgentSnapshot,
} from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { buildSupportDiagnosticsPayload, captureSupportScreenshot } from "@/lib/support-diagnostics";
import {
  loadManufacturerPrinterRuntimeSnapshot,
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
import { abandonPrintJobAction, printDiagnosticTestLabelAction, relinkSelectedPrinterAction } from "./print-workflow-recovery-actions";
import { runSingleFlightAction } from "./singleFlightAction";
import {
  buildCalibrationPayload as buildBatchCalibrationPayload,
  defaultCalibrationProfileState,
  mergeStoredCalibrationProfile,
  type CalibrationProfileState,
} from "./batchPrintWorkflowHelpers";
import type {
  BatchRow,
  LocalPrinterRow,
  PrintJobRow,
  PrinterConnectionStatus,
  PrinterSelectionNotice,
  RegisteredPrinterRow,
} from "./types";

type ToastLike = (options: { title?: string; description?: string; variant?: "default" | "destructive" }) => unknown;

type ReleaseApprovalState = {
  approvalRequired: boolean;
  approvalId: string;
  status: string;
  expiresAt?: string | null;
  threshold?: number | null;
};

type PrintControlAction = "pause" | "stop";

type UseBatchPrintWorkflowParams = {
  isManufacturer: boolean;
  userId?: string | null;
  toast: ToastLike;
  getAvailableInventory: (batch: BatchRow) => number;
  onBatchesChanged?: () => Promise<void> | void;
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
  const [directRemainingToPrint, setDirectRemainingToPrint] = useState<number | null>(null);
  const [detectedPrinters, setDetectedPrinters] = useState<LocalPrinterRow[]>([]);
  const [selectedPrinterId, setSelectedPrinterId] = useState("");
  const [registeredPrinters, setRegisteredPrinters] = useState<RegisteredPrinterRow[]>([]);
  const [selectedPrinterProfileId, setSelectedPrinterProfileId] = useState("");
  const [recentPrintJobs, setRecentPrintJobs] = useState<PrintJobRow[]>([]);
  const [sampleScanCodeByJobId, setSampleScanCodeByJobId] = useState<Record<string, string>>({});
  const [releaseApprovalState, setReleaseApprovalState] = useState<ReleaseApprovalState | null>(null);
  const [printControlDialog, setPrintControlDialog] = useState<{
    action: PrintControlAction | null;
    job: PrintJobRow | null;
    reason: string;
    submitting: boolean;
  }>({ action: null, job: null, reason: "", submitting: false });
  const [printReissueDialog, setPrintReissueDialog] = useState<{
    job: PrintJobRow | null;
    reason: string;
    submitting: boolean;
  }>({ job: null, reason: "", submitting: false });
  const [printControlBusyJobId, setPrintControlBusyJobId] = useState<string | null>(null);
  const [printCooldownUntil, setPrintCooldownUntil] = useState<number>(0);
  const [printCooldownNow, setPrintCooldownNow] = useState<number>(() => Date.now());
  const [switchingPrinter, setSwitchingPrinter] = useState(false);
  const [relinkingPrinter, setRelinkingPrinter] = useState(false);
  const [calibrationProfile, setCalibrationProfile] = useState<CalibrationProfileState>(defaultCalibrationProfileState);
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
  const actionInFlightRef = useRef(new Map<string, Promise<void>>());

  const printJobsQuery = usePrintJobs(printBatch?.id, 8, false);
  const printerRuntimeQuery = useManufacturerPrinterRuntime(true, false);

  const printerReady = printerStatus.connected && printerStatus.eligibleForPrinting;
  const printerHasInventory =
    detectedPrinters.length > 0 || Boolean(printerStatus.selectedPrinterId || printerStatus.printerId);
  const activeLocalPrinterId = String(
    chooseStablePrinterSelection(
      detectedPrinters,
      selectedPrinterId,
      printerStatus.selectedPrinterId,
      printerStatus.printerId
    )?.printerId ||
      selectedPrinterId ||
      printerStatus.selectedPrinterId ||
      printerStatus.printerId ||
      ""
  ).trim();
  const selectedDetectedPrinter = useMemo(
    () =>
      detectedPrinters.find((row) => row.printerId === activeLocalPrinterId) ||
      chooseStablePrinterSelection(
        detectedPrinters,
        selectedPrinterId,
        printerStatus.selectedPrinterId,
        printerStatus.printerId
      ) ||
      null,
    [activeLocalPrinterId, detectedPrinters, printerStatus.printerId, printerStatus.selectedPrinterId, selectedPrinterId]
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
  const selectedLocalProfileRegistrationStale = Boolean(
    selectedPrinterProfile?.connectionType === "LOCAL_AGENT" &&
      printerReady &&
      selectedPrinterProfile.printerRegistrationId &&
      printerStatus.registrationId &&
      selectedPrinterProfile.printerRegistrationId !== printerStatus.registrationId &&
      selectedLocalProfileMatchesAgent
  );
  const selectedPrinterCanPrint = Boolean(
    selectedPrinterProfile &&
      selectedPrinterProfile.isActive &&
      (selectedPrinterProfile.connectionType !== "LOCAL_AGENT"
        ? selectedPrinterProfile.registryStatus?.state === "READY"
        : printerReady && selectedLocalProfileMatchesAgent && !selectedLocalProfileRegistrationStale)
  );
  const selectedPrinterNotice = useMemo<PrinterSelectionNotice>(() => {
    if (selectedPrinterProfile?.connectionType !== "LOCAL_AGENT") {
      return buildManagedNetworkPrinterNotice(selectedPrinterProfile);
    }

    return {
      title: printerDiagnostics.title,
      summary: selectedLocalProfileRegistrationStale
        ? "The printer is ready on this computer, but the saved printer link belongs to an older connector install."
        : printerReady
        ? `${selectedDetectedPrinter?.printerName || printerStatus.selectedPrinterName || printerStatus.printerName || "Printer on this computer"} is ready.`
        : printerDiagnostics.summary,
      detail: selectedLocalProfileRegistrationStale
        ? "Relink this saved printer to the current connector before starting the print run."
        : !printerReady
        ? printerDiagnostics.detail
        : "This printer is ready for approved MSCQR printing.",
      tone: selectedLocalProfileRegistrationStale ? "warning" : printerDiagnostics.tone,
    };
  }, [
    printerDiagnostics.detail,
    printerDiagnostics.summary,
    printerDiagnostics.title,
    printerDiagnostics.tone,
    printerReady,
    printerStatus.printerName,
    printerStatus.selectedPrinterName,
    selectedDetectedPrinter?.printerName,
    selectedLocalProfileRegistrationStale,
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

  const buildCalibrationPayload = () =>
    buildBatchCalibrationPayload({ calibrationProfile, selectedDetectedPrinter, printerStatus });

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
    const nextPreferredPrinterId = String(
      chooseStablePrinterSelection(
        snapshot.detectedPrinters as LocalPrinterRow[],
        selectedPrinterId || preferredLocalPrinterId,
        snapshot.remoteStatus.selectedPrinterId,
        snapshot.remoteStatus.printerId
      )?.printerId ||
        preferredLocalPrinterId ||
        snapshot.preferredPrinterId ||
        ""
    ).trim();
    if (nextPreferredPrinterId) {
      setSelectedPrinterId((previous) => {
        const repaired = chooseStablePrinterSelection(
          snapshot.detectedPrinters as LocalPrinterRow[],
          previous || nextPreferredPrinterId,
          snapshot.remoteStatus.selectedPrinterId,
          snapshot.remoteStatus.printerId
        );
        return repaired?.printerId || previous || nextPreferredPrinterId;
      });
    }
    applyRegisteredPrintersSnapshot(
      snapshot.registeredPrinters as RegisteredPrinterRow[],
      nextPreferredPrinterId || snapshot.preferredPrinterId
    );
  };

  useEffect(() => {
    if (!printCooldownUntil || printCooldownUntil <= Date.now()) return;
    const timer = window.setInterval(() => setPrintCooldownNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [printCooldownUntil]);

  const cooldownRemainingSeconds = Math.max(0, Math.ceil((printCooldownUntil - printCooldownNow) / 1000));

  const recordPrintCooldown = (response: any) => {
    const retryAfter = Number(response?.retryAfterSeconds ?? response?.retryAfterSec ?? 90);
    const seconds = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.max(90, Math.ceil(retryAfter)) : 90;
    setPrintCooldownNow(Date.now());
    setPrintCooldownUntil(Date.now() + seconds * 1000);
    setPrintProgressError(`Printing is cooling down. You can try again after ${seconds} seconds.`);
  };

  const handlePrintControlFailure = (response: any, fallback: string) => {
    if (response?.code === "RATE_LIMITED" || response?.errorCode === "rate_limited") {
      recordPrintCooldown(response);
      toast({
        title: "Printing is cooling down",
        description: "Printed labels are preserved. Try again after 90 seconds and MSCQR will continue from the last safe point.",
        variant: "destructive",
      });
      return;
    }
    toast({
      title: "Print run needs attention",
      description: sanitizePrinterUiError(response?.error || response?.message, fallback),
      variant: "destructive",
    });
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
      return true;
    }
    if (printerFailureInFlightRef.current) return true;

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
          context: params.context,
          details: params.diagnostics || null,
        })
      );
      if (screenshot) form.append("screenshot", screenshot);
      const response = await apiClient.createSupportIssueReport(form);
      return Boolean(response.success);
    } catch {
      // Avoid interrupting print flow when auto-reporting fails.
      return false;
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

  const loadPrinterStatus = async (options: { force?: boolean } = {}) => {
    if (!isManufacturer) return;
    if (options.force) {
      try {
        applyPrinterRuntimeSnapshot(await loadManufacturerPrinterRuntimeSnapshot(true, { force: true }));
      } catch {
        if (printerStatus.connected && printerStatus.eligibleForPrinting) return;
        setRegisteredPrinters([]);
        setDetectedPrinters([]);
      }
      return;
    }
    const response = await printerRuntimeQuery.refetch();
    if (!response.data) {
      if (printerStatus.connected && printerStatus.eligibleForPrinting) return;
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
      const raw = getOptionalLocalStorageItem("functional", key);
      if (!raw) return;
      const parsed = JSON.parse(raw) as Partial<CalibrationProfileState>;
      if (!parsed || typeof parsed !== "object") return;
      setCalibrationProfile((previous) => mergeStoredCalibrationProfile(previous, parsed));
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
    setReleaseApprovalState(null);
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
    void loadPrinterStatus({ force: true });
    void loadRecentPrintJobs();
  };

  const handlePrintDialogOpenChange = (open: boolean) => {
    setPrintOpen(open);
    if (!open) {
      setPrintBatch(null);
      setReleaseApprovalState(null);
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
    if (switchingPrinter) return;
    if (!selectedPrinterId) return;
    setSwitchingPrinter(true);
    try {
      const response = await apiClient.selectLocalPrinter(selectedPrinterId);
      if (!response.success) {
        toast({
          title: "Switch failed",
          description: sanitizePrinterUiError(response.error, "Could not switch the printer on this computer."),
          variant: "destructive",
        });
        return;
      }
      toast({ title: "Printer updated", description: "The printer on this computer has been updated." });
      await loadPrinterStatus({ force: true });
    } finally {
      setSwitchingPrinter(false);
    }
  };
  const relinkSelectedPrinter = async () => {
    if (relinkingPrinter) return;
    await runSingleFlightAction(actionInFlightRef, `relink-printer:${selectedPrinterProfile?.id || "none"}`, () => relinkSelectedPrinterAction({
      selectedPrinterProfile,
      setRelinkingPrinter,
      setSelectedPrinterProfileId,
      loadPrinterStatus,
      toast,
    }));
  };
  const abandonPrintJob = async (jobId: string) => {
    await runSingleFlightAction(actionInFlightRef, `abandon-print-job:${jobId}`, () => abandonPrintJobAction({
      jobId,
      currentPrintJobId: printJobId,
      setPrinting,
      setPrintJobId,
      setDirectRemainingToPrint,
      loadRecentPrintJobs,
      onBatchesChanged,
      toast,
    }));
  };

  const openPrintControlDialog = (action: PrintControlAction, job: PrintJobRow) => {
    setPrintControlDialog({ action, job, reason: "", submitting: false });
  };

  const closePrintControlDialog = () => {
    if (printControlDialog.submitting) return;
    setPrintControlDialog({ action: null, job: null, reason: "", submitting: false });
  };

  const replaceRecentPrintJob = (nextJob: PrintJobRow) => {
    setRecentPrintJobs((previous) => {
      const found = previous.some((row) => row.id === nextJob.id);
      return found ? previous.map((row) => (row.id === nextJob.id ? nextJob : row)) : [nextJob, ...previous].slice(0, 8);
    });
    syncPrintJobProgress(nextJob, progressStateSetters);
  };

  const submitPrintControlDialog = async () => {
    const { action, job } = printControlDialog;
    const reason = printControlDialog.reason.trim();
    if (!action || !job) return;
    if (reason.length < 8) {
      toast({
        title: "Reason required",
        description: action === "stop" ? "Enter why this print run should be stopped." : "Enter why this print run is being paused.",
        variant: "destructive",
      });
      return;
    }

    return runSingleFlightAction(actionInFlightRef, `${action}-print-job:${job.id}:${reason}`, async () => {
      setPrintControlDialog((current) => ({ ...current, submitting: true }));
      setPrintControlBusyJobId(job.id);
      try {
        const response = action === "pause" ? await apiClient.pausePrintJob(job.id, reason) : await apiClient.stopPrintJob(job.id, reason);
        if (!response.success) {
          handlePrintControlFailure(response, action === "pause" ? "Print run could not be paused." : "Print run could not be stopped.");
          return;
        }
        if (response.data) replaceRecentPrintJob(response.data as PrintJobRow);
        await Promise.allSettled([loadRecentPrintJobs(), onBatchesChanged?.()]);
        setPrintControlDialog({ action: null, job: null, reason: "", submitting: false });
        toast({
          title: action === "pause" ? "Print run paused" : "Print run stopped",
          description:
            action === "pause"
              ? "MSCQR stopped new label dispatch. Already confirmed labels remain recorded."
              : "MSCQR stopped new label dispatch and preserved confirmed labels.",
        });
      } finally {
        setPrintControlBusyJobId(null);
        setPrintControlDialog((current) => ({ ...current, submitting: false }));
      }
    });
  };

  const resumePrintJob = async (jobId: string) => {
    const trimmedJobId = String(jobId || "").trim();
    if (!trimmedJobId) return;
    if (cooldownRemainingSeconds > 0) return;

    return runSingleFlightAction(actionInFlightRef, `resume-print-job:${trimmedJobId}`, async () => {
      setPrintControlBusyJobId(trimmedJobId);
      try {
        const response = await apiClient.resumePrintJob(trimmedJobId);
        if (!response.success) {
          handlePrintControlFailure(response, "Print run could not be resumed.");
          return;
        }
        if (response.data) replaceRecentPrintJob(response.data as PrintJobRow);
        setPrintProgressError(null);
        setPrintCooldownUntil(0);
        await Promise.allSettled([loadRecentPrintJobs(), onBatchesChanged?.()]);
        toast({
          title: "Print run resumed",
          description: "MSCQR will continue from labels that are still pending. Confirmed labels will not be duplicated.",
        });
      } finally {
        setPrintControlBusyJobId(null);
      }
    });
  };

  const openPrintReissueDialog = (job: PrintJobRow) => {
    setPrintReissueDialog({ job, reason: "", submitting: false });
  };

  const closePrintReissueDialog = () => {
    if (printReissueDialog.submitting) return;
    setPrintReissueDialog({ job: null, reason: "", submitting: false });
  };

  const submitPrintReissueRequest = async () => {
    const job = printReissueDialog.job;
    const reason = printReissueDialog.reason.trim();
    if (!job) return;
    if (reason.length < 8) {
      toast({
        title: "Reason required",
        description: "Enter why replacement labels are required before submitting the request.",
        variant: "destructive",
      });
      return;
    }

    return runSingleFlightAction(actionInFlightRef, `request-print-reissue:${job.id}:${reason}`, async () => {
      setPrintReissueDialog((current) => ({ ...current, submitting: true }));
      try {
        const response = await apiClient.createPrintReissueRequest(job.id, { reason });
        if (!response.success) {
          handlePrintControlFailure(response, "Reissue request could not be submitted.");
          return;
        }
        setPrintReissueDialog({ job: null, reason: "", submitting: false });
        toast({
          title: "Reissue request submitted",
          description: "An admin must approve replacement labels before MSCQR creates a new print run.",
        });
      } finally {
        setPrintReissueDialog((current) => ({ ...current, submitting: false }));
      }
    });
  };
  const confirmPrintedLabels = async (jobId: string) => {
    if (printing) return;
    const trimmedJobId = String(jobId || "").trim();
    if (!trimmedJobId) return;
    return runSingleFlightAction(actionInFlightRef, `confirm-print-job:${trimmedJobId}`, async () => {
    setPrinting(true);
    try {
      const response = await apiClient.confirmPrintJobPrinted(trimmedJobId, {
        operatorNote: "Operator confirmed labels physically printed from the MSCQR admin workflow.",
      });
      if (!response.success) {
        toast({
          title: "Confirmation needs attention",
          description: sanitizePrinterUiError(response.error || response.message, "MSCQR could not confirm this print run."),
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Labels confirmed",
        description: "MSCQR marked the acknowledged labels as physically printed and updated the audit trail.",
      });
      await loadRecentPrintJobs();
      await onBatchesChanged?.();
      const status = await apiClient.getPrintJobStatus(trimmedJobId);
      if (status.success && status.data) {
        syncPrintJobProgress(status.data as PrintJobRow, {
          setPrintProgressTotal,
          setPrintProgressPrinted,
          setPrintProgressRemaining,
          setDirectRemainingToPrint,
          setPrintProgressDispatchMode,
          setPrintProgressPrinterName,
          setPrintProgressPhase,
          setPrintProgressError,
          setPrintProgressOpen,
          setPrintProgressCurrentCode,
        });
      }
    } finally {
      setPrinting(false);
    }
    });
  };
  const setSampleScanCode = (jobId: string, value: string) => {
    const trimmedJobId = String(jobId || "").trim();
    if (!trimmedJobId) return;
    setSampleScanCodeByJobId((previous) => ({ ...previous, [trimmedJobId]: value }));
  };
  const verifySampleScan = async (jobId: string) => {
    if (printing) return;
    const trimmedJobId = String(jobId || "").trim();
    if (!trimmedJobId) return;
    const publicCode = String(sampleScanCodeByJobId[trimmedJobId] || "").trim();
    if (!publicCode) {
      toast({
        title: "Scan one printed label",
        description: "Scan or paste the exact MSCQR verify code from one physical label before verification.",
        variant: "destructive",
      });
      return;
    }
    return runSingleFlightAction(actionInFlightRef, `sample-scan:${trimmedJobId}:${publicCode}`, async () => {
    setPrinting(true);
    try {
      const response = await apiClient.capturePrintJobSampleScan(trimmedJobId, publicCode);
      if (!response.success) {
        toast({
          title: "Sample scan rejected",
          description: sanitizePrinterUiError(response.error || response.message, "That QR code is not part of this print run."),
          variant: "destructive",
        });
        return;
      }
      toast({
        title: "Sample scan verified",
        description: response.data?.sampleScanPolicy?.satisfied
          ? "MSCQR recorded the scan and the print run has enough sample proof for release."
          : "MSCQR recorded that the scanned label belongs to this confirmed print run.",
      });
      setSampleScanCodeByJobId((previous) => ({ ...previous, [trimmedJobId]: "" }));
      await loadRecentPrintJobs();
      await onBatchesChanged?.();
    } finally {
      setPrinting(false);
    }
    });
  };
  const releaseBatch = async () => {
    if (printing) return;
    const batchId = String(printBatch?.id || "").trim();
    if (!batchId) return;
    if (
      typeof window !== "undefined" &&
      !window.confirm("Release this batch? MSCQR will lock the completed print and sample-scan workflow for supply-chain release.")
    ) {
      return;
    }
    return runSingleFlightAction(actionInFlightRef, `release-batch:${batchId}`, async () => {
    setPrinting(true);
    try {
      const response = await apiClient.releaseBatch(batchId);
      if (!response.success) {
        const readiness = response.data?.readiness;
        const firstFailure =
          Array.isArray(readiness?.failures) && readiness.failures.length > 0
            ? String(readiness.failures[0]?.message || "")
            : "";
        toast({
          title: "Batch not ready for release",
          description: sanitizePrinterUiError(
            firstFailure || response.error || response.message,
            "Complete print acknowledgement, physical confirmation, and sample scan proof before release."
          ),
          variant: "destructive",
        });
        return;
      }
      if (response.data?.approvalRequired && response.data.approvalId) {
        setReleaseApprovalState({
          approvalRequired: true,
          approvalId: response.data.approvalId,
          status: response.data.status || "PENDING",
          expiresAt: response.data.expiresAt || null,
          threshold: response.data.approvalPolicy?.threshold ?? null,
        });
        toast({
          title: "Release approval requested",
          description:
            "A different authorized checker from the platform, brand, or assigned manufacturer must approve this high-value batch.",
        });
        await loadRecentPrintJobs();
        await onBatchesChanged?.();
        return;
      }
      setReleaseApprovalState(null);
      toast({
        title: "Batch released",
        description: "MSCQR locked the batch for supply-chain release and recorded the audit evidence.",
      });
      await loadRecentPrintJobs();
      await onBatchesChanged?.();
      setPrintBatch((current) =>
        current && current.id === batchId
          ? {
              ...current,
              lifecycleState: "RELEASED",
              releasedAt: response.data?.batch?.releasedAt || current.releasedAt || new Date().toISOString(),
            }
          : current
      );
    } finally {
      setPrinting(false);
    }
    });
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
    if (printing) return;
    const actionKey = `create-print-job:${printBatch?.id || "none"}:${selectedPrinterProfile?.id || "none"}:${printQuantity}`;
    return runSingleFlightAction(actionInFlightRef, actionKey, async () => {
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
        printJobId,
        directRemainingToPrint,
        ...progressStateSetters,
      });
    } finally {
      setPrinting(false);
    }
    });
  };

  const refreshPendingPrintStatus = async () => {
    if (printing) return;
    if (!printJobId) return;

    return runSingleFlightAction(actionInFlightRef, `refresh-print-job:${printJobId}`, async () => {
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
        printJobId,
        directRemainingToPrint,
        ...progressStateSetters,
      });
    } finally {
      setPrinting(false);
    }
    });
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
      void loadPrinterStatus({ force: true });
    },
    selectedPrinterProfileId,
    onSelectedPrinterProfileIdChange: setSelectedPrinterProfileId,
    selectedPrinterProfile,
    detectedPrinters,
    selectedPrinterId,
    onSelectedPrinterIdChange: setSelectedPrinterId,
    switchingPrinter,
    onSwitchSelectedPrinter: switchSelectedPrinter,
    relinkingPrinter,
    selectedLocalProfileRegistrationStale,
    onRelinkSelectedPrinter: relinkSelectedPrinter,
    onPrintDiagnosticTestLabel: () => {
      if (printing) return;
      void runSingleFlightAction(actionInFlightRef, `diagnostic-test-label:${selectedPrinterProfile?.id || "none"}`, () =>
        printDiagnosticTestLabelAction({ selectedPrinterProfile, setPrinting, toast })
      );
    },
    printing,
    onStartPrint: createPrintJob,
    selectedPrinterCanPrint,
    printJobId,
    printProgressPrinterName,
    printProgressDispatchMode,
    formatDispatchModeLabel,
    directRemainingToPrint,
    printControlDialog,
    printReissueDialog,
    printControlBusyJobId,
    printCooldownRemainingSeconds: cooldownRemainingSeconds,
    onOpenPrintControlDialog: openPrintControlDialog,
    onClosePrintControlDialog: closePrintControlDialog,
    onPrintControlReasonChange: (reason: string) => setPrintControlDialog((current) => ({ ...current, reason })),
    onSubmitPrintControlDialog: submitPrintControlDialog,
    onResumePrintJob: resumePrintJob,
    onOpenPrintReissueDialog: openPrintReissueDialog,
    onClosePrintReissueDialog: closePrintReissueDialog,
    onPrintReissueReasonChange: (reason: string) => setPrintReissueDialog((current) => ({ ...current, reason })),
    onSubmitPrintReissueRequest: submitPrintReissueRequest,
    onRefreshPrintStatus: refreshPendingPrintStatus,
    recentPrintJobs,
    releaseApprovalState,
    sampleScanCodeByJobId,
    onSampleScanCodeChange: setSampleScanCode,
    onAbandonPrintJob: abandonPrintJob,
    onConfirmPrintedLabels: confirmPrintedLabels,
    onVerifySampleScan: verifySampleScan,
    onReleaseBatch: releaseBatch,
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

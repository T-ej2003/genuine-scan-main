import type { Dispatch, SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { setOptionalLocalStorageItem } from "@/lib/consent";
import { chooseStablePrinterSelection } from "@/lib/printer-diagnostics";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { canPollVisibleDocument, jitterMs, pollingPolicy } from "@/lib/query-polling-policy";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";

import { resolveMaxPrintRunQuantity } from "./print-run-limits";
import { defaultPrinterStatus } from "./print-workflow-utils";
import type {
  BatchRow,
  LocalPrinterRow,
  PrintJobRow,
  PrinterConnectionStatus,
  RegisteredPrinterRow,
} from "./types";

type ToastLike = (options: {
  title?: string;
  description?: string;
  variant?: "default" | "destructive";
}) => unknown;

type PrintProgressSetters = {
  setPrintProgressOpen: Dispatch<SetStateAction<boolean>>;
  setPrintProgressPhase: Dispatch<SetStateAction<string>>;
  setPrintProgressTotal: Dispatch<SetStateAction<number>>;
  setPrintProgressPrinted: Dispatch<SetStateAction<number>>;
  setPrintProgressRemaining: Dispatch<SetStateAction<number>>;
  setPrintProgressCurrentCode: Dispatch<SetStateAction<string | null>>;
  setPrintProgressError: Dispatch<SetStateAction<string | null>>;
  setPrintProgressNotice?: Dispatch<SetStateAction<string | null>>;
  setPrintProgressPrinterName: Dispatch<SetStateAction<string | null>>;
  setPrintProgressDispatchMode: Dispatch<SetStateAction<"LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | null>>;
  setDirectRemainingToPrint: Dispatch<SetStateAction<number | null>>;
};

type AutoReportPrinterFailure = (params: {
  context: string;
  reason: string;
  diagnostics?: Record<string, unknown>;
}) => Promise<boolean> | boolean;

export const isPrintJobServerSettled = (job: PrintJobRow | null | undefined) => {
  if (!job) return false;
  const total = Number(job.session?.totalItems || job.itemCount || job.quantity || 0);
  const confirmed = Number(job.session?.confirmedItems || 0);
  const sessionStatus = String(job.session?.status || "").toUpperCase();
  const pipelineState = String(job.pipelineState || "").toUpperCase();
  return (
    job.status === "CONFIRMED" ||
    job.status === "PARTIALLY_COMPLETED" ||
    job.status === "FAILED" ||
    job.status === "CANCELLED" ||
    job.status === "STOPPED" ||
    pipelineState === "STOPPED" ||
    sessionStatus === "COMPLETED" ||
    sessionStatus === "FAILED" ||
    sessionStatus === "CANCELLED" ||
    sessionStatus === "STOPPED" ||
    Boolean(job.confirmedAt) ||
    (total > 0 && confirmed >= total)
  );
};

export const formatActionablePrintWorkflowError = (
  response: any,
  fallback = "Complete the previous step before continuing."
) => {
  const code = String(response?.errorCode || response?.code || "").trim();
  const requiredPreviousStep = String(response?.requiredPreviousStep || "").trim();
  const userMessage = String(response?.userMessage || response?.message || response?.error || "").trim();
  const mapped: Record<string, string> = {
    PHYSICAL_CONFIRMATION_REQUIRED: "Confirm physical printing before scanning or releasing.",
    SAMPLE_SCAN_REQUIRED: "Scan one printed label before release.",
    PRINTER_TEST_LABEL_REQUIRED: "Send and confirm a live printer setup test label before production printing.",
    APPROVAL_REQUIRED: "A different authorized checker must approve this high-value release.",
    CHECKER_REQUIRED: "A different authorized checker must approve this release.",
    MAKER_CANNOT_APPROVE: "The release checker must be a different user.",
    QR_NOT_IN_PRINT_JOB: "Scan a label from this print job.",
    QR_VERIFY_TOKEN_REQUIRED: "Scan the exact MSCQR verify QR or paste its verify URL.",
    PRINT_JOB_NOT_CONFIRMED: "Confirm physical printing before release.",
    BATCH_ALREADY_RELEASED: "This batch has already been released.",
    INVALID_STATE_TRANSITION: userMessage || "Complete the previous batch step first.",
  };
  const base = mapped[code] || userMessage || fallback;
  return requiredPreviousStep && !base.includes(requiredPreviousStep) ? `${base} Next step: ${requiredPreviousStep}.` : base;
};

type BatchPrintOperationContext = PrintProgressSetters & {
  toast: ToastLike;
  printBatch: BatchRow | null;
  printQuantity: string;
  getAvailableInventory: (batch: BatchRow) => number;
  selectedPrinterProfile: RegisteredPrinterRow | null;
  selectedPrinterId: string;
  detectedPrinters: LocalPrinterRow[];
  printerStatus: PrinterConnectionStatus;
  activeLocalPrinterId: string;
  selectedPrinterCanPrint: boolean;
  setPrinterStatus: Dispatch<SetStateAction<PrinterConnectionStatus>>;
  buildCalibrationPayload: () => Record<string, unknown>;
  autoReportPrinterFailure: AutoReportPrinterFailure;
  onBatchesChanged?: () => Promise<void> | void;
  loadRecentPrintJobs: () => Promise<void>;
  setPrintJobId: Dispatch<SetStateAction<string>>;
  printJobId: string;
  directRemainingToPrint: number | null;
};

export const syncProgressFromPrintJob = (
  job: PrintJobRow | null,
  {
    setPrintProgressTotal,
    setPrintProgressPrinted,
    setPrintProgressRemaining,
    setDirectRemainingToPrint,
    setPrintProgressDispatchMode,
    setPrintProgressPrinterName,
    setPrintProgressPhase,
    setPrintProgressError,
    setPrintProgressNotice,
  }: PrintProgressSetters
) => {
  if (!job) return;

  const total = Number(job.session?.totalItems || job.itemCount || job.quantity || 0);
  const confirmed = Math.min(total || Number.MAX_SAFE_INTEGER, Number(job.session?.confirmedItems || 0));
  const remaining =
    typeof job.session?.remainingToPrint === "number"
      ? Math.max(0, job.session.remainingToPrint)
      : Math.max(0, total - confirmed);
  const serverCompleted =
    job.status === "CONFIRMED" ||
    String(job.session?.status || "").toUpperCase() === "COMPLETED" ||
    Boolean(job.confirmedAt) ||
    (total > 0 && confirmed >= total);

  if (total > 0) setPrintProgressTotal(total);
  setPrintProgressPrinted(serverCompleted && total > 0 ? total : confirmed);
  setPrintProgressRemaining(serverCompleted ? 0 : remaining);
  setDirectRemainingToPrint(serverCompleted ? 0 : remaining);
  setPrintProgressDispatchMode((previous) => job.printMode || previous || null);
  setPrintProgressPrinterName((previous) => {
    const resolvedName = String(job.printer?.name || "").trim();
    return resolvedName || previous || null;
  });

  if (serverCompleted) {
    setPrintProgressPhase("Print job completed");
    setPrintProgressError(null);
    setPrintProgressNotice?.(null);
    return;
  }
  const stoppedOrPartial =
    job.status === "PARTIALLY_COMPLETED" ||
    job.status === "STOPPED" ||
    String(job.pipelineState || "").toUpperCase() === "STOPPED" ||
    String(job.session?.status || "").toUpperCase() === "STOPPED";
  if (stoppedOrPartial) {
    setPrintProgressPhase(job.status === "PARTIALLY_COMPLETED" ? "Partially completed" : "Print run stopped");
    setPrintProgressError(null);
    setPrintProgressNotice?.("Unprinted labels remain recoverable through the controlled recovery flow.");
    return;
  }
  if (job.status === "FAILED") {
    const safeError = sanitizePrinterUiError(
      job.failureReason || job.session?.failedReason,
      "This print job needs attention before it can continue."
    );
    const failedBeforePrint = /blocked before reaching the printer|payload rejected before print|generated zebra zpl looks unsafe|unsafe_zpl_payload/i.test(
      `${safeError} ${job.failureReason || ""} ${job.session?.failedReason || ""}`
    );
    setPrintProgressPhase(failedBeforePrint ? "Failed before print" : "Print job failed");
    setPrintProgressError(safeError);
    setPrintProgressNotice?.(
      failedBeforePrint
        ? "No labels were printed. Remaining labels are recoverable after the payload fix."
        : "Review printer setup and recovery guidance before retrying."
    );
    return;
  }
  if (job.status === "CANCELLED") {
    setPrintProgressPhase("Print job cancelled");
    setPrintProgressError(sanitizePrinterUiError(job.failureReason, "This print job was cancelled before completion."));
    return;
  }
  const awaitingConfirmation =
    Boolean(job.awaitingConfirmation) ||
    Number(job.session?.awaitingConfirmationCount || 0) > 0 ||
    Number(job.session?.counts?.AGENT_ACKED || 0) > 0 ||
    job.pipelineState === "PRINTER_ACKNOWLEDGED";

  if (awaitingConfirmation) {
    setPrintProgressPhase("Waiting for printer confirmation");
    setPrintProgressError(null);
    return;
  }

  if (job.printMode === "LOCAL_AGENT") {
    if (job.pipelineState === "QUEUED" || job.status === "PENDING") {
      setPrintProgressPhase("Waiting for connector");
      setPrintProgressError(null);
      setPrintProgressNotice?.("The connector has not claimed this job yet.");
      return;
    }
    if (job.pipelineState === "SENT_TO_PRINTER" || job.status === "SENT") {
      setPrintProgressPhase(confirmed > 0 ? "Sent to printer" : "Connector claimed");
      setPrintProgressError(null);
      setPrintProgressNotice?.(confirmed > 0 ? "Connector has started confirming printed labels." : "Connector claimed the job and is preparing spool submission.");
      return;
    }
  }

  if (job.printMode === "NETWORK_DIRECT" || job.printMode === "NETWORK_IPP") {
    setPrintProgressPhase(
      job.printMode === "NETWORK_IPP"
        ? job.status === "SENT"
          ? "Dispatched to registered IPP printer"
          : "Preparing network IPP dispatch"
        : job.status === "SENT"
          ? "Dispatched to registered network printer"
          : "Preparing network printer dispatch"
    );
    return;
  }

  setPrintProgressPhase("Local print session active");
};

const sleep = (ms: number) => new Promise((resolve) => window.setTimeout(resolve, ms));

const logPrintTiming = (event: string, details: Record<string, unknown>) => {
  console.info(event, details);
};

const reportLocalPrinterHeartbeat = async () => {
  const local = await apiClient.getLocalPrintAgentStatus();
  if (!local.success || !local.data) return null;
  const data = local.data as {
    connected?: boolean;
    printerName?: string;
    printerId?: string;
    selectedPrinterId?: string;
    selectedPrinterName?: string;
    deviceName?: string;
    agentVersion?: string;
    protocolVersion?: string;
    buildVersion?: string;
    transportDiagnosticsVersion?: string;
    capabilities?: Record<string, unknown> | null;
    error?: string;
    agentId?: string;
    deviceFingerprint?: string;
    publicKeyPem?: string;
    clientCertFingerprint?: string;
    heartbeatNonce?: string;
    heartbeatIssuedAt?: string;
    heartbeatSignature?: string;
    capabilitySummary?: Record<string, unknown>;
    printers?: unknown[];
    calibrationProfile?: Record<string, unknown>;
  };
  const heartbeat = await apiClient.reportPrinterHeartbeat({
    connected: Boolean(data.connected),
    printerName: data.printerName || undefined,
    printerId: data.printerId || undefined,
    selectedPrinterId: data.selectedPrinterId || undefined,
    selectedPrinterName: data.selectedPrinterName || undefined,
    deviceName: data.deviceName || undefined,
    agentVersion: data.agentVersion || undefined,
    protocolVersion: data.protocolVersion || undefined,
    buildVersion: data.buildVersion || undefined,
    transportDiagnosticsVersion: data.transportDiagnosticsVersion || undefined,
    capabilities: data.capabilities || undefined,
    error: data.error || undefined,
    agentId: data.agentId || undefined,
    deviceFingerprint: data.deviceFingerprint || undefined,
    publicKeyPem: data.publicKeyPem || undefined,
    clientCertFingerprint: data.clientCertFingerprint || undefined,
    heartbeatNonce: data.heartbeatNonce || undefined,
    heartbeatIssuedAt: data.heartbeatIssuedAt || undefined,
    heartbeatSignature: data.heartbeatSignature || undefined,
    capabilitySummary: data.capabilitySummary || undefined,
    printers: Array.isArray(data.printers) ? (data.printers as any) : [],
    calibrationProfile: data.calibrationProfile || undefined,
  });
  return heartbeat.success && heartbeat.data ? heartbeat.data : null;
};

export const printJobCreateFailureMessage = (response: {
  status?: number;
  code?: string;
  errorCode?: string;
  error?: string;
  message?: string;
  requestId?: string | null;
  data?: unknown;
  details?: {
    missingFields?: string[];
    validationIssuePaths?: string[];
  };
}) => {
  const errorCode = String(response.errorCode || response.code || "").trim().toLowerCase();
  const requestId = String(response.requestId || "").trim();
  const requestSuffix = requestId ? ` Request ID: ${requestId}.` : "";
  if (response.status === 401 || errorCode === "unauthenticated" || errorCode === "session_expired") {
    return "Your session expired. Refresh or sign in again, then start the print run.";
  }
  if (errorCode === "printer_not_verified") {
    return "Finish printer verification or choose a verified printer before starting this print run.";
  }
  if (errorCode === "printer_test_label_required") {
    return "Send and confirm a live printer setup test label before starting production printing.";
  }
  if (errorCode === "missing_printer_session") {
    return "Persistent printer session is disconnected. Start MSCQR Connector 2026.6.25 or newer, then retry.";
  }
  if (errorCode === "connector_update_required" || errorCode === "persistent_session_connector_update_required") {
    return "Connector update required. Install the latest MSCQR printer connector, then refresh printer status.";
  }
  if (errorCode === "printer_session_required" || errorCode === "printer_session_disconnected") {
    return "Persistent printer session is disconnected. Start MSCQR Connector 2026.6.25 or newer, then retry.";
  }
  if (errorCode === "printer_mapping_missing") {
    return "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup.";
  }
  if (errorCode === "batch_not_printable") {
    return "There are no labels ready to print in this batch.";
  }
  if (errorCode === "invalid_state_transition") {
    const responseData =
      response.data && typeof response.data === "object" && !Array.isArray(response.data)
        ? (response.data as { details?: Record<string, unknown> })
        : {};
    const details = responseData.details || {};
    const message = String(details.userMessage || response.message || response.error || "").trim();
    if (message) return message;
    if (details.canRepairAutomatically) {
      return "Batch state is being repaired from previous print evidence. Refresh and try again.";
    }
    return "This batch needs to be allocated before printing.";
  }
  if (errorCode === "printer_selection_mismatch") {
    const message = String(response.message || response.error || "").trim();
    if (/fax|pdf|zdesigner|printer on this computer/i.test(message)) {
      return sanitizePrinterUiError(message, message);
    }
    return "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup.";
  }
  if (errorCode === "invalid_printer" || errorCode === "printer_not_found" || errorCode === "unsupported_printer_route") {
    const message = String(response.message || response.error || "").trim();
    if (/fax|pdf|zdesigner|printer on this computer/i.test(message)) {
      return sanitizePrinterUiError(message, message);
    }
    return "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup.";
  }
  if (errorCode === "invalid_payload") {
    const hasValidationDetails =
      (response.details?.missingFields?.length || 0) > 0 ||
      (response.details?.validationIssuePaths?.length || 0) > 0;
    if (hasValidationDetails) {
      return "The print job request is missing required information. Refresh the page and try again.";
    }
    return `Print job could not be started.${requestSuffix} Please refresh printer setup and try again.`;
  }
  if (errorCode === "printer_status_unavailable") {
    return "Printer status is temporarily unavailable.";
  }
  if (errorCode === "print_job_transaction_failed") {
    return `Print job could not be saved.${requestSuffix || " Please try again."}`;
  }
  if (errorCode === "print_item_reservation_failed") {
    return "Some labels are still locked by a failed print run. Close and release the failed run, then start printing again.";
  }
  if (errorCode === "print_signing_configuration_invalid") {
    return `Print token signing is not configured correctly.${requestSuffix} Contact support with this request ID.`;
  }
  if (errorCode === "internal_print_job_create_failed") {
    return `Print job could not be started.${requestSuffix} Please refresh printer setup and try again.`;
  }
  if (errorCode === "print_service_unavailable") {
    return "Printing is temporarily unavailable. Please try again.";
  }
  return sanitizePrinterUiError(
    response.message || response.error,
    "The print job could not be started right now."
  );
};

export const pollPrintJobUntilSettled = async (
  jobId: string,
  progressSetters: PrintProgressSetters,
  timeoutMs = 90_000
) => {
  const startedAt = Date.now();
  let latest: PrintJobRow | null = null;

  while (Date.now() - startedAt < timeoutMs) {
    const response = await apiClient.getPrintJobStatus(jobId, {
      force: true,
      minIntervalMs: pollingPolicy.activePrintJobStatusMinRefreshMs,
    });
    if (response.success && response.data) {
      latest = response.data as PrintJobRow;
      syncProgressFromPrintJob(latest, progressSetters);
      if (isPrintJobServerSettled(latest)) {
        return { settled: true as const, job: latest };
      }
    }
    await sleep(canPollVisibleDocument() ? jitterMs(pollingPolicy.activePrintJobMs) : pollingPolicy.hiddenTabBackoffMs);
  }

  return { settled: false as const, job: latest };
};

export const createPrintJob = async (context: BatchPrintOperationContext) => {
  const {
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
    setPrintJobId,
    setPrintProgressOpen,
    setPrintProgressPhase,
    setPrintProgressError,
    setPrintProgressNotice,
    setPrintProgressCurrentCode,
    setPrintProgressPrinted,
    setPrintProgressTotal,
    setPrintProgressRemaining,
    setPrintProgressPrinterName,
    setPrintProgressDispatchMode,
    setDirectRemainingToPrint,
  } = context;

  if (!printBatch) return;
  const quantity = parseInt(printQuantity, 10);
  if (!Number.isFinite(quantity) || quantity <= 0) {
    toast({ title: "Enter a valid quantity", variant: "destructive" });
    return;
  }

  const availableInventory = getAvailableInventory(printBatch);
  const maxRunQuantity = resolveMaxPrintRunQuantity(availableInventory);
  if (quantity > maxRunQuantity) {
    toast({
      title: "Quantity too large",
      description: `Maximum per run: ${maxRunQuantity.toLocaleString()} labels.`,
      variant: "destructive",
    });
    return;
  }
  if (availableInventory > 0 && quantity > availableInventory) {
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
    const preferredLocalPrinter = chooseStablePrinterSelection(
      detectedPrinters,
      selectedPrinterId,
      printerStatus.selectedPrinterId,
      printerStatus.printerId
    );
    const preferredLocalPrinterId = String(preferredLocalPrinter?.printerId || selectedPrinterId || "").trim();
    const savedNativePrinterId = String(selectedPrinterProfile.nativePrinterId || "").trim();
    const targetLocalPrinterId = String(
      preferredLocalPrinterId || savedNativePrinterId || activeLocalPrinterId || ""
    ).trim();
    if (targetLocalPrinterId) {
      const selectedBeforePrint = await apiClient.selectLocalPrinter(targetLocalPrinterId);
      if (!selectedBeforePrint.success) {
        const message = sanitizePrinterUiError(
          selectedBeforePrint.error,
          "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup."
        );
        toast({ title: "Printer switch failed", description: message, variant: "destructive" });
        setPrintProgressOpen(true);
        setPrintProgressPhase("Print needs attention");
        setPrintProgressError(message);
        return;
      }
      const heartbeatStatus = await reportLocalPrinterHeartbeat();
      if (heartbeatStatus) {
        setPrinterStatus((previous) => ({ ...previous, ...(heartbeatStatus as PrinterConnectionStatus) }));
      }
    }

    const livePrinterStatus = await apiClient.getPrinterConnectionStatus({ force: true, minIntervalMs: 0 });
    const refreshRateLimited =
      livePrinterStatus.status === 429 || String(livePrinterStatus.code || "").toUpperCase() === "RATE_LIMITED";
    const effectiveLiveStatus = (livePrinterStatus.data || printerStatus) as PrinterConnectionStatus;
    if (
      refreshRateLimited &&
      buildSecurePrintReadiness(printerStatus).ready &&
      detectedPrinters.some((row) => row.printerId === selectedPrinterId && row.online !== false)
    ) {
      toast({
        title: "Using last ready printer status",
        description: "Printer status refresh is temporarily paused. Last trusted status is retained.",
      });
    } else if (
      !livePrinterStatus.success ||
      !livePrinterStatus.data ||
      !buildSecurePrintReadiness(effectiveLiveStatus).ready
    ) {
      setPrinterStatus({
        ...defaultPrinterStatus,
        printers: detectedPrinters,
        error:
          livePrinterStatus.error ||
          (detectedPrinters.length > 0 ? "Printer connection requires attention" : "Printer unavailable"),
      });
      const updateRequired =
        Boolean((effectiveLiveStatus as any).persistentSessionUpdateRequired || (effectiveLiveStatus as any).connectorUpdateRequired) ||
        String(livePrinterStatus.code || livePrinterStatus.errorCode || "").toLowerCase() === "connector_update_required";
      toast({
        title: updateRequired ? "Connector update required" : "Printer session disconnected",
        description: updateRequired
          ? "Connector update required. Install the latest MSCQR printer connector, then refresh printer status."
          : "Persistent printer session is disconnected. Start MSCQR Connector 2026.6.25 or newer, then retry.",
        variant: "destructive",
      });
      return;
    }

    setPrinterStatus(effectiveLiveStatus);
    const selectedPrinter =
      detectedPrinters.find((row) => row.printerId === selectedPrinterId) ||
      detectedPrinters.find(
        (row) => row.printerId === effectiveLiveStatus.selectedPrinterId
      ) ||
      null;

    if (selectedPrinter && selectedPrinter.online === false) {
      toast({
        title: "Selected printer offline",
        description: "Switch to an online printer and retry.",
        variant: "destructive",
      });
      return;
    }

    if (
      savedNativePrinterId &&
      activeLocalPrinterId &&
      savedNativePrinterId !== activeLocalPrinterId &&
      !detectedPrinters.some((row) => row.printerId === targetLocalPrinterId && row.online !== false)
    ) {
      toast({
        title: "Selected printer changed",
        description: "Choose the same printer in MSCQR and on this computer, then try again.",
        variant: "destructive",
      });
      return;
    }
  } else if (!selectedPrinterCanPrint) {
    toast({
      title: "Network printer needs attention",
      description: sanitizePrinterUiError(
        selectedPrinterProfile.registryStatus?.detail || selectedPrinterProfile.registryStatus?.summary,
        "This saved printer route needs attention before printing."
      ),
      variant: "destructive",
    });
    return;
  }

  try {
    if (selectedPrinterProfile.connectionType === "LOCAL_AGENT" && selectedPrinterId) {
      setOptionalLocalStorageItem(
        "functional",
        `printer-calibration:${selectedPrinterId}`,
        JSON.stringify({
          printerId: selectedPrinterId,
          ...buildCalibrationPayload(),
        })
      );
    }
  } catch {
    // Local persistence is best-effort only.
  }

  setPrintProgressOpen(true);
  setPrintProgressPhase("Creating secure print session");
  setPrintProgressError(null);
  setPrintProgressNotice?.(null);
  setPrintProgressCurrentCode(null);
  setPrintProgressPrinted(0);
  setPrintProgressTotal(quantity);
  setPrintProgressRemaining(quantity);
  setPrintProgressPrinterName(selectedPrinterProfile.name);
  setPrintProgressDispatchMode(selectedPrinterProfile.connectionType);

  if (selectedPrinterProfile.connectionType === "LOCAL_AGENT") {
    const backendConfiguration = await apiClient.configureLocalPrintAgentBackend(window.location.origin);
    if (!backendConfiguration.success) {
      console.warn("Local print agent backend configuration failed:", backendConfiguration.error);
    }
  }

  const createStartedAt = Date.now();
  const response = await apiClient.createPrintJob({
    batchId: printBatch.id,
    printerId: selectedPrinterProfile.id,
    quantity,
  });

  if (!response.success) {
    const responseData = response.data as { activePrintJobId?: unknown; job?: Partial<PrintJobRow> | null } | undefined;
    const activePrintJobId = String(responseData?.activePrintJobId || responseData?.job?.id || "").trim();
    if (activePrintJobId) {
      setPrintJobId(activePrintJobId);
      setPrintProgressOpen(true);
      setPrintProgressError(null);
      setPrintProgressCurrentCode(null);
      syncProgressFromPrintJob((responseData?.job || null) as PrintJobRow | null, context);
      toast({
        title: "Active print run found",
        description: "A live print job already exists for this batch, so MSCQR resumed its current status instead of creating a duplicate run.",
      });

      setPrintProgressNotice?.("The live status panel is tracking this print run now.");
      return;
    }

    const raw = String(response.errorCode || response.code || response.error || "Error").toLowerCase();
    const isBusy =
      (raw.includes("conflict") ||
        raw.includes("busy") ||
        raw.includes("retry") ||
        raw.includes("active_print_job_exists") ||
        raw.includes("print_job_conflict")) &&
      !raw.includes("invalid_state_transition");
    const responseMessage = String(response.message || response.error || "").trim();
    const safeError = printJobCreateFailureMessage(response);
    const failedBeforePrint = /blocked before reaching the printer|payload rejected before print|generated zebra zpl looks unsafe|unsafe_zpl_payload/i.test(
      `${safeError} ${responseMessage} ${raw}`
    );
    toast({
      title: isBusy ? "Batch busy" : "Print needs attention",
      description: isBusy ? "These codes were just allocated by another job. Please retry." : safeError,
      variant: "destructive",
    });
    setPrintProgressPhase(failedBeforePrint ? "Failed before print" : "Print needs attention");
    setPrintProgressError(safeError);
    const autoReportEligible = ![
      "connector_update_required",
      "persistent_session_connector_update_required",
      "printer_session_required",
      "printer_session_disconnected",
      "missing_printer_session",
      "printer_not_verified",
      "printer_test_label_required",
    ].includes(raw);
    const reportSent = autoReportEligible
      ? await autoReportPrinterFailure({
          context: "create_print_job",
          reason: responseMessage || "Print job setup failed",
          diagnostics: { batchId: printBatch.id, quantity, printJobRequestId: response.requestId || null },
        })
      : true;
    if (!reportSent && response.requestId) {
      toast({
        title: "Could not send diagnostics automatically",
        description: `Please copy request ID: ${response.requestId}`,
        variant: "destructive",
      });
    }
    return;
  }

  const data = (response.data || {}) as {
    printJobId?: string;
    tokenCount?: number;
    mode?: string;
    pipelineState?: string;
    printer?: { name?: string };
  };
  const createCompletedAt = Date.now();
  setPrintJobId(data.printJobId || "");
  setDirectRemainingToPrint(typeof data.tokenCount === "number" ? data.tokenCount : null);
  setPrintProgressTotal(typeof data.tokenCount === "number" ? data.tokenCount : quantity);
  setPrintProgressRemaining(typeof data.tokenCount === "number" ? data.tokenCount : quantity);

  const createdJobId = String(data.printJobId || "").trim();
  const createdMode = String(data.mode || selectedPrinterProfile.connectionType).trim();
  const isServerDispatchedMode = createdMode === "NETWORK_DIRECT" || createdMode === "NETWORK_IPP";

  setPrintProgressPrinterName(String(data.printer?.name || selectedPrinterProfile.name || "").trim() || null);
  setPrintProgressDispatchMode(
    createdMode === "NETWORK_DIRECT" ? "NETWORK_DIRECT" : createdMode === "NETWORK_IPP" ? "NETWORK_IPP" : "LOCAL_AGENT"
  );

  if (!createdJobId) {
    const setupMessage = "The print job could not be started correctly. Please try again.";
    toast({ title: "Print job setup incomplete", description: setupMessage, variant: "destructive" });
    setPrintProgressError(setupMessage);
    return;
  }

  if (isServerDispatchedMode) {
    toast({
      title: createdMode === "NETWORK_IPP" ? "Shared printer job started" : "Factory printer job started",
      description:
        createdMode === "NETWORK_IPP"
          ? `Sending ${quantity} label${quantity === 1 ? "" : "s"} to ${selectedPrinterProfile.name} over ${
              selectedPrinterProfile.deliveryMode === "SITE_GATEWAY" ? "the site print link" : "the saved shared printer"
            }.`
          : `Dispatching ${quantity} label${quantity === 1 ? "" : "s"} to ${selectedPrinterProfile.name}.`,
    });
    setPrintProgressPhase(
      createdMode === "NETWORK_IPP"
        ? selectedPrinterProfile.deliveryMode === "SITE_GATEWAY"
          ? "Waiting for site print link"
          : "Sending to saved shared printer"
        : "Sending to saved factory printer"
    );

    setPrintProgressNotice?.("The live status panel is tracking this print run now.");
  } else {
    logPrintTiming("print.job.created", {
      printJobId: createdJobId,
      mode: createdMode || "LOCAL_AGENT",
      tokenCount: typeof data.tokenCount === "number" ? data.tokenCount : null,
      durationMs: createCompletedAt - createStartedAt,
    });
    setPrintProgressPhase("Persistent printer session active");
    setPrintProgressNotice?.("The connector receives labels over its signed persistent session.");
    toast({
      title: "Print run started",
      description: `MSCQR queued approved labels for ${selectedPrinterProfile.name}. The connector will stream backend-confirmed progress.`,
    });
    setPrintProgressPhase("Waiting for connector progress");
    setPrintProgressNotice?.("Waiting for backend-confirmed printer progress.");
  }
};

export const retryPendingDirectPrint = async (context: BatchPrintOperationContext) => {
  const {
    toast,
    printJobId,
    directRemainingToPrint,
    loadRecentPrintJobs,
    setPrintProgressOpen,
    setPrintProgressNotice,
  } = context;

  if (!printJobId) return;

  setPrintProgressOpen(true);
  const statusResponse = await apiClient.getPrintJobStatus(printJobId);
  if (statusResponse.success && statusResponse.data) {
    syncProgressFromPrintJob(statusResponse.data as PrintJobRow, context);
    setPrintProgressNotice?.(null);
  } else if (statusResponse.status === 429 || String(statusResponse.code || "").toUpperCase() === "RATE_LIMITED") {
    const seconds = Math.max(1, Math.ceil(Number(statusResponse.retryAfterSec || 10)));
    setPrintProgressNotice?.(`Status refresh paused for ${seconds} seconds. The print run remains active.`);
    return;
  }

  const latestJob = (statusResponse.data as PrintJobRow | undefined) || null;
  if (latestJob?.status === "CONFIRMED") {
    toast({
      title: "Print job already complete",
      description: `${latestJob.session?.confirmedItems || latestJob.quantity} labels are already confirmed.`,
    });
    await loadRecentPrintJobs();
    return;
  }
  if (latestJob?.status === "FAILED" || latestJob?.status === "CANCELLED") {
    toast({
      title: "Print job needs attention",
      description:
        sanitizePrinterUiError(
          latestJob?.failureReason || latestJob?.session?.failedReason,
          latestJob?.status === "CANCELLED" ? "This print job was cancelled before completion." : "This print job needs attention."
        ),
      variant: "destructive",
    });
    return;
  }

  const remaining = latestJob?.session?.remainingToPrint ?? directRemainingToPrint ?? latestJob?.quantity ?? 1;
  toast({
    title: "Print job still running",
    description: `There are still ${remaining} label${remaining === 1 ? "" : "s"} waiting for printer confirmation.`,
  });
};

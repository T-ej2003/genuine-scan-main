import type { Dispatch, SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

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
  setPrintProgressPrinterName: Dispatch<SetStateAction<string | null>>;
  setPrintProgressDispatchMode: Dispatch<SetStateAction<"LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | null>>;
  setDirectRemainingToPrint: Dispatch<SetStateAction<number | null>>;
};

type AutoReportPrinterFailure = (params: {
  context: string;
  reason: string;
  diagnostics?: Record<string, unknown>;
}) => Promise<void> | void;

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
  }: PrintProgressSetters
) => {
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
  setPrintProgressDispatchMode((previous) => job.printMode || previous || null);
  setPrintProgressPrinterName((previous) => {
    const resolvedName = String(job.printer?.name || "").trim();
    return resolvedName || previous || null;
  });

  if (job.status === "CONFIRMED") {
    setPrintProgressPhase("Print job completed");
    setPrintProgressError(null);
    return;
  }
  if (job.status === "FAILED") {
    setPrintProgressPhase("Print job failed");
    setPrintProgressError(
      sanitizePrinterUiError(
        job.failureReason || job.session?.failedReason,
        "This print job needs attention before it can continue."
      )
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

export const pollPrintJobUntilSettled = async (
  jobId: string,
  progressSetters: PrintProgressSetters,
  timeoutMs = 90_000
) => {
  const startedAt = Date.now();
  let latest: PrintJobRow | null = null;

  while (Date.now() - startedAt < timeoutMs) {
    const response = await apiClient.getPrintJobStatus(jobId);
    if (response.success && response.data) {
      latest = response.data as PrintJobRow;
      syncProgressFromPrintJob(latest, progressSetters);
      if (latest.status === "CONFIRMED" || latest.status === "FAILED" || latest.status === "CANCELLED") {
        return { settled: true as const, job: latest };
      }
    }
    await sleep(1200);
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
    onBatchesChanged,
    loadRecentPrintJobs,
    setPrintJobId,
    setPrintProgressOpen,
    setPrintProgressPhase,
    setPrintProgressError,
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
    const livePrinterStatus = await apiClient.getPrinterConnectionStatus();
    if (
      !livePrinterStatus.success ||
      !livePrinterStatus.data ||
      !(livePrinterStatus.data as { connected?: boolean }).connected ||
      !(livePrinterStatus.data as { eligibleForPrinting?: boolean }).eligibleForPrinting
    ) {
      setPrinterStatus({
        ...defaultPrinterStatus,
        printers: detectedPrinters,
        error:
          livePrinterStatus.error ||
          (detectedPrinters.length > 0 ? "Printer connection requires attention" : "Printer unavailable"),
      });
      toast({
        title: "Printer unavailable",
        description: sanitizePrinterUiError(
          livePrinterStatus.error,
          "Reconnect the MSCQR Connector or choose a ready workstation printer before creating a job."
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
      detectedPrinters.find(
        (row) => row.printerId === (livePrinterStatus.data as { selectedPrinterId?: string }).selectedPrinterId
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
      selectedPrinterProfile.nativePrinterId &&
      activeLocalPrinterId &&
      selectedPrinterProfile.nativePrinterId !== activeLocalPrinterId
    ) {
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
        "This saved printer route needs attention before printing."
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
    // Local persistence is best-effort only.
  }

  setPrintProgressOpen(true);
  setPrintProgressPhase("Creating secure print session");
  setPrintProgressError(null);
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

  const response = await apiClient.createPrintJob({
    batchId: printBatch.id,
    printerId: selectedPrinterProfile.id,
    quantity,
  });

  if (!response.success) {
    const activePrintJobId = String((response.data as any)?.activePrintJobId || (response.data as any)?.job?.id || "").trim();
    if (activePrintJobId) {
      setPrintJobId(activePrintJobId);
      setPrintProgressOpen(true);
      setPrintProgressError(null);
      setPrintProgressCurrentCode(null);
      syncProgressFromPrintJob(((response.data as any)?.job || null) as PrintJobRow | null, context);
      toast({
        title: "Active print run found",
        description: "A live print job already exists for this batch, so MSCQR resumed its current status instead of creating a duplicate run.",
      });

      const pollResult = await pollPrintJobUntilSettled(activePrintJobId, context, 45_000);
      if (pollResult.settled && pollResult.job?.status === "CONFIRMED") {
        toast({
          title: "Print job completed",
          description: `${pollResult.job.session?.confirmedItems || pollResult.job.quantity} labels are confirmed.`,
        });
      } else if (pollResult.settled && pollResult.job?.status === "FAILED") {
        toast({
          title: "Print job needs attention",
          description: sanitizePrinterUiError(
            pollResult.job.failureReason || pollResult.job.session?.failedReason,
            "The active print job needs attention before it can continue."
          ),
          variant: "destructive",
        });
      } else {
        toast({
          title: "Print job still running",
          description: "The existing print job is still active. The live status panel is tracking it now.",
        });
      }

      await onBatchesChanged?.();
      await loadRecentPrintJobs();
      return;
    }

    const raw = String(response.error || "Error").toLowerCase();
    const isBusy = raw.includes("conflict") || raw.includes("busy") || raw.includes("retry");
    const safeError = sanitizePrinterUiError(response.error, "The print job could not be started right now.");
    toast({
      title: isBusy ? "Batch busy" : "Print job failed",
      description: isBusy ? "These codes were just allocated by another job. Please retry." : safeError,
      variant: "destructive",
    });
    setPrintProgressError(safeError);
    void autoReportPrinterFailure({
      context: "create_print_job",
      reason: response.error || "Print job setup failed",
      diagnostics: { batchId: printBatch.id, quantity },
    });
    return;
  }

  const data = (response.data || {}) as {
    printJobId?: string;
    tokenCount?: number;
    mode?: string;
    pipelineState?: string;
    printer?: { name?: string };
  };
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
      title: createdMode === "NETWORK_IPP" ? "Office printer job started" : "Factory printer job started",
      description:
        createdMode === "NETWORK_IPP"
          ? `Sending ${quantity} label${quantity === 1 ? "" : "s"} to ${selectedPrinterProfile.name} over ${
              selectedPrinterProfile.deliveryMode === "SITE_GATEWAY" ? "the site connector" : "the office printer route"
            }.`
          : `Dispatching ${quantity} label${quantity === 1 ? "" : "s"} to ${selectedPrinterProfile.name}.`,
    });
    setPrintProgressPhase(
      createdMode === "NETWORK_IPP"
        ? selectedPrinterProfile.deliveryMode === "SITE_GATEWAY"
          ? "Waiting for site connector dispatch"
          : "Sending to saved office printer"
        : "Sending to saved factory printer"
    );

    const pollResult = await pollPrintJobUntilSettled(createdJobId, context);
    if (pollResult.settled && pollResult.job?.status === "CONFIRMED") {
      toast({
        title: createdMode === "NETWORK_IPP" ? "Office printer job complete" : "Factory printer job complete",
        description: `${pollResult.job.session?.confirmedItems || quantity} labels confirmed by the server.`,
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
        description: "This print job is still running. Review the live status below.",
      });
    }
  } else {
    toast({
      title: "Connector print started",
      description: `MSCQR has queued approved labels for ${selectedPrinterProfile.name}. The connector will claim and print them securely.`,
    });
    setPrintProgressPhase(
      data.pipelineState === "QUEUED" ? "Waiting for connector claim" : "Connector print session active"
    );

    const pollResult = await pollPrintJobUntilSettled(createdJobId, context, 60_000);
    if (pollResult.settled && pollResult.job?.status === "CONFIRMED") {
      toast({
        title: "Connector print complete",
        description: `${pollResult.job.session?.confirmedItems || quantity} labels were confirmed through the controlled connector pipeline.`,
      });
      setPrintProgressPhase("Completed");
      setPrintProgressError(null);
    } else if (pollResult.settled && pollResult.job?.status === "FAILED") {
      const safeError = sanitizePrinterUiError(
        pollResult.job.failureReason || pollResult.job.session?.failedReason,
        "The connector or printer could not complete this label run."
      );
      toast({
        title: "Connector print needs attention",
        description: safeError,
        variant: "destructive",
      });
      setPrintProgressError(safeError);
      void autoReportPrinterFailure({
        context: "connector_print",
        reason: safeError,
        diagnostics: {
          printJobId: createdJobId,
          printedCount: pollResult.job.session?.confirmedItems || 0,
          remainingToPrint: pollResult.job.session?.remainingToPrint ?? null,
          printerId: selectedPrinterProfile.id,
        },
      });
    } else {
      toast({
        title: "Connector print continues in background",
        description: "The secure connector is still processing this job. Refresh the print status to see the latest confirmed count.",
      });
    }
  }

  await onBatchesChanged?.();
  await loadRecentPrintJobs();
};

export const retryPendingDirectPrint = async (context: BatchPrintOperationContext) => {
  const {
    toast,
    printJobId,
    directRemainingToPrint,
    loadRecentPrintJobs,
    setPrintProgressOpen,
  } = context;

  if (!printJobId) return;

  setPrintProgressOpen(true);
  const statusResponse = await apiClient.getPrintJobStatus(printJobId);
  if (statusResponse.success && statusResponse.data) {
    syncProgressFromPrintJob(statusResponse.data as PrintJobRow, context);
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
  const pollResult = await pollPrintJobUntilSettled(printJobId, context, 45_000);
  if (pollResult.settled && pollResult.job?.status === "CONFIRMED") {
    toast({
      title: "Print job completed",
      description: `${pollResult.job.session?.confirmedItems || pollResult.job.quantity} labels are now confirmed.`,
    });
  } else if (pollResult.settled && pollResult.job?.status === "FAILED") {
    toast({
      title: "Print job needs attention",
      description: sanitizePrinterUiError(
        pollResult.job.failureReason || pollResult.job.session?.failedReason,
        "The connector or printer could not complete the remaining labels."
      ),
      variant: "destructive",
    });
  } else {
    toast({
      title: "Print job still running",
      description: `The connector still has ${remaining} label${remaining === 1 ? "" : "s"} to confirm.`,
    });
  }
  await loadRecentPrintJobs();
};

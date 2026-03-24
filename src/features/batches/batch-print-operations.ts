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
  setPrintLockToken: Dispatch<SetStateAction<string>>;
  setPrintJobTokensCount: Dispatch<SetStateAction<number>>;
  printJobId: string;
  printLockToken: string;
  printJobTokensCount: number;
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

export const runAutoDirectPrint = async (
  jobId: string,
  lockToken: string,
  requestedQty: number,
  context: Pick<
    BatchPrintOperationContext,
    | "selectedPrinterId"
    | "printerStatus"
    | "buildCalibrationPayload"
    | "autoReportPrinterFailure"
    | "setPrintProgressOpen"
    | "setPrintProgressTotal"
    | "setPrintProgressPrinted"
    | "setPrintProgressRemaining"
    | "setPrintProgressCurrentCode"
    | "setPrintProgressError"
    | "setPrintProgressPhase"
    | "setDirectRemainingToPrint"
  >
) => {
  const {
    selectedPrinterId,
    printerStatus,
    buildCalibrationPayload,
    autoReportPrinterFailure,
    setPrintProgressOpen,
    setPrintProgressTotal,
    setPrintProgressPrinted,
    setPrintProgressRemaining,
    setPrintProgressCurrentCode,
    setPrintProgressError,
    setPrintProgressPhase,
    setDirectRemainingToPrint,
  } = context;

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
    const issueResponse = await apiClient.requestDirectPrintTokens(jobId, lockToken, nextBatchSize);
    if (!issueResponse.success) {
      const safeError = sanitizePrinterUiError(
        issueResponse.error,
        "Printing could not continue right now. Start a fresh print job and try again."
      );
      setPrintProgressError(safeError);
      return { success: false, printedCount, remainingToPrint, error: safeError };
    }

    const issueData = (issueResponse.data || {}) as {
      items?: Array<{ printItemId: string; qrId: string; code: string; renderToken: string }>;
      remainingToPrint?: number;
      jobConfirmed?: boolean;
    };
    const items = Array.isArray(issueData.items) ? issueData.items : [];

    if (typeof issueData.remainingToPrint === "number") {
      remainingToPrint = issueData.remainingToPrint;
      setDirectRemainingToPrint(issueData.remainingToPrint);
      setPrintProgressRemaining(issueData.remainingToPrint);
    }

    if (items.length === 0) {
      if (issueData.jobConfirmed || remainingToPrint === 0) {
        setPrintProgressPhase("Print session completed");
        return { success: true, printedCount, remainingToPrint: 0, error: null };
      }

      const pausedMessage = "Printing paused before all labels were confirmed. Retry the remaining labels.";
      setPrintProgressError(pausedMessage);
      return { success: false, printedCount, remainingToPrint, error: pausedMessage };
    }

    for (const item of items) {
      setPrintProgressPhase("Resolving token and sending print command");
      setPrintProgressCurrentCode(item.code);

      const resolveResponse = await apiClient.resolveDirectPrintToken(jobId, {
        printLockToken: lockToken,
        renderToken: item.renderToken,
      });

      if (!resolveResponse.success) {
        const safeError = sanitizePrinterUiError(
          resolveResponse.error,
          "Printing could not continue right now. Start a fresh print job and try again."
        );
        await apiClient.reportDirectPrintFailure(jobId, {
          printLockToken: lockToken,
          reason: resolveResponse.error || `Failed to resolve render token for ${item.code}.`,
          printItemId: item.printItemId,
          retries: 0,
        });
        setPrintProgressError(safeError);
        void autoReportPrinterFailure({
          context: "resolve_direct_print_token",
          reason: resolveResponse.error || `Failed to resolve render token for ${item.code}.`,
          diagnostics: { jobId, printItemId: item.printItemId, code: item.code },
        });
        return { success: false, printedCount, remainingToPrint, error: safeError };
      }

      const resolvedData = (resolveResponse.data || {}) as {
        printItemId?: string;
        scanUrl?: string;
        payloadContent?: string;
        payloadHash?: string;
        payloadType?: string;
        previewLabel?: string;
        commandLanguage?: string;
        printer?: { nativePrinterId?: string };
      };
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
        const incompleteMessage =
          "Printing could not continue because this secure print session is incomplete. Start a fresh print job.";
        setPrintProgressError(incompleteMessage);
        return { success: false, printedCount, remainingToPrint, error: incompleteMessage };
      }

      const localPrintResponse = await apiClient.printWithLocalAgent({
        printJobId: jobId,
        qrId: item.qrId,
        code: item.code,
        scanUrl,
        payloadType: resolvedData.payloadType as
          | "ZPL"
          | "TSPL"
          | "SBPL"
          | "EPL"
          | "CPCL"
          | "ESC_POS"
          | "JSON"
          | "OTHER"
          | undefined,
        payloadContent,
        payloadHash,
        previewLabel: resolvedData.previewLabel || undefined,
        commandLanguage: resolvedData.commandLanguage || undefined,
        copies: 1,
        printerId:
          selectedPrinterId || printerStatus.selectedPrinterId || resolvedData.printer?.nativePrinterId || undefined,
        printPath: "auto",
        labelLanguage:
          resolvedData.commandLanguage && resolvedData.commandLanguage !== "OTHER"
            ? (resolvedData.commandLanguage as "AUTO" | "ZPL" | "EPL" | "CPCL" | "TSPL" | "ESC_POS")
            : "AUTO",
        mediaSize:
          (printerStatus.capabilitySummary?.mediaSizes && printerStatus.capabilitySummary.mediaSizes[0]) || undefined,
        calibrationProfile: buildCalibrationPayload(),
      });

      if (!localPrintResponse.success) {
        const safeError = sanitizePrinterUiError(
          localPrintResponse.error,
          "The workstation printer could not complete this label."
        );
        await apiClient.reportDirectPrintFailure(jobId, {
          printLockToken: lockToken,
          reason: localPrintResponse.error || `Local print failed for ${item.code}.`,
          printItemId,
          retries: 0,
          agentMetadata: {
            selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
            printPath: "auto",
            labelLanguage: "AUTO",
            payloadType,
            payloadHash,
            calibrationProfile: buildCalibrationPayload(),
          },
        });
        setPrintProgressError(safeError);
        void autoReportPrinterFailure({
          context: "local_print",
          reason: localPrintResponse.error || `Local print failed for ${item.code}.`,
          diagnostics: {
            jobId,
            printItemId,
            code: item.code,
            selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
            printPath: "auto",
            labelLanguage: "AUTO",
            payloadType,
          },
        });
        return { success: false, printedCount, remainingToPrint, error: safeError };
      }

      setPrintProgressPhase("Confirming printed label with server");
      const confirmResponse = await apiClient.confirmDirectPrintItem(jobId, {
        printLockToken: lockToken,
        printItemId,
        agentMetadata: {
          localPrintSuccess: true,
          localAgentVersion: (localPrintResponse as { data?: { agentVersion?: string } }).data?.agentVersion || null,
          selectedPrinterId: selectedPrinterId || printerStatus.selectedPrinterId || null,
          selectedPrinterName: printerStatus.selectedPrinterName || printerStatus.printerName || null,
          printPath: "auto",
          labelLanguage: "AUTO",
          payloadType,
          payloadHash,
          calibrationProfile: buildCalibrationPayload(),
        },
      });

      if (!confirmResponse.success) {
        const safeError = sanitizePrinterUiError(
          confirmResponse.error,
          "MSCQR could not confirm the printed labels. Start a fresh print job for any remaining quantity."
        );
        await apiClient.reportDirectPrintFailure(jobId, {
          printLockToken: lockToken,
          reason: confirmResponse.error || `Failed to confirm print item ${item.code}.`,
          printItemId,
          retries: 0,
        });
        setPrintProgressError(safeError);
        return { success: false, printedCount, remainingToPrint, error: safeError };
      }

      const confirmData = (confirmResponse.data || {}) as { remainingToPrint?: number };
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
        : "Auto print stopped before all labels completed. Retry the remaining labels.",
  };
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
    setPrintLockToken,
    setPrintJobTokensCount,
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

  const response = await apiClient.createPrintJob({
    batchId: printBatch.id,
    printerId: selectedPrinterProfile.id,
    quantity,
  });

  if (!response.success) {
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
    printLockToken?: string;
    tokenCount?: number;
    mode?: string;
    printer?: { name?: string };
  };
  setPrintJobId(data.printJobId || "");
  setPrintLockToken(data.printLockToken || "");
  setPrintJobTokensCount(typeof data.tokenCount === "number" ? data.tokenCount : 0);
  setDirectRemainingToPrint(typeof data.tokenCount === "number" ? data.tokenCount : null);
  setPrintProgressTotal(typeof data.tokenCount === "number" ? data.tokenCount : quantity);
  setPrintProgressRemaining(typeof data.tokenCount === "number" ? data.tokenCount : quantity);

  const createdJobId = String(data.printJobId || "").trim();
  const createdLockToken = String(data.printLockToken || "").trim();
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
        description: "This print job is still running. Review the live status below or in Printer Setup.",
      });
    }
  } else {
    if (!createdLockToken) {
      const sessionMessage = "The workstation print session could not be started correctly. Please try again.";
      toast({ title: "Print job setup incomplete", description: sessionMessage, variant: "destructive" });
      setPrintProgressError(sessionMessage);
      return;
    }

    toast({
      title: "Workstation print started",
      description: `MSCQR is sending approved labels to ${selectedPrinterProfile.name}.`,
    });

    const autoResult = await runAutoDirectPrint(createdJobId, createdLockToken, typeof data.tokenCount === "number" ? data.tokenCount : quantity, context);

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

  await onBatchesChanged?.();
  await loadRecentPrintJobs();
};

export const retryPendingDirectPrint = async (context: BatchPrintOperationContext) => {
  const {
    toast,
    printJobId,
    printLockToken,
    directRemainingToPrint,
    printJobTokensCount,
    loadRecentPrintJobs,
    setPrintProgressOpen,
  } = context;

  if (!printJobId || !printLockToken) return;

  setPrintProgressOpen(true);
  const statusResponse = await apiClient.getPrintJobStatus(printJobId);
  if (statusResponse.success && statusResponse.data) {
    syncProgressFromPrintJob(statusResponse.data as PrintJobRow, context);
  }

  const remaining =
    ((statusResponse.data as PrintJobRow | undefined)?.session?.remainingToPrint ?? directRemainingToPrint ?? printJobTokensCount ?? 1);

  const retryResult = await runAutoDirectPrint(printJobId, printLockToken, Math.max(1, remaining), context);
  if (!retryResult.success) {
    toast({
      title: "Retry needs attention",
      description:
        retryResult.error || `Printed ${retryResult.printedCount}. Remaining: ${retryResult.remainingToPrint}.`,
      variant: "destructive",
    });
    return;
  }

  toast({
    title: "Retry completed",
    description: `${retryResult.printedCount} additional labels printed.`,
  });
  await loadRecentPrintJobs();
};

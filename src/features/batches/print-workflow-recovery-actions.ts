import type { Dispatch, SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { clearRequestCoordinator } from "@/lib/api/request-coordinator";
import { queryClient } from "@/lib/query-client";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

import type { PrintJobRow, RegisteredPrinterRow } from "./types";

type ToastLike = (options: { title?: string; description?: string; variant?: "default" | "destructive" }) => unknown;

export const updateRecentPrintJob = (nextJob: PrintJobRow, setRecentPrintJobs: Dispatch<SetStateAction<PrintJobRow[]>>) => {
  setRecentPrintJobs((previous) => {
    const found = previous.some((row) => row.id === nextJob.id);
    return found ? previous.map((row) => (row.id === nextJob.id ? nextJob : row)) : [nextJob, ...previous].slice(0, 8);
  });
  if (nextJob.runSummary) {
    queryClient.setQueriesData<PrintJobRow[]>({ queryKey: ["printing", "jobs"] }, (jobs) =>
      jobs?.map((job) => job.id === nextJob.id ? { ...job, ...nextJob } : job));
  }
};

export const refreshPrintRunConflict = async (
  jobId: string,
  setRecentPrintJobs: Dispatch<SetStateAction<PrintJobRow[]>>,
  refresh: () => Promise<unknown>,
) => {
  clearRequestCoordinator(["manufacturer-print-jobs:", "manufacturer-print-job-status:"]);
  setRecentPrintJobs((jobs) => jobs.map((job) => job.id === jobId && job.runSummary
    ? { ...job, runSummary: { ...job.runSummary, allowedActions: [] } }
    : job));
  await refresh();
};

export const relinkSelectedPrinterAction = async (params: {
  selectedPrinterProfile: RegisteredPrinterRow | null;
  setRelinkingPrinter: (value: boolean) => void;
  setSelectedPrinterProfileId: (value: string) => void;
  loadPrinterStatus: (options: { force?: boolean }) => Promise<void>;
  toast: ToastLike;
}) => {
  if (!params.selectedPrinterProfile?.id) return;
  params.setRelinkingPrinter(true);
  try {
    const response = await apiClient.relinkLocalAgentPrinter(params.selectedPrinterProfile.id);
    if (!response.success) {
      params.toast({
        title: "Printer relink failed",
        description: sanitizePrinterUiError(
          response.error,
          "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup."
        ),
        variant: "destructive",
      });
      return;
    }

    const repairedPrinterId = String((response.data as any)?.printer?.id || "").trim();
    params.toast({ title: "Printer relinked", description: "The saved printer is now linked to this computer's connector." });
    await params.loadPrinterStatus({ force: true });
    if (repairedPrinterId) params.setSelectedPrinterProfileId(repairedPrinterId);
  } finally {
    params.setRelinkingPrinter(false);
  }
};

export const abandonPrintJobAction = async (params: {
  jobId: string;
  currentPrintJobId: string | null;
  setPrinting: (value: boolean) => void;
  setPrintJobId: (value: string) => void;
  setDirectRemainingToPrint: (value: number | null) => void;
  loadRecentPrintJobs: () => Promise<void>;
  onBatchesChanged?: () => Promise<void> | void;
  toast: ToastLike;
}) => {
  if (!params.jobId) return;
  params.setPrinting(true);
  try {
    const response = await apiClient.abandonPrintJob(params.jobId);
    if (!response.success) {
      params.toast({
        title: "Could not close print run",
        description: sanitizePrinterUiError(response.error, "This print run could not be safely closed."),
        variant: "destructive",
      });
      return;
    }
    if (params.currentPrintJobId === params.jobId) {
      params.setPrintJobId("");
      params.setDirectRemainingToPrint(null);
    }
    params.toast({ title: "Print run closed", description: "The unconfirmed labels were released so you can start again." });
    await params.loadRecentPrintJobs();
    await params.onBatchesChanged?.();
  } finally {
    params.setPrinting(false);
  }
};

export const printDiagnosticTestLabelAction = async (params: {
  selectedPrinterProfile: RegisteredPrinterRow | null;
  setPrinting: (value: boolean) => void;
  toast: ToastLike;
}) => {
  if (!params.selectedPrinterProfile?.id) return;
  params.setPrinting(true);
  try {
    const response = await apiClient.testPrinterLabel(params.selectedPrinterProfile.id);
    const data = (response.data || {}) as { outcome?: string; message?: string };
    if (response.success && data.outcome === "queued") {
      params.toast({
        title: "Diagnostic test label queued",
        description: data.message || "Keep MSCQR Connector running. Production printing unlocks after the connector prints and confirms this setup label.",
      });
      return;
    }
    if (!response.success || data.outcome !== "confirmed") {
      params.toast({
        title: "Diagnostic test label needs attention",
        description: sanitizePrinterUiError(
          response.error || data.message,
          "Print the diagnostic label again after checking label size, darkness, media type, driver RAW datatype, and ZPL mode."
        ),
        variant: "destructive",
      });
      return;
    }
    params.toast({
      title: "Diagnostic test label printed",
      description: data.message || "The printer accepted a known-good MSCQR ZPL diagnostic label.",
    });
  } finally {
    params.setPrinting(false);
  }
};

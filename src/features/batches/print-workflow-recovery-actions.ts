import apiClient from "@/lib/api-client";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

import type { RegisteredPrinterRow } from "./types";

type ToastLike = (options: { title?: string; description?: string; variant?: "default" | "destructive" }) => unknown;

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
    if (repairedPrinterId) params.setSelectedPrinterProfileId(repairedPrinterId);
    params.toast({ title: "Printer relinked", description: "The saved printer is now linked to this computer's connector." });
    await params.loadPrinterStatus({ force: true });
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

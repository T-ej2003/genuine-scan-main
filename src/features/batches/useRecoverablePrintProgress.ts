import { useCallback, useEffect, useRef, type Dispatch, type SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { updateActivePrintSession, useActivePrintSession } from "@/lib/active-print-session";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

import type { PrintJobRow } from "./types";

type UseRecoverablePrintProgressParams = {
  printJobId: string;
  setPrintJobId: Dispatch<SetStateAction<string>>;
  setPrintProgressOpen: Dispatch<SetStateAction<boolean>>;
  setPrintProgressPhase: Dispatch<SetStateAction<string>>;
  setPrintProgressNotice: Dispatch<SetStateAction<string | null>>;
  replaceRecentPrintJob: (job: PrintJobRow) => void;
};

export function useRecoverablePrintProgress({
  printJobId,
  setPrintJobId,
  setPrintProgressOpen,
  setPrintProgressPhase,
  setPrintProgressNotice,
  replaceRecentPrintJob,
}: UseRecoverablePrintProgressParams) {
  const activePrintSession = useActivePrintSession();
  const handledRecoveryRequestRef = useRef(0);

  const recoverActivePrintView = useCallback(
    async (jobId: string, terminal: boolean) => {
      const recoveredJobId = String(jobId || "").trim();
      if (!recoveredJobId) return;
      setPrintJobId((current) => current || recoveredJobId);
      setPrintProgressOpen(true);
      setPrintProgressPhase((current) =>
        current && current !== "Preparing print pipeline"
          ? current
          : terminal
            ? "Print run status recovered"
            : "Recover interrupted view"
      );
      setPrintProgressNotice(
        terminal
          ? "Recovered interrupted view. Refreshing the latest terminal print evidence."
          : "Print is still running. Recovered interrupted view and refreshing connector progress."
      );
      updateActivePrintSession({
        active: !terminal,
        jobId: recoveredJobId,
        modalOpen: true,
        terminal,
      });

      const response = await apiClient.getPrintJobStatus(recoveredJobId);
      if (!response.success || !response.data) {
        if (response.status === 429 || String(response.code || "").toUpperCase() === "RATE_LIMITED") {
          const seconds = Math.max(1, Math.ceil(Number(response.retryAfterSec || 10)));
          setPrintProgressNotice(`Status refresh paused for ${seconds} seconds. The print run remains recoverable.`);
          return;
        }
        setPrintProgressNotice(
          sanitizePrinterUiError(response.error, "Recovered the print view. Latest status is temporarily unavailable.")
        );
        return;
      }

      replaceRecentPrintJob(response.data as PrintJobRow);
    },
    [
      replaceRecentPrintJob,
      setPrintJobId,
      setPrintProgressNotice,
      setPrintProgressOpen,
      setPrintProgressPhase,
    ]
  );

  useEffect(() => {
    const requestId = activePrintSession.recoveryRequestId;
    if (!requestId || requestId <= handledRecoveryRequestRef.current) return;
    handledRecoveryRequestRef.current = requestId;
    if (!activePrintSession.jobId) return;
    void recoverActivePrintView(activePrintSession.jobId, activePrintSession.terminal);
  }, [
    activePrintSession.jobId,
    activePrintSession.recoveryRequestId,
    activePrintSession.terminal,
    recoverActivePrintView,
  ]);

  useEffect(() => {
    if (printJobId || !activePrintSession.jobId || !activePrintSession.active) return;
    setPrintJobId(activePrintSession.jobId);
    setPrintProgressPhase("Recover interrupted view");
    setPrintProgressNotice("Print is still running. Use the top status button to view progress.");
  }, [
    activePrintSession.active,
    activePrintSession.jobId,
    printJobId,
    setPrintJobId,
    setPrintProgressNotice,
    setPrintProgressPhase,
  ]);
}

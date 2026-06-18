import { useEffect, useRef, type Dispatch, type SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { updateActivePrintSession } from "@/lib/active-print-session";
import { canPollVisibleDocument, jitterMs, pollingPolicy } from "@/lib/query-polling-policy";

import {
  isPrintJobServerSettled,
  syncProgressFromPrintJob as syncPrintJobProgress,
} from "./batch-print-operations";
import { isTerminalPrintProgressPhase } from "./print-workflow-utils";
import type { PrintJobRow } from "./types";

type ProgressStateSetters = Parameters<typeof syncPrintJobProgress>[1];

type ActivePrintJobPollingParams = {
  printJobId: string;
  printProgressOpen: boolean;
  printProgressPhase: string;
  printProgressPrinted: number;
  printProgressTotal: number;
  printing: boolean;
  progressStateSetters: ProgressStateSetters;
  setPrintProgressNotice: Dispatch<SetStateAction<string | null>>;
  loadRecentPrintJobs: () => Promise<void>;
  onBatchesChanged?: () => Promise<void> | void;
};

export function useActivePrintJobPolling({
  printJobId,
  printProgressOpen,
  printProgressPhase,
  printProgressPrinted,
  printProgressTotal,
  printing,
  progressStateSetters,
  setPrintProgressNotice,
  loadRecentPrintJobs,
  onBatchesChanged,
}: ActivePrintJobPollingParams) {
  const completedRefreshJobIdsRef = useRef(new Set<string>());

  useEffect(() => {
    if (!printJobId) return;
    const terminal =
      isTerminalPrintProgressPhase(printProgressPhase) ||
      (printProgressTotal > 0 && printProgressPrinted >= printProgressTotal);
    updateActivePrintSession({
      active: !terminal,
      jobId: printJobId,
      modalOpen: printProgressOpen,
      terminal,
    });
  }, [printJobId, printProgressOpen, printProgressPhase, printProgressPrinted, printProgressTotal]);

  useEffect(() => {
    if (printing) return;
    if (!printJobId) return;
    if (isTerminalPrintProgressPhase(printProgressPhase)) return;

    let cancelled = false;
    let inFlight = false;
    const polledJobId = printJobId;
    const startedAt = Date.now();
    let nextDelayMs = jitterMs(pollingPolicy.activePrintJobMs);

    const syncLatest = async () => {
      if (cancelled || inFlight) return false;
      if (!canPollVisibleDocument()) return false;
      if (Date.now() - startedAt > pollingPolicy.activePrintJobTimeoutMs) {
        setPrintProgressNotice("Live status polling paused. The print run remains visible; refresh status when you need the latest connector evidence.");
        updateActivePrintSession({
          active: true,
          jobId: polledJobId,
          modalOpen: printProgressOpen,
          terminal: false,
        });
        return true;
      }
      inFlight = true;
      try {
        const response = await apiClient.getPrintJobStatus(polledJobId, {
          force: true,
          minIntervalMs: pollingPolicy.activePrintJobStatusMinRefreshMs,
        });
        if (cancelled) return false;
        if (!response.success || !response.data) {
          if (response.status === 429 || String(response.code || "").toUpperCase() === "RATE_LIMITED") {
            const seconds = Math.max(1, Math.ceil(Number(response.retryAfterSec || 10)));
            nextDelayMs = seconds * 1000;
            setPrintProgressNotice(`Status refresh paused for ${seconds} seconds. The print run remains active.`);
          }
          return false;
        }

        const job = response.data as PrintJobRow;
        nextDelayMs = jitterMs(pollingPolicy.activePrintJobMs);
        setPrintProgressNotice(null);
        syncPrintJobProgress(job, progressStateSetters);
        const settled = isPrintJobServerSettled(job);
        if (settled && !completedRefreshJobIdsRef.current.has(polledJobId)) {
          completedRefreshJobIdsRef.current.add(polledJobId);
          updateActivePrintSession({
            active: false,
            jobId: polledJobId,
            modalOpen: printProgressOpen,
            terminal: true,
          });
          const total = Number(job.session?.totalItems || job.itemCount || job.quantity || 0);
          const confirmed = Number(job.session?.confirmedItems || 0);
          const completed =
            job.status === "CONFIRMED" ||
            String(job.session?.status || "").toUpperCase() === "COMPLETED" ||
            Boolean(job.confirmedAt) ||
            (total > 0 && confirmed >= total);
          if (completed) {
            void Promise.allSettled([loadRecentPrintJobs(), onBatchesChanged?.()]);
          }
        }
        return settled;
      } finally {
        inFlight = false;
      }
    };

    let timer: number | null = null;
    const scheduleNext = () => {
      if (cancelled) return;
      timer = window.setTimeout(async () => {
        const settled = await syncLatest();
        if (!cancelled && !settled) scheduleNext();
      }, nextDelayMs);
    };
    void (async () => {
      const settled = await syncLatest();
      if (!cancelled && !settled) scheduleNext();
    })();

    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [
    loadRecentPrintJobs,
    onBatchesChanged,
    printJobId,
    printProgressOpen,
    printProgressPhase,
    progressStateSetters,
    printing,
    setPrintProgressNotice,
  ]);
}

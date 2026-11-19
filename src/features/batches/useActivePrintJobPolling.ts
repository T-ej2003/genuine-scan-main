import { useEffect, useRef, useSyncExternalStore, type Dispatch, type SetStateAction } from "react";

import apiClient from "@/lib/api-client";
import { getAuthenticatedStreamScope, onRequestCoordinatorScopeChange } from "@/lib/api/request-coordinator";
import { updateActivePrintSession } from "@/lib/active-print-session";
import { primePrintJobRealtimeSnapshot, usePrintJobRealtime } from "@/lib/print-job-realtime-store";
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

const markSettledRefresh = (seen: Map<string, "SETTLED" | "CONFIRMED">, job: PrintJobRow) => {
  const previous = seen.get(job.id);
  const next = job.status === "CONFIRMED" ? "CONFIRMED" : "SETTLED";
  if (previous === "CONFIRMED" || (previous === "SETTLED" && next === "SETTLED")) return false;
  seen.set(job.id, next);
  return true;
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
  const refreshedSettledJobsRef = useRef(new Map<string, "SETTLED" | "CONFIRMED">());
  const securityScope = useSyncExternalStore(onRequestCoordinatorScopeChange, getAuthenticatedStreamScope, getAuthenticatedStreamScope);
  const realtime = usePrintJobRealtime(printJobId);
  const realtimeJob = realtime.job as PrintJobRow | null;
  const realtimeJobRef = useRef(realtimeJob);
  realtimeJobRef.current = realtimeJob;
  const callbacksRef = useRef({ loadRecentPrintJobs, onBatchesChanged, progressStateSetters, setPrintProgressNotice });
  callbacksRef.current = { loadRecentPrintJobs, onBatchesChanged, progressStateSetters, setPrintProgressNotice };

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
    if (!printJobId || !realtime.job) return;
    const job = realtime.job as PrintJobRow;
    syncPrintJobProgress(job, progressStateSetters);
    if (isPrintJobServerSettled(job) && markSettledRefresh(refreshedSettledJobsRef.current, job)) {
      updateActivePrintSession({
        active: false,
        jobId: printJobId,
        modalOpen: printProgressOpen,
        terminal: true,
      });
      void Promise.allSettled([loadRecentPrintJobs(), onBatchesChanged?.()]);
    }
  }, [loadRecentPrintJobs, onBatchesChanged, printJobId, printProgressOpen, progressStateSetters, realtime.job]);

  useEffect(() => {
    if (printing) return;
    if (!printJobId) return;
    if (isTerminalPrintProgressPhase(printProgressPhase)) return;
    if (isPrintJobServerSettled(realtimeJobRef.current)) return;

    let cancelled = false;
    let inFlight = false;
    const polledJobId = printJobId;
    const polledScope = securityScope;
    const startedAt = Date.now();
    let nextDelayMs = jitterMs(pollingPolicy.activePrintJobMs);
    let failedAttempts = 0;

    const syncLatest = async () => {
      if (cancelled || polledScope !== getAuthenticatedStreamScope()) return true;
      if (inFlight) return false;
      if (!canPollVisibleDocument()) return false;
      if (Date.now() - startedAt > pollingPolicy.activePrintJobTimeoutMs) {
        callbacksRef.current.setPrintProgressNotice("Realtime status remains active. Slow fallback polling is paused for this long-running print run.");
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
          minIntervalMs: pollingPolicy.activePrintJobStatusMinRefreshMs,
        });
        if (cancelled || polledScope !== getAuthenticatedStreamScope()) return true;
        if (!response.success || !response.data) {
          if (response.status === 429 || String(response.code || "").toUpperCase() === "RATE_LIMITED") {
            const seconds = Math.max(1, Math.ceil(Number(response.retryAfterSec || 10)));
            nextDelayMs = Math.max(seconds * 1000, pollingPolicy.activePrintJobMs);
            callbacksRef.current.setPrintProgressNotice(`Status refresh paused for ${seconds} seconds. The print run remains active.`);
          }
          return false;
        }

        const job = response.data as PrintJobRow;
        if (job.id !== polledJobId) return false;
        if (!primePrintJobRealtimeSnapshot(polledJobId, job, polledScope)) return isPrintJobServerSettled(realtimeJobRef.current);
        failedAttempts = 0;
        nextDelayMs = jitterMs(pollingPolicy.activePrintJobMs);
        callbacksRef.current.setPrintProgressNotice(null);
        syncPrintJobProgress(job, callbacksRef.current.progressStateSetters);
        const settled = isPrintJobServerSettled(job);
        if (settled && markSettledRefresh(refreshedSettledJobsRef.current, job)) {
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
            void Promise.allSettled([callbacksRef.current.loadRecentPrintJobs(), callbacksRef.current.onBatchesChanged?.()]);
          }
        }
        return settled;
      } catch {
        if (cancelled) return false;
        failedAttempts += 1;
        nextDelayMs = Math.min(5 * 60_000, pollingPolicy.activePrintJobMs * 2 ** Math.min(failedAttempts, 3));
        callbacksRef.current.setPrintProgressNotice("Status is temporarily unavailable. The print result is uncertain; use Refresh status to check again.");
        return false;
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
    printJobId,
    printProgressOpen,
    printProgressPhase,
    printing,
    securityScope,
  ]);
  return realtimeJob;
}

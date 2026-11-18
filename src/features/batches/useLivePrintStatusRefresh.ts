import { useEffect, useRef, useState } from "react";

import apiClient from "@/lib/api-client";
import { getAuthenticatedStreamScope } from "@/lib/api/request-coordinator";
import { updateActivePrintSession } from "@/lib/active-print-session";
import { primePrintJobRealtimeSnapshot } from "@/lib/print-job-realtime-store";
import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

import { isPrintJobServerSettled, syncProgressFromPrintJob as syncPrintJobProgress } from "./batch-print-operations";
import {
  getLivePrintStatusRefreshDecision,
  getLivePrintStatusRetryAfterMs,
  LIVE_PRINT_STATUS_REFRESH_MIN_MS,
} from "./print-status-refresh-control";
import type { PrintJobRow } from "./types";

type ProgressStateSetters = Parameters<typeof syncPrintJobProgress>[1];

type LivePrintStatusRefreshParams = {
  printJobId: string;
  progressStateSetters: ProgressStateSetters;
  replaceRecentPrintJob: (job: PrintJobRow) => void;
  setPrintProgressNotice: (notice: string | null) => void;
};

export function useLivePrintStatusRefresh({
  printJobId,
  progressStateSetters,
  replaceRecentPrintJob,
  setPrintProgressNotice,
}: LivePrintStatusRefreshParams) {
  const [refreshing, setRefreshing] = useState(false);
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [nowTick, setNowTick] = useState(() => Date.now());
  const inFlightRef = useRef<Promise<void> | null>(null);
  const lastRefreshAtRef = useRef(0);

  useEffect(() => {
    if (!cooldownUntil || cooldownUntil <= Date.now()) return;
    const timer = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [cooldownUntil]);

  const cooldownRemainingSeconds = Math.max(0, Math.ceil((cooldownUntil - nowTick) / 1000));

  const refresh = async () => {
    const requestScope = getAuthenticatedStreamScope();
    const currentJobId = String(printJobId || "").trim();
    if (!currentJobId) return;
    if (inFlightRef.current) return inFlightRef.current;

    const timestamp = Date.now();
    const decision = getLivePrintStatusRefreshDecision(timestamp, lastRefreshAtRef.current, cooldownUntil);
    if (!decision.allowed) {
      setNowTick(timestamp);
      setCooldownUntil(decision.nextAllowedAt);
      setPrintProgressNotice(`Status refresh is cooling down for ${decision.waitSeconds} seconds. The print run remains visible.`);
      return;
    }

    setRefreshing(true);
    lastRefreshAtRef.current = timestamp;
    setNowTick(timestamp);
    setCooldownUntil(timestamp + LIVE_PRINT_STATUS_REFRESH_MIN_MS);
    inFlightRef.current = (async () => {
      let response: Awaited<ReturnType<typeof apiClient.getPrintJobStatus>>;
      try {
        response = await apiClient.getPrintJobStatus(currentJobId, { force: true });
      } catch {
        if (requestScope !== getAuthenticatedStreamScope()) return;
        setPrintProgressNotice("Status refresh is temporarily unavailable. The print result remains uncertain.");
        return;
      }
      if (requestScope !== getAuthenticatedStreamScope()) return;
      if (!response.success || !response.data) {
        if (response.status === 429 || String(response.code || "").toUpperCase() === "RATE_LIMITED") {
          const retryAfterMs = getLivePrintStatusRetryAfterMs(response.retryAfterSec);
          const seconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
          setNowTick(Date.now());
          setCooldownUntil(Date.now() + retryAfterMs);
          setPrintProgressNotice(`Status refresh paused for ${seconds} seconds. The print run remains visible.`);
          return;
        }
        setPrintProgressNotice(
          sanitizePrinterUiError(response.error, "Status refresh is temporarily unavailable. The print run remains visible.")
        );
        return;
      }

      const job = response.data as PrintJobRow;
      if (!primePrintJobRealtimeSnapshot(currentJobId, job, requestScope)) return;
      syncPrintJobProgress(job, progressStateSetters);
      replaceRecentPrintJob(job);
      if (isPrintJobServerSettled(job)) {
        updateActivePrintSession({
          active: false,
          jobId: currentJobId,
          modalOpen: true,
          terminal: true,
        });
      }
    })().finally(() => {
      setRefreshing(false);
      inFlightRef.current = null;
    });

    return inFlightRef.current;
  };

  return {
    refresh,
    refreshing,
    cooldownRemainingSeconds,
  };
}

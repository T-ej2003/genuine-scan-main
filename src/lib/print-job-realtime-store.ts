import { useEffect, useSyncExternalStore } from "react";

import apiClient from "@/lib/api-client";
import { normalizePrintJobView } from "@/lib/print-job-view";

type PrintJobSnapshot = {
  job: any | null;
  connected: boolean;
  lastEventAt: number | null;
  error: boolean;
};

const snapshots = new Map<string, PrintJobSnapshot>();
const listeners = new Map<string, Set<() => void>>();
const subscriptions = new Map<string, { refs: number; stop: () => void }>();
const reconciliations = new Map<string, { timer: ReturnType<typeof setTimeout> | null; inFlight: boolean; pending: boolean; lastFetchAt: number }>();
const RECONCILE_MIN_INTERVAL_MS = 10_000;

const emptySnapshot: PrintJobSnapshot = {
  job: null,
  connected: false,
  lastEventAt: null,
  error: false,
};

const getSnapshot = (jobId: string) => snapshots.get(jobId) || emptySnapshot;

const emit = (jobId: string) => {
  for (const listener of listeners.get(jobId) || []) listener();
};

const updateSnapshot = (jobId: string, patch: Partial<PrintJobSnapshot>) => {
  snapshots.set(jobId, {
    ...getSnapshot(jobId),
    ...patch,
  });
  emit(jobId);
};

const extractPrintJobView = (payload: any) => {
  if (!payload) return null;
  if (payload.envelope === "MSCQR_SSE_V1") {
    const eventPayload = payload.payload || {};
    return eventPayload.view || eventPayload.job || eventPayload.data || null;
  }
  return payload.view || payload.job || payload.data || null;
};

const isTerminal = (job: any) =>
  ["CONFIRMED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED", "STOPPED"].includes(String(job?.status || "").toUpperCase());

// A stopped session can still accept signed confirmations for acknowledged items.
const isFinalForReconciliation = (job: any) =>
  ["CONFIRMED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED"].includes(String(job?.status || "").toUpperCase());

const isValidJobView = (jobId: string, job: any) =>
  job && typeof job === "object" && job.id === jobId && typeof job.status === "string" &&
  Number.isFinite(Date.parse(String(job.updatedAt || job.createdAt || "")));

const acceptJobView = (jobId: string, view: any) => {
  const job = normalizePrintJobView(view);
  if (!isValidJobView(jobId, job)) return false;
  const current = getSnapshot(jobId).job;
  if (current) {
    if (String(current.status).toUpperCase() === "CONFIRMED" && String(job.status).toUpperCase() !== "CONFIRMED") return false;
    if (isTerminal(current) && !isTerminal(job)) return false;
    const previousAt = Date.parse(String(current.updatedAt || current.createdAt || ""));
    const incomingAt = Date.parse(String(job.updatedAt || job.createdAt || ""));
    if (Number.isFinite(previousAt) && incomingAt < previousAt) return false;
    if (Number(job.session?.confirmedItems || 0) < Number(current.session?.confirmedItems || 0)) return false;
  }
  updateSnapshot(jobId, { job, connected: true, error: false, lastEventAt: Date.now() });
  return true;
};

const reconcileJob = (jobId: string) => {
  const state = reconciliations.get(jobId) || { timer: null, inFlight: false, pending: false, lastFetchAt: 0 };
  reconciliations.set(jobId, state);
  if (isFinalForReconciliation(getSnapshot(jobId).job)) return;
  if (state.inFlight) { state.pending = true; return; }
  if (state.timer) return;
  const delay = Math.max(0, state.lastFetchAt + RECONCILE_MIN_INTERVAL_MS - Date.now());
  state.timer = setTimeout(async () => {
    state.timer = null;
    if (state.inFlight || isFinalForReconciliation(getSnapshot(jobId).job)) return;
    state.inFlight = true;
    state.lastFetchAt = Date.now();
    try {
      const response = await apiClient.getPrintJobStatus(jobId, { force: true, minIntervalMs: RECONCILE_MIN_INTERVAL_MS });
      if (reconciliations.get(jobId) === state && response.success && response.data) acceptJobView(jobId, response.data);
    } catch {
      if (reconciliations.get(jobId) === state) updateSnapshot(jobId, { error: true });
    } finally {
      state.inFlight = false;
      if (state.pending && reconciliations.get(jobId) === state) {
        state.pending = false;
        reconcileJob(jobId);
      }
    }
  }, delay);
};

const subscribeJob = (jobId: string) => {
  const existing = subscriptions.get(jobId);
  if (existing) {
    existing.refs += 1;
    return () => {
      existing.refs -= 1;
      if (existing.refs <= 0) {
        existing.stop();
        subscriptions.delete(jobId);
      }
    };
  }

  if (typeof (apiClient as any).streamPrintJobStatus !== "function") {
    updateSnapshot(jobId, { connected: false, error: false });
    return () => undefined;
  }

  const stopStream = (apiClient as any).streamPrintJobStatus(
    jobId,
    (payload: any) => {
      const job = extractPrintJobView(payload);
      const eventPayload = payload?.envelope === "MSCQR_SSE_V1" ? payload.payload : payload;
      if (eventPayload?.printJobId && eventPayload.printJobId !== jobId) return;
      if (job && acceptJobView(jobId, job)) return;
      if (eventPayload?.printJobId === jobId && payload?.type !== "keepalive") reconcileJob(jobId);
    },
    {
      onOpen: () => {
        updateSnapshot(jobId, { connected: true, error: false });
        if (getSnapshot(jobId).job) reconcileJob(jobId);
      },
      onError: () => updateSnapshot(jobId, { connected: false, error: true }),
    }
  );
  const stop = () => {
    if (typeof stopStream === "function") stopStream();
    const reconciliation = reconciliations.get(jobId);
    if (reconciliation?.timer) clearTimeout(reconciliation.timer);
    reconciliations.delete(jobId);
  };
  subscriptions.set(jobId, { refs: 1, stop });
  return () => {
    const current = subscriptions.get(jobId);
    if (!current) return;
    current.refs -= 1;
    if (current.refs <= 0) {
      current.stop();
      subscriptions.delete(jobId);
    }
  };
};

export const primePrintJobRealtimeSnapshot = (jobId: string, job: any) => {
  if (!jobId || !job) return false;
  return acceptJobView(jobId, job);
};

export const getPrintJobRealtimeDebugState = () => ({
  snapshots: snapshots.size,
  listeners: Array.from(listeners.entries()).map(([jobId, set]) => ({ jobId, count: set.size })),
  subscriptions: Array.from(subscriptions.entries()).map(([jobId, subscription]) => ({
    jobId,
    refs: subscription.refs,
  })),
});

export const resetPrintJobRealtimeStoreForTests = () => {
  for (const subscription of subscriptions.values()) {
    subscription.stop();
  }
  subscriptions.clear();
  for (const state of reconciliations.values()) if (state.timer) clearTimeout(state.timer);
  reconciliations.clear();
  listeners.clear();
  snapshots.clear();
};

export const usePrintJobRealtime = (jobId: string | null | undefined) => {
  const normalizedJobId = String(jobId || "").trim();

  useEffect(() => {
    if (!normalizedJobId) return undefined;
    return subscribeJob(normalizedJobId);
  }, [normalizedJobId]);

  return useSyncExternalStore(
    (listener) => {
      if (!normalizedJobId) return () => undefined;
      let set = listeners.get(normalizedJobId);
      if (!set) {
        set = new Set();
        listeners.set(normalizedJobId, set);
      }
      set.add(listener);
      return () => {
        set?.delete(listener);
        if (set?.size === 0) listeners.delete(normalizedJobId);
      };
    },
    () => getSnapshot(normalizedJobId),
    () => emptySnapshot
  );
};

import { useEffect, useSyncExternalStore } from "react";

import apiClient from "@/lib/api-client";

type PrintJobSnapshot = {
  job: any | null;
  connected: boolean;
  lastEventAt: number | null;
  error: boolean;
};

const snapshots = new Map<string, PrintJobSnapshot>();
const listeners = new Map<string, Set<() => void>>();
const subscriptions = new Map<string, { refs: number; stop: () => void }>();

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
      const job = payload?.view || payload?.job || payload?.data || null;
      updateSnapshot(jobId, {
        job,
        connected: true,
        error: false,
        lastEventAt: Date.now(),
      });
    },
    {
      onOpen: () => updateSnapshot(jobId, { connected: true, error: false }),
      onError: () => updateSnapshot(jobId, { connected: false, error: true }),
    }
  );
  const stop = typeof stopStream === "function" ? stopStream : () => undefined;
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
  if (!jobId || !job) return;
  updateSnapshot(jobId, {
    job,
    lastEventAt: Date.now(),
    error: false,
  });
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

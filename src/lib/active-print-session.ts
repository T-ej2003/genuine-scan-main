import { useSyncExternalStore } from "react";

export type ActivePrintSessionState = {
  active: boolean;
  jobId: string | null;
  modalOpen: boolean;
  terminal: boolean;
  updatedAt: number;
};

const listeners = new Set<() => void>();

let state: ActivePrintSessionState = {
  active: false,
  jobId: null,
  modalOpen: false,
  terminal: false,
  updatedAt: Date.now(),
};

const notify = () => {
  for (const listener of listeners) listener();
};

export const getActivePrintSessionSnapshot = () => state;

export const subscribeActivePrintSession = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};

export const updateActivePrintSession = (next: Partial<Omit<ActivePrintSessionState, "updatedAt">>) => {
  const merged = { ...state, ...next, updatedAt: Date.now() };
  if (
    merged.active === state.active &&
    merged.jobId === state.jobId &&
    merged.modalOpen === state.modalOpen &&
    merged.terminal === state.terminal
  ) {
    return;
  }
  state = merged;
  notify();
};

export const clearActivePrintSession = (jobId?: string | null) => {
  const requestedJobId = String(jobId || "").trim();
  if (requestedJobId && state.jobId && state.jobId !== requestedJobId) return;
  updateActivePrintSession({
    active: false,
    jobId: null,
    modalOpen: false,
    terminal: true,
  });
};

export const isActivePrintSessionSuppressed = () => state.active && state.modalOpen && !state.terminal;

export const useActivePrintSession = () =>
  useSyncExternalStore(subscribeActivePrintSession, getActivePrintSessionSnapshot, getActivePrintSessionSnapshot);

export const useActivePrintSessionSuppression = () => {
  const snapshot = useActivePrintSession();
  return snapshot.active && snapshot.modalOpen && !snapshot.terminal;
};

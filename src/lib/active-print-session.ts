import { useSyncExternalStore } from "react";

export type ActivePrintSessionState = {
  active: boolean;
  jobId: string | null;
  modalOpen: boolean;
  terminal: boolean;
  recoveryRequestId: number;
  updatedAt: number;
};

const listeners = new Set<() => void>();

let state: ActivePrintSessionState = {
  active: false,
  jobId: null,
  modalOpen: false,
  terminal: false,
  recoveryRequestId: 0,
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
    merged.terminal === state.terminal &&
    merged.recoveryRequestId === state.recoveryRequestId
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
    recoveryRequestId: 0,
  });
};

export const requestActivePrintSessionRecovery = () => {
  if (!state.jobId) return;
  updateActivePrintSession({ recoveryRequestId: state.recoveryRequestId + 1 });
};

export const hasRecoverableActivePrintSession = (snapshot: ActivePrintSessionState = state) =>
  Boolean(snapshot.jobId && (snapshot.active || snapshot.terminal));

export const getActivePrintRecoveryLabel = (snapshot: ActivePrintSessionState = state) => {
  if (!hasRecoverableActivePrintSession(snapshot)) return null;
  if (snapshot.terminal) return "View print result";
  return snapshot.modalOpen ? "View print progress" : "Resume print progress";
};

export const isActivePrintSessionSuppressed = () => Boolean(state.jobId && state.active && !state.terminal);

export const useActivePrintSession = () =>
  useSyncExternalStore(subscribeActivePrintSession, getActivePrintSessionSnapshot, getActivePrintSessionSnapshot);

export const useActivePrintSessionSuppression = () => {
  const snapshot = useActivePrintSession();
  return Boolean(snapshot.jobId && snapshot.active && !snapshot.terminal);
};

export const pollingPolicy = {
  printerIdleHeartbeatMs: 90_000,
  printerSetupRefreshMs: 45_000,
  printerRuntimeRefreshMs: 60_000,
  activePrintJobMs: 3_000,
  hiddenTabBackoffMs: 30_000,
  dashboardFallbackMs: 120_000,
  notificationsMs: 180_000,
  attentionQueueMs: 180_000,
  telemetryRouteDebounceMs: 1_000,
} as const;

export const isBrowserDocumentVisible = () =>
  typeof document === "undefined" || document.visibilityState === "visible";

export const canPollVisibleDocument = () => isBrowserDocumentVisible() && typeof navigator !== "undefined" && navigator.onLine !== false;

export const jitterMs = (baseMs: number, ratio = 0.15) => {
  const safeBase = Math.max(0, Math.floor(baseMs));
  const spread = Math.max(0, Math.floor(safeBase * ratio));
  if (spread <= 0) return safeBase;
  return safeBase + Math.floor(Math.random() * spread);
};

export const visibleRefetchInterval = (baseMs: number) => () =>
  canPollVisibleDocument() ? jitterMs(baseMs, 0.1) : false;

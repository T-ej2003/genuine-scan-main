export const LIVE_PRINT_STATUS_REFRESH_MIN_MS = 30_000;
export const LIVE_PRINT_STATUS_429_FALLBACK_MS = 30_000;

export const getLivePrintStatusRefreshDecision = (
  now: number,
  lastRefreshAt: number,
  cooldownUntil: number
) => {
  const nextAllowedAt = Math.max(lastRefreshAt + LIVE_PRINT_STATUS_REFRESH_MIN_MS, cooldownUntil);
  const allowed = now >= nextAllowedAt;
  return {
    allowed,
    nextAllowedAt,
    waitSeconds: allowed ? 0 : Math.max(1, Math.ceil((nextAllowedAt - now) / 1000)),
  };
};

export const getLivePrintStatusRetryAfterMs = (retryAfterSec?: unknown) => {
  const seconds = Number(retryAfterSec || 0);
  return Number.isFinite(seconds) && seconds > 0
    ? Math.ceil(seconds * 1000)
    : LIVE_PRINT_STATUS_429_FALLBACK_MS;
};

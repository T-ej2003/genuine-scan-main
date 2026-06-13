import type { ApiResponse } from "@/lib/api/internal-client-core";

const DEFAULT_TTL_MS = 30_000;
const DEFAULT_MIN_REFRESH_MS = 10_000;
const DEFAULT_RATE_LIMIT_COOLDOWN_MS = 10_000;
const PAUSED_MESSAGE = "Activity is refreshing too often. Please try again in a moment.";

type CacheEntry<T> = {
  lastGood?: ApiResponse<T>;
  lastGoodAt: number;
  lastAttemptAt: number;
  cooldownUntil: number;
  rateLimitHits: number;
  inFlight: Promise<ApiResponse<T>> | null;
};

type ControlledGetOptions = {
  ttlMs?: number;
  minRefreshMs?: number;
  bypassCache?: boolean;
};

const entries = new Map<string, CacheEntry<unknown>>();

const now = () => Date.now();

const fallbackBackoffMs = (hits: number) => {
  if (hits <= 1) return 10_000;
  if (hits === 2) return 20_000;
  if (hits === 3) return 30_000;
  return 60_000;
};

const retryAfterMs = (response: ApiResponse<unknown>, hits: number) => {
  const seconds = Number(response.retryAfterSec);
  return Number.isFinite(seconds) && seconds > 0
    ? Math.ceil(seconds * 1000)
    : Math.min(60_000, Math.max(DEFAULT_RATE_LIMIT_COOLDOWN_MS, fallbackBackoffMs(hits)));
};

const secondsUntil = (timestamp: number) => Math.max(1, Math.ceil((timestamp - now()) / 1000));

const isRateLimited = (response: ApiResponse<unknown>) =>
  response.status === 429 || String(response.code || "").toUpperCase() === "RATE_LIMITED";

const pausedFromLastGood = <T>(entry: CacheEntry<unknown>, cooldownUntil: number): ApiResponse<T> | null => {
  if (!entry.lastGood?.success) return null;
  return {
    ...(entry.lastGood as ApiResponse<T>),
    degraded: true,
    code: "RATE_LIMITED",
    status: entry.lastGood.status,
    retryAfterSec: secondsUntil(cooldownUntil),
    message: PAUSED_MESSAGE,
  };
};

const pausedFailure = <T>(cooldownUntil: number): ApiResponse<T> => ({
  success: false,
  status: 429,
  code: "RATE_LIMITED",
  retryAfterSec: secondsUntil(cooldownUntil),
  error: PAUSED_MESSAGE,
});

export const controlledDashboardGet = async <T>(
  key: string,
  fetcher: () => Promise<ApiResponse<T>>,
  options: ControlledGetOptions = {}
): Promise<ApiResponse<T>> => {
  const timestamp = now();
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const minRefreshMs = options.minRefreshMs ?? DEFAULT_MIN_REFRESH_MS;
  const entry =
    (entries.get(key) as CacheEntry<T> | undefined) ||
    ({
      lastGoodAt: 0,
      lastAttemptAt: 0,
      cooldownUntil: 0,
      rateLimitHits: 0,
      inFlight: null,
    } satisfies CacheEntry<T>);

  entries.set(key, entry as CacheEntry<unknown>);

  if (entry.cooldownUntil > timestamp) {
    return pausedFromLastGood<T>(entry, entry.cooldownUntil) || pausedFailure<T>(entry.cooldownUntil);
  }

  if (!options.bypassCache && entry.lastGood?.success && timestamp - entry.lastGoodAt < ttlMs) {
    return entry.lastGood;
  }

  if (!options.bypassCache && entry.lastGood?.success && timestamp - entry.lastAttemptAt < minRefreshMs) {
    return entry.lastGood;
  }

  if (entry.inFlight) return entry.inFlight;

  entry.lastAttemptAt = timestamp;
  entry.inFlight = fetcher()
    .then((response) => {
      if (response.success) {
        entry.lastGood = response;
        entry.lastGoodAt = now();
        entry.cooldownUntil = 0;
        entry.rateLimitHits = 0;
        return response;
      }

      if (isRateLimited(response)) {
        entry.rateLimitHits += 1;
        const cooldownUntil = now() + retryAfterMs(response, entry.rateLimitHits);
        entry.cooldownUntil = cooldownUntil;
        return pausedFromLastGood<T>(entry, cooldownUntil) || { ...response, error: PAUSED_MESSAGE };
      }

      if ((response.status === 0 || Number(response.status || 0) >= 500) && entry.lastGood?.success) {
        return {
          ...entry.lastGood,
          degraded: true,
          message: "Activity is temporarily unavailable. Showing the latest saved view.",
        };
      }

      return response;
    })
    .finally(() => {
      entry.inFlight = null;
    });

  return entry.inFlight;
};

export const clearDashboardReadCache = (prefixes?: string[]) => {
  if (!prefixes?.length) {
    entries.clear();
    return;
  }

  for (const key of entries.keys()) {
    if (prefixes.some((prefix) => key.startsWith(prefix))) {
      entries.delete(key);
    }
  }
};

export const getDashboardRequestControlState = () =>
  Array.from(entries.entries()).map(([key, entry]) => ({
    key,
    hasLastGood: Boolean(entry.lastGood?.success),
    cooldownUntil: entry.cooldownUntil,
    rateLimitHits: entry.rateLimitHits,
    inFlight: Boolean(entry.inFlight),
  }));

if (typeof window !== "undefined") {
  window.addEventListener("auth:logout", () => clearDashboardReadCache());
}

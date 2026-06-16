import type { ApiResponse } from "@/lib/api/internal-client-core";

type FamilyParams = string | number | boolean | null | undefined | Record<string, unknown>;

type CoordinatedReadOptions = {
  family: string;
  params?: FamilyParams;
  ttlMs?: number;
  minRefreshMs?: number;
  force?: boolean;
  staleMessage?: string;
  cooldownMessage?: string;
};

type ReadState<T = unknown> = {
  lastGood?: ApiResponse<T>;
  lastGoodAt: number;
  lastAttemptAt: number;
  cooldownUntil: number;
  rateLimitHits: number;
  inFlight: Promise<ApiResponse<T>> | null;
};

type PersistedState = {
  lastGood?: ApiResponse<unknown>;
  lastGoodAt?: number;
  cooldownUntil?: number;
  rateLimitHits?: number;
};

const DEFAULT_TTL_MS = 30_000;
const DEFAULT_MIN_REFRESH_MS = 10_000;
const DEFAULT_COOLDOWN_MESSAGE = "Request refresh is temporarily paused. Showing the latest available data.";
const STORAGE_PREFIX = "mscqr:request-coordinator:v1:";
const CHANNEL_NAME = "mscqr-request-coordinator";

const states = new Map<string, ReadState<unknown>>();

const now = () => Date.now();

const stableStringify = (value: unknown): string => {
  if (value === null || value === undefined) return "";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(record[key])}`)
    .join(",")}}`;
};

const normalizeKeyPart = (value: unknown) =>
  String(value ?? "")
    .trim()
    .replace(/[^a-zA-Z0-9._:-]+/g, "_")
    .slice(0, 240);

export const buildRequestFamilyKey = (family: string, params?: FamilyParams) => {
  const normalizedFamily = normalizeKeyPart(family);
  const normalizedParams = normalizeKeyPart(stableStringify(params));
  return normalizedParams ? `${normalizedFamily}:${normalizedParams}` : normalizedFamily;
};

const storageKeyFor = (key: string) => `${STORAGE_PREFIX}${key}`;

const canUseStorage = () => typeof window !== "undefined" && typeof window.localStorage !== "undefined";

const readPersisted = (key: string): PersistedState | null => {
  if (!canUseStorage()) return null;
  try {
    const raw = window.localStorage.getItem(storageKeyFor(key));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as PersistedState;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
};

const writePersisted = (key: string, state: ReadState<unknown>) => {
  if (!canUseStorage()) return;
  try {
    window.localStorage.setItem(
      storageKeyFor(key),
      JSON.stringify({
        lastGood: state.lastGood,
        lastGoodAt: state.lastGoodAt,
        cooldownUntil: state.cooldownUntil,
        rateLimitHits: state.rateLimitHits,
      } satisfies PersistedState)
    );
  } catch {
    // Best effort cache only.
  }
};

let channel: BroadcastChannel | null | undefined;

const getChannel = () => {
  if (channel !== undefined) return channel;
  if (typeof BroadcastChannel === "undefined") {
    channel = null;
    return channel;
  }
  channel = new BroadcastChannel(CHANNEL_NAME);
  channel.onmessage = (event) => {
    const key = String(event.data?.key || "").trim();
    if (!key) return;
    const persisted = readPersisted(key);
    if (!persisted) return;
    const state = getState(key);
    if (persisted.lastGood?.success && (!state.lastGoodAt || Number(persisted.lastGoodAt || 0) > state.lastGoodAt)) {
      state.lastGood = persisted.lastGood;
      state.lastGoodAt = Number(persisted.lastGoodAt || 0);
    }
    if (Number(persisted.cooldownUntil || 0) > state.cooldownUntil) {
      state.cooldownUntil = Number(persisted.cooldownUntil || 0);
      state.rateLimitHits = Math.max(state.rateLimitHits, Number(persisted.rateLimitHits || 0));
    }
  };
  return channel;
};

const broadcastState = (key: string) => {
  try {
    getChannel()?.postMessage({ key });
  } catch {
    // Ignore cross-tab sync failures.
  }
};

const clearPersisted = (prefixes?: string[]) => {
  if (!canUseStorage()) return;
  try {
    const storage = window.localStorage;
    for (let index = storage.length - 1; index >= 0; index -= 1) {
      const storageKey = storage.key(index);
      if (!storageKey?.startsWith(STORAGE_PREFIX)) continue;
      const familyKey = storageKey.slice(STORAGE_PREFIX.length);
      if (!prefixes?.length || prefixes.some((prefix) => familyKey.startsWith(prefix))) {
        storage.removeItem(storageKey);
      }
    }
  } catch {
    // Best effort cache only.
  }
};

const hydrateState = (key: string, state: ReadState<unknown>) => {
  const persisted = readPersisted(key);
  if (!persisted) return state;
  if (persisted.lastGood?.success) {
    state.lastGood = persisted.lastGood;
    state.lastGoodAt = Number(persisted.lastGoodAt || 0);
  }
  state.cooldownUntil = Math.max(state.cooldownUntil, Number(persisted.cooldownUntil || 0));
  state.rateLimitHits = Math.max(state.rateLimitHits, Number(persisted.rateLimitHits || 0));
  return state;
};

const getState = <T>(key: string): ReadState<T> => {
  const existing = states.get(key) as ReadState<T> | undefined;
  if (existing) return existing;
  const created = hydrateState(key, {
    lastGoodAt: 0,
    lastAttemptAt: 0,
    cooldownUntil: 0,
    rateLimitHits: 0,
    inFlight: null,
  }) as ReadState<T>;
  states.set(key, created as ReadState<unknown>);
  return created;
};

const secondsUntil = (timestamp: number) => Math.max(1, Math.ceil((timestamp - now()) / 1000));

const isRateLimited = (response: ApiResponse<unknown>) =>
  response.status === 429 ||
  String(response.code || "").toUpperCase() === "RATE_LIMITED" ||
  String(response.errorCode || "").toUpperCase() === "RATE_LIMITED";

const fallbackBackoffMs = (hits: number) => {
  if (hits <= 1) return 10_000;
  if (hits === 2) return 20_000;
  if (hits === 3) return 30_000;
  return 60_000;
};

const retryAfterMs = (response: ApiResponse<unknown>, hits: number) => {
  const seconds = Number(response.retryAfterSec);
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds * 1000) : fallbackBackoffMs(hits);
};

const staleFromLastGood = <T>(
  entry: ReadState<T>,
  cooldownUntil: number,
  message: string
): ApiResponse<T> | null => {
  if (!entry.lastGood?.success) return null;
  return {
    ...entry.lastGood,
    degraded: true,
    code: "RATE_LIMITED",
    errorCode: "RATE_LIMITED",
    retryAfterSec: secondsUntil(cooldownUntil),
    message,
  };
};

const cooldownFailure = <T>(cooldownUntil: number, message: string): ApiResponse<T> => ({
  success: false,
  status: 429,
  code: "RATE_LIMITED",
  errorCode: "RATE_LIMITED",
  retryAfterSec: secondsUntil(cooldownUntil),
  error: message,
});

export const coordinateProtectedRead = async <T>(
  options: CoordinatedReadOptions,
  fetcher: () => Promise<ApiResponse<T>>
): Promise<ApiResponse<T>> => {
  const key = buildRequestFamilyKey(options.family, options.params);
  const state = getState<T>(key);
  const timestamp = now();
  const ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
  const minRefreshMs = options.minRefreshMs ?? DEFAULT_MIN_REFRESH_MS;
  const cooldownMessage = options.cooldownMessage || DEFAULT_COOLDOWN_MESSAGE;

  if (state.cooldownUntil > timestamp && !options.force) {
    return staleFromLastGood(state, state.cooldownUntil, cooldownMessage) || cooldownFailure<T>(state.cooldownUntil, cooldownMessage);
  }

  if (!options.force && state.lastGood?.success && timestamp - state.lastGoodAt < ttlMs) {
    return state.lastGood;
  }

  if (!options.force && state.lastGood?.success && timestamp - state.lastAttemptAt < minRefreshMs) {
    return state.lastGood;
  }

  if (state.inFlight) return state.inFlight;

  state.lastAttemptAt = timestamp;
  state.inFlight = fetcher()
    .then((response) => {
      if (response.success) {
        state.lastGood = response;
        state.lastGoodAt = now();
        state.cooldownUntil = 0;
        state.rateLimitHits = 0;
        writePersisted(key, state as ReadState<unknown>);
        broadcastState(key);
        return response;
      }

      if (isRateLimited(response)) {
        state.rateLimitHits += 1;
        state.cooldownUntil = now() + retryAfterMs(response, state.rateLimitHits);
        writePersisted(key, state as ReadState<unknown>);
        broadcastState(key);
        return staleFromLastGood(state, state.cooldownUntil, cooldownMessage) || {
          ...response,
          error: response.error || cooldownMessage,
        };
      }

      if ((response.status === 0 || Number(response.status || 0) >= 500) && state.lastGood?.success) {
        return {
          ...state.lastGood,
          degraded: true,
          message: options.staleMessage || "Showing the latest available data while refresh recovers.",
        };
      }

      return response;
    })
    .finally(() => {
      state.inFlight = null;
    });

  return state.inFlight;
};

export const clearRequestCoordinator = (prefixes?: string[]) => {
  clearPersisted(prefixes);
  if (!prefixes?.length) {
    states.clear();
    return;
  }

  for (const key of Array.from(states.keys())) {
    if (prefixes.some((prefix) => key.startsWith(prefix))) {
      states.delete(key);
    }
  }
};

export const getRequestCoordinatorState = () =>
  Array.from(states.entries()).map(([key, state]) => ({
    key,
    hasLastGood: Boolean(state.lastGood?.success),
    cooldownUntil: state.cooldownUntil,
    rateLimitHits: state.rateLimitHits,
    inFlight: Boolean(state.inFlight),
  }));

if (typeof window !== "undefined") {
  window.addEventListener("auth:logout", () => clearRequestCoordinator());
}

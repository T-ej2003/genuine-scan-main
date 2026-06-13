import { type ApiResponse } from "@/lib/api/internal-client-core";

export type ControlledPrinterGetOptions = {
  force?: boolean;
  minIntervalMs?: number;
};

type PrinterRefreshMeta = {
  refreshPaused?: boolean;
  rateLimited?: boolean;
  retryAfterSec?: number;
  notice?: string;
};

type PrinterGetCacheState = {
  data: unknown;
  fetchedAt: number;
  cooldownUntil: number;
  inFlight: Promise<ApiResponse<unknown>> | null;
  rateLimitHits: number;
};

type PrinterMutationState = {
  inFlight: Promise<ApiResponse<unknown>> | null;
};

export const PRINTER_STATUS_MIN_REFRESH_MS = 45_000;
export const PRINTER_LIST_MIN_REFRESH_MS = 60_000;
export const PRINTER_HEARTBEAT_MIN_REFRESH_MS = 90_000;

const PRINTER_RATE_LIMIT_FALLBACK_MS = 10_000;
const PRINTER_RATE_LIMIT_NOTICE =
  "Printer status refresh is temporarily paused. Printing can continue if the printer was already ready.";

const printerGetCache = new Map<string, PrinterGetCacheState>();
const printerMutationCache = new Map<string, PrinterMutationState>();

const isRateLimitedResponse = (response: ApiResponse<unknown>) =>
  response.status === 429 ||
  String(response.code || "").trim().toUpperCase() === "RATE_LIMITED" ||
  String(response.code || "").trim().toLowerCase() === "rate_limited";

const getRetryAfterMs = (response: ApiResponse<unknown>, hits: number) => {
  const fromResponse = Number(response.retryAfterSec || 0);
  if (Number.isFinite(fromResponse) && fromResponse > 0) {
    return Math.min(60_000, Math.ceil(fromResponse * 1000));
  }

  if (hits <= 1) return PRINTER_RATE_LIMIT_FALLBACK_MS;
  if (hits === 2) return 20_000;
  if (hits === 3) return 30_000;
  return 60_000;
};

const withPrinterRefreshMeta = <T>(data: T, response: ApiResponse<unknown>): T & PrinterRefreshMeta => {
  if (!data || typeof data !== "object") return data as T & PrinterRefreshMeta;
  return {
    ...(data as Record<string, unknown>),
    refreshPaused: true,
    rateLimited: true,
    retryAfterSec: response.retryAfterSec,
    notice: PRINTER_RATE_LIMIT_NOTICE,
  } as T & PrinterRefreshMeta;
};

export const controlledPrinterGet = async <T>(
  cacheKey: string,
  minIntervalMs: number,
  request: () => Promise<ApiResponse<T>>,
  options?: ControlledPrinterGetOptions
): Promise<ApiResponse<T>> => {
  const now = Date.now();
  const state =
    printerGetCache.get(cacheKey) ||
    {
      data: undefined,
      fetchedAt: 0,
      cooldownUntil: 0,
      inFlight: null,
      rateLimitHits: 0,
    };
  printerGetCache.set(cacheKey, state);

  const fresh = state.data !== undefined && now - state.fetchedAt < (options?.minIntervalMs ?? minIntervalMs);
  const coolingDown = state.data !== undefined && now < state.cooldownUntil;

  if ((!options?.force && fresh) || coolingDown) {
    const data = coolingDown
      ? withPrinterRefreshMeta(state.data as T, {
          success: false,
          status: 429,
          code: "RATE_LIMITED",
          retryAfterSec: Math.ceil((state.cooldownUntil - now) / 1000),
        })
      : (state.data as T);
    return { success: true, data };
  }

  if (state.inFlight) return state.inFlight as Promise<ApiResponse<T>>;

  state.inFlight = request()
    .then((response) => {
      if (response.success && response.data !== undefined) {
        state.data = response.data;
        state.fetchedAt = Date.now();
        state.cooldownUntil = 0;
        state.rateLimitHits = 0;
        return response;
      }

      if (isRateLimitedResponse(response)) {
        state.rateLimitHits += 1;
        state.cooldownUntil = Date.now() + getRetryAfterMs(response, state.rateLimitHits);
        if (state.data !== undefined) {
          return {
            success: true,
            data: withPrinterRefreshMeta(state.data as T, response),
            status: response.status,
            code: response.code,
            retryAfterSec: response.retryAfterSec,
          } satisfies ApiResponse<T>;
        }
      }

      return response;
    })
    .finally(() => {
      state.inFlight = null;
    }) as Promise<ApiResponse<unknown>>;

  return state.inFlight as Promise<ApiResponse<T>>;
};

export const controlledPrinterMutation = async <T>(
  actionKey: string,
  request: () => Promise<ApiResponse<T>>
): Promise<ApiResponse<T>> => {
  const cacheKey = String(actionKey || "").trim();
  if (!cacheKey) return request();

  const state = printerMutationCache.get(cacheKey) || { inFlight: null };
  printerMutationCache.set(cacheKey, state);

  if (state.inFlight) return state.inFlight as Promise<ApiResponse<T>>;

  state.inFlight = request()
    .finally(() => {
      state.inFlight = null;
      printerMutationCache.delete(cacheKey);
    }) as Promise<ApiResponse<unknown>>;

  return state.inFlight as Promise<ApiResponse<T>>;
};

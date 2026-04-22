import { emitMutationEvent } from "@/lib/mutation-events";
import { recordSupportNetworkLog, reportSupportRuntimeIssue } from "@/lib/support-diagnostics";

export const BASE_URL = import.meta.env.VITE_API_URL || "/api";

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  degraded?: boolean;
  code?: string;
}

type RequestOptions = RequestInit & {
  skipJson?: boolean;
  timeoutMs?: number;
  skipAuthRefresh?: boolean;
  suppressMutationEvent?: boolean;
};

const stripHtmlError = (value: string) =>
  value
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();

const normalizeErrorMessage = (status: number, payload: unknown) => {
  if (payload && typeof payload === "object") {
    const message = String((payload as any).error || (payload as any).message || "").trim();
    if (message) return message;
  }

  const raw = typeof payload === "string" ? payload.trim() : "";
  if (status === 413) return "Upload too large. Please retry with a smaller attachment.";
  if (!raw) return `HTTP ${status}`;

  const cleaned = stripHtmlError(raw);
  return cleaned || `HTTP ${status}`;
};

export type ApiClientCore = {
  setToken(token: string | null): void;
  getToken(): string | null;
  logout(): void;
  request<T>(endpoint: string, options?: RequestOptions): Promise<ApiResponse<T>>;
};

export function createApiClientCore(): ApiClientCore {
  let token: string | null = null;
  const getCache = new Map<string, unknown>();
  let refreshInFlight: Promise<ApiResponse<{ user: any }>> | null = null;

  const setToken = (nextToken: string | null) => {
    token = nextToken;
  };

  const getToken = () => token;

  const logout = () => {
    setToken(null);
    getCache.clear();
  };

  const emitLogout = () => {
    window.dispatchEvent(new Event("auth:logout"));
  };

  const emitStepUpRequired = (detail: {
    endpoint: string;
    method: string;
    stepUpMethod?: "ADMIN_MFA" | "PASSWORD_REAUTH" | null;
    message?: string;
  }) => {
    window.dispatchEvent(new CustomEvent("auth:step-up-required", { detail }));
  };

  const readCookie = (name: string) => {
    try {
      const match = document.cookie
        .split(";")
        .map((c) => c.trim())
        .find((c) => c.startsWith(`${name}=`));
      if (!match) return "";
      return decodeURIComponent(match.split("=").slice(1).join("="));
    } catch {
      return "";
    }
  };

  const readCsrfCookieForEndpoint = (endpoint: string) => {
    const preferVerifyCookie = endpoint.startsWith("/verify/");
    const candidates = preferVerifyCookie
      ? ["mscqr_verify_csrf", "aq_csrf"]
      : ["aq_csrf", "mscqr_verify_csrf"];

    for (const candidate of candidates) {
      const value = readCookie(candidate);
      if (value) return value;
    }
    return "";
  };

  const hasCookieBackedSession = () => Boolean(readCookie("aq_access") || readCookie("aq_refresh") || readCookie("mscqr_verify_session"));

  const isAuthRefreshEndpoint = (endpoint: string) =>
    endpoint === "/auth/login" ||
    endpoint === "/auth/refresh" ||
    endpoint === "/auth/logout" ||
    endpoint === "/auth/accept-invite" ||
    endpoint.startsWith("/auth/mfa/");

  const request = async <T>(endpoint: string, options: RequestOptions = {}): Promise<ApiResponse<T>> => {
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };

    const method = String(options.method || "GET").toUpperCase();
    const cacheKey = `${getToken() || "cookie"}:${endpoint}`;

    const hasBody = options.body !== undefined && options.body !== null;
    const isForm = typeof FormData !== "undefined" && options.body instanceof FormData;

    if (!options.skipJson && hasBody && !isForm) {
      headers["Content-Type"] = "application/json";
    }
    const hasAuthorizationHeader = Object.keys(headers).some((key) => key.toLowerCase() === "authorization");
    if (getToken() && !hasAuthorizationHeader) headers["Authorization"] = `Bearer ${getToken()}`;

    const isStateChanging = !["GET", "HEAD", "OPTIONS"].includes(method);
    if (isStateChanging) {
      const hasIdempotencyHeader = Object.keys(headers).some((key) => key.toLowerCase() === "x-idempotency-key");
      if (!hasIdempotencyHeader) {
        const generatedKey =
          typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
            ? crypto.randomUUID()
            : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
        headers["x-idempotency-key"] = generatedKey;
      }

      const csrf = readCsrfCookieForEndpoint(endpoint);
      if (csrf && !headers["x-csrf-token"] && !headers["X-CSRF-Token"]) {
        headers["x-csrf-token"] = csrf;
      }
    }

    const controller = new AbortController();
    const timeoutMs = options.timeoutMs ?? 20_000;
    const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
    const startedAt = typeof performance !== "undefined" ? performance.now() : Date.now();

    const elapsedMs = () => {
      const now = typeof performance !== "undefined" ? performance.now() : Date.now();
      return Math.max(1, Math.round(now - startedAt));
    };

    const pushNetworkLog = (entry: { status: number | null; ok: boolean; error?: string }) => {
      recordSupportNetworkLog({
        method,
        endpoint,
        status: entry.status,
        ok: entry.ok,
        durationMs: elapsedMs(),
        error: entry.error,
      });
    };

    const refreshOnce = async () => {
      if (refreshInFlight) return refreshInFlight;
      refreshInFlight = request<{ user: any }>("/auth/refresh", {
        method: "POST",
        skipAuthRefresh: true,
      }).finally(() => {
        refreshInFlight = null;
      });
      return refreshInFlight;
    };

    try {
      const response = await fetch(`${BASE_URL}${endpoint}`, {
        ...options,
        headers,
        cache: "no-store",
        credentials: "include",
        signal: controller.signal,
      });

      if (response.status === 304 && method === "GET") {
        pushNetworkLog({ status: response.status, ok: true });
        const cached = getCache.get(cacheKey);
        if (cached !== undefined) return { success: true, data: cached as T };
        return { success: false, error: "Stale cache miss (HTTP 304)" };
      }

      const contentType = response.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");

      const payload: any = isJson
        ? await response.json().catch((): null => null)
        : await response.text().catch((): string => "");

      if (response.status === 401 && !options.skipAuthRefresh && !isAuthRefreshEndpoint(endpoint)) {
        const message =
          (payload && typeof payload === "object" && (payload.error || payload.message)) ||
          (typeof payload === "string" && payload) ||
          "Not authenticated";

        if (!getToken() && !hasCookieBackedSession()) {
          pushNetworkLog({ status: response.status, ok: false, error: message });
          return { success: false, error: message };
        }

        const refreshed = await refreshOnce();
        if (refreshed.success) {
          return request<T>(endpoint, { ...options, skipAuthRefresh: true });
        }

        logout();
        emitLogout();
        pushNetworkLog({ status: response.status, ok: false, error: message });
        return { success: false, error: message };
      }

      if (!response.ok) {
        const message = normalizeErrorMessage(response.status, payload);
        pushNetworkLog({ status: response.status, ok: false, error: message });
        const responseCode =
          payload && typeof payload === "object" && typeof (payload as any).code === "string"
            ? String((payload as any).code)
            : undefined;
        const responseData =
          payload && typeof payload === "object" && "data" in payload ? (payload as any).data : undefined;
        if (response.status === 428 && responseCode === "STEP_UP_REQUIRED") {
          emitStepUpRequired({
            endpoint,
            method,
            stepUpMethod:
              responseData && typeof responseData === "object" && typeof (responseData as any).stepUpMethod === "string"
                ? ((responseData as any).stepUpMethod as "ADMIN_MFA" | "PASSWORD_REAUTH")
                : null,
            message,
          });
        }
        if (response.status >= 500) {
          reportSupportRuntimeIssue({
            source: "network",
            message: `Server error (${response.status}) on ${method} ${endpoint}`,
          });
        }
        return {
          success: false,
          error: message,
          code: responseCode,
          data: responseData,
        };
      }

      pushNetworkLog({ status: response.status, ok: true });

      if (payload && typeof payload === "object" && "success" in payload) {
        if (method === "GET" && payload.success) {
          getCache.set(cacheKey, (payload as ApiResponse<T>).data as T);
        }
        if (method !== "GET" && method !== "HEAD" && payload.success && !options.suppressMutationEvent) {
          emitMutationEvent({ endpoint, method });
        }
        return payload as ApiResponse<T>;
      }

      if (method === "GET") {
        getCache.set(cacheKey, payload as T);
      }

      if (method !== "GET" && method !== "HEAD" && !options.suppressMutationEvent) {
        emitMutationEvent({ endpoint, method });
      }
      return { success: true, data: payload as T };
    } catch (error: any) {
      const isAbort = error?.name === "AbortError";
      const message = isAbort ? "Request timed out" : "Network error - is the backend running?";
      pushNetworkLog({ status: null, ok: false, error: message });
      reportSupportRuntimeIssue({
        source: "network",
        message: `${method} ${endpoint}: ${message}`,
      });
      return { success: false, error: message };
    } finally {
      window.clearTimeout(timeout);
    }
  };

  return {
    setToken,
    getToken,
    logout,
    request,
  };
}

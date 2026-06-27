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
  errorCode?: string;
  status?: number;
  retryAfterSec?: number;
  unknownOutcome?: boolean;
  requestId?: string;
}

type RequestOptions = RequestInit & {
  skipJson?: boolean;
  timeoutMs?: number;
  skipAuthRefresh?: boolean;
  suppressMutationEvent?: boolean;
};

const SESSION_EXPIRED_MESSAGE = "Your session has expired. Please sign in again.";

const friendlyUnauthenticatedMessage = (message?: string | null) => {
  const normalized = String(message || "").trim();
  if (!normalized) return SESSION_EXPIRED_MESSAGE;
  if (/no token provided|no refresh token|not authenticated|unauthorized/i.test(normalized)) {
    return SESSION_EXPIRED_MESSAGE;
  }
  return normalized;
};

const extractAccessToken = (payload: unknown) => {
  if (!payload || typeof payload !== "object") return "";
  const value =
    (payload as { accessToken?: unknown }).accessToken ??
    (payload as { token?: unknown }).token ??
    ((payload as { auth?: { accessToken?: unknown; token?: unknown } }).auth?.accessToken ||
      (payload as { auth?: { token?: unknown } }).auth?.token);
  return typeof value === "string" && value.trim() ? value.trim() : "";
};

const stripHtmlError = (value: string) =>
  normalizeWhitespace(
    extractPlainTextFromHtml(value) ||
      decodeKnownHtmlEntities(String(value || ""))
  );

const normalizeWhitespace = (value: string) => {
  let result = "";
  let pendingSpace = false;

  for (const character of String(value || "")) {
    const isWhitespace = character === " " || character === "\n" || character === "\r" || character === "\t" || character === "\f";
    if (isWhitespace) {
      pendingSpace = result.length > 0;
      continue;
    }

    if (pendingSpace) result += " ";
    result += character;
    pendingSpace = false;
  }

  return result.trim();
};

const decodeKnownHtmlEntities = (value: string) => {
  const entityMap: Record<string, string> = {
    nbsp: " ",
    amp: "&",
    lt: "<",
    gt: ">",
    quot: '"',
    apos: "'",
  };

  let result = "";
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character !== "&") {
      result += character;
      continue;
    }

    const endIndex = value.indexOf(";", index + 1);
    if (endIndex === -1 || endIndex - index > 12) {
      result += character;
      continue;
    }

    const entity = value.slice(index + 1, endIndex);
    if (entityMap[entity]) {
      result += entityMap[entity];
      index = endIndex;
      continue;
    }

    if (entity.startsWith("#")) {
      const radix = entity[1]?.toLowerCase() === "x" ? 16 : 10;
      const numeric = entity[1]?.toLowerCase() === "x" ? entity.slice(2) : entity.slice(1);
      const codePoint = Number.parseInt(numeric, radix);
      if (Number.isFinite(codePoint) && codePoint > 0) {
        result += String.fromCodePoint(codePoint);
        index = endIndex;
        continue;
      }
    }

    result += character;
  }

  return result;
};

const readTagNameFromMarkup = (rawTag: string, isClosing: boolean) => {
  const source = isClosing ? rawTag.slice(1) : rawTag;
  let tagName = "";
  for (const character of source) {
    const isTagCharacter =
      (character >= "a" && character <= "z") ||
      (character >= "A" && character <= "Z") ||
      (character >= "0" && character <= "9") ||
      character === ":" ||
      character === "-" ||
      character === "_";

    if (!isTagCharacter) break;
    tagName += character.toLowerCase();
  }
  return tagName;
};

const extractPlainTextFromHtmlWithDom = (value: string) => {
  if (typeof DOMParser === "undefined") return "";
  try {
    const document = new DOMParser().parseFromString(value, "text/html");
    for (const element of Array.from(document.querySelectorAll("script, style"))) {
      element.remove();
    }
    return document.body?.textContent || document.documentElement?.textContent || "";
  } catch {
    return "";
  }
};

const extractPlainTextFromHtmlLinear = (value: string) => {
  const blockTags = new Set(["br", "p", "div", "li", "tr", "section", "article", "header", "footer"]);
  let result = "";
  let pendingSpace = false;
  let ignoredTag: string | null = null;

  const appendCharacter = (character: string) => {
    const isWhitespace = character === " " || character === "\n" || character === "\r" || character === "\t" || character === "\f";
    if (isWhitespace) {
      pendingSpace = result.length > 0;
      return;
    }
    if (pendingSpace) result += " ";
    result += character;
    pendingSpace = false;
  };

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];

    if (ignoredTag) {
      if (character !== "<") continue;
      const tagEnd = value.indexOf(">", index + 1);
      if (tagEnd === -1) break;
      const rawTag = value.slice(index + 1, tagEnd).trim();
      const isClosing = rawTag.startsWith("/");
      const tagName = readTagNameFromMarkup(rawTag, isClosing);
      if (isClosing && tagName === ignoredTag) {
        ignoredTag = null;
      }
      index = tagEnd;
      continue;
    }

    if (character === "<") {
      const tagEnd = value.indexOf(">", index + 1);
      if (tagEnd === -1) break;
      const rawTag = value.slice(index + 1, tagEnd).trim();
      const isClosing = rawTag.startsWith("/");
      const tagName = readTagNameFromMarkup(rawTag, isClosing);
      if (!isClosing && (tagName === "script" || tagName === "style")) {
        ignoredTag = tagName;
      }
      if (blockTags.has(tagName)) {
        pendingSpace = result.length > 0;
      }
      index = tagEnd;
      continue;
    }

    if (character === "&") {
      const endIndex = value.indexOf(";", index + 1);
      if (endIndex !== -1 && endIndex - index <= 12) {
        const decoded = decodeKnownHtmlEntities(value.slice(index, endIndex + 1));
        if (decoded !== value.slice(index, endIndex + 1)) {
          for (const decodedCharacter of decoded) appendCharacter(decodedCharacter);
          index = endIndex;
          continue;
        }
      }
    }

    appendCharacter(character);
  }

  return result;
};

const extractPlainTextFromHtml = (value: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) return "";

  const linearText = extractPlainTextFromHtmlLinear(normalized);
  if (linearText) return linearText;

  return extractPlainTextFromHtmlWithDom(normalized);
};

const isPublicScanOrVerifyEndpoint = (endpoint?: string) =>
  Boolean(endpoint && (endpoint.startsWith("/scan") || endpoint.startsWith("/verify")));

const publicScanOrVerifyFallback = (status: number) => {
  if (status === 400) return "This scan link is invalid or expired. Please scan the label again.";
  if (status === 404) return "This label could not be found in the MSCQR registry.";
  if (status === 410) return "This label is no longer active. Please contact the brand for support.";
  if (status === 429) return "Too many verification attempts. Please wait a moment and try again.";
  if (status >= 500) return "We could not verify this label right now. Please try again shortly.";
  return "We could not verify this label. Please check the code and try again.";
};

const looksLikeTechnicalPublicError = (message: string) =>
  /^HTTP\s+\d{3}$/i.test(message) ||
  /^Cannot\s+(GET|POST|PUT|PATCH|DELETE)\s+/i.test(message) ||
  /<!doctype html|<html/i.test(message);

const normalizeErrorMessage = (status: number, payload: unknown, endpoint?: string) => {
  if (payload && typeof payload === "object") {
    const message = String((payload as any).error || (payload as any).message || "").trim();
    if (message) return message;
  }

  const raw = typeof payload === "string" ? payload.trim() : "";
  if (status === 413) return "Upload too large. Please retry with a smaller attachment.";
  if (!raw) return isPublicScanOrVerifyEndpoint(endpoint) ? publicScanOrVerifyFallback(status) : `HTTP ${status}`;

  const cleaned = stripHtmlError(raw);
  if (isPublicScanOrVerifyEndpoint(endpoint) && (!cleaned || looksLikeTechnicalPublicError(cleaned))) {
    return publicScanOrVerifyFallback(status);
  }
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
  const endpointCooldowns = new Map<string, { until: number; hits: number }>();
  let refreshInFlight: Promise<ApiResponse<{ user: any; auth?: any; accessToken?: string }>> | null = null;

  const normalizeCooldownEndpoint = (endpoint: string) => {
    const [path, rawQuery = ""] = String(endpoint || "").split("?");
    const normalizedPath = path
      .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/gi, ":id")
      .replace(/\/[A-Za-z0-9_-]{16,}(?=\/|$)/g, "/:id");
    if (normalizedPath === "/manufacturer/printers" && rawQuery.includes("includeInactive=true")) {
      return "/manufacturer/printers?includeInactive";
    }
    if (normalizedPath === "/qr/stats") return "/qr/stats";
    if (normalizedPath === "/qr/batches") return "/qr/batches";
    if (normalizedPath === "/dashboard/stats") return "/dashboard/stats";
    if (normalizedPath === "/dashboard/attention-queue") return "/dashboard/attention-queue";
    if (normalizedPath === "/notifications") return "/notifications";
    if (normalizedPath === "/auth/me") return "/auth/me";
    return normalizedPath;
  };

  const parseRetryAfterSeconds = (value: string | null) => {
    const numeric = Number(value || "");
    if (Number.isFinite(numeric) && numeric > 0) return numeric;
    const timestamp = Date.parse(String(value || ""));
    if (Number.isFinite(timestamp)) return Math.max(1, Math.ceil((timestamp - Date.now()) / 1000));
    return undefined;
  };

  const nextFallbackBackoffSeconds = (hits: number) => {
    if (hits <= 1) return 10;
    if (hits === 2) return 20;
    if (hits === 3) return 30;
    return 60;
  };

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
    const cooldownKey = `${method}:${normalizeCooldownEndpoint(endpoint)}`;
    const cooldown = endpointCooldowns.get(cooldownKey);
    if (cooldown && Date.now() < cooldown.until) {
      return {
        success: false,
        error: "Request paused after rate limit. Please wait before retrying.",
        status: 429,
        code: "RATE_LIMITED",
        errorCode: "RATE_LIMITED",
        retryAfterSec: Math.ceil((cooldown.until - Date.now()) / 1000),
      };
    }

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
      refreshInFlight = request<{ user: any; auth?: any; accessToken?: string }>("/auth/refresh", {
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
      const requestId = response.headers.get("x-request-id") || response.headers.get("x-correlation-id") || undefined;

      if (response.status === 304 && method === "GET") {
        pushNetworkLog({ status: response.status, ok: true });
        const cached = getCache.get(cacheKey);
        if (cached !== undefined) return { success: true, data: cached as T, requestId };
        return { success: false, error: "Stale cache miss (HTTP 304)", requestId };
      }

      const contentType = response.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");

      const payload: any = isJson
        ? await response.json().catch((): null => null)
        : await response.text().catch((): string => "");

      if (response.status === 401 && !options.skipAuthRefresh && !isAuthRefreshEndpoint(endpoint)) {
        const rawMessage =
          (payload && typeof payload === "object" && (payload.error || payload.message)) ||
          (typeof payload === "string" && payload) ||
          "Not authenticated";
        const message = friendlyUnauthenticatedMessage(rawMessage);

        setToken(null);
        const refreshed = await refreshOnce();
        if (refreshed.success) {
          const nextToken = extractAccessToken(refreshed.data);
          if (nextToken) setToken(nextToken);
          return request<T>(endpoint, { ...options, skipAuthRefresh: true });
        }

        logout();
        emitLogout();
        pushNetworkLog({ status: response.status, ok: false, error: message });
        return { success: false, error: message, status: response.status, code: "UNAUTHENTICATED", requestId };
      }

      if (!response.ok) {
        const message = normalizeErrorMessage(response.status, payload, endpoint);
        pushNetworkLog({ status: response.status, ok: false, error: message });
        const responseCode =
          payload && typeof payload === "object" && typeof (payload as any).code === "string"
            ? String((payload as any).code)
            : payload && typeof payload === "object" && typeof (payload as any).errorCode === "string"
              ? String((payload as any).errorCode)
            : undefined;
        const retryAfterHeader = parseRetryAfterSeconds(response.headers.get("retry-after"));
        const retryAfterPayload =
          payload && typeof payload === "object" && "retryAfterSec" in payload
            ? Number((payload as any).retryAfterSec)
            : payload && typeof payload === "object" && "retryAfterSeconds" in payload
              ? Number((payload as any).retryAfterSeconds)
            : NaN;
        const retryAfterSec =
          Number.isFinite(retryAfterPayload) && retryAfterPayload > 0
            ? retryAfterPayload
            : Number.isFinite(retryAfterHeader) && Number(retryAfterHeader) > 0
              ? retryAfterHeader
              : undefined;
        if (response.status === 429) {
          const previousHits = endpointCooldowns.get(cooldownKey)?.hits || 0;
          const hits = previousHits + 1;
          const seconds = retryAfterSec || nextFallbackBackoffSeconds(hits);
          endpointCooldowns.set(cooldownKey, { until: Date.now() + Math.max(1, seconds) * 1000, hits });
        }
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
          errorCode: responseCode,
          status: response.status,
          retryAfterSec,
          data: responseData,
          requestId,
        };
      }

      pushNetworkLog({ status: response.status, ok: true });
      endpointCooldowns.delete(cooldownKey);

      if (payload && typeof payload === "object" && "success" in payload) {
        if (method === "GET" && payload.success) {
          getCache.set(cacheKey, (payload as ApiResponse<T>).data as T);
        }
        if (method !== "GET" && method !== "HEAD" && payload.success && !options.suppressMutationEvent) {
          emitMutationEvent({ endpoint, method });
        }
        return { ...(payload as ApiResponse<T>), status: response.status, requestId };
      }

      if (method === "GET") {
        getCache.set(cacheKey, payload as T);
      }

      if (method !== "GET" && method !== "HEAD" && !options.suppressMutationEvent) {
        emitMutationEvent({ endpoint, method });
      }
      return { success: true, data: payload as T, status: response.status, requestId };
    } catch (error: any) {
      const isAbort = error?.name === "AbortError";
      const message = isAbort ? "Request timed out" : "Network error - is the backend running?";
      pushNetworkLog({ status: null, ok: false, error: message });
      reportSupportRuntimeIssue({
        source: "network",
        message: `${method} ${endpoint}: ${message}`,
      });
      return {
        success: false,
        error: message,
        status: 0,
        code: isAbort ? "REQUEST_TIMEOUT" : "NETWORK_ERROR",
        unknownOutcome: isAbort && isStateChanging,
      };
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

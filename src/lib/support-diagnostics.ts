import { frontendRelease } from "@/lib/observability/release";

export type SupportNetworkLog = {
  id: string;
  at: string;
  method: string;
  endpoint: string;
  status: number | null;
  ok: boolean;
  durationMs: number;
  error?: string;
};

export type SupportRuntimeIssue = {
  id: string;
  at: string;
  message: string;
  stack?: string;
  source: "runtime" | "network";
};

const MAX_NETWORK_LOGS = 60;
const MAX_RUNTIME_ISSUES = 40;
const DIAGNOSTIC_NETWORK_LOG_LIMIT = 20;
const DIAGNOSTIC_RUNTIME_ISSUE_LIMIT = 10;
const MAX_DIAGNOSTIC_STRING_LENGTH = 1200;
const MAX_DIAGNOSTIC_STACK_LENGTH = 3000;
export const SUPPORT_DIAGNOSTICS_MAX_JSON_BYTES = 120 * 1024;
const SUPPORT_SCREENSHOT_TARGET_MIME = "image/jpeg";
export const SUPPORT_SCREENSHOT_MAX_BYTES = 550 * 1024;
const SUPPORT_SCREENSHOT_MAX_DIMENSION = 1280;
const SUPPORT_SCREENSHOT_QUALITY_STEPS = [0.78, 0.7, 0.62, 0.54];
const SUPPORT_SCREENSHOT_RESIZE_FACTOR = 0.82;
const SUPPORT_SCREENSHOT_RESIZE_ATTEMPTS = 4;
const SUPPORT_GENERIC_SUBMISSION_ERROR =
  "We could not submit the report right now. Please try again or contact support.";
const SUPPORT_AUTH_SUBMISSION_ERROR =
  "Your session is not authorised for this action. Please refresh and sign in again.";
const SUPPORT_RATE_LIMIT_SUBMISSION_ERROR = "Too many reports. Please wait and try again.";
const SUPPORT_TOO_LARGE_SUBMISSION_ERROR =
  "The attached screenshot or diagnostics were too large to upload. Please try again.";
const SENSITIVE_PARAM_RE =
  /(token|secret|password|pass|session|cookie|csrf|xsrf|jwt|bearer|authorization|auth|invite|otp|mfa|code|proof|signature|signed|key)/i;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{10,}/gi;
const COOKIE_RE = /\b(cookie|set-cookie|authorization|x-csrf-token|x-xsrf-token)\s*[:=]\s*[^;\s]+/gi;

const networkLogs: SupportNetworkLog[] = [];
const runtimeIssues: SupportRuntimeIssue[] = [];
const listeners = new Set<(issue: SupportRuntimeIssue) => void>();

const nextId = () =>
  `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;

const pushBounded = <T,>(arr: T[], value: T, max: number) => {
  arr.push(value);
  if (arr.length > max) arr.splice(0, arr.length - max);
};

const truncateDiagnosticString = (value: string, max = MAX_DIAGNOSTIC_STRING_LENGTH) =>
  value.length > max ? `${value.slice(0, max - 3).trimEnd()}...` : value;

const redactSensitiveText = (value: unknown, max = MAX_DIAGNOSTIC_STRING_LENGTH) => {
  const text = String(value || "");
  return truncateDiagnosticString(
    text
      .replace(BEARER_RE, "Bearer [redacted]")
      .replace(JWT_RE, "[redacted-jwt]")
      .replace(COOKIE_RE, "$1=[redacted]")
      .replace(/([?&][^=]*(?:token|secret|password|session|csrf|jwt|invite|otp|mfa|code|proof|signature|key)[^=]*=)[^&#\s]+/gi, "$1[redacted]")
      .replace(/\b([A-Za-z0-9_-]*(?:token|secret|password|session|csrf|jwt|invite|otp|mfa|proof|signature|key)[A-Za-z0-9_-]*=)[^&;\s]+/gi, "$1[redacted]"),
    max
  );
};

const getUrlBase = () => (typeof window !== "undefined" ? window.location.origin : "https://mscqr.local");

export const sanitizeSupportUrl = (value: unknown, includeOrigin = false) => {
  const text = String(value || "").trim();
  if (!text) return "";

  try {
    const url = new URL(text, getUrlBase());
    const params = new URLSearchParams();
    url.searchParams.forEach((paramValue, key) => {
      params.set(key, SENSITIVE_PARAM_RE.test(key) ? "[redacted]" : redactSensitiveText(paramValue, 160));
    });
    const search = params.toString();
    const origin = includeOrigin ? url.origin : "";
    const hash = url.hash ? "#[redacted]" : "";
    return truncateDiagnosticString(`${origin}${url.pathname}${search ? `?${search}` : ""}${hash}`, 1000);
  } catch {
    return redactSensitiveText(text, 1000);
  }
};

export const getSanitizedSupportSourcePath = () => {
  if (typeof window === "undefined") return "";
  return sanitizeSupportUrl(`${window.location.pathname}${window.location.search}`, false);
};

export const getSanitizedSupportPageUrl = () => {
  if (typeof window === "undefined") return "";
  return sanitizeSupportUrl(window.location.href, true);
};

export const recordSupportNetworkLog = (entry: Omit<SupportNetworkLog, "id" | "at">) => {
  pushBounded(
    networkLogs,
    {
      id: nextId(),
      at: new Date().toISOString(),
      ...entry,
      endpoint: sanitizeSupportUrl(entry.endpoint, false),
      error: entry.error ? redactSensitiveText(entry.error, 800) : undefined,
    },
    MAX_NETWORK_LOGS
  );
};

export const reportSupportRuntimeIssue = (entry: Omit<SupportRuntimeIssue, "id" | "at">) => {
  const issue: SupportRuntimeIssue = {
    id: nextId(),
    at: new Date().toISOString(),
    source: entry.source,
    message: redactSensitiveText(entry.message, MAX_DIAGNOSTIC_STRING_LENGTH),
    stack: entry.stack ? redactSensitiveText(entry.stack, MAX_DIAGNOSTIC_STACK_LENGTH) : undefined,
  };
  pushBounded(runtimeIssues, issue, MAX_RUNTIME_ISSUES);
  listeners.forEach((listener) => {
    try {
      listener(issue);
    } catch {
      // no-op
    }
  });
};

export const onSupportIssue = (listener: (issue: SupportRuntimeIssue) => void) => {
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const getSupportNetworkLogs = () => networkLogs.slice();
export const getSupportRuntimeIssues = () => runtimeIssues.slice();

export const getSupportEnvironmentSnapshot = () => {
  const nav = typeof navigator !== "undefined" ? navigator : ({} as Navigator);
  const connection = (nav as any).connection || {};
  return {
    url: getSanitizedSupportPageUrl(),
    path: getSanitizedSupportSourcePath(),
    userAgent: redactSensitiveText(nav.userAgent || "", 500),
    language: nav.language || "",
    platform: nav.platform || "",
    online: typeof nav.onLine === "boolean" ? nav.onLine : true,
    viewport:
      typeof window !== "undefined"
        ? { width: window.innerWidth, height: window.innerHeight, pixelRatio: window.devicePixelRatio || 1 }
        : null,
    timezone:
      typeof Intl !== "undefined" ? Intl.DateTimeFormat().resolvedOptions().timeZone : undefined,
    connection: {
      effectiveType: connection.effectiveType || null,
      downlink: connection.downlink || null,
      rtt: connection.rtt || null,
    },
  };
};

const sanitizeNetworkLogs = () =>
  getSupportNetworkLogs()
    .slice(-DIAGNOSTIC_NETWORK_LOG_LIMIT)
    .map((entry) => ({
      ...entry,
      endpoint: sanitizeSupportUrl(entry.endpoint, false),
      error: entry.error ? redactSensitiveText(entry.error, 800) : undefined,
    }));

const sanitizeRuntimeIssues = () =>
  getSupportRuntimeIssues()
    .slice(-DIAGNOSTIC_RUNTIME_ISSUE_LIMIT)
    .map((issue) => ({
      ...issue,
      message: redactSensitiveText(issue.message, MAX_DIAGNOSTIC_STRING_LENGTH),
      stack: issue.stack ? redactSensitiveText(issue.stack, MAX_DIAGNOSTIC_STACK_LENGTH) : undefined,
    }));

export const buildSupportDiagnosticsPayload = () => ({
  release: frontendRelease,
  environment: getSupportEnvironmentSnapshot(),
  networkLogs: sanitizeNetworkLogs(),
  runtimeIssues: sanitizeRuntimeIssues(),
  privacy: {
    redacted: true,
    networkLogLimit: DIAGNOSTIC_NETWORK_LOG_LIMIT,
    runtimeIssueLimit: DIAGNOSTIC_RUNTIME_ISSUE_LIMIT,
  },
});

export const serializeSupportDiagnosticsPayload = (payload: Record<string, unknown>) => {
  const serialized = JSON.stringify(payload);
  if (serialized.length <= SUPPORT_DIAGNOSTICS_MAX_JSON_BYTES) return serialized;

  const compact = {
    release: payload.release,
    environment: payload.environment,
    privacy: {
      redacted: true,
      truncated: true,
      maxBytes: SUPPORT_DIAGNOSTICS_MAX_JSON_BYTES,
    },
  };
  return JSON.stringify(compact);
};

const stripMarkup = (value: string) =>
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

export const formatSupportIssueSubmissionError = (
  raw: string | null | undefined,
  context: { status?: number | null; code?: string | null; unknownOutcome?: boolean } = {}
) => {
  if (context.status === 0 || context.unknownOutcome) return SUPPORT_GENERIC_SUBMISSION_ERROR;

  const text = stripMarkup(String(raw || ""));
  const lowered = text.toLowerCase();
  if (lowered.includes("413 request entity too large") || lowered.includes("payload too large")) {
    return SUPPORT_TOO_LARGE_SUBMISSION_ERROR;
  }
  if (
    lowered.includes("request could not be satisfied") ||
    lowered.includes("request blocked") ||
    lowered.includes("cloudfront") ||
    lowered.startsWith("error:")
  ) {
    return SUPPORT_GENERIC_SUBMISSION_ERROR;
  }
  if (context.status === 401 || context.status === 403) return SUPPORT_AUTH_SUBMISSION_ERROR;
  if (context.status === 429) return SUPPORT_RATE_LIMIT_SUBMISSION_ERROR;
  if (context.status === 413) return SUPPORT_TOO_LARGE_SUBMISSION_ERROR;
  if (!text) return SUPPORT_GENERIC_SUBMISSION_ERROR;
  if (text.length > 220) return `${text.slice(0, 217).trimEnd()}...`;
  return text;
};

const canvasToBlob = (canvas: HTMLCanvasElement, type: string, quality?: number) =>
  new Promise<Blob | null>((resolve) => {
    canvas.toBlob((value) => resolve(value), type, quality);
  });

const drawScaledCanvas = (source: HTMLCanvasElement, scale: number) => {
  const next = document.createElement("canvas");
  next.width = Math.max(1, Math.round(source.width * scale));
  next.height = Math.max(1, Math.round(source.height * scale));
  const context = next.getContext("2d");
  if (!context) return source;
  context.imageSmoothingEnabled = true;
  context.imageSmoothingQuality = "high";
  context.drawImage(source, 0, 0, next.width, next.height);
  return next;
};

const clampCanvasDimensions = (source: HTMLCanvasElement) => {
  const largestEdge = Math.max(source.width, source.height);
  if (largestEdge <= SUPPORT_SCREENSHOT_MAX_DIMENSION) return source;
  return drawScaledCanvas(source, SUPPORT_SCREENSHOT_MAX_DIMENSION / largestEdge);
};

const encodeSupportScreenshot = async (source: HTMLCanvasElement) => {
  let working = clampCanvasDimensions(source);
  let best: Blob | null = null;

  for (let attempt = 0; attempt < SUPPORT_SCREENSHOT_RESIZE_ATTEMPTS; attempt += 1) {
    for (const quality of SUPPORT_SCREENSHOT_QUALITY_STEPS) {
      const blob = await canvasToBlob(working, SUPPORT_SCREENSHOT_TARGET_MIME, quality);
      if (!blob) continue;
      best = blob;
      if (blob.size <= SUPPORT_SCREENSHOT_MAX_BYTES) return blob;
    }
    if (attempt < SUPPORT_SCREENSHOT_RESIZE_ATTEMPTS - 1) {
      working = drawScaledCanvas(working, SUPPORT_SCREENSHOT_RESIZE_FACTOR);
    }
  }

  return best;
};

export const captureSupportScreenshot = async (): Promise<File | null> => {
  if (typeof window === "undefined" || typeof document === "undefined") return null;
  try {
    const { default: html2canvas } = await import("html2canvas");
    const viewportWidth = Math.max(1, Math.round(window.innerWidth || document.documentElement.clientWidth || 1));
    const viewportHeight = Math.max(1, Math.round(window.innerHeight || document.documentElement.clientHeight || 1));
    const scrollX = Math.round(window.scrollX || window.pageXOffset || 0);
    const scrollY = Math.round(window.scrollY || window.pageYOffset || 0);

    const canvas = await html2canvas(document.documentElement, {
      scale: 1,
      useCORS: true,
      allowTaint: false,
      logging: false,
      backgroundColor: "#ffffff",
      x: scrollX,
      y: scrollY,
      scrollX,
      scrollY,
      width: viewportWidth,
      height: viewportHeight,
      windowWidth: viewportWidth,
      windowHeight: viewportHeight,
    });
    const blob = await encodeSupportScreenshot(canvas);
    if (!blob) return null;
    return new File([blob], `support-${Date.now()}.jpg`, { type: SUPPORT_SCREENSHOT_TARGET_MIME });
  } catch {
    return null;
  }
};

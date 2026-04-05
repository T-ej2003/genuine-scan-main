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
const SUPPORT_SCREENSHOT_TARGET_MIME = "image/jpeg";
const SUPPORT_SCREENSHOT_MAX_BYTES = 850 * 1024;
const SUPPORT_SCREENSHOT_MAX_DIMENSION = 1600;
const SUPPORT_SCREENSHOT_QUALITY_STEPS = [0.82, 0.74, 0.66, 0.58];
const SUPPORT_SCREENSHOT_RESIZE_FACTOR = 0.82;
const SUPPORT_SCREENSHOT_RESIZE_ATTEMPTS = 4;

const networkLogs: SupportNetworkLog[] = [];
const runtimeIssues: SupportRuntimeIssue[] = [];
const listeners = new Set<(issue: SupportRuntimeIssue) => void>();

const nextId = () =>
  `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 9)}`;

const pushBounded = <T,>(arr: T[], value: T, max: number) => {
  arr.push(value);
  if (arr.length > max) arr.splice(0, arr.length - max);
};

export const recordSupportNetworkLog = (entry: Omit<SupportNetworkLog, "id" | "at">) => {
  pushBounded(
    networkLogs,
    {
      id: nextId(),
      at: new Date().toISOString(),
      ...entry,
    },
    MAX_NETWORK_LOGS
  );
};

export const reportSupportRuntimeIssue = (entry: Omit<SupportRuntimeIssue, "id" | "at">) => {
  const issue: SupportRuntimeIssue = {
    id: nextId(),
    at: new Date().toISOString(),
    ...entry,
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
    url: typeof window !== "undefined" ? window.location.href : "",
    path: typeof window !== "undefined" ? `${window.location.pathname}${window.location.search}` : "",
    userAgent: nav.userAgent || "",
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

export const buildSupportDiagnosticsPayload = () => ({
  release: frontendRelease,
  environment: getSupportEnvironmentSnapshot(),
  networkLogs: getSupportNetworkLogs(),
  runtimeIssues: getSupportRuntimeIssues(),
});

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

export const formatSupportIssueSubmissionError = (raw: string | null | undefined) => {
  const text = stripMarkup(String(raw || ""));
  if (!text) return "Please try again.";
  if (text.toLowerCase().includes("413 request entity too large")) {
    return "The attached screenshot was too large to upload. Please try again.";
  }
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

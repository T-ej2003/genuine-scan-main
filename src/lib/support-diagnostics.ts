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
  environment: getSupportEnvironmentSnapshot(),
  networkLogs: getSupportNetworkLogs(),
  runtimeIssues: getSupportRuntimeIssues(),
});

export const captureSupportScreenshot = async (): Promise<File | null> => {
  if (typeof window === "undefined" || typeof document === "undefined") return null;
  try {
    const { default: html2canvas } = await import("html2canvas");
    const canvas = await html2canvas(document.body, {
      scale: Math.max(1, Math.min(window.devicePixelRatio || 1, 2)),
      useCORS: true,
      allowTaint: false,
      logging: false,
      backgroundColor: "#ffffff",
    });
    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob((value) => resolve(value), "image/png", 0.92)
    );
    if (!blob) return null;
    return new File([blob], `support-${Date.now()}.png`, { type: "image/png" });
  } catch {
    return null;
  }
};

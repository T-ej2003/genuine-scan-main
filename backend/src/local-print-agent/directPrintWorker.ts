import os from "os";
import { createHash } from "crypto";
import WebSocket from "ws";

import { listLocalPrinters, resolveSelectedPrinter, waitForLocalPrintJobCompletion } from "./cups";
import { printLabel } from "./render";
import { loadAgentState } from "./state";
import { buildPrinterAgentActionPayload, buildPrinterAgentSessionPayload, signPrinterAgentPayload } from "../services/printerAgentSigningService";
import {
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} from "../services/localAgentProtocol";
import { buildPrintPayloadDiagnostics } from "../printing/printPayloadSafety";
import { randomOpaqueToken } from "./crypto";
import { resolveLocalPrintAgentBuildVersion, resolveLocalPrintAgentVersion } from "./version";

const DIRECT_PRINT_POLL_MS = Math.max(2000, Number(process.env.PRINT_AGENT_DIRECT_POLL_MS || 4000) || 4000);
const DIRECT_PRINT_MAX_BACKOFF_MS = Math.max(
  DIRECT_PRINT_POLL_MS,
  Number(process.env.PRINT_AGENT_DIRECT_MAX_BACKOFF_MS || 30_000) || 30_000
);
const DIRECT_PRINT_IDLE_MIN_BACKOFF_MS = Math.max(
  15_000,
  Number(process.env.PRINT_AGENT_DIRECT_IDLE_MIN_BACKOFF_MS || 20_000) || 20_000
);
const DIRECT_PRINT_ACTIVE_WAKE_WINDOW_MS = Math.max(
  5_000,
  Math.min(30_000, Number(process.env.PRINT_AGENT_DIRECT_ACTIVE_WAKE_WINDOW_MS || 15_000) || 15_000)
);
const DIRECT_PRINT_ACTIVE_WAKE_MAX_CLAIMS = Math.max(
  1,
  Math.min(6, Number(process.env.PRINT_AGENT_DIRECT_ACTIVE_WAKE_MAX_CLAIMS || 4) || 4)
);
const DIRECT_PRINT_ACTIVE_WAKE_RETRY_MS = Math.max(
  750,
  Math.min(5_000, Number(process.env.PRINT_AGENT_DIRECT_ACTIVE_WAKE_RETRY_MS || 1_000) || 1_000)
);
const PRINT_AGENT_SESSION_MODE = String(process.env.PRINT_AGENT_SESSION_MODE || "websocket").trim().toLowerCase();
const PRINT_AGENT_SESSION_HEARTBEAT_MS = Math.max(10_000, Number(process.env.PRINT_AGENT_SESSION_HEARTBEAT_MS || 15_000) || 15_000);
const PRINT_AGENT_SESSION_RECONNECT_MAX_MS = Math.max(15_000, Number(process.env.PRINT_AGENT_SESSION_RECONNECT_MAX_MS || 60_000) || 60_000);
const AGENT_VERSION = resolveLocalPrintAgentVersion(process.env.PRINT_AGENT_VERSION);
const AGENT_BUILD_VERSION = resolveLocalPrintAgentBuildVersion(process.env.PRINT_AGENT_VERSION, process.env.PRINT_AGENT_BUILD_VERSION);
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");
const sha256Short = (value: unknown) => {
  const normalized = String(value || "").trim();
  return normalized ? sha256Hex(normalized).slice(0, 16) : null;
};

const safeDiagnosticValue = (value: unknown, max = 160) => {
  const source = Array.isArray(value) ? value.join(",") : String(value || "");
  const normalized = source.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim();
  return normalized ? normalized.slice(0, max) : null;
};

const safeDiagnosticToken = (value: unknown, max = 64) =>
  String(safeDiagnosticValue(value, max) || "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, max) || null;

const safeRejectHeaderNames = [
  "server",
  "via",
  "x-cache",
  "x-amz-cf-pop",
  "x-amz-cf-id",
  "date",
  "content-type",
  "content-length",
  "x-request-id",
];

export const buildSafePersistentSessionRejectHeaders = (headers: Record<string, unknown> = {}) => {
  const safeHeaders: Record<string, string> = {};
  for (const name of safeRejectHeaderNames) {
    const value = safeDiagnosticValue(headers[name], name === "x-amz-cf-id" ? 120 : 160);
    if (value) safeHeaders[name] = value;
  }
  return safeHeaders;
};

export const buildPersistentSessionRejectReasonCode = (statusCode: number | null, headers: Record<string, unknown> = {}) => {
  const explicit = safeDiagnosticToken(headers["x-mscqr-reject-code"], 80);
  if (explicit) return explicit;
  const parts = [`http_${statusCode || "upgrade_rejected"}`];
  const xCache = safeDiagnosticToken(headers["x-cache"], 48);
  const server = safeDiagnosticToken(headers.server, 32);
  if (xCache) parts.push(`xcache_${xCache}`);
  if (server) parts.push(`server_${server}`);
  return parts.join(";").slice(0, 180);
};

export const sanitizePersistentSessionRejectBodyPreview = (body: string, maxChars = 500) =>
  String(body || "")
    .replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "<redacted-pem>")
    .replace(
      /("(?:privateKeyPem|publicKeyPem|heartbeatSignature|signature|token|cookie|csrf|authorization)"\s*:\s*")[^"]*(")/gi,
      "$1<redacted>$2"
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer <redacted>")
    .slice(0, maxChars);

export const readPersistentSessionRejectBodyPreview = (response: any, maxChars = 500) =>
  new Promise<string | null>((resolve) => {
    let preview = "";
    let settled = false;
    let timer: NodeJS.Timeout | null = null;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve(sanitizePersistentSessionRejectBodyPreview(preview, maxChars).trim() || null);
    };
    timer = setTimeout(finish, 2_000);
    try {
      response?.setEncoding?.("utf8");
      response?.on?.("data", (chunk: unknown) => {
        if (preview.length >= maxChars) return;
        preview += String(chunk || "").slice(0, maxChars - preview.length);
      });
      response?.on?.("end", finish);
      response?.on?.("error", finish);
      response?.on?.("aborted", finish);
      if (response?.readableEnded || response?.complete) finish();
    } catch {
      finish();
    }
  });

export const buildPersistentSessionConnectDiagnostics = (params: {
  backendUrl: string;
  sessionUrl: string;
  selectedPrinterId: string;
  agentId: string;
  deviceFingerprint: string;
}) => {
  const session = new URL(params.sessionUrl);
  const backend = new URL(normalizeBackendBaseUrl(params.backendUrl));
  return {
    sessionUrlOrigin: session.origin,
    sessionUrlPathname: session.pathname,
    backendBaseOrigin: backend.origin,
    selectedPrinterId: params.selectedPrinterId,
    agentIdHash: sha256Short(params.agentId),
    deviceFingerprintHash: sha256Short(params.deviceFingerprint),
    buildVersion: AGENT_BUILD_VERSION || AGENT_VERSION,
    supportsPersistentPrintSession: LOCAL_AGENT_CAPABILITIES.supportsPersistentPrintSession === true,
    proxyEnvPresent: {
      HTTPS_PROXY: Boolean(process.env.HTTPS_PROXY),
      HTTP_PROXY: Boolean(process.env.HTTP_PROXY),
      NO_PROXY: Boolean(process.env.NO_PROXY),
    },
  };
};

const clampRetryAfterMs = (value: unknown) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DIRECT_PRINT_POLL_MS;
  return Math.max(DIRECT_PRINT_POLL_MS, Math.min(DIRECT_PRINT_MAX_BACKOFF_MS, Math.floor(parsed)));
};

const addRetryJitterMs = (value: number) => {
  const jitter = Math.floor(Math.random() * Math.min(5_000, Math.max(500, Math.floor(value * 0.2))));
  return clampRetryAfterMs(value + jitter);
};

export const resolveNoWorkRetryAfterMs = (serverRetryAfterMs: unknown, noWorkCount: number) => {
  const serverRetry = clampRetryAfterMs(serverRetryAfterMs);
  const exponent = Math.min(3, Math.max(0, noWorkCount - 1));
  const idleMax = Math.max(DIRECT_PRINT_MAX_BACKOFF_MS, DIRECT_PRINT_IDLE_MIN_BACKOFF_MS);
  const idleBackoff = Math.min(idleMax, DIRECT_PRINT_IDLE_MIN_BACKOFF_MS * 2 ** exponent);
  return Math.max(DIRECT_PRINT_IDLE_MIN_BACKOFF_MS, addRetryJitterMs(Math.max(serverRetry, idleBackoff)));
};

export const resolveActiveWakeRetryAfterMs = (attempt: number) => {
  const exponent = Math.min(3, Math.max(0, attempt - 1));
  const base = Math.min(5_000, Math.max(DIRECT_PRINT_POLL_MS, DIRECT_PRINT_ACTIVE_WAKE_RETRY_MS * 2 ** exponent));
  const jitter = Math.floor(Math.random() * Math.min(500, Math.max(100, Math.floor(base * 0.1))));
  return Math.min(5_000, base + jitter);
};

export const isCloudConnectivityError = (error: any) => {
  const code = String(error?.code || error?.cause?.code || error?.errno || "").toUpperCase();
  const message = String(error?.message || error || "").toLowerCase();
  return (
    ["ENOTFOUND", "ETIMEDOUT", "ECONNRESET", "ECONNREFUSED", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH"].includes(code) ||
    message.includes("fetch failed") ||
    message.includes("network") ||
    message.includes("timed out")
  );
};

export const isBackendRateLimitError = (error: any) => Number(error?.status || 0) === 429;

export const resolveConnectivityRetryAfterMs = (failureCount: number) => {
  const exponent = Math.min(5, Math.max(0, failureCount - 1));
  const base = Math.min(DIRECT_PRINT_MAX_BACKOFF_MS, DIRECT_PRINT_POLL_MS * 2 ** exponent);
  const jitter = Math.floor(Math.random() * Math.min(2_500, Math.max(500, Math.floor(base * 0.2))));
  return clampRetryAfterMs(base + jitter);
};

const resolveBackendUrl = async () => {
  const state = await loadAgentState();
  const configured = String(
    state.backendUrl || process.env.PRINT_AGENT_BACKEND_URL || process.env.PRINT_GATEWAY_BACKEND_URL || ""
  )
    .trim()
    .replace(/\/+$/, "");
  return configured ? normalizeBackendBaseUrl(configured) : null;
};

const buildSignedBody = async (params: {
  action: "claim" | "ack" | "confirm" | "fail";
  printerId: string;
  printJobId?: string | null;
  printItemId?: string | null;
}) => {
  const state = await loadAgentState();
  const issuedAt = new Date().toISOString();
  const nonce = randomOpaqueToken(12);
  const signedPayload = buildPrinterAgentActionPayload({
    action: params.action,
    agentId: state.agentId,
    deviceFingerprint: state.deviceFingerprint,
    printerId: params.printerId,
    printJobId: params.printJobId || null,
    printItemId: params.printItemId || null,
    nonce,
    issuedAt,
  });

  return {
    state,
    body: {
      agentId: state.agentId,
      deviceFingerprint: state.deviceFingerprint,
      printerId: params.printerId,
      issuedAt,
      nonce,
      signature: signPrinterAgentPayload(state.privateKeyPem, signedPayload),
    },
  };
};

const postBackend = async <T>(path: string, body: Record<string, unknown>) => {
  const backendUrl = await resolveBackendUrl();
  if (!backendUrl) return null;

  const response = await fetch(`${backendUrl}/api${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = Object.assign(
      new Error(String((payload as any)?.error || `Direct-print agent request failed: HTTP ${response.status}`)),
      {
        status: response.status,
        errorCode: (payload as any)?.errorCode || (payload as any)?.code || null,
        requestId: (payload as any)?.requestId || response.headers.get("x-request-id") || null,
        validationIssuePaths: (payload as any)?.details?.validationIssuePaths || [],
        missingFields: (payload as any)?.details?.missingFields || [],
        serverTime: (payload as any)?.serverTime || null,
        timestampSkewSeconds: (payload as any)?.timestampSkewSeconds ?? null,
        retryAfterMs: (payload as any)?.retryAfterMs ?? null,
      }
    );
    throw error;
  }
  return payload as T;
};

type SessionProgressType =
  | "heartbeat"
  | "chunk_ack"
  | "chunk_spooled"
  | "chunk_confirmed"
  | "chunk_failed"
  | "label_spooled"
  | "label_confirmed"
  | "label_failed"
  | "test_ack"
  | "test_confirmed"
  | "test_failed";

type SessionContext = {
  sessionId: string;
  registrationId: string;
  selectedPrinterId: string;
  connectorVersion: string;
  messageSeq: number;
};

type PersistentPrintSessionStatus = {
  mode: "websocket" | "rest" | "polling";
  supported: boolean;
  connected: boolean;
  sessionId: string | null;
  registrationId: string | null;
  selectedPrinterId: string | null;
  lastConnectedAt: string | null;
  lastHeartbeatAt: string | null;
  lastDisconnectedAt: string | null;
  lastError: string | null;
  lastRejectReasonCode: string | null;
};

const persistentPrintSessionStatus: PersistentPrintSessionStatus = {
  mode: "websocket",
  supported: true,
  connected: false,
  sessionId: null,
  registrationId: null,
  selectedPrinterId: null,
  lastConnectedAt: null,
  lastHeartbeatAt: null,
  lastDisconnectedAt: null,
  lastError: null,
  lastRejectReasonCode: null,
};

export const getPersistentPrintSessionStatus = () => ({ ...persistentPrintSessionStatus });

const updatePersistentSessionStatus = (patch: Partial<PersistentPrintSessionStatus>) => {
  Object.assign(persistentPrintSessionStatus, patch);
};

export const normalizeBackendBaseUrl = (backendUrl: string) => {
  const trimmed = String(backendUrl || "").trim().replace(/\/+$/, "");
  return trimmed.replace(/\/api$/i, "");
};

export const resolveSessionUrl = (backendUrl: string) => {
  const url = new URL(`${normalizeBackendBaseUrl(backendUrl)}/api/printer-agent/session`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
};

const buildSignedSessionMessage = async (params: {
  type: "hello" | SessionProgressType;
  session?: SessionContext | null;
  selectedPrinterId: string;
  selectedPrinterName?: string | null;
  chunkId?: string | null;
  printJobId?: string | null;
  printItemId?: string | null;
  testJobId?: string | null;
  deviceJobRef?: string | null;
  payloadHash?: string | null;
  bytesWritten?: number | null;
  printPath?: string | null;
  labelLanguage?: string | null;
  payloadType?: string | null;
  error?: string | null;
  printerHealth?: Record<string, unknown> | null;
}) => {
  const state = await loadAgentState();
  const issuedAt = new Date().toISOString();
  const nonce = randomOpaqueToken(12);
  const messageSeq = params.type === "hello" ? null : (params.session!.messageSeq += 1);
  const connectorVersion = AGENT_BUILD_VERSION || AGENT_VERSION;
  const signedPayload = buildPrinterAgentSessionPayload({
    messageType: params.type,
    registrationId: params.session?.registrationId || null,
    agentId: state.agentId,
    deviceFingerprint: state.deviceFingerprint,
    selectedPrinterId: params.selectedPrinterId,
    connectorVersion,
    sessionId: params.session?.sessionId || null,
    chunkId: params.chunkId || null,
    printJobId: params.printJobId || null,
    printItemId: params.printItemId || null,
    testJobId: params.testJobId || null,
    messageSeq,
    nonce,
    issuedAt,
  });
  const common = {
    type: params.type,
    nonce,
    issuedAt,
    signature: signPrinterAgentPayload(state.privateKeyPem, signedPayload),
  };
  if (params.type === "hello") {
    return {
      ...common,
      agentId: state.agentId,
      deviceFingerprint: state.deviceFingerprint,
      selectedPrinterId: params.selectedPrinterId,
      connectorVersion,
      registrationId: null,
      selectedPrinterName: params.selectedPrinterName || null,
      printerHealth: params.printerHealth || null,
    };
  }
  return {
    ...common,
    sessionId: params.session!.sessionId,
    chunkId: params.chunkId || null,
    printJobId: params.printJobId || null,
    printItemId: params.printItemId || null,
    testJobId: params.testJobId || null,
    messageSeq,
    ...(params.deviceJobRef ? { deviceJobRef: params.deviceJobRef } : {}),
    ...(params.payloadHash ? { payloadHash: params.payloadHash } : {}),
    ...(params.bytesWritten ? { bytesWritten: Math.floor(params.bytesWritten) } : {}),
    ...(params.printPath ? { printPath: params.printPath } : {}),
    ...(params.labelLanguage ? { labelLanguage: params.labelLanguage } : {}),
    ...(params.payloadType ? { payloadType: params.payloadType } : {}),
    ...(params.error ? { error: params.error } : {}),
    ...(params.printerHealth ? { printerHealth: params.printerHealth } : {}),
  };
};

const sendSessionMessage = async (
  ws: WebSocket,
  session: SessionContext,
  selectedPrinterId: string,
  params: Omit<Parameters<typeof buildSignedSessionMessage>[0], "session" | "selectedPrinterId">
) => {
  if (ws.readyState !== WebSocket.OPEN) throw new Error("Printer session is not connected.");
  const body = await buildSignedSessionMessage({
    ...params,
    session,
    selectedPrinterId,
  });
  ws.send(JSON.stringify(body));
};

const optionalString = (value: unknown) => {
  const normalized = String(value || "").trim();
  return normalized || undefined;
};

const claimNextLocalJob = async () => {
  const state = await loadAgentState();
  const inventory = await listLocalPrinters();
  const selection = resolveSelectedPrinter(inventory.printers, state.selectedPrinterId);
  const selectedPrinterId = String(selection.printerId || "").trim();
  if (!selectedPrinterId || !state.selectedPrinterId) {
    return { success: true, data: null, retryAfterMs: DIRECT_PRINT_IDLE_MIN_BACKOFF_MS };
  }
  const signed = await buildSignedBody({
    action: "claim",
    printerId: selectedPrinterId,
  });

  return postBackend<{ success: boolean; data?: any; retryAfterMs?: number }>("/printer-agent/local/claim", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: LOCAL_AGENT_CAPABILITIES,
    selectedPrinterId,
    ...(optionalString(selection.printerName) ? { selectedPrinterName: optionalString(selection.printerName) } : {}),
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
  });
};

const ackLocalJob = async (payload: {
  printerId: string;
  printJobId: string;
  printSessionId?: string | null;
  printItemId: string;
  code?: string | null;
  payloadHash: string;
  printPath: string;
  labelLanguage: string;
  jobRef?: string | null;
  markDispatched?: boolean;
  bytesWritten?: number | null;
  queueConfirmationUnavailable?: boolean;
}) => {
  const signed = await buildSignedBody({
    action: "ack",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  const markDispatched = payload.markDispatched !== false;
  const bytesWritten = Number(payload.bytesWritten || 0);
  const body = {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    printJobId: payload.printJobId,
    ...(payload.printSessionId ? { printSessionId: payload.printSessionId } : {}),
    printItemId: payload.printItemId,
    ...(payload.code ? { code: payload.code } : {}),
    payloadHash: payload.payloadHash,
    ...(bytesWritten > 0 ? { bytesWritten: Math.floor(bytesWritten) } : {}),
    ...(payload.jobRef ? { deviceJobRef: payload.jobRef } : {}),
    markDispatched,
    ...(markDispatched
      ? {
          dispatchMetadata: {
            printPath: payload.printPath,
            labelLanguage: payload.labelLanguage,
            jobRef: payload.jobRef || null,
            queueConfirmationUnavailable: Boolean(payload.queueConfirmationUnavailable),
          },
        }
      : {}),
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
      printPath: payload.printPath,
      labelLanguage: payload.labelLanguage,
      jobRef: payload.jobRef || null,
      queueConfirmationUnavailable: Boolean(payload.queueConfirmationUnavailable),
    },
  };

  try {
    await postBackend("/printer-agent/local/ack", body);
  } catch (error: any) {
    throw Object.assign(error, {
      localAgentStage: markDispatched ? "dispatch_ack" : "pre_spool_ack",
      spoolerAttempted: markDispatched,
    });
  }
};

const confirmLocalJob = async (payload: {
  printerId: string;
  printJobId: string;
  printItemId: string;
  payloadHash: string;
  printPath: string;
  labelLanguage: string;
  jobRef?: string | null;
  bytesWritten?: number | null;
}) => {
  const signed = await buildSignedBody({
    action: "confirm",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  const bytesWritten = Number(payload.bytesWritten || 0);
  await postBackend("/printer-agent/local/confirm", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    payloadHash: payload.payloadHash,
    ...(bytesWritten > 0 ? { bytesWritten: Math.floor(bytesWritten) } : {}),
    deviceJobRef: payload.jobRef || null,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
      printPath: payload.printPath,
      labelLanguage: payload.labelLanguage,
      jobRef: payload.jobRef || null,
    },
  });
};

const failLocalJob = async (payload: {
  printerId: string;
  printJobId: string;
  printItemId: string;
  reason: string;
}) => {
  const signed = await buildSignedBody({
    action: "fail",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  await postBackend("/printer-agent/local/fail", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    reason: payload.reason,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
    },
  });
};

const ackLocalTestJob = async (payload: {
  printerId: string;
  testJobId: string;
  payloadHash: string;
  payloadType?: string | null;
  printPath: string;
  labelLanguage: string;
  jobRef?: string | null;
  bytesWritten?: number | null;
}) => {
  const signed = await buildSignedBody({
    action: "ack",
    printerId: payload.printerId,
  });
  const bytesWritten = Number(payload.bytesWritten || 0);
  await postBackend("/printer-agent/local/test/ack", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    testJobId: payload.testJobId,
    payloadHash: payload.payloadHash,
    payloadType: payload.payloadType || null,
    ...(bytesWritten > 0 ? { bytesWritten: Math.floor(bytesWritten) } : {}),
    deviceJobRef: payload.jobRef || null,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
      printPath: payload.printPath,
      labelLanguage: payload.labelLanguage,
      jobRef: payload.jobRef || null,
    },
  });
};

const confirmLocalTestJob = async (payload: {
  printerId: string;
  testJobId: string;
  payloadHash: string;
  payloadType?: string | null;
  printPath: string;
  labelLanguage: string;
  jobRef?: string | null;
  bytesWritten?: number | null;
}) => {
  const signed = await buildSignedBody({
    action: "confirm",
    printerId: payload.printerId,
  });
  const bytesWritten = Number(payload.bytesWritten || 0);
  await postBackend("/printer-agent/local/test/confirm", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    testJobId: payload.testJobId,
    payloadHash: payload.payloadHash,
    payloadType: payload.payloadType || null,
    ...(bytesWritten > 0 ? { bytesWritten: Math.floor(bytesWritten) } : {}),
    deviceJobRef: payload.jobRef || null,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
      printPath: payload.printPath,
      labelLanguage: payload.labelLanguage,
      jobRef: payload.jobRef || null,
    },
  });
};

const failLocalTestJob = async (payload: {
  printerId: string;
  testJobId: string;
  reason: string;
}) => {
  const signed = await buildSignedBody({
    action: "fail",
    printerId: payload.printerId,
  });
  await postBackend("/printer-agent/local/test/fail", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    testJobId: payload.testJobId,
    reason: payload.reason,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      buildVersion: AGENT_BUILD_VERSION,
    },
  });
};

export const isPreSpoolAckRejection = (error: any) =>
  String(error?.localAgentStage || "") === "pre_spool_ack" &&
  (Number(error?.status || 0) === 400 ||
    Number(error?.status || 0) === 401 ||
    Number(error?.status || 0) === 426 ||
    String(error?.errorCode || "").includes("ack") ||
    String(error?.errorCode || "") === "agent_timestamp_expired" ||
    String(error?.errorCode || "") === "connector_update_required");

export const shouldReportLocalPrintFailureToBackend = (error: any, spoolerAttempted: boolean) => {
  if (!spoolerAttempted && isPreSpoolAckRejection(error)) return false;
  return true;
};

export const validateClaimedLocalPrintJobForAttempt = (payload: any) => {
  const printJobId = String(payload?.printJobId || "").trim();
  const printSessionId = String(payload?.printSessionId || "").trim();
  const printItemId = String(payload?.printItemId || "").trim();
  const code = String(payload?.code || "").trim();
  const scanUrl = String(payload?.scanUrl || "").trim();
  const payloadContent = typeof payload?.payloadContent === "string" ? payload.payloadContent : "";
  const payloadHash = String(payload?.payloadHash || "").trim();
  if (!printJobId || !printItemId) throw Object.assign(new Error("Claim response is missing job or item identity."), { errorCode: "claim_identity_missing" });
  if (!code) throw Object.assign(new Error("Claim response is missing the QR code."), { errorCode: "claim_code_missing" });
  if (!scanUrl) throw Object.assign(new Error("Claim response is missing the scan URL."), { errorCode: "claim_scan_url_missing" });
  if (!payloadContent || !payloadHash) {
    throw Object.assign(new Error("Claim response is missing its approved print payload."), { errorCode: "claim_payload_missing" });
  }
  if (sha256Hex(payloadContent) !== payloadHash) {
    throw Object.assign(new Error("Claim response approved payload hash mismatch."), { errorCode: "claim_payload_hash_mismatch" });
  }
  return { printJobId, printSessionId, printItemId, code, scanUrl, payloadContent, payloadHash };
};

const runLocalDiagnosticTestJob = async (payload: any, printerId: string) => {
  const testJobId = String(payload?.testJobId || "").trim();
  const backendPrinterId = String(payload?.printer?.id || "").trim() || printerId;
  const payloadContent = typeof payload?.payloadContent === "string" ? payload.payloadContent : "";
  const payloadHash = String(payload?.payloadHash || "").trim();
  if (!testJobId || !payloadContent || !payloadHash) {
    throw Object.assign(new Error("Diagnostic test claim is missing its approved ZPL payload."), {
      errorCode: "test_claim_payload_missing",
    });
  }
  if (sha256Hex(payloadContent) !== payloadHash) {
    throw Object.assign(new Error("Diagnostic test payload hash mismatch."), { errorCode: "test_payload_hash_mismatch" });
  }
  const payloadDiagnostics = buildPrintPayloadDiagnostics({
    payloadType: payload.payloadType || "ZPL",
    labelLanguage: payload.commandLanguage || "ZPL",
    payloadContent,
  });
  console.info("local direct-print diagnostic test payload validated", {
    testJobId,
    printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
    payloadDiagnostics,
  });
  try {
    const result = await printLabel({
      printerId,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
      printerLanguages: ["ZPL"],
      calibrationProfile: null,
      request: {
        code: String(payload.code || "MSCQR-TEST").trim(),
        scanUrl: String(payload.scanUrl || "MSCQR-DIAGNOSTIC-TEST").trim(),
        payloadType: payload.payloadType || "ZPL",
        payloadContent,
        payloadHash,
        previewLabel: payload.previewLabel || "MSCQR TEST",
        copies: 1,
        printPath: "label-language",
        labelLanguage: payload.commandLanguage || "ZPL",
      },
    });
    await ackLocalTestJob({
      printerId: backendPrinterId,
      testJobId,
      payloadHash,
      payloadType: payload.payloadType || "ZPL",
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
    });
    await confirmLocalTestJob({
      printerId: backendPrinterId,
      testJobId,
      payloadHash,
      payloadType: payload.payloadType || "ZPL",
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
    });
    console.info("local direct-print diagnostic test label sent", {
      testJobId,
      printerId,
      printPath: result.printPath,
      bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
    });
  } catch (error: any) {
    await failLocalTestJob({
      printerId: backendPrinterId,
      testJobId,
      reason: error?.message || "Diagnostic test label failed.",
    }).catch(() => undefined);
    throw error;
  }
};

const runPersistentDiagnosticTestJob = async (
  ws: WebSocket,
  session: SessionContext,
  payload: any,
  selectedPrinterId: string
) => {
  const testJobId = String(payload?.testJobId || "").trim();
  const payloadContent = typeof payload?.payloadContent === "string" ? payload.payloadContent : "";
  const payloadHash = String(payload?.payloadHash || "").trim();
  if (!testJobId || !payloadContent || !payloadHash) {
    throw Object.assign(new Error("Persistent diagnostic test is missing its approved payload."), {
      errorCode: "test_claim_payload_missing",
    });
  }
  if (sha256Hex(payloadContent) !== payloadHash) {
    throw Object.assign(new Error("Persistent diagnostic test payload hash mismatch."), {
      errorCode: "test_payload_hash_mismatch",
    });
  }
  const payloadDiagnostics = buildPrintPayloadDiagnostics({
    payloadType: payload.payloadType || "ZPL",
    labelLanguage: payload.commandLanguage || "ZPL",
    payloadContent,
  });
  try {
    const result = await printLabel({
      printerId: selectedPrinterId,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || selectedPrinterId).trim(),
      printerLanguages: ["ZPL"],
      calibrationProfile: null,
      request: {
        code: String(payload.code || "MSCQR-TEST").trim(),
        scanUrl: String(payload.scanUrl || "MSCQR-DIAGNOSTIC-TEST").trim(),
        payloadType: payload.payloadType || "ZPL",
        payloadContent,
        payloadHash,
        previewLabel: payload.previewLabel || "MSCQR TEST",
        copies: 1,
        printPath: "label-language",
        labelLanguage: payload.commandLanguage || "ZPL",
      },
    });
    await sendSessionMessage(ws, session, selectedPrinterId, {
      type: "test_ack",
      testJobId,
      payloadHash,
      payloadType: payload.payloadType || "ZPL",
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      deviceJobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
    });
    await sendSessionMessage(ws, session, selectedPrinterId, {
      type: "test_confirmed",
      testJobId,
      payloadHash,
      payloadType: payload.payloadType || "ZPL",
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      deviceJobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
    });
    console.info("persistent printer session test label confirmed", {
      sessionId: session.sessionId,
      testJobId,
      selectedPrinterId,
      printPath: result.printPath,
    });
  } catch (error: any) {
    await sendSessionMessage(ws, session, selectedPrinterId, {
      type: "test_failed",
      testJobId,
      error: error?.message || "Persistent diagnostic test label failed.",
    }).catch(() => undefined);
    throw error;
  }
};

const runPersistentPrintChunk = async (
  ws: WebSocket,
  session: SessionContext,
  payload: any,
  selectedPrinterId: string
) => {
  const chunkId = String(payload?.chunkId || "").trim();
  const printJobId = String(payload?.printJobId || "").trim();
  const labels = Array.isArray(payload?.labels) ? payload.labels : [];
  if (!chunkId || !printJobId || !labels.length) {
    throw Object.assign(new Error("Persistent print chunk is missing required identity or labels."), {
      errorCode: "chunk_payload_missing",
    });
  }
  const printer = payload.printer && typeof payload.printer === "object" ? payload.printer : {};
  const printerName = String(printer.name || printer.selectedPrinterName || selectedPrinterId).trim();
  const calibrationProfile =
    payload.calibrationProfile && typeof payload.calibrationProfile === "object"
      ? (payload.calibrationProfile as Record<string, unknown>)
      : null;

  await sendSessionMessage(ws, session, selectedPrinterId, {
    type: "chunk_ack",
    chunkId,
    printJobId,
  });

  for (const label of labels) {
    const printItemId = String(label?.printItemId || "").trim();
    const code = String(label?.code || "").trim();
    const scanUrl = String(label?.scanUrl || "").trim();
    const payloadContent = typeof label?.payloadContent === "string" ? label.payloadContent : "";
    const payloadHash = String(label?.payloadHash || "").trim();
    if (!printItemId || !code || !scanUrl || !payloadContent || !payloadHash) {
      throw Object.assign(new Error("Persistent chunk label is missing required approved print fields."), {
        errorCode: "chunk_label_payload_missing",
      });
    }
    if (sha256Hex(payloadContent) !== payloadHash) {
      throw Object.assign(new Error("Persistent chunk label approved payload hash mismatch."), {
        errorCode: "chunk_label_payload_hash_mismatch",
      });
    }

    const payloadDiagnostics = buildPrintPayloadDiagnostics({
      payloadType: label.payloadType || null,
      labelLanguage: label.commandLanguage || null,
      payloadContent,
    });
    console.info("persistent printer session spool start", {
      sessionId: session.sessionId,
      chunkId,
      printJobId,
      printItemId,
      payloadDiagnostics,
    });
    try {
      const result = await printLabel({
        printerId: selectedPrinterId,
        printerName,
        printerLanguages: Array.isArray(printer.languages) ? printer.languages : [],
        calibrationProfile,
        request: {
          code,
          scanUrl,
          payloadType: label.payloadType || null,
          payloadContent,
          payloadHash,
          previewLabel: label.previewLabel || null,
          copies: 1,
          printPath: label.printPath || "auto",
          labelLanguage: label.commandLanguage || null,
        },
      });
      await sendSessionMessage(ws, session, selectedPrinterId, {
        type: "label_spooled",
        chunkId,
        printJobId,
        printItemId,
        payloadHash,
        printPath: result.printPath,
        labelLanguage: result.labelLanguage,
        deviceJobRef: result.jobRef,
        bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
      });

      const completion = await waitForLocalPrintJobCompletion({
        printerId: selectedPrinterId,
        jobRef: result.jobRef,
      });
      if ((completion as any)?.confirmationUnavailable || (completion as any)?.confirmed === false) {
        throw Object.assign(new Error("Local queue did not provide terminal print confirmation."), {
          errorCode: "queue_confirmation_unavailable",
        });
      }

      await sendSessionMessage(ws, session, selectedPrinterId, {
        type: "label_confirmed",
        chunkId,
        printJobId,
        printItemId,
        payloadHash,
        printPath: result.printPath,
        labelLanguage: result.labelLanguage,
        deviceJobRef: result.jobRef,
        bytesWritten: result.bytesWritten ?? payloadDiagnostics.payloadByteLength,
      });
    } catch (error: any) {
      await sendSessionMessage(ws, session, selectedPrinterId, {
        type: "label_failed",
        chunkId,
        printJobId,
        printItemId,
        payloadHash,
        error: error?.message || "Persistent print label failed.",
      }).catch(() => undefined);
      await sendSessionMessage(ws, session, selectedPrinterId, {
        type: "chunk_failed",
        chunkId,
        printJobId,
        error: error?.message || "Persistent print chunk failed.",
      }).catch(() => undefined);
      throw error;
    }
  }

  await sendSessionMessage(ws, session, selectedPrinterId, {
    type: "chunk_confirmed",
    chunkId,
    printJobId,
  });
  console.info("persistent printer session chunk confirmed", {
    sessionId: session.sessionId,
    chunkId,
    printJobId,
    labels: labels.length,
  });
};

type DirectPrintCycleResult = {
  retryAfterMs: number;
  noWork: boolean;
};

type TimingContext = {
  startedAt: number;
  claimCount: number;
  source: "poll" | "local_wake";
};

const logPrintTiming = (event: string, details: Record<string, unknown>) => {
  console.info(event, details);
};

const runOnce = async (timing?: TimingContext): Promise<DirectPrintCycleResult> => {
  const claimStartedAt = Date.now();
  if (timing) {
    timing.claimCount += 1;
    logPrintTiming("print.connector.claim.started", {
      source: timing.source,
      claimCount: timing.claimCount,
      elapsedMs: claimStartedAt - timing.startedAt,
    });
  }
  const claimed = await claimNextLocalJob();
  if (!claimed?.data) {
    const retryAfterMs = clampRetryAfterMs(claimed?.retryAfterMs);
    if (timing) {
      logPrintTiming("print.connector.claim.returned", {
        source: timing.source,
        hasWork: false,
        claimCount: timing.claimCount,
        durationMs: Date.now() - claimStartedAt,
        elapsedMs: Date.now() - timing.startedAt,
        retryAfterMs,
      });
    }
    return { retryAfterMs, noWork: true };
  }

  const payload = claimed.data;
  if (timing) {
    logPrintTiming("print.connector.claim.returned", {
      source: timing.source,
      hasWork: true,
      claimCount: timing.claimCount,
      durationMs: Date.now() - claimStartedAt,
      elapsedMs: Date.now() - timing.startedAt,
      retryAfterMs: clampRetryAfterMs(claimed?.retryAfterMs),
      printJobId: String(payload.printJobId || "").trim() || null,
      printSessionId: String(payload.printSessionId || "").trim() || null,
      printItemId: String(payload.printItemId || "").trim() || null,
    });
  }
  console.info("local direct-print claim returned work", {
    printJobId: String(payload.printJobId || "").trim() || null,
    printSessionId: String(payload.printSessionId || "").trim() || null,
    printItemId: String(payload.printItemId || "").trim() || null,
    payloadHashPresent: Boolean(String(payload.payloadHash || "").trim()),
  });
  const calibrationProfile =
    payload.calibrationProfile && typeof payload.calibrationProfile === "object"
      ? (payload.calibrationProfile as Record<string, unknown>)
      : null;
  const printerId = String(
    payload.printer?.nativePrinterId || payload.printer?.selectedPrinterId || payload.selectedPrinterId || ""
  ).trim();
  let validated;

  if (!printerId) {
    await failLocalJob({
      printerId: "unknown-printer",
      printJobId: String(payload.printJobId || "").trim(),
      printItemId: String(payload.printItemId || "").trim(),
      reason: "Local agent has no selected workstation printer for this job.",
    });
    return { retryAfterMs: clampRetryAfterMs(claimed?.retryAfterMs), noWork: false };
  }

  const printJobId = String(payload.printJobId || "").trim();
  const printItemId = String(payload.printItemId || "").trim();
  let spoolerAttempted = false;

  try {
    if (payload.testJobId) {
      await runLocalDiagnosticTestJob(payload, printerId);
      return { retryAfterMs: clampRetryAfterMs(claimed?.retryAfterMs), noWork: false };
    }

    validated = validateClaimedLocalPrintJobForAttempt(payload);
    const payloadDiagnostics = buildPrintPayloadDiagnostics({
      payloadType: payload.payloadType || null,
      labelLanguage: payload.commandLanguage || payload.labelLanguage || null,
      payloadContent: validated.payloadContent,
    });
    console.info("local direct-print payload validated", {
      printJobId,
      printSessionId: validated.printSessionId,
      printItemId,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
      agentVersion: AGENT_VERSION,
      payloadDiagnostics,
    });
    await ackLocalJob({
      printerId,
      printJobId,
      printSessionId: validated.printSessionId,
      printItemId,
      code: validated.code,
      payloadHash: validated.payloadHash,
      printPath: "agent-claimed",
      labelLanguage: payload.commandLanguage || payload.labelLanguage || "AUTO",
      jobRef: null,
      markDispatched: false,
      bytesWritten: payloadDiagnostics.payloadByteLength,
    });
    console.info("local direct-print item acknowledged", {
      printJobId,
      printItemId,
      printerId,
    });

    console.info("local direct-print spooler start", {
      printJobId,
      printItemId,
      printerId,
      payloadType: payload.payloadType || null,
      payloadDiagnostics,
    });
    spoolerAttempted = true;
    const result = await printLabel({
      printerId,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
      printerLanguages: Array.isArray(payload.printer?.languages) ? payload.printer.languages : [],
      calibrationProfile,
      request: {
        code: validated.code,
        scanUrl: validated.scanUrl,
        payloadType: payload.payloadType || null,
        payloadContent: validated.payloadContent,
        payloadHash: validated.payloadHash,
        previewLabel: payload.previewLabel || null,
        copies: 1,
        printPath: payload.printPath || "auto",
        labelLanguage: payload.commandLanguage || payload.labelLanguage || null,
        mediaSize: payload.mediaSize || null,
      },
    });

    console.info("local direct-print spooler result", {
      printJobId,
      printItemId,
      printerId,
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef || null,
      bytesWritten: result.bytesWritten ?? null,
    });
    if (timing) {
      logPrintTiming("print.connector.spool.submitted", {
        source: timing.source,
        printJobId,
        printItemId,
        elapsedMs: Date.now() - timing.startedAt,
        claimCount: timing.claimCount,
        printPath: result.printPath,
        bytesWritten: result.bytesWritten ?? null,
      });
    }

    await ackLocalJob({
      printerId,
      printJobId,
      printSessionId: validated.printSessionId,
      printItemId,
      code: validated.code,
      payloadHash: validated.payloadHash,
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? null,
    });
    const completion = await waitForLocalPrintJobCompletion({
      printerId,
      jobRef: result.jobRef,
    });
    if ((completion as any)?.confirmationUnavailable || (completion as any)?.confirmed === false) {
      await ackLocalJob({
        printerId,
        printJobId,
        printSessionId: validated.printSessionId,
        printItemId,
        code: validated.code,
        payloadHash: validated.payloadHash,
        printPath: result.printPath,
        labelLanguage: result.labelLanguage,
        jobRef: result.jobRef,
        bytesWritten: result.bytesWritten ?? null,
        queueConfirmationUnavailable: true,
      });
      console.warn("local direct-print queue confirmation unavailable after dispatch", {
        printJobId,
        printItemId,
        printerId,
        jobRef: result.jobRef || null,
        queue: (completion as any)?.queue || null,
      });
      return { retryAfterMs: clampRetryAfterMs(claimed?.retryAfterMs), noWork: false };
    }
    await confirmLocalJob({
      printerId,
      printJobId,
      printItemId,
      payloadHash: validated.payloadHash,
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
      bytesWritten: result.bytesWritten ?? null,
    });
    console.info("local direct-print item confirmed", {
      printJobId,
      printItemId,
      printerId,
      jobRef: result.jobRef || null,
    });
    if (timing) {
      logPrintTiming("print.connector.confirmed", {
        source: timing.source,
        printJobId,
        printItemId,
        elapsedMs: Date.now() - timing.startedAt,
        claimCount: timing.claimCount,
      });
    }
  } catch (error: any) {
    let failureReported = false;
    const shouldReportFailure = shouldReportLocalPrintFailureToBackend(error, spoolerAttempted);
    if (printJobId && printItemId && shouldReportFailure) {
      await failLocalJob({
        printerId,
        printJobId,
        printItemId,
        reason: error?.message || "Local direct-print pipeline failed.",
      })
        .then(() => {
          failureReported = true;
        })
        .catch((reportError: any) => {
          console.error("local direct-print failure report failed", {
            printJobId,
            printItemId,
            printerId,
            error: reportError?.message || reportError,
            errorCode: reportError?.errorCode || null,
            serverTime: reportError?.serverTime || null,
            timestampSkewSeconds: reportError?.timestampSkewSeconds ?? null,
          });
        });
    }
    console.error("local direct-print item failed", {
      printJobId,
      printItemId,
      printerId,
      error: error?.message || error,
      errorCode: error?.errorCode || null,
      localAgentStage: error?.localAgentStage || null,
      spoolerAttempted,
      requestId: error?.requestId || null,
      validationIssuePaths: error?.validationIssuePaths || [],
      missingFields: error?.missingFields || [],
      failureReported,
      operatorMessage: !shouldReportFailure
        ? "Connector ACK rejected by backend before printing. Update connector or contact support."
        : null,
    });
    throw error;
  }

  return { retryAfterMs: clampRetryAfterMs(claimed?.retryAfterMs), noWork: false };
};

let activeDirectPrintWorkerStop: (() => void) | null = null;
let activeDirectPrintWorkerWake: ((reason?: string) => void) | null = null;

let activeWakeUntil = 0;
let activeWakeRemainingClaims = 0;
let activeWakeAttempt = 0;

const hasActiveWakeBudget = () =>
  Date.now() < activeWakeUntil && activeWakeRemainingClaims > 0;

const consumeActiveWakeClaim = () => {
  if (!hasActiveWakeBudget()) return false;
  activeWakeRemainingClaims = Math.max(0, activeWakeRemainingClaims - 1);
  activeWakeAttempt += 1;
  return true;
};

export const requestDirectPrintWake = (reason = "user_print_job_created") => {
  activeWakeUntil = Date.now() + DIRECT_PRINT_ACTIVE_WAKE_WINDOW_MS;
  activeWakeRemainingClaims = Math.max(activeWakeRemainingClaims, DIRECT_PRINT_ACTIVE_WAKE_MAX_CLAIMS);
  activeWakeAttempt = 0;
  console.info("print.connector.wake.sent", {
    source: "local_helper",
    reason,
    wakeWindowMs: DIRECT_PRINT_ACTIVE_WAKE_WINDOW_MS,
    maxClaimRequests: DIRECT_PRINT_ACTIVE_WAKE_MAX_CLAIMS,
  });
  activeDirectPrintWorkerWake?.(reason);
  return {
    accepted: true,
    wakeWindowMs: DIRECT_PRINT_ACTIVE_WAKE_WINDOW_MS,
    maxClaimRequests: DIRECT_PRINT_ACTIVE_WAKE_MAX_CLAIMS,
  };
};

const startPersistentPrintSessionWorker = () => {
  let stopped = false;
  let activeSocket: WebSocket | null = null;
  let reconnectAttempt = 0;
  let sleepWake: (() => void) | null = null;

  const sleep = (ms: number) =>
    new Promise<void>((resolve) => {
      let wake = () => undefined;
      const timer = setTimeout(() => {
        if (sleepWake === wake) sleepWake = null;
        resolve();
      }, ms);
      wake = () => {
        clearTimeout(timer);
        if (sleepWake === wake) sleepWake = null;
        resolve();
      };
      sleepWake = wake;
    });

  activeDirectPrintWorkerWake = () => {
    sleepWake?.();
  };

  const resolveSelection = async () => {
    const state = await loadAgentState();
    const inventory = await listLocalPrinters();
    const selection = resolveSelectedPrinter(inventory.printers, state.selectedPrinterId);
    const selectedPrinterId = String(selection.printerId || "").trim();
    if (!selectedPrinterId || !state.selectedPrinterId) return null;
    return {
      state,
      inventory,
      selection,
      selectedPrinterId,
      selectedPrinterName: optionalString(selection.printerName) || selectedPrinterId,
    };
  };

  const loop = async () => {
    while (!stopped) {
      const backendUrl = await resolveBackendUrl();
      const selection = backendUrl ? await resolveSelection().catch(() => null) : null;
      if (!backendUrl || !selection) {
        updatePersistentSessionStatus({
          connected: false,
          sessionId: null,
          registrationId: null,
          selectedPrinterId: selection?.selectedPrinterId || null,
          lastError: backendUrl ? "No selected local printer available for persistent session." : "Backend URL is not configured.",
          lastRejectReasonCode: null,
        });
        await sleep(DIRECT_PRINT_IDLE_MIN_BACKOFF_MS);
        continue;
      }

      let heartbeatTimer: NodeJS.Timeout | null = null;
      let session: SessionContext | null = null;
      let processing = false;
      const sessionUrl = resolveSessionUrl(backendUrl);
      const sessionPath = new URL(sessionUrl).pathname;
      console.info(
        "persistent printer session opening",
        buildPersistentSessionConnectDiagnostics({
          backendUrl,
          sessionUrl,
          selectedPrinterId: selection.selectedPrinterId,
          agentId: selection.state.agentId,
          deviceFingerprint: selection.state.deviceFingerprint,
        })
      );
      const ws = new WebSocket(sessionUrl);
      activeSocket = ws;

      const closeSession = () => {
        if (heartbeatTimer) {
          clearInterval(heartbeatTimer);
          heartbeatTimer = null;
        }
        if (activeSocket === ws) activeSocket = null;
        updatePersistentSessionStatus({
          connected: false,
          sessionId: null,
          registrationId: null,
          selectedPrinterId: selection.selectedPrinterId,
          lastDisconnectedAt: new Date().toISOString(),
        });
      };

      await new Promise<void>((resolve) => {
        let finished = false;
        const finish = () => {
          if (finished) return;
          finished = true;
          closeSession();
          resolve();
        };

        ws.on("open", () => {
          reconnectAttempt = 0;
          updatePersistentSessionStatus({ lastRejectReasonCode: null });
          void buildSignedSessionMessage({
            type: "hello",
            selectedPrinterId: selection.selectedPrinterId,
            selectedPrinterName: selection.selectedPrinterName,
              printerHealth: {
                deviceName: os.hostname(),
                agentVersion: AGENT_VERSION,
                buildVersion: AGENT_BUILD_VERSION,
                protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
                transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
                capabilities: LOCAL_AGENT_CAPABILITIES,
                selectedPrinterId: selection.selectedPrinterId,
                selectedPrinterName: selection.selectedPrinterName,
                printers: selection.inventory.printers.length,
            },
          }).then((hello) => ws.send(JSON.stringify(hello))).catch((error) => {
            console.error("persistent printer session hello failed", { error: error?.message || error });
            updatePersistentSessionStatus({ lastError: error?.message || "Persistent session hello failed." });
            ws.close();
          });
        });

        ws.on("message", (raw: any) => {
          void (async () => {
            let payload: any;
            try {
              payload = JSON.parse(String(raw));
            } catch {
              return;
            }
            if (payload?.type === "session_ready") {
              session = {
                sessionId: String(payload.sessionId || "").trim(),
                registrationId: String(payload.registrationId || "").trim(),
                selectedPrinterId: selection.selectedPrinterId,
                connectorVersion: AGENT_BUILD_VERSION || AGENT_VERSION,
                messageSeq: 0,
              };
              if (!session.sessionId || !session.registrationId) {
                ws.close();
                return;
              }
              heartbeatTimer = setInterval(() => {
                if (!session || ws.readyState !== WebSocket.OPEN) return;
                void sendSessionMessage(ws, session, selection.selectedPrinterId, {
                  type: "heartbeat",
                  printerHealth: {
                    deviceName: os.hostname(),
                    agentVersion: AGENT_VERSION,
                    buildVersion: AGENT_BUILD_VERSION,
                    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
                    transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
                    capabilities: LOCAL_AGENT_CAPABILITIES,
                    selectedPrinterId: selection.selectedPrinterId,
                    selectedPrinterName: selection.selectedPrinterName,
                  },
                })
                  .then(() => updatePersistentSessionStatus({ lastHeartbeatAt: new Date().toISOString(), lastError: null }))
                  .catch((error: any) => updatePersistentSessionStatus({ lastError: error?.message || "Persistent session heartbeat failed." }));
              }, PRINT_AGENT_SESSION_HEARTBEAT_MS);
              updatePersistentSessionStatus({
                connected: true,
                sessionId: session.sessionId,
                registrationId: session.registrationId,
                selectedPrinterId: selection.selectedPrinterId,
                lastConnectedAt: new Date().toISOString(),
                lastHeartbeatAt: new Date().toISOString(),
                lastError: null,
              });
              console.info("persistent printer session connected", {
                sessionId: session.sessionId,
                registrationId: session.registrationId,
                selectedPrinterId: selection.selectedPrinterId,
              });
              return;
            }
            if (payload?.type === "error") {
              const reasonCode = String(payload.errorCode || "").trim() || null;
              updatePersistentSessionStatus({
                lastError: String(payload.error || payload.errorCode || "Persistent session error").slice(0, 500),
                lastRejectReasonCode: reasonCode,
              });
              return;
            }
            if (!session || processing) return;
            if (payload?.type === "test_label") {
              processing = true;
              try {
                await runPersistentDiagnosticTestJob(ws, session, payload, selection.selectedPrinterId);
              } catch (error: any) {
                console.error("persistent printer session test failed", { error: error?.message || error });
              } finally {
                processing = false;
              }
              return;
            }
            if (payload?.type === "print_chunk") {
              processing = true;
              try {
                await runPersistentPrintChunk(ws, session, payload, selection.selectedPrinterId);
              } catch (error: any) {
                console.error("persistent printer session chunk failed", {
                  chunkId: String(payload?.chunkId || "").trim() || null,
                  printJobId: String(payload?.printJobId || "").trim() || null,
                  error: error?.message || error,
                  errorCode: error?.errorCode || null,
                });
              } finally {
                processing = false;
              }
            }
          })();
        });

        ws.on("close", finish);
        ws.on("unexpected-response", (_request: any, response: any) => {
          const statusCode = Number(response?.statusCode || 0) || null;
          const safeHeaders = buildSafePersistentSessionRejectHeaders(response?.headers || {});
          const reasonCode = buildPersistentSessionRejectReasonCode(statusCode, response?.headers || {});
          const message = `Persistent session upgrade rejected on ${sessionPath}${statusCode ? ` with HTTP ${statusCode}` : ""}.`;
          void readPersistentSessionRejectBodyPreview(response).then((bodyPreview) => {
            console.error("persistent printer session upgrade rejected", {
              path: sessionPath,
              statusCode,
              reasonCode,
              responseHeaders: safeHeaders,
              responseBodyPreview: bodyPreview,
            });
            updatePersistentSessionStatus({
              connected: false,
              sessionId: null,
              registrationId: null,
              selectedPrinterId: selection.selectedPrinterId,
              lastDisconnectedAt: new Date().toISOString(),
              lastError: message,
              lastRejectReasonCode: reasonCode,
            });
            finish();
          });
        });
        ws.on("error", (error: any) => {
          console.error("persistent printer session socket error", { path: sessionPath, error: (error as any)?.message || error });
          updatePersistentSessionStatus({ lastError: (error as any)?.message || "Persistent session socket error." });
          finish();
        });
      });

      if (stopped) break;
      reconnectAttempt += 1;
      const backoff = Math.min(
        PRINT_AGENT_SESSION_RECONNECT_MAX_MS,
        DIRECT_PRINT_POLL_MS * 2 ** Math.min(5, Math.max(0, reconnectAttempt - 1))
      );
      await sleep(addRetryJitterMs(backoff));
    }
  };

  void loop();

  activeDirectPrintWorkerStop = () => {
    stopped = true;
    sleepWake?.();
    activeSocket?.close();
    activeDirectPrintWorkerWake = null;
    activeDirectPrintWorkerStop = null;
  };
  return activeDirectPrintWorkerStop;
};

export const startDirectPrintWorker = () => {
  if (activeDirectPrintWorkerStop) return activeDirectPrintWorkerStop;
  if (PRINT_AGENT_SESSION_MODE === "rest" || PRINT_AGENT_SESSION_MODE === "polling") {
    console.warn("PRINT_AGENT_SESSION_MODE legacy value ignored; persistent WebSocket session is required.");
  }
  return startPersistentPrintSessionWorker();
};

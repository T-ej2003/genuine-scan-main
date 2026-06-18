import os from "os";
import { createHash } from "crypto";

import { listLocalPrinters, resolveSelectedPrinter, waitForLocalPrintJobCompletion } from "./cups";
import { printLabel } from "./render";
import { loadAgentState } from "./state";
import { buildPrinterAgentActionPayload, signPrinterAgentPayload } from "../services/printerAgentSigningService";
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
const AGENT_VERSION = resolveLocalPrintAgentVersion(process.env.PRINT_AGENT_VERSION);
const AGENT_BUILD_VERSION = resolveLocalPrintAgentBuildVersion(process.env.PRINT_AGENT_VERSION, process.env.PRINT_AGENT_BUILD_VERSION);
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

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
  return configured || null;
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

export const startDirectPrintWorker = () => {
  if (activeDirectPrintWorkerStop) return activeDirectPrintWorkerStop;

  let stopped = false;
  let connectivityFailureCount = 0;
  let noWorkCount = 0;
  let lastNoWorkLogAt = 0;
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

  const loop = async () => {
    while (!stopped) {
      const activeWakeClaim = consumeActiveWakeClaim();
      const timing: TimingContext = {
        startedAt: Date.now(),
        claimCount: 0,
        source: activeWakeClaim ? "local_wake" : "poll",
      };
      try {
        if (await resolveBackendUrl()) {
          const result = await runOnce(timing);
          connectivityFailureCount = 0;
          noWorkCount = result.noWork ? noWorkCount + 1 : 0;
          const retryAfterMs =
            result.noWork && hasActiveWakeBudget()
              ? resolveActiveWakeRetryAfterMs(activeWakeAttempt)
              : result.noWork
                ? resolveNoWorkRetryAfterMs(result.retryAfterMs, noWorkCount)
                : clampRetryAfterMs(result.retryAfterMs);
          if (result.noWork && Date.now() - lastNoWorkLogAt > 60_000) {
            lastNoWorkLogAt = Date.now();
            console.debug("local direct-print claim idle", { retryAfterMs, noWorkCount });
          }
          await sleep(retryAfterMs);
          continue;
        }
      } catch (error) {
        const cloudConnectivityIssue = isCloudConnectivityError(error);
        connectivityFailureCount = cloudConnectivityIssue ? connectivityFailureCount + 1 : 0;
        const retryAfterMs = cloudConnectivityIssue
          ? resolveConnectivityRetryAfterMs(connectivityFailureCount)
          : clampRetryAfterMs((error as any)?.retryAfterMs);
        if (isBackendRateLimitError(error)) {
          activeWakeUntil = 0;
          activeWakeRemainingClaims = 0;
          console.warn("print.connector.rate_limited", {
            source: timing.source,
            elapsedMs: Date.now() - timing.startedAt,
            claimCount: timing.claimCount,
            retryAfterMs,
            requestId: (error as any)?.requestId || null,
            backoffDecision: "active_wake_stopped_server_retry_respected",
          });
        }
        console.error("local direct-print worker cycle failed:", {
          error: (error as any)?.message || error,
          errorCode: (error as any)?.errorCode || null,
          cloudConnectivityIssue,
          retryAfterMs,
        });
        if ((error as any)?.serverTime || (error as any)?.timestampSkewSeconds != null) {
          console.error("local direct-print backend time check failed", {
            errorCode: (error as any)?.errorCode || null,
            localTime: new Date().toISOString(),
            serverTime: (error as any)?.serverTime || null,
            timestampSkewSeconds: (error as any)?.timestampSkewSeconds ?? null,
            retryAfterMs,
          });
        }
        await sleep(retryAfterMs);
        continue;
      }
      await sleep(DIRECT_PRINT_POLL_MS);
    }
  };

  void loop();

  activeDirectPrintWorkerStop = () => {
    stopped = true;
    sleepWake?.();
    activeDirectPrintWorkerWake = null;
    activeDirectPrintWorkerStop = null;
  };
  return activeDirectPrintWorkerStop;
};

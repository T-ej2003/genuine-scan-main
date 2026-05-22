import os from "os";
import { createHash } from "crypto";

import { listLocalPrinters, resolveSelectedPrinter, waitForLocalPrintJobCompletion } from "./cups";
import { printLabel } from "./render";
import { loadAgentState } from "./state";
import { buildPrinterAgentActionPayload, signPrinterAgentPayload } from "../services/printerAgentSigningService";
import { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";
import { randomOpaqueToken } from "../utils/security";

const DIRECT_PRINT_POLL_MS = Math.max(2000, Number(process.env.PRINT_AGENT_DIRECT_POLL_MS || 4000) || 4000);
const DIRECT_PRINT_MAX_BACKOFF_MS = Math.max(
  DIRECT_PRINT_POLL_MS,
  Number(process.env.PRINT_AGENT_DIRECT_MAX_BACKOFF_MS || 60_000) || 60_000
);
const AGENT_VERSION = String(process.env.PRINT_AGENT_VERSION || "1.0.0").trim() || "1.0.0";
const AGENT_BUILD_VERSION = String(process.env.PRINT_AGENT_BUILD_VERSION || AGENT_VERSION).trim() || AGENT_VERSION;
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const clampRetryAfterMs = (value: unknown) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return DIRECT_PRINT_POLL_MS;
  return Math.max(DIRECT_PRINT_POLL_MS, Math.min(DIRECT_PRINT_MAX_BACKOFF_MS, Math.floor(parsed)));
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
  const selectedPrinterId = selection.printerId || "unknown-printer";
  const signed = await buildSignedBody({
    action: "claim",
    printerId: selectedPrinterId,
  });

  return postBackend<{ success: boolean; data?: any; retryAfterMs?: number }>("/printer-agent/local/claim", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
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
}) => {
  const signed = await buildSignedBody({
    action: "ack",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  const markDispatched = payload.markDispatched !== false;
  const body = {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    printJobId: payload.printJobId,
    ...(payload.printSessionId ? { printSessionId: payload.printSessionId } : {}),
    printItemId: payload.printItemId,
    ...(payload.code ? { code: payload.code } : {}),
    payloadHash: payload.payloadHash,
    bytesWritten: Math.max(1, payload.payloadHash.length),
    ...(payload.jobRef ? { deviceJobRef: payload.jobRef } : {}),
    markDispatched,
    ...(markDispatched
      ? {
          dispatchMetadata: {
            printPath: payload.printPath,
            labelLanguage: payload.labelLanguage,
            jobRef: payload.jobRef || null,
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
}) => {
  const signed = await buildSignedBody({
    action: "confirm",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  await postBackend("/printer-agent/local/confirm", {
    ...signed.body,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: AGENT_BUILD_VERSION,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    payloadHash: payload.payloadHash,
    bytesWritten: Math.max(1, payload.payloadHash.length),
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

const runOnce = async () => {
  const claimed = await claimNextLocalJob();
  if (!claimed?.data) {
    const retryAfterMs = clampRetryAfterMs(claimed?.retryAfterMs);
    console.info("local direct-print claim returned no work", { retryAfterMs });
    return retryAfterMs;
  }

  const payload = claimed.data;
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
    return;
  }

  const printJobId = String(payload.printJobId || "").trim();
  const printItemId = String(payload.printItemId || "").trim();
  let spoolerAttempted = false;

  try {
    validated = validateClaimedLocalPrintJobForAttempt(payload);
    console.info("local direct-print payload validated", {
      printJobId,
      printSessionId: validated.printSessionId,
      printItemId,
      code: validated.code,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
      agentVersion: AGENT_VERSION,
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
    });

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
    });
    await waitForLocalPrintJobCompletion({
      printerId,
      jobRef: result.jobRef,
    });
    await confirmLocalJob({
      printerId,
      printJobId,
      printItemId,
      payloadHash: validated.payloadHash,
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
    });
    console.info("local direct-print item confirmed", {
      printJobId,
      printItemId,
      printerId,
      jobRef: result.jobRef || null,
    });
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

  return clampRetryAfterMs(claimed?.retryAfterMs);
};

export const startDirectPrintWorker = () => {
  let stopped = false;

  const loop = async () => {
    while (!stopped) {
      try {
        if (await resolveBackendUrl()) {
          const retryAfterMs = await runOnce();
          await new Promise((resolve) => setTimeout(resolve, clampRetryAfterMs(retryAfterMs)));
          continue;
        }
      } catch (error) {
        console.error("local direct-print worker cycle failed:", error);
        const retryAfterMs = clampRetryAfterMs((error as any)?.retryAfterMs);
        if ((error as any)?.serverTime || (error as any)?.timestampSkewSeconds != null) {
          console.error("local direct-print backend time check failed", {
            errorCode: (error as any)?.errorCode || null,
            serverTime: (error as any)?.serverTime || null,
            timestampSkewSeconds: (error as any)?.timestampSkewSeconds ?? null,
            retryAfterMs,
          });
        }
        await new Promise((resolve) => setTimeout(resolve, retryAfterMs));
        continue;
      }
      await new Promise((resolve) => setTimeout(resolve, DIRECT_PRINT_POLL_MS));
    }
  };

  void loop();

  return () => {
    stopped = true;
  };
};

import os from "os";

import { listLocalPrinters, resolveSelectedPrinter, waitForLocalPrintJobCompletion } from "./cups";
import { printLabel } from "./render";
import { loadAgentState } from "./state";
import { buildPrinterAgentActionPayload, signPrinterAgentPayload } from "../services/printerAgentSigningService";
import { randomOpaqueToken } from "../utils/security";

const DIRECT_PRINT_POLL_MS = Math.max(2000, Number(process.env.PRINT_AGENT_DIRECT_POLL_MS || 4000) || 4000);
const AGENT_VERSION = String(process.env.PRINT_AGENT_VERSION || "1.0.0").trim() || "1.0.0";

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
    throw new Error(String((payload as any)?.error || `Direct-print agent request failed: HTTP ${response.status}`));
  }
  return payload as T;
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

  return postBackend<{ success: boolean; data?: any }>("/printer-agent/local/claim", {
    ...signed.body,
    selectedPrinterId,
    selectedPrinterName: selection.printerName,
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
  });
};

const ackLocalJob = async (payload: {
  printerId: string;
  printJobId: string;
  printItemId: string;
  payloadHash: string;
  printPath: string;
  labelLanguage: string;
  jobRef?: string | null;
}) => {
  const signed = await buildSignedBody({
    action: "ack",
    printerId: payload.printerId,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
  });

  await postBackend("/printer-agent/local/ack", {
    ...signed.body,
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    payloadHash: payload.payloadHash,
    bytesWritten: Math.max(1, payload.payloadHash.length),
    deviceJobRef: payload.jobRef || null,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      printPath: payload.printPath,
      labelLanguage: payload.labelLanguage,
      jobRef: payload.jobRef || null,
    },
  });
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
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    payloadHash: payload.payloadHash,
    bytesWritten: Math.max(1, payload.payloadHash.length),
    deviceJobRef: payload.jobRef || null,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
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
    printJobId: payload.printJobId,
    printItemId: payload.printItemId,
    reason: payload.reason,
    agentMetadata: {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
    },
  });
};

const runOnce = async () => {
  const claimed = await claimNextLocalJob();
  if (!claimed?.data) return;

  const payload = claimed.data;
  const calibrationProfile =
    payload.calibrationProfile && typeof payload.calibrationProfile === "object"
      ? (payload.calibrationProfile as Record<string, unknown>)
      : null;
  const printerId = String(
    payload.printer?.nativePrinterId || payload.printer?.selectedPrinterId || payload.selectedPrinterId || ""
  ).trim();

  if (!printerId) {
    await failLocalJob({
      printerId: "unknown-printer",
      printJobId: String(payload.printJobId || "").trim(),
      printItemId: String(payload.printItemId || "").trim(),
      reason: "Local agent has no selected workstation printer for this job.",
    });
    return;
  }

  try {
    const result = await printLabel({
      printerId,
      printerName: String(payload.printer?.name || payload.selectedPrinterName || printerId).trim(),
      printerLanguages: Array.isArray(payload.printer?.languages) ? payload.printer.languages : [],
      calibrationProfile,
      request: {
        code: String(payload.code || "").trim(),
        scanUrl: String(payload.scanUrl || "").trim(),
        payloadType: payload.payloadType || null,
        payloadContent: payload.payloadContent || null,
        payloadHash: payload.payloadHash || null,
        previewLabel: payload.previewLabel || null,
        copies: 1,
        printPath: payload.printPath || "auto",
        labelLanguage: payload.commandLanguage || payload.labelLanguage || null,
        mediaSize: payload.mediaSize || null,
      },
    });

    await ackLocalJob({
      printerId,
      printJobId: String(payload.printJobId || "").trim(),
      printItemId: String(payload.printItemId || "").trim(),
      payloadHash: String(payload.payloadHash || "").trim(),
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
      printJobId: String(payload.printJobId || "").trim(),
      printItemId: String(payload.printItemId || "").trim(),
      payloadHash: String(payload.payloadHash || "").trim(),
      printPath: result.printPath,
      labelLanguage: result.labelLanguage,
      jobRef: result.jobRef,
    });
  } catch (error: any) {
    await failLocalJob({
      printerId,
      printJobId: String(payload.printJobId || "").trim(),
      printItemId: String(payload.printItemId || "").trim(),
      reason: error?.message || "Local direct-print pipeline failed.",
    });
    throw error;
  }
};

export const startDirectPrintWorker = () => {
  let stopped = false;

  const loop = async () => {
    while (!stopped) {
      try {
        if (await resolveBackendUrl()) {
          await runOnce();
        }
      } catch (error) {
        console.error("local direct-print worker cycle failed:", error);
      }
      await new Promise((resolve) => setTimeout(resolve, DIRECT_PRINT_POLL_MS));
    }
  };

  void loop();

  return () => {
    stopped = true;
  };
};

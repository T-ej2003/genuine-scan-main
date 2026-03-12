import os from "os";
import { createHash } from "crypto";

import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { submitPdfToIppPrinter } from "../printing/ippClient";
import { loadAgentState } from "./state";

const BACKEND_URL = String(process.env.PRINT_GATEWAY_BACKEND_URL || "").trim().replace(/\/+$/, "");
const GATEWAY_ID = String(process.env.PRINT_GATEWAY_ID || "").trim();
const GATEWAY_SECRET = String(process.env.PRINT_GATEWAY_SECRET || "").trim();
const GATEWAY_POLL_MS = Math.max(2500, Number(process.env.PRINT_GATEWAY_POLL_MS || 5000) || 5000);
const AGENT_VERSION = String(process.env.PRINT_AGENT_VERSION || "1.0.0").trim() || "1.0.0";

const sha256Hex = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

const configured = () => Boolean(BACKEND_URL && GATEWAY_ID && GATEWAY_SECRET);

const gatewayHeaders = () => ({
  "Content-Type": "application/json",
  "x-printer-gateway-id": GATEWAY_ID,
  "x-printer-gateway-secret": GATEWAY_SECRET,
});

const postGateway = async <T>(path: string, body: Record<string, unknown>) => {
  const response = await fetch(`${BACKEND_URL}/api${path}`, {
    method: "POST",
    headers: gatewayHeaders(),
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(String((payload as any)?.error || `Gateway request failed: HTTP ${response.status}`));
  }
  return payload as T;
};

const heartbeat = async (error?: string | null) => {
  const state = await loadAgentState();
  await postGateway("/print-gateway/heartbeat", {
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
    agentId: state.agentId,
    deviceFingerprint: state.deviceFingerprint,
    error: error || undefined,
  });
};

const claimNextJob = async () => {
  const response = await postGateway<{ success: boolean; data?: any }>("/print-gateway/ipp/claim", {
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
  });
  return response?.data || null;
};

const confirmJob = async (payload: {
  printJobId: string;
  printItemId: string;
  payloadHash: string;
  bytesWritten: number;
  ippJobId?: number | null;
}) => {
  await postGateway("/print-gateway/ipp/confirm", payload);
};

const failJob = async (payload: {
  printJobId: string;
  printItemId: string;
  reason: string;
}) => {
  await postGateway("/print-gateway/ipp/fail", payload);
};

const runOnce = async () => {
  const claimed = await claimNextJob();
  if (!claimed) return;

  const pdf = await renderPdfLabelBuffer({
    code: String(claimed.code || "").trim(),
    scanUrl: String(claimed.scanUrl || "").trim(),
    previewLabel: String(claimed.previewLabel || "MSCQR QR LABEL").trim(),
    calibrationProfile:
      claimed.calibrationProfile && typeof claimed.calibrationProfile === "object"
        ? (claimed.calibrationProfile as Record<string, unknown>)
        : null,
  });
  const payloadHash = sha256Hex(pdf);

  try {
    const result = await submitPdfToIppPrinter({
      profile: {
        host: claimed.printer?.host,
        port: claimed.printer?.port,
        resourcePath: claimed.printer?.resourcePath,
        tlsEnabled: claimed.printer?.tlsEnabled,
        printerUri: claimed.printer?.printerUri,
      },
      pdf,
      jobName: `${String(claimed.jobNumber || "MSCQR").trim() || "MSCQR"}-${String(claimed.code || "").trim()}`,
      requestingUserName: GATEWAY_ID,
    });

    await confirmJob({
      printJobId: String(claimed.printJobId || "").trim(),
      printItemId: String(claimed.printItemId || "").trim(),
      payloadHash,
      bytesWritten: pdf.length,
      ippJobId: result.jobId,
    });
  } catch (error: any) {
    await failJob({
      printJobId: String(claimed.printJobId || "").trim(),
      printItemId: String(claimed.printItemId || "").trim(),
      reason: error?.message || "Gateway IPP dispatch failed.",
    });
    throw error;
  }
};

export const startGatewayWorker = () => {
  if (!configured()) {
    return () => undefined;
  }

  let stopped = false;
  const loop = async () => {
    while (!stopped) {
      try {
        await heartbeat(null);
        await runOnce();
      } catch (error: any) {
        console.error("gateway worker cycle failed:", error);
        try {
          await heartbeat(error?.message || "Gateway worker cycle failed.");
        } catch (heartbeatError) {
          console.error("gateway worker heartbeat failed:", heartbeatError);
        }
      }
      await new Promise((resolve) => setTimeout(resolve, GATEWAY_POLL_MS));
    }
  };

  void loop();
  return () => {
    stopped = true;
  };
};

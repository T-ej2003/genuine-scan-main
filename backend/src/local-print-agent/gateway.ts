import os from "os";
import { createHash } from "crypto";

import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { inspectIppJob, submitPdfToIppPrinter } from "../printing/ippClient";
import { sendRawPayloadToNetworkPrinter } from "../services/networkPrinterSocketService";
import { getZebraTotalLabelCount, waitForZebraLabelConfirmation } from "../services/zebraPrinterStatusService";
import { loadAgentState } from "./state";

const BACKEND_URL = String(process.env.PRINT_GATEWAY_BACKEND_URL || "").trim().replace(/\/+$/, "");
const GATEWAY_ID = String(process.env.PRINT_GATEWAY_ID || "").trim();
const GATEWAY_SECRET = String(process.env.PRINT_GATEWAY_SECRET || "").trim();
const GATEWAY_POLL_MS = Math.max(2500, Number(process.env.PRINT_GATEWAY_POLL_MS || 5000) || 5000);
const AGENT_VERSION = String(process.env.PRINT_AGENT_VERSION || "1.0.0").trim() || "1.0.0";
const GATEWAY_IPP_CONFIRM_POLL_MS = Math.max(
  500,
  Number(process.env.PRINT_GATEWAY_IPP_CONFIRM_POLL_MS || 1500) || 1500
);
const GATEWAY_IPP_CONFIRM_TIMEOUT_MS = Math.max(
  5_000,
  Number(process.env.PRINT_GATEWAY_IPP_CONFIRM_TIMEOUT_MS || 120_000) || 120_000
);

const sha256Hex = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

type GatewayConnectionType = "NETWORK_IPP" | "NETWORK_DIRECT";

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
  const response = await postGateway<{ success: boolean; data?: { connectionType?: GatewayConnectionType } }>(
    "/print-gateway/heartbeat",
    {
      deviceName: os.hostname(),
      agentVersion: AGENT_VERSION,
      agentId: state.agentId,
      deviceFingerprint: state.deviceFingerprint,
      error: error || undefined,
    }
  );
  return response?.data || null;
};

const claimNextJob = async (connectionType: GatewayConnectionType) => {
  const path = connectionType === "NETWORK_DIRECT" ? "/print-gateway/direct/claim" : "/print-gateway/ipp/claim";
  const response = await postGateway<{ success: boolean; data?: any }>(path, {
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
  });
  return response?.data || null;
};

const claimTestJob = async () => {
  const response = await postGateway<{ success: boolean; data?: any }>("/print-gateway/test/claim", {
    deviceName: os.hostname(),
    agentVersion: AGENT_VERSION,
  });
  return response?.data || null;
};

const ackJob = async (connectionType: GatewayConnectionType, payload: Record<string, unknown>) => {
  const path = connectionType === "NETWORK_DIRECT" ? "/print-gateway/direct/ack" : "/print-gateway/ipp/ack";
  await postGateway(path, payload);
};

const confirmJob = async (connectionType: GatewayConnectionType, payload: Record<string, unknown>) => {
  const path = connectionType === "NETWORK_DIRECT" ? "/print-gateway/direct/confirm" : "/print-gateway/ipp/confirm";
  await postGateway(path, payload);
};

const ackTestJob = async (payload: Record<string, unknown>) => {
  await postGateway("/print-gateway/test/ack", payload);
};

const confirmTestJob = async (payload: Record<string, unknown>) => {
  await postGateway("/print-gateway/test/confirm", payload);
};

const failJob = async (
  connectionType: GatewayConnectionType,
  payload: {
    printJobId: string;
    printItemId: string;
    reason: string;
    gatewayMetadata?: Record<string, unknown>;
  }
) => {
  const path = connectionType === "NETWORK_DIRECT" ? "/print-gateway/direct/fail" : "/print-gateway/ipp/fail";
  await postGateway(path, payload);
};

const failTestJob = async (payload: {
  testJobId: string;
  reason: string;
  gatewayMetadata?: Record<string, unknown>;
}) => {
  await postGateway("/print-gateway/test/fail", payload);
};

const waitForIppCompletion = async (claimed: any, ippJobId: number) => {
  const deadline = Date.now() + GATEWAY_IPP_CONFIRM_TIMEOUT_MS;

  while (Date.now() < deadline) {
    const inspection = await inspectIppJob({
      profile: {
        host: claimed.printer?.host,
        port: claimed.printer?.port,
        resourcePath: claimed.printer?.resourcePath,
        tlsEnabled: claimed.printer?.tlsEnabled,
        printerUri: claimed.printer?.printerUri,
      },
      jobId: ippJobId,
    });
    const reasons = inspection.jobStateReasons.map((value) => value.toLowerCase());

    if (inspection.jobState === 9) {
      if (reasons.some((reason) => reason.includes("completed-with-errors") || reason.includes("job-completed-with-errors"))) {
        throw new Error(`IPP job ${ippJobId} completed with printer-reported errors: ${inspection.jobStateReasons.join(", ")}`);
      }
      return inspection;
    }

    if (inspection.jobState === 7 || inspection.jobState === 8) {
      throw new Error(
        `IPP job ${ippJobId} reached terminal failure state ${inspection.jobState}: ${
          inspection.jobStateMessage || inspection.jobStateReasons.join(", ") || "printer rejected the job"
        }`
      );
    }

    await sleep(GATEWAY_IPP_CONFIRM_POLL_MS);
  }

  throw new Error(`IPP job ${ippJobId} did not reach terminal completion before the gateway confirmation timeout.`);
};

const runIppJob = async (claimed: any) => {
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
  if (!result.jobId) {
    throw new Error("Gateway IPP printer accepted the payload but did not return a job id for terminal confirmation.");
  }

  await ackJob("NETWORK_IPP", {
    printJobId: String(claimed.printJobId || "").trim(),
    printItemId: String(claimed.printItemId || "").trim(),
    payloadHash,
    bytesWritten: pdf.length,
    deviceJobRef: result.jobId ? String(result.jobId) : null,
    ippJobId: result.jobId || undefined,
    payloadType: "PDF",
    gatewayMetadata: {
      printerUri: result.printerUri,
      endpointUrl: result.endpointUrl,
      jobUri: result.jobUri,
    },
  });

  const inspection = await waitForIppCompletion(claimed, Number(result.jobId || 0));
  await confirmJob("NETWORK_IPP", {
    printJobId: String(claimed.printJobId || "").trim(),
    printItemId: String(claimed.printItemId || "").trim(),
    payloadHash,
    bytesWritten: pdf.length,
    deviceJobRef: result.jobId ? String(result.jobId) : null,
    ippJobId: result.jobId || undefined,
    payloadType: "PDF",
    gatewayMetadata: {
      printerUri: inspection.printerUri,
      endpointUrl: inspection.endpointUrl,
      jobUri: inspection.jobUri,
      jobState: inspection.jobState,
      jobStateReasons: inspection.jobStateReasons,
      jobStateMessage: inspection.jobStateMessage,
      impressionsCompleted: inspection.impressionsCompleted,
      mediaSheetsCompleted: inspection.mediaSheetsCompleted,
      pagesCompleted: inspection.pagesCompleted,
    },
  });
};

const runDirectJob = async (claimed: any) => {
  const printerIpAddress = String(claimed.printer?.ipAddress || "").trim();
  const printerPort = Number(claimed.printer?.port || 0) || 0;
  if (!printerIpAddress || printerPort <= 0) {
    throw new Error("Gateway-backed direct printer is missing IP/port information.");
  }

  const payloadContent = String(claimed.payloadContent || "");
  const payloadHash = String(claimed.payloadHash || "").trim();
  if (!payloadContent || !payloadHash) {
    throw new Error("Gateway-backed direct job is missing its approved payload.");
  }
  if (sha256Hex(payloadContent) !== payloadHash) {
    throw new Error("Gateway-backed direct payload hash mismatch.");
  }

  const startingLabelCount = await getZebraTotalLabelCount({
    ipAddress: printerIpAddress,
    port: printerPort,
  });
  const socketResult = await sendRawPayloadToNetworkPrinter({
    ipAddress: printerIpAddress,
    port: printerPort,
    payload: payloadContent,
  });

  const deviceJobRef = `zebra-odometer:${startingLabelCount}`;
  await ackJob("NETWORK_DIRECT", {
    printJobId: String(claimed.printJobId || "").trim(),
    printItemId: String(claimed.printItemId || "").trim(),
    payloadHash,
    bytesWritten: socketResult.bytesWritten,
    payloadType: String(claimed.payloadType || "").trim() || null,
    deviceJobRef,
    gatewayMetadata: {
      startingLabelCount,
      expectedIncrement: 1,
      printerIpAddress,
      printerPort,
    },
  });

  const zebraStatus = await waitForZebraLabelConfirmation({
    ipAddress: printerIpAddress,
    port: printerPort,
    startingLabelCount,
    expectedIncrement: 1,
  });

  await confirmJob("NETWORK_DIRECT", {
    printJobId: String(claimed.printJobId || "").trim(),
    printItemId: String(claimed.printItemId || "").trim(),
    payloadHash,
    bytesWritten: socketResult.bytesWritten,
    payloadType: String(claimed.payloadType || "").trim() || null,
    deviceJobRef,
    gatewayMetadata: {
      startingLabelCount,
      confirmedLabelCount: zebraStatus.lastCount,
      expectedIncrement: 1,
      printerIpAddress,
      printerPort,
    },
  });
};

const runIppTestJob = async (claimed: any) => {
  const pdf = await renderPdfLabelBuffer({
    code: String(claimed.code || "").trim(),
    scanUrl: String(claimed.scanUrl || "").trim(),
    previewLabel: String(claimed.previewLabel || "MSCQR PRINTER TEST LABEL").trim(),
    calibrationProfile:
      claimed.calibrationProfile && typeof claimed.calibrationProfile === "object"
        ? (claimed.calibrationProfile as Record<string, unknown>)
        : null,
  });
  const payloadHash = sha256Hex(pdf);

  const result = await submitPdfToIppPrinter({
    profile: {
      host: claimed.printer?.host,
      port: claimed.printer?.port,
      resourcePath: claimed.printer?.resourcePath,
      tlsEnabled: claimed.printer?.tlsEnabled,
      printerUri: claimed.printer?.printerUri,
    },
    pdf,
    jobName: `${String(claimed.jobNumber || "MSCQR-SETUP").trim() || "MSCQR-SETUP"}-${String(claimed.code || "").trim()}`,
    requestingUserName: GATEWAY_ID,
  });
  if (!result.jobId) {
    throw new Error("Gateway IPP printer accepted the setup test but did not return a job id for completion confirmation.");
  }

  await ackTestJob({
    testJobId: String(claimed.testJobId || "").trim(),
    payloadHash,
    bytesWritten: pdf.length,
    deviceJobRef: result.jobId ? String(result.jobId) : null,
    ippJobId: result.jobId || undefined,
    payloadType: "PDF",
    gatewayMetadata: {
      printerUri: result.printerUri,
      endpointUrl: result.endpointUrl,
      jobUri: result.jobUri,
    },
  });

  const inspection = await waitForIppCompletion(claimed, Number(result.jobId || 0));
  await confirmTestJob({
    testJobId: String(claimed.testJobId || "").trim(),
    payloadHash,
    bytesWritten: pdf.length,
    deviceJobRef: result.jobId ? String(result.jobId) : null,
    ippJobId: result.jobId || undefined,
    payloadType: "PDF",
    gatewayMetadata: {
      printerUri: inspection.printerUri,
      endpointUrl: inspection.endpointUrl,
      jobUri: inspection.jobUri,
      jobState: inspection.jobState,
      jobStateReasons: inspection.jobStateReasons,
      jobStateMessage: inspection.jobStateMessage,
      impressionsCompleted: inspection.impressionsCompleted,
      mediaSheetsCompleted: inspection.mediaSheetsCompleted,
      pagesCompleted: inspection.pagesCompleted,
    },
  });
};

const runDirectTestJob = async (claimed: any) => {
  const printerIpAddress = String(claimed.printer?.ipAddress || "").trim();
  const printerPort = Number(claimed.printer?.port || 0) || 0;
  if (!printerIpAddress || printerPort <= 0) {
    throw new Error("Gateway-backed direct printer is missing IP/port information.");
  }

  const payloadContent = String(claimed.payloadContent || "");
  const payloadHash = String(claimed.payloadHash || "").trim();
  if (!payloadContent || !payloadHash) {
    throw new Error("Gateway-backed setup test is missing its approved payload.");
  }
  if (sha256Hex(payloadContent) !== payloadHash) {
    throw new Error("Gateway-backed setup test payload hash mismatch.");
  }

  const startingLabelCount = await getZebraTotalLabelCount({
    ipAddress: printerIpAddress,
    port: printerPort,
  });
  const socketResult = await sendRawPayloadToNetworkPrinter({
    ipAddress: printerIpAddress,
    port: printerPort,
    payload: payloadContent,
  });

  const deviceJobRef = `zebra-odometer:${startingLabelCount}`;
  await ackTestJob({
    testJobId: String(claimed.testJobId || "").trim(),
    payloadHash,
    bytesWritten: socketResult.bytesWritten,
    payloadType: String(claimed.payloadType || "").trim() || null,
    deviceJobRef,
    gatewayMetadata: {
      startingLabelCount,
      expectedIncrement: 1,
      printerIpAddress,
      printerPort,
    },
  });

  const zebraStatus = await waitForZebraLabelConfirmation({
    ipAddress: printerIpAddress,
    port: printerPort,
    startingLabelCount,
    expectedIncrement: 1,
  });

  await confirmTestJob({
    testJobId: String(claimed.testJobId || "").trim(),
    payloadHash,
    bytesWritten: socketResult.bytesWritten,
    payloadType: String(claimed.payloadType || "").trim() || null,
    deviceJobRef,
    gatewayMetadata: {
      startingLabelCount,
      confirmedLabelCount: zebraStatus.lastCount,
      expectedIncrement: 1,
      printerIpAddress,
      printerPort,
    },
  });
};

const runOnce = async (connectionType: GatewayConnectionType) => {
  const claimed = await claimNextJob(connectionType);
  if (!claimed) {
    const claimedTest = await claimTestJob();
    if (!claimedTest) return;

    try {
      if (connectionType === "NETWORK_DIRECT") {
        await runDirectTestJob(claimedTest);
        return;
      }

      await runIppTestJob(claimedTest);
    } catch (error: any) {
      await failTestJob({
        testJobId: String(claimedTest.testJobId || "").trim(),
        reason: error?.message || "Gateway setup test failed.",
        gatewayMetadata: {
          connectionType,
        },
      }).catch(() => undefined);
      throw error;
    }
    return;
  }

  try {
    if (connectionType === "NETWORK_DIRECT") {
      await runDirectJob(claimed);
      return;
    }

    await runIppJob(claimed);
  } catch (error: any) {
    await failJob(connectionType, {
      printJobId: String(claimed.printJobId || "").trim(),
      printItemId: String(claimed.printItemId || "").trim(),
      reason: error?.message || "Gateway dispatch failed.",
      gatewayMetadata: {
        connectionType,
      },
    }).catch(() => undefined);
    throw error;
  }
};

export const startGatewayWorker = () => {
  if (!configured()) {
    return () => undefined;
  }

  let stopped = false;
  let connectionType: GatewayConnectionType | null = null;
  const loop = async () => {
    while (!stopped) {
      try {
        const heartbeatData = await heartbeat(null);
        connectionType = (heartbeatData?.connectionType as GatewayConnectionType | undefined) || connectionType;
        if (connectionType) {
          await runOnce(connectionType);
        }
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

import { randomUUID } from "node:crypto";

import { logger } from "../utils/logger";
import { runNetworkPrintingWorker } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { sendRawPayloadToNetworkPrinter } from "./networkPrinterSocketService";
import { buildApprovedPrintPayload } from "./printPayloadService";

const activeDispatches = new Set<string>();

const qr = (item: any) => ({
  id: item.qrCodeId,
  code: item.code,
  displayCode: item.displayCode,
  batchId: item.batchId,
  licenseeId: item.licenseeId,
  tokenNonce: item.tokenNonce,
  tokenIssuedAt: item.tokenIssuedAt ? new Date(item.tokenIssuedAt) : null,
  tokenExpiresAt: item.tokenExpiresAt ? new Date(item.tokenExpiresAt) : null,
  tokenHash: item.tokenHash,
  replayEpoch: item.replayEpoch,
});

const dispatchChunk = async (jobId?: string | null) => {
  const requestId = randomUUID();
  const claim = await runNetworkPrintingWorker({
    operation: "CLAIM_DIRECT",
    requestId,
    jobId,
    details: { limit: 100 },
  });
  if (!claim?.available) return false;
  const payload = claim.items.map((item: any) =>
    buildApprovedPrintPayload({
      printer: claim.printer,
      qr: qr(item),
      manufacturerId: claim.job.manufacturerId,
      printJobId: claim.job.id,
      printItemId: item.id,
      jobNumber: claim.job.jobNumber,
      reprintOfJobId: claim.job.reprintOfJobId,
    }).payloadContent
  ).join("");
  try {
    const sent = await sendRawPayloadToNetworkPrinter({
      ipAddress: String(claim.printer.ipAddress || claim.printer.host || ""),
      port: Number(claim.printer.port || 9100),
      payload,
    });
    await runNetworkPrintingWorker({
      operation: "CONFIRM",
      requestId: randomUUID(),
      jobId: claim.job.id,
      details: { itemIds: claim.items.map((item: any) => item.id), transportReference: `tcp:${sent.bytesWritten}` },
    });
  } catch (error: any) {
    await runNetworkPrintingWorker({
      operation: "FAIL",
      requestId: randomUUID(),
      jobId: claim.job.id,
      details: { itemIds: claim.items.map((item: any) => item.id), reason: String(error?.message || "network_transport_failed").slice(0, 500) },
    });
    throw error;
  }
  return true;
};

const runJob = async (jobId?: string | null) => {
  while (await dispatchChunk(jobId)) {
    if (!jobId) break;
  }
};

export const startNetworkDirectDispatch = async (params: { jobId: string; actorUserId: string }) => {
  if (activeDispatches.has(params.jobId)) return { started: false, reason: "already_running" as const };
  activeDispatches.add(params.jobId);
  setImmediate(async () => {
    try {
      await runJob(params.jobId);
    } catch (error: any) {
      logger.error("Network-direct dispatcher failed", { jobId: params.jobId, error: error?.message || error });
    } finally {
      activeDispatches.delete(params.jobId);
    }
  });
  return { started: true };
};

export const resumePendingNetworkDirectJobs = async () => {
  for (let index = 0; index < 25 && await dispatchChunk(null); index += 1) {
    // bounded worker drain
  }
};

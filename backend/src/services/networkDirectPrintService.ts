import { randomUUID } from "node:crypto";

import { logger } from "../utils/logger";
import { runNetworkPrintingWorker } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { sendRawPayloadToNetworkPrinter } from "./networkPrinterSocketService";
import { buildApprovedPrintPayload } from "./printPayloadService";
import { getZebraTotalLabelCount, waitForZebraLabelConfirmation } from "./zebraPrinterStatusService";

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
  let physicalAttemptStarted=false;
  let reservationStarted=false;
  try {
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
    const ipAddress=String(claim.printer.ipAddress || claim.printer.host || '');
    const port=Number(claim.printer.port || 9100);
    if(!ipAddress || !Number.isInteger(port) || port<1 || port>65535) throw new Error('Invalid direct printer configuration.');
    const startingLabelCount=await getZebraTotalLabelCount({ipAddress,port});
    if(!Number.isSafeInteger(startingLabelCount) || startingLabelCount<0)throw new Error('Printer returned an invalid odometer baseline.');
    reservationStarted=true;
    await runNetworkPrintingWorker({operation:'RESERVE_DISPATCH',requestId:randomUUID(),jobId:claim.job.id,details:{itemIds:claim.items.map((item:any)=>item.id)}});
    physicalAttemptStarted=true;
    const sent = await sendRawPayloadToNetworkPrinter({
      ipAddress: String(claim.printer.ipAddress || claim.printer.host || ""),
      port: Number(claim.printer.port || 9100),
      payload,
    });
    await runNetworkPrintingWorker({
      operation: "ACK",
      requestId: randomUUID(),
      jobId: claim.job.id,
      details: { itemIds: claim.items.map((item: any) => item.id), transportReference: `tcp:${sent.bytesWritten}`, startingLabelCount },
    });
    const completion=await waitForZebraLabelConfirmation({ipAddress,port,startingLabelCount,expectedIncrement:claim.items.length});
    await runNetworkPrintingWorker({operation:'CONFIRM',requestId:randomUUID(),jobId:claim.job.id,
      details:{itemIds:claim.items.map((item:any)=>item.id),transportReference:`tcp:${sent.bytesWritten}`,
        confirmationEvidence:{kind:'ZEBRA_ODOMETER',printerId:claim.printer.id,startingLabelCount,confirmedLabelCount:completion.lastCount}}});
  } catch (error: any) {
    if(physicalAttemptStarted || reservationStarted) {
      logger.error('Network-direct physical outcome requires reconciliation',{jobId:claim.job.id});
      throw error;
    }
    await runNetworkPrintingWorker({
      operation: "FAIL",
      requestId: randomUUID(),
      jobId: claim.job.id,
      details: { itemIds: claim.items.map((item: any) => item.id), failureClassification:'PRE_DISPATCH_FAILURE', reason: String(error?.message || "network_preparation_failed").slice(0, 500) },
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

import { randomUUID } from "node:crypto";

import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { buildIppConnectionInfo, inspectIppJob, submitPdfToIppPrinter } from "../printing/ippClient";
import { runNetworkPrintingWorker } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { logger } from "../utils/logger";
import { buildApprovedPrintContext } from "./printPayloadService";

const activeDispatches = new Set<string>();

export const isGatewayFresh = (lastSeenAt?: Date | string | null) =>
  Boolean(lastSeenAt && Date.now() - new Date(lastSeenAt).getTime() <= 45_000);

const dispatchChunk = async (jobId?: string | null) => {
  const claim = await runNetworkPrintingWorker({
    operation: "CLAIM_IPP",
    requestId: randomUUID(),
    jobId,
    details: { limit: 25 },
  });
  if (!claim?.available) return false;
  let physicalAttemptStarted=false;
  try {
    const connection=buildIppConnectionInfo(claim.printer);
    if(!Number.isInteger(connection.port) || connection.port<1 || connection.port>65535)throw new Error('Invalid IPP printer configuration.');
    for (const item of claim.items) {
      const context = buildApprovedPrintContext({
        qr: {
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
        },
        manufacturerId: claim.job.manufacturerId,
        reprintOfJobId: claim.job.reprintOfJobId,
      });
      const pdf = await renderPdfLabelBuffer({
        code: item.code,
        scanUrl: context.scanUrl,
        previewLabel: context.previewLabel,
        calibrationProfile: claim.printer.calibrationProfile,
      });
      physicalAttemptStarted=true;
      const submitted = await submitPdfToIppPrinter({
        profile: claim.printer,
        pdf,
        jobName: `${claim.job.jobNumber}-${item.id}`,
        requestingUserName: "mscqr-print-worker",
      });
      await runNetworkPrintingWorker({
        operation: "ACK",
        requestId: randomUUID(),
        jobId: claim.job.id,
        details: { itemIds: [item.id], transportReference: submitted.jobId ? `ipp:${submitted.jobId}` : submitted.jobUri || "ipp:accepted",ippJobId:submitted.jobId },
      });
      if(!submitted.jobId)throw new Error('IPP accepted transport without a verifiable job identity. Reconciliation required.');
      const deadline=Date.now()+120000;
      let completed=false;
      while(Date.now()<deadline) {
        const status=await inspectIppJob({profile:claim.printer,jobId:submitted.jobId});
        if(status.jobStateReasons.some(reason=>/completed-with-errors/i.test(reason)) || [7,8].includes(Number(status.jobState)))throw new Error('IPP device reported an unsuccessful or uncertain physical outcome.');
        if(status.jobState===9) {
          await runNetworkPrintingWorker({operation:'CONFIRM',requestId:randomUUID(),jobId:claim.job.id,
            details:{itemIds:[item.id],transportReference:`ipp:${submitted.jobId}`,confirmationEvidence:{kind:'IPP_COMPLETED',printerId:claim.printer.id,ippJobId:submitted.jobId,jobState:9,jobStateReasons:status.jobStateReasons}}});
          completed=true;break;
        }
        await new Promise(resolve=>setTimeout(resolve,1500));
      }
      if(!completed)throw new Error('IPP device completion is uncertain; automatic replay refused.');
    }
  } catch (error: any) {
    if(!physicalAttemptStarted) {
      await runNetworkPrintingWorker({
        operation: "FAIL",
        requestId: randomUUID(),
        jobId: claim.job.id,
        details: { itemIds: claim.items.map((item:any)=>item.id),failureClassification:'PRE_DISPATCH_FAILURE', reason: String(error?.message || "ipp_preparation_failed").slice(0, 500) },
      });
    } else {
      logger.error('IPP physical outcome requires reconciliation',{jobId:claim.job.id});
    }
    throw error;
  }
  return true;
};

const runJob = async (jobId?: string | null) => {
  while (await dispatchChunk(jobId)) {
    if (!jobId) break;
  }
};

export const startNetworkIppDispatch = async (params: { jobId: string; actorUserId: string }) => {
  if (activeDispatches.has(params.jobId)) return { started: false, reason: "already_running" as const };
  activeDispatches.add(params.jobId);
  setImmediate(async () => {
    try {
      await runJob(params.jobId);
    } catch (error: any) {
      logger.error("Network IPP dispatcher failed", { jobId: params.jobId, error: error?.message || error });
    } finally {
      activeDispatches.delete(params.jobId);
    }
  });
  return { started: true };
};

export const resumePendingNetworkIppJobs = async () => {
  for (let index = 0; index < 25 && await dispatchChunk(null); index += 1) {
    // bounded worker drain
  }
};

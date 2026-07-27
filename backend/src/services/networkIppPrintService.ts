import { randomUUID } from "node:crypto";

import { renderPdfLabelBuffer } from "../printing/pdfLabel";
import { submitPdfToIppPrinter } from "../printing/ippClient";
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
  const confirmed: string[] = [];
  try {
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
      const submitted = await submitPdfToIppPrinter({
        profile: claim.printer,
        pdf,
        jobName: `${claim.job.jobNumber}-${item.id}`,
        requestingUserName: "mscqr-print-worker",
      });
      await runNetworkPrintingWorker({
        operation: "CONFIRM",
        requestId: randomUUID(),
        jobId: claim.job.id,
        details: { itemIds: [item.id], transportReference: submitted.jobId ? `ipp:${submitted.jobId}` : submitted.jobUri || "ipp:accepted" },
      });
      confirmed.push(item.id);
    }
  } catch (error: any) {
    const remaining = claim.items.map((item: any) => item.id).filter((id: string) => !confirmed.includes(id));
    if (remaining.length) {
      await runNetworkPrintingWorker({
        operation: "FAIL",
        requestId: randomUUID(),
        jobId: claim.job.id,
        details: { itemIds: remaining, reason: String(error?.message || "ipp_transport_failed").slice(0, 500) },
      });
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

import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { buildApprovedPrintPayload } from "./printPayloadService";
import { buildPrintConfirmationDeadline } from "./printConfirmationService";
import { failStopPrintSession } from "./printLifecycleService";

export const LOCAL_AGENT_NO_WORK_RETRY_MS = Math.max(
  2_000,
  Math.min(60_000, Number(process.env.LOCAL_AGENT_NO_WORK_RETRY_MS || 8_000) || 8_000)
);
export const LOCAL_AGENT_BUSY_RETRY_MS = Math.max(
  1_000,
  Math.min(30_000, Number(process.env.LOCAL_AGENT_BUSY_RETRY_MS || 5_000) || 5_000)
);

export const reserveLocalAgentItem = async (params: { printSessionId: string; actorUserId: string }) => {
  const now = new Date();
  const confirmationDeadlineAt = buildPrintConfirmationDeadline(now);
  return prisma.$transaction(async (tx) => {
    const row = await tx.printItem.findFirst({
      where: { printSessionId: params.printSessionId, state: PrintItemState.RESERVED },
      orderBy: { code: "asc" },
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            displayCode: true,
            batchId: true,
            licenseeId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
            replayEpoch: true,
            status: true,
          },
        },
      },
    });
    if (!row) return null;

    const session = await tx.printSession.findUnique({ where: { id: params.printSessionId }, select: { issuedItems: true } });
    const updated = await tx.printItem.updateMany({
      where: { id: row.id, state: PrintItemState.RESERVED },
      data: {
        state: PrintItemState.ISSUED,
        pipelineState: PrintPipelineState.SENT_TO_PRINTER,
        issuedAt: now,
        confirmationDeadlineAt,
        issueSequence: Number(session?.issuedItems || 0) + 1,
      },
    });
    if (updated.count === 0) return null;

    await tx.printItemEvent.create({
      data: {
        printItemId: row.id,
        eventType: PrintItemEventType.ISSUED,
        previousState: PrintItemState.RESERVED,
        nextState: PrintItemState.ISSUED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.LOCAL_AGENT,
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
          confirmationDeadlineAt: confirmationDeadlineAt.toISOString(),
        },
      },
    });

    await tx.printSession.update({
      where: { id: params.printSessionId },
      data: { issuedItems: { increment: 1 } },
    });

    return row;
  });
};

export const countLocalAgentClaimItems = async (params: { printerIds: string[]; manufacturerId: string }) => {
  const sessionFilter = {
    status: "ACTIVE" as const,
    printerId: { in: params.printerIds },
    printJob: {
      status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
      printMode: PrintDispatchMode.LOCAL_AGENT,
      manufacturerId: params.manufacturerId,
    },
  };
  const [availableItemCount, inFlightItemCount] = await Promise.all([
    prisma.printItem.count({
      where: {
        state: PrintItemState.RESERVED,
        printSession: { is: sessionFilter },
      },
    }),
    prisma.printItem.count({
      where: {
        state: { in: [PrintItemState.ISSUED, PrintItemState.AGENT_ACKED] },
        printSession: { is: sessionFilter },
      },
    }),
  ]);
  return { availableItemCount, inFlightItemCount };
};

export const buildClaimApprovedPayloadOrFail = async (params: {
  job: any;
  item: any;
  registration: { id: string; agentId: string };
}) => {
  const { job, item, registration } = params;
  if (item.qrCode.status !== QRStatus.ACTIVATED) {
    const reason = `QR ${item.code} is not in ACTIVATED state for local direct printing.`;
    await failStopAndMarkJob(job, item, reason, { dispatchMode: PrintDispatchMode.LOCAL_AGENT });
    return { ok: false as const, status: 409, error: "Reserved QR code is not printable anymore.", code: "qr_not_printable" };
  }

  try {
    return {
      ok: true as const,
      payload: buildApprovedPrintPayload({
        printer: {
          id: job.printer.id,
          name: job.printer.name,
          connectionType: job.printer.connectionType,
          commandLanguage: job.printer.commandLanguage,
          nativePrinterId: job.printer.nativePrinterId,
          ipAddress: job.printer.ipAddress,
          port: job.printer.port,
          calibrationProfile: job.printer.calibrationProfile || null,
          capabilitySummary: job.printer.capabilitySummary || null,
          metadata: job.printer.metadata || null,
        },
        qr: item.qrCode,
        manufacturerId: job.manufacturerId,
        printJobId: job.id,
        printItemId: item.id,
        jobNumber: job.jobNumber,
        reprintOfJobId: job.reprintOfJobId,
      }),
    };
  } catch (payloadError: any) {
    const reason = payloadError?.message || "Approved print payload could not be generated.";
    console.error("local_agent_claim", {
      event: "payload_generation_failed",
      registrationId: registration.id,
      agentId: registration.agentId,
      printJobId: job.id,
      printSessionId: job.printSession.id,
      printItemId: item.id,
      code: item.code,
      error: reason,
    });
    await failStopAndMarkJob(job, item, reason, {
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      failureStage: "claim_payload_generation",
    });
    return {
      ok: false as const,
      status: 409,
      error: "The approved print payload could not be prepared for this label.",
      code: "print_payload_invalid",
    };
  }
};

const failStopAndMarkJob = async (job: any, item: any, reason: string, metadata: Record<string, unknown>) => {
  await failStopPrintSession({
    printSessionId: job.printSession.id,
    printJobId: job.id,
    batchId: job.batchId,
    licenseeId: job.batch.licenseeId || null,
    actorUserId: job.manufacturerId,
    reason,
    printItemId: item.id,
    metadata,
  });
  await prisma.printJob.update({
    where: { id: job.id },
    data: { status: PrintJobStatus.FAILED, pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION, failureReason: reason },
  });
};

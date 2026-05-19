import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
} from "@prisma/client";

import prisma from "../config/database";
import { buildPrintConfirmationDeadline } from "./printConfirmationService";

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
            batchId: true,
            licenseeId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
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

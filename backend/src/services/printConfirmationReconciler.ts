import { PrintItemState, PrintJobStatus, PrintPipelineState, PrintSessionStatus } from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { resumePendingNetworkDirectJobs } from "./networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./networkIppPrintService";
import { failStopPrintSession } from "./printLifecycleService";
import { withDistributedLease } from "./distributedLeaseService";

const RECONCILE_INTERVAL_MS = Math.max(
  5_000,
  Math.min(5 * 60_000, Number(process.env.PRINT_CONFIRMATION_RECONCILE_INTERVAL_MS || 15_000) || 15_000)
);
const ISSUED_WITHOUT_ACK_TIMEOUT_MS = Math.max(
  10_000,
  Math.min(30 * 60_000, Number(process.env.PRINT_ISSUED_WITHOUT_ACK_TIMEOUT_MS || 5 * 60_000) || 5 * 60_000)
);

export const reconcileExpiredAcknowledgedItems = async () => {
  const now = new Date();
  const issuedAckCutoff = new Date(now.getTime() - ISSUED_WITHOUT_ACK_TIMEOUT_MS);
  const expiredItems = await prisma.printItem.findMany({
    where: {
      OR: [
        {
          state: PrintItemState.AGENT_ACKED,
          confirmationDeadlineAt: {
            lte: now,
          },
        },
        {
          state: PrintItemState.ISSUED,
          agentAckedAt: null,
          OR: [
            {
              confirmationDeadlineAt: {
                lte: now,
              },
            },
            {
              confirmationDeadlineAt: null,
              issuedAt: {
                lte: issuedAckCutoff,
              },
            },
          ],
        },
      ],
      printSession: {
        is: {
          status: PrintSessionStatus.ACTIVE,
          printJob: {
            status: {
              in: [PrintJobStatus.PENDING, PrintJobStatus.SENT],
            },
          },
        },
      },
    },
    select: {
      id: true,
      code: true,
      state: true,
      issuedAt: true,
      confirmationDeadlineAt: true,
      printSessionId: true,
      printSession: {
        select: {
          id: true,
          printJob: {
            select: {
              id: true,
              batchId: true,
              manufacturerId: true,
              batch: {
                select: {
                  licenseeId: true,
                },
              },
            },
          },
        },
      },
    },
    orderBy: [{ confirmationDeadlineAt: "asc" }, { issueSequence: "asc" }],
    take: 50,
  });

  const seenSessions = new Set<string>();
  for (const item of expiredItems) {
    if (seenSessions.has(item.printSessionId)) continue;
    seenSessions.add(item.printSessionId);

    try {
      await failStopPrintSession({
        printSessionId: item.printSessionId,
        printJobId: item.printSession.printJob.id,
        batchId: item.printSession.printJob.batchId,
        licenseeId: item.printSession.printJob.batch.licenseeId || null,
        actorUserId: item.printSession.printJob.manufacturerId,
        reason:
          item.state === PrintItemState.ISSUED
            ? `Printer agent did not acknowledge issued label ${item.code} before the deadline.`
            : `Printer confirmation deadline expired for ${item.code}.`,
        printItemId: item.id,
        metadata: {
          reconciliation: true,
          source: "print_confirmation_reconciler",
          itemState: item.state,
          issuedAt: item.issuedAt?.toISOString?.() || null,
          confirmationDeadlineAt: item.confirmationDeadlineAt?.toISOString?.() || null,
        },
      });
      await prisma.printJob.update({
        where: { id: item.printSession.printJob.id },
        data: {
          pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION,
        },
      });
    } catch (error: any) {
      logger.error("Failed to reconcile expired acknowledged print item", {
        printItemId: item.id,
        printSessionId: item.printSessionId,
        error: error?.message || error,
      });
    }
  }
};

export const runPrintConfirmationReconciliationCycle = async () => {
  await reconcileExpiredAcknowledgedItems();
  await Promise.allSettled([resumePendingNetworkDirectJobs(), resumePendingNetworkIppJobs()]);
};

export const startPrintConfirmationReconciler = () => {
  let stopped = false;
  let timer: NodeJS.Timeout | null = null;

  const tick = async () => {
    if (stopped) return;
    try {
      await withDistributedLease(
        "print-confirmation-reconciler",
        Math.max(RECONCILE_INTERVAL_MS * 3, 60_000),
        runPrintConfirmationReconciliationCycle
      );
    } catch (error: any) {
      logger.error("Print confirmation reconciliation cycle failed", {
        error: error?.message || error,
      });
    } finally {
      if (!stopped) {
        timer = setTimeout(() => {
          void tick();
        }, RECONCILE_INTERVAL_MS);
      }
    }
  };

  void tick();

  return () => {
    stopped = true;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
};

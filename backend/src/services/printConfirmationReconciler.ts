import { PrintItemState, PrintJobStatus, PrintSessionStatus } from "@prisma/client";

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

export const reconcileExpiredAcknowledgedItems = async () => {
  const now = new Date();
  const expiredItems = await prisma.printItem.findMany({
    where: {
      state: PrintItemState.AGENT_ACKED,
      confirmationDeadlineAt: {
        lte: now,
      },
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
        reason: `Printer confirmation deadline expired for ${item.code}.`,
        printItemId: item.id,
        metadata: {
          reconciliation: true,
          source: "print_confirmation_reconciler",
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

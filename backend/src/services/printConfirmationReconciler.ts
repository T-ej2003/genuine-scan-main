import { randomUUID } from "node:crypto";

import { logger } from "../utils/logger";
import { reconcilePrintingLifecycle } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { resumePendingNetworkDirectJobs } from "./networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./networkIppPrintService";
import { withDistributedLease } from "./distributedLeaseService";

const RECONCILE_INTERVAL_MS = Math.max(
  5_000,
  Math.min(5 * 60_000, Number(process.env.PRINT_CONFIRMATION_RECONCILE_INTERVAL_MS || 15_000) || 15_000)
);
let shutdownRequested = false;

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const printReconcilerDisabled = () =>
  parseBool(process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS, false) ||
  !parseBool(process.env.RUN_PRINT_RECONCILER, true);

const isShutdownStarted = () => {
  const normalized = String(process.env.INTEGRATION_SHUTDOWN_STARTED || "").trim().toLowerCase();
  return shutdownRequested || ["1", "true", "yes", "on"].includes(normalized);
};

export const reconcileExpiredAcknowledgedItems = async () => {
  if (isShutdownStarted()) return;
  await reconcilePrintingLifecycle({
    operation: "EXPIRE_CONFIRMATIONS",
    requestId: randomUUID(),
    limit: 50,
  });
  await reconcilePrintingLifecycle({
    operation: "RECONCILE_BATCHES",
    requestId: randomUUID(),
    limit: 100,
  });
};

export const runPrintConfirmationReconciliationCycle = async () => {
  if (isShutdownStarted()) return;
  await reconcileExpiredAcknowledgedItems();
  if (isShutdownStarted()) return;
  await Promise.allSettled([resumePendingNetworkDirectJobs(), resumePendingNetworkIppJobs()]);
};

export const startPrintConfirmationReconciler = () => {
  if (printReconcilerDisabled()) return () => undefined;

  let stopped = false;
  let timer: NodeJS.Timeout | null = null;
  shutdownRequested = false;

  const tick = async () => {
    if (stopped || isShutdownStarted()) return;
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
    shutdownRequested = true;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
};

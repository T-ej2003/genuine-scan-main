import dotenv from "dotenv";
import path from "path";

import prisma from "./config/database";
import { logger } from "./utils/logger";
import { releaseMetadata } from "./observability/release";
import { initBackendMonitoring } from "./observability/sentry";
import { startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } from "./services/siemOutboxService";
import { startCompliancePackScheduler, stopCompliancePackScheduler } from "./services/compliancePackService";
import { resumePendingNetworkDirectJobs } from "./services/networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./services/networkIppPrintService";
import { startPrintConfirmationReconciler } from "./services/printConfirmationReconciler";
import { startAnalyticsRollupWorker } from "./services/analyticsRollupService";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

initBackendMonitoring();

let stopPrintConfirmationReconcilerWorker: (() => void) | null = null;
let stopAnalyticsRollupWorker: (() => void) | null = null;
let keepAlive: NodeJS.Timeout | null = null;
let shuttingDown = false;

const boot = async () => {
  logger.info("Worker starting", {
    release: releaseMetadata.release,
    gitSha: releaseMetadata.shortGitSha,
    environment: releaseMetadata.environment,
  });

  startSecurityEventOutboxWorker();
  startCompliancePackScheduler();
  await resumePendingNetworkDirectJobs().catch((error) => {
    logger.error("Worker failed to resume pending network-direct jobs", { error: error?.message || error });
  });
  await resumePendingNetworkIppJobs().catch((error) => {
    logger.error("Worker failed to resume pending network IPP jobs", { error: error?.message || error });
  });
  stopPrintConfirmationReconcilerWorker = startPrintConfirmationReconciler();
  stopAnalyticsRollupWorker = startAnalyticsRollupWorker();

  keepAlive = setInterval(() => {
    logger.debug("Worker heartbeat", {
      release: releaseMetadata.release,
    });
  }, 60_000);
};

const shutdown = async (signal: string) => {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info("Worker shutting down", { signal });

  if (keepAlive) clearInterval(keepAlive);
  keepAlive = null;
  stopPrintConfirmationReconcilerWorker?.();
  stopPrintConfirmationReconcilerWorker = null;
  stopAnalyticsRollupWorker?.();
  stopAnalyticsRollupWorker = null;
  stopSecurityEventOutboxWorker();
  stopCompliancePackScheduler();
  await prisma.$disconnect().catch(() => undefined);
  process.exit(0);
};

void boot().catch((error) => {
  logger.error("Worker failed to start", { error: error?.message || error });
  process.exit(1);
});

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});
process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

import dotenv from "dotenv";
import path from "path";

import prisma from "./config/database";
import { logger } from "./utils/logger";
import { releaseMetadata } from "./observability/release";
import { initBackendMonitoring } from "./observability/sentry";
import { startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } from "./services/siemOutboxService";
import { startAuditLogOutboxWorker, stopAuditLogOutboxWorker } from "./services/auditLogOutboxService";
import { startCompliancePackScheduler, stopCompliancePackScheduler } from "./services/compliancePackService";
import {
  startLegacyQrRiskReportScheduler,
  stopLegacyQrRiskReportScheduler,
} from "./services/legacyQrRiskReportJobService";
import { resumePendingNetworkDirectJobs } from "./services/networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./services/networkIppPrintService";
import { startPrintConfirmationReconciler } from "./services/printConfirmationReconciler";
import { startAnalyticsRollupWorker } from "./services/analyticsRollupService";
import {
  startHotEventPartitionMaintenanceWorker,
  stopHotEventPartitionMaintenanceWorker,
} from "./services/hotEventPartitionService";
import { closeRedisConnections, getRedisHealth } from "./services/redisService";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

initBackendMonitoring();

let stopPrintConfirmationReconcilerWorker: (() => void) | null = null;
let stopAnalyticsRollupWorker: (() => void) | null = null;
let stopHotEventPartitionWorker: (() => void) | null = null;
let keepAlive: NodeJS.Timeout | null = null;
let shuttingDown = false;

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const startKeepAlive = () => {
  keepAlive = setInterval(() => {
    logger.debug("Worker heartbeat", {
      release: releaseMetadata.release,
    });
  }, 60_000);
};

const boot = async () => {
  logger.info("Worker starting", {
    release: releaseMetadata.release,
    gitSha: releaseMetadata.shortGitSha,
    environment: releaseMetadata.environment,
  });

  if (parseBool(process.env.INTEGRATION_WORKER_BOOT_ONLY, false)) {
    if (parseBool(process.env.INTEGRATION_WORKER_ASSERT_REDIS_READY, false)) {
      const redis = await getRedisHealth();
      if (!redis.ready) {
        throw new Error("Integration worker boot-only mode requires a ready Redis dependency.");
      }
    }
    logger.info("Worker boot-only mode enabled; long-running workers skipped");
    startKeepAlive();
    return;
  }

  startSecurityEventOutboxWorker();
  startAuditLogOutboxWorker();
  startCompliancePackScheduler();
  startLegacyQrRiskReportScheduler();
  await resumePendingNetworkDirectJobs().catch((error) => {
    logger.error("Worker failed to resume pending network-direct jobs", { error: error?.message || error });
  });
  await resumePendingNetworkIppJobs().catch((error) => {
    logger.error("Worker failed to resume pending network IPP jobs", { error: error?.message || error });
  });
  stopPrintConfirmationReconcilerWorker = startPrintConfirmationReconciler();
  stopAnalyticsRollupWorker = startAnalyticsRollupWorker();
  stopHotEventPartitionWorker = startHotEventPartitionMaintenanceWorker();
  startKeepAlive();
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
  stopHotEventPartitionWorker?.();
  stopHotEventPartitionWorker = null;
  stopHotEventPartitionMaintenanceWorker();
  stopSecurityEventOutboxWorker();
  stopAuditLogOutboxWorker();
  stopCompliancePackScheduler();
  stopLegacyQrRiskReportScheduler();
  await closeRedisConnections().catch(() => undefined);
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

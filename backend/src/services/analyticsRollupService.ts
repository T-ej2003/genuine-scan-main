import { Prisma } from "@prisma/client";
import { randomUUID } from "crypto";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { withDistributedLease } from "./distributedLeaseService";

const ROLLUP_INTERVAL_MS = Math.max(
  60_000,
  Math.min(15 * 60_000, Number(process.env.ANALYTICS_ROLLUP_REFRESH_MS || 180_000) || 180_000)
);
const ROLLUP_LEASE_MS = Math.max(ROLLUP_INTERVAL_MS * 2, 5 * 60_000);
const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const refreshInventoryStatusRollups = async () => {
  const requestId = randomUUID();
  const [row] = await prisma.$queryRaw<Array<{ updatedBatches: number }>>(Prisma.sql`
    SELECT app_rls.refresh_inventory_status_rollups(${requestId}::text) AS "updatedBatches"
  `);
  return { updatedBatches: Number(row?.updatedBatches || 0) };
};

export const refreshScanMetricsHourlyRollups = async () => {
  const requestId = randomUUID();
  const [row] = await prisma.$queryRaw<Array<{ updatedBuckets: number }>>(Prisma.sql`
    SELECT app_rls.refresh_scan_metrics_hourly_rollups(${requestId}::text) AS "updatedBuckets"
  `);
  return { updatedBuckets: Number(row?.updatedBuckets || 0) };
};

export const refreshAnalyticsRollups = async () => {
  const [inventory, hourly] = await Promise.all([
    refreshInventoryStatusRollups(),
    refreshScanMetricsHourlyRollups(),
  ]);
  return { inventory, hourly };
};

let activeAnalyticsRollupStop: (() => void) | null = null;

export const startAnalyticsRollupWorker = () => {
  if (activeAnalyticsRollupStop) return activeAnalyticsRollupStop;
  if (
    parseBool(process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS, false) ||
    !parseBool(process.env.RUN_ANALYTICS_ROLLUP_WORKER, true)
  ) {
    return () => undefined;
  }

  let stopped = false;
  let timer: NodeJS.Timeout | null = null;
  const tick = async () => {
    if (stopped) return;
    try {
      const lease = await withDistributedLease("analytics-rollup-refresh", ROLLUP_LEASE_MS, refreshAnalyticsRollups);
      if (lease.acquired) logger.info("Analytics rollups refreshed", lease.result || {});
    } catch (error: any) {
      logger.error("Analytics rollup refresh failed", { error: error?.message || error });
    } finally {
      if (!stopped) timer = setTimeout(() => void tick(), ROLLUP_INTERVAL_MS);
    }
  };

  const stop = () => {
    if (stopped) return;
    stopped = true;
    if (timer) clearTimeout(timer);
    timer = null;
    if (activeAnalyticsRollupStop === stop) activeAnalyticsRollupStop = null;
  };
  activeAnalyticsRollupStop = stop;
  void tick();
  return stop;
};

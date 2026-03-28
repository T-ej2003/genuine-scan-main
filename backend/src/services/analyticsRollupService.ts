import { Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";
import { withDistributedLease } from "./distributedLeaseService";

const INVENTORY_CHECKPOINT_KEY = "rollup:inventory-status";
const SCAN_HOURLY_CHECKPOINT_KEY = "rollup:scan-metrics-hourly";
const INVENTORY_GRACE_MS = 10 * 60_000;
const SCAN_GRACE_MS = 2 * 60 * 60_000;
const ROLLUP_INTERVAL_MS = Math.max(
  60_000,
  Math.min(15 * 60_000, Number(process.env.ANALYTICS_ROLLUP_REFRESH_MS || 180_000) || 180_000)
);
const ROLLUP_LEASE_MS = Math.max(ROLLUP_INTERVAL_MS * 2, 5 * 60_000);

type InventoryStatusCountField =
  | "dormant"
  | "active"
  | "activated"
  | "allocated"
  | "printed"
  | "redeemed"
  | "blocked"
  | "scanned";

const statusKeyMap: Record<QRStatus, InventoryStatusCountField> = {
  DORMANT: "dormant",
  ACTIVE: "active",
  ALLOCATED: "allocated",
  ACTIVATED: "activated",
  PRINTED: "printed",
  REDEEMED: "redeemed",
  BLOCKED: "blocked",
  SCANNED: "scanned",
};

const getCheckpointDate = async (key: string) => {
  const row = await prisma.systemCheckpoint.findUnique({
    where: { key },
    select: { value: true },
  });
  const candidate = String((row?.value as Record<string, unknown> | null)?.cursor || "").trim();
  const parsed = candidate ? new Date(candidate) : null;
  return parsed && Number.isFinite(parsed.getTime()) ? parsed : null;
};

const setCheckpointDate = async (key: string, value: Date) => {
  await prisma.systemCheckpoint.upsert({
    where: { key },
    create: {
      key,
      value: { cursor: value.toISOString() } as Prisma.InputJsonValue,
    },
    update: {
      value: { cursor: value.toISOString() } as Prisma.InputJsonValue,
    },
  });
};

const chunk = <T>(values: T[], size: number) => {
  const batches: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    batches.push(values.slice(index, index + size));
  }
  return batches;
};

const loadChangedBatchIds = async (since: Date | null) => {
  if (!since) {
    const rows = await prisma.batch.findMany({
      select: { id: true },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    });
    return rows.map((row) => row.id);
  }

  const rows = await prisma.$queryRaw<Array<{ batchId: string }>>(Prisma.sql`
    SELECT DISTINCT "batchId"
    FROM "QRCode"
    WHERE "batchId" IS NOT NULL
      AND "updatedAt" >= ${since}
  `);

  return rows.map((row) => row.batchId).filter(Boolean);
};

export const refreshInventoryStatusRollups = async () => {
  const now = new Date();
  const checkpoint = await getCheckpointDate(INVENTORY_CHECKPOINT_KEY);
  const since = checkpoint ? new Date(checkpoint.getTime() - INVENTORY_GRACE_MS) : null;
  const batchIds = await loadChangedBatchIds(since);
  if (!batchIds.length) {
    await setCheckpointDate(INVENTORY_CHECKPOINT_KEY, now);
    return { updatedBatches: 0 };
  }

  let updatedBatches = 0;
  for (const batchIdsChunk of chunk(batchIds, 500)) {
    const [batches, groups] = await Promise.all([
      prisma.batch.findMany({
        where: { id: { in: batchIdsChunk } },
        select: {
          id: true,
          licenseeId: true,
          manufacturerId: true,
          totalCodes: true,
        },
      }),
      prisma.qRCode.groupBy({
        by: ["batchId", "status"],
        where: {
          batchId: { in: batchIdsChunk },
        },
        _count: { _all: true },
      }),
    ]);

    const countsMap = new Map<
      string,
      {
        totalCodes: number;
        licenseeId: string;
        manufacturerId: string | null;
        dormant: number;
        active: number;
        activated: number;
        allocated: number;
        printed: number;
        redeemed: number;
        blocked: number;
        scanned: number;
      }
    >();

    for (const batch of batches) {
      countsMap.set(batch.id, {
        totalCodes: batch.totalCodes,
        licenseeId: batch.licenseeId,
        manufacturerId: batch.manufacturerId || null,
        dormant: 0,
        active: 0,
        activated: 0,
        allocated: 0,
        printed: 0,
        redeemed: 0,
        blocked: 0,
        scanned: 0,
      });
    }

    for (const group of groups) {
      if (!group.batchId) continue;
      const current = countsMap.get(group.batchId);
      if (!current) continue;
      const field = statusKeyMap[group.status];
      current[field] = Number(group._count._all || 0);
    }

    await prisma.$transaction(
      Array.from(countsMap.entries()).map(([batchId, counts]) =>
        prisma.inventoryStatusRollup.upsert({
          where: { batchId },
          create: {
            batchId,
            licenseeId: counts.licenseeId,
            manufacturerId: counts.manufacturerId,
            totalCodes: counts.totalCodes,
            dormant: counts.dormant,
            active: counts.active,
            activated: counts.activated,
            allocated: counts.allocated,
            printed: counts.printed,
            redeemed: counts.redeemed,
            blocked: counts.blocked,
            scanned: counts.scanned,
            refreshedAt: now,
          },
          update: {
            licenseeId: counts.licenseeId,
            manufacturerId: counts.manufacturerId,
            totalCodes: counts.totalCodes,
            dormant: counts.dormant,
            active: counts.active,
            activated: counts.activated,
            allocated: counts.allocated,
            printed: counts.printed,
            redeemed: counts.redeemed,
            blocked: counts.blocked,
            scanned: counts.scanned,
            refreshedAt: now,
          },
        })
      )
    );

    updatedBatches += countsMap.size;
  }

  await setCheckpointDate(INVENTORY_CHECKPOINT_KEY, now);
  return { updatedBatches };
};

type ScanMetricsHourlyRow = {
  hourBucket: Date;
  licenseeId: string;
  batchId: string | null;
  manufacturerId: string | null;
  totalScanEvents: number;
  firstScanEvents: number;
  repeatScanEvents: number;
  blockedEvents: number;
  trustedOwnerEvents: number;
  externalEvents: number;
  namedLocationEvents: number;
  knownDeviceEvents: number;
  uniqueQrCodes: number;
  firstScannedAt: Date | null;
  lastScannedAt: Date | null;
};

const buildRollupBucketKey = (row: {
  hourBucket: Date;
  licenseeId: string;
  batchId: string | null;
  manufacturerId: string | null;
}) =>
  [
    row.hourBucket.toISOString(),
    row.licenseeId,
    row.batchId || "__none__",
    row.manufacturerId || "__none__",
  ].join("|");

export const refreshScanMetricsHourlyRollups = async () => {
  const now = new Date();
  const checkpoint = await getCheckpointDate(SCAN_HOURLY_CHECKPOINT_KEY);
  const since = checkpoint ? new Date(checkpoint.getTime() - SCAN_GRACE_MS) : new Date(Date.now() - 7 * 24 * 60 * 60_000);

  const rows = await prisma.$queryRaw<ScanMetricsHourlyRow[]>(Prisma.sql`
    SELECT
      date_trunc('hour', s."scannedAt") AS "hourBucket",
      s."licenseeId" AS "licenseeId",
      s."batchId" AS "batchId",
      b."manufacturerId" AS "manufacturerId",
      COUNT(*)::int AS "totalScanEvents",
      SUM(CASE WHEN s."isFirstScan" THEN 1 ELSE 0 END)::int AS "firstScanEvents",
      SUM(CASE WHEN s."isFirstScan" THEN 0 ELSE 1 END)::int AS "repeatScanEvents",
      SUM(CASE WHEN s."status" = CAST('BLOCKED' AS "QRStatus") THEN 1 ELSE 0 END)::int AS "blockedEvents",
      SUM(CASE WHEN s."isTrustedOwnerContext" THEN 1 ELSE 0 END)::int AS "trustedOwnerEvents",
      SUM(CASE WHEN s."isTrustedOwnerContext" THEN 0 ELSE 1 END)::int AS "externalEvents",
      SUM(CASE WHEN COALESCE(NULLIF(s."locationName", ''), NULLIF(s."locationCity", ''), NULLIF(s."locationCountry", '')) IS NOT NULL THEN 1 ELSE 0 END)::int AS "namedLocationEvents",
      SUM(CASE WHEN NULLIF(s."device", '') IS NOT NULL THEN 1 ELSE 0 END)::int AS "knownDeviceEvents",
      COUNT(DISTINCT s."qrCodeId")::int AS "uniqueQrCodes",
      MIN(s."scannedAt") AS "firstScannedAt",
      MAX(s."scannedAt") AS "lastScannedAt"
    FROM "QrScanLog" s
    LEFT JOIN "Batch" b ON b."id" = s."batchId"
    WHERE s."scannedAt" >= ${since}
    GROUP BY 1, 2, 3, 4
    ORDER BY 1 ASC
  `);

  if (!rows.length) {
    await setCheckpointDate(SCAN_HOURLY_CHECKPOINT_KEY, now);
    return { updatedBuckets: 0 };
  }

  for (const rowChunk of chunk(rows, 250)) {
    await prisma.$transaction(
      rowChunk.map((row) =>
        prisma.scanMetricsHourlyRollup.upsert({
          where: {
            bucketKey: buildRollupBucketKey(row),
          },
          create: {
            bucketKey: buildRollupBucketKey(row),
            hourBucket: row.hourBucket,
            licenseeId: row.licenseeId,
            batchId: row.batchId,
            manufacturerId: row.manufacturerId,
            totalScanEvents: Number(row.totalScanEvents || 0),
            firstScanEvents: Number(row.firstScanEvents || 0),
            repeatScanEvents: Number(row.repeatScanEvents || 0),
            blockedEvents: Number(row.blockedEvents || 0),
            trustedOwnerEvents: Number(row.trustedOwnerEvents || 0),
            externalEvents: Number(row.externalEvents || 0),
            namedLocationEvents: Number(row.namedLocationEvents || 0),
            knownDeviceEvents: Number(row.knownDeviceEvents || 0),
            uniqueQrCodes: Number(row.uniqueQrCodes || 0),
            firstScannedAt: row.firstScannedAt,
            lastScannedAt: row.lastScannedAt,
          },
          update: {
            totalScanEvents: Number(row.totalScanEvents || 0),
            firstScanEvents: Number(row.firstScanEvents || 0),
            repeatScanEvents: Number(row.repeatScanEvents || 0),
            blockedEvents: Number(row.blockedEvents || 0),
            trustedOwnerEvents: Number(row.trustedOwnerEvents || 0),
            externalEvents: Number(row.externalEvents || 0),
            namedLocationEvents: Number(row.namedLocationEvents || 0),
            knownDeviceEvents: Number(row.knownDeviceEvents || 0),
            uniqueQrCodes: Number(row.uniqueQrCodes || 0),
            firstScannedAt: row.firstScannedAt,
            lastScannedAt: row.lastScannedAt,
          },
        })
      )
    );
  }

  await setCheckpointDate(SCAN_HOURLY_CHECKPOINT_KEY, now);
  return { updatedBuckets: rows.length };
};

export const refreshAnalyticsRollups = async () => {
  const [inventory, hourly] = await Promise.all([
    refreshInventoryStatusRollups(),
    refreshScanMetricsHourlyRollups(),
  ]);

  return {
    inventory,
    hourly,
  };
};

export const startAnalyticsRollupWorker = () => {
  let stopped = false;
  let timer: NodeJS.Timeout | null = null;

  const tick = async () => {
    if (stopped) return;

    try {
      const lease = await withDistributedLease("analytics-rollup-refresh", ROLLUP_LEASE_MS, refreshAnalyticsRollups);
      if (lease.acquired) {
        logger.info("Analytics rollups refreshed", lease.result || {});
      }
    } catch (error: any) {
      logger.error("Analytics rollup refresh failed", {
        error: error?.message || error,
      });
    } finally {
      if (!stopped) {
        timer = setTimeout(() => {
          void tick();
        }, ROLLUP_INTERVAL_MS);
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

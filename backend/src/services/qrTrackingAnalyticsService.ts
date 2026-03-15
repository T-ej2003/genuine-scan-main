import { Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { compactDeviceLabel, reverseGeocode } from "./locationService";
import {
  countAllocatedInventory,
  countBlockedInventory,
  countDormantInventory,
  countPrintedInventory,
  countRedeemedInventory,
} from "./qrStatusMetrics";

export type TrackingAnalyticsScopeMode = "inventory" | "activity";

export type TrackingAnalyticsFilters = {
  licenseeId?: string;
  manufacturerId?: string;
  batchQuery?: string;
  code?: string;
  status?: QRStatus;
  firstScan?: boolean;
  from?: Date;
  to?: Date;
  limit: number;
  offset: number;
};

export type TrackingAnalyticsTotals = {
  total: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  created: number;
};

export type TrackingAnalyticsEventSummary = {
  totalScanEvents: number;
  firstScanEvents: number;
  repeatScanEvents: number;
  blockedEvents: number;
  trustedOwnerEvents: number;
  externalEvents: number;
  namedLocationEvents: number;
  knownDeviceEvents: number;
};

export type TrackingAnalyticsTrendPoint = {
  label: string;
  total: number;
  dormant: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  scanEvents: number;
};

export type TrackingAnalyticsBatchRow = {
  id: string;
  name: string;
  licenseeId: string;
  startCode: string;
  endCode: string;
  totalCodes: number;
  batchInventoryTotal: number;
  scopeCodeCount: number;
  scanEventCount: number;
  createdAt: string;
  counts: Record<string, number>;
};

const TRACKING_STATUSES: QRStatus[] = [
  QRStatus.DORMANT,
  QRStatus.ACTIVE,
  QRStatus.ALLOCATED,
  QRStatus.ACTIVATED,
  QRStatus.PRINTED,
  QRStatus.REDEEMED,
  QRStatus.BLOCKED,
  QRStatus.SCANNED,
];
const INSENSITIVE = Prisma.QueryMode.insensitive;

const emptyTotals = (): TrackingAnalyticsTotals => ({
  total: 0,
  dormant: 0,
  allocated: 0,
  printed: 0,
  redeemed: 0,
  blocked: 0,
  created: 0,
});

const emptyEventSummary = (): TrackingAnalyticsEventSummary => ({
  totalScanEvents: 0,
  firstScanEvents: 0,
  repeatScanEvents: 0,
  blockedEvents: 0,
  trustedOwnerEvents: 0,
  externalEvents: 0,
  namedLocationEvents: 0,
  knownDeviceEvents: 0,
});

const normalizeCountBucket = (status: string | null | undefined) => {
  const normalized = String(status || "").trim().toUpperCase();
  if (normalized === "DORMANT") return "dormant" as const;
  if (normalized === "PRINTED") return "printed" as const;
  if (normalized === "BLOCKED") return "blocked" as const;
  if (normalized === "REDEEMED" || normalized === "SCANNED") return "redeemed" as const;
  return "allocated" as const;
};

const appendDateFilter = (conditions: Prisma.Sql[], alias: string, filters: TrackingAnalyticsFilters) => {
  if (filters.from) conditions.push(Prisma.sql`${Prisma.raw(alias)}."scannedAt" >= ${filters.from}`);
  if (filters.to) conditions.push(Prisma.sql`${Prisma.raw(alias)}."scannedAt" <= ${filters.to}`);
};

const buildMatchingLogWhereSql = (filters: TrackingAnalyticsFilters) => {
  const conditions: Prisma.Sql[] = [];
  const batchQuery = String(filters.batchQuery || "").trim();
  const codeQuery = String(filters.code || "").trim();
  const batchPattern = `%${batchQuery}%`;
  const codePattern = `%${codeQuery}%`;

  if (filters.licenseeId) conditions.push(Prisma.sql`s."licenseeId" = ${filters.licenseeId}`);
  if (filters.manufacturerId) conditions.push(Prisma.sql`b."manufacturerId" = ${filters.manufacturerId}`);
  if (batchQuery) {
    conditions.push(Prisma.sql`(b."id" ILIKE ${batchPattern} OR b."name" ILIKE ${batchPattern})`);
  }
  if (codeQuery) conditions.push(Prisma.sql`s."code" ILIKE ${codePattern}`);
  if (filters.status) conditions.push(Prisma.sql`s."status" = CAST(${filters.status} AS "QRStatus")`);
  if (typeof filters.firstScan === "boolean") conditions.push(Prisma.sql`s."isFirstScan" = ${filters.firstScan}`);
  appendDateFilter(conditions, "s", filters);

  return conditions.length > 0
    ? Prisma.sql`WHERE ${Prisma.join(conditions, " AND ")}`
    : Prisma.empty;
};

const buildLogWhereObject = (filters: TrackingAnalyticsFilters): Prisma.QrScanLogWhereInput => {
  const batchQuery = String(filters.batchQuery || "").trim();
  const batchFilter: Prisma.BatchNullableRelationFilter | undefined =
    filters.manufacturerId || batchQuery
      ? {
          is: {
            ...(filters.manufacturerId ? { manufacturerId: filters.manufacturerId } : {}),
            ...(batchQuery
              ? {
                  OR: [
                    { id: { contains: batchQuery, mode: INSENSITIVE } },
                    { name: { contains: batchQuery, mode: INSENSITIVE } },
                  ],
                }
              : {}),
          },
        }
      : undefined;

  return {
    ...(filters.licenseeId ? { licenseeId: filters.licenseeId } : {}),
    ...(filters.code ? { code: { contains: filters.code, mode: INSENSITIVE } } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(typeof filters.firstScan === "boolean" ? { isFirstScan: filters.firstScan } : {}),
    ...(filters.from || filters.to
      ? {
          scannedAt: {
            ...(filters.from ? { gte: filters.from } : {}),
            ...(filters.to ? { lte: filters.to } : {}),
          },
        }
      : {}),
    ...(batchFilter ? { batch: batchFilter } : {}),
  };
};

const buildInventoryQrWhere = (filters: TrackingAnalyticsFilters): Prisma.QRCodeWhereInput => {
  const batchQuery = String(filters.batchQuery || "").trim();
  const batchCondition =
    filters.manufacturerId || batchQuery
      ? {
          batch: {
            is: {
              ...(filters.manufacturerId ? { manufacturerId: filters.manufacturerId } : {}),
              ...(batchQuery
                ? {
                    OR: [
                      { id: { contains: batchQuery, mode: INSENSITIVE } },
                      { name: { contains: batchQuery, mode: INSENSITIVE } },
                    ],
                  }
                : {}),
            },
          },
        }
      : {};

  return {
    ...(filters.licenseeId ? { licenseeId: filters.licenseeId } : {}),
    ...(filters.code ? { code: { contains: filters.code, mode: INSENSITIVE } } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...batchCondition,
    batchId: { not: null },
  };
};

const buildTotalsFromRows = (rows: TrackingAnalyticsBatchRow[]): TrackingAnalyticsTotals => {
  const totals = emptyTotals();
  totals.created = rows.length;
  for (const row of rows) {
    totals.total += Number(row.scopeCodeCount || row.totalCodes || 0);
    totals.dormant += countDormantInventory(row.counts);
    totals.allocated += countAllocatedInventory(row.counts);
    totals.printed += countPrintedInventory(row.counts);
    totals.redeemed += countRedeemedInventory(row.counts);
    totals.blocked += countBlockedInventory(row.counts);
  }
  return totals;
};

const parseTrendLabelDate = (label: string) => {
  const parsed = new Date(`${label} ${new Date().getFullYear()}`);
  return Number.isFinite(parsed.getTime()) ? parsed.getTime() : Number.POSITIVE_INFINITY;
};

const collapseTrendRows = (rows: TrackingAnalyticsTrendPoint[]) =>
  rows
    .slice()
    .sort((left, right) => parseTrendLabelDate(left.label) - parseTrendLabelDate(right.label))
    .slice(-14);

type TrackingEventMetrics = {
  quantities: {
    scanEvents: number;
    matchedBatches: number;
  };
  summary: TrackingAnalyticsEventSummary;
  batchEventCountMap: Map<string, number>;
  trendMap: Map<string, number>;
};

const loadEventMetrics = async (filters: TrackingAnalyticsFilters): Promise<TrackingEventMetrics> => {
  const whereSql = buildMatchingLogWhereSql(filters);

  type QuantityRow = { scanEvents: number; matchedBatches: number };
  type BatchEventRow = { batchId: string | null; scanEvents: number };
  type TrendRow = { label: string; scanEvents: number };

  const [quantityRows, summaryRows, batchRows, trendRows] = await Promise.all([
    prisma.$queryRaw<QuantityRow[]>(Prisma.sql`
      WITH matching_logs AS (
        SELECT s."id", s."batchId"
        FROM "QrScanLog" s
        LEFT JOIN "Batch" b ON b."id" = s."batchId"
        ${whereSql}
      )
      SELECT
        COUNT(*)::int AS "scanEvents",
        COUNT(DISTINCT "batchId") FILTER (WHERE "batchId" IS NOT NULL)::int AS "matchedBatches"
      FROM matching_logs
    `),
    prisma.$queryRaw<TrackingAnalyticsEventSummary[]>(Prisma.sql`
      WITH matching_logs AS (
        SELECT
          s."isFirstScan",
          s."status",
          s."isTrustedOwnerContext",
          s."locationName",
          s."locationCity",
          s."locationRegion",
          s."locationCountry",
          s."device",
          s."userAgent"
        FROM "QrScanLog" s
        LEFT JOIN "Batch" b ON b."id" = s."batchId"
        ${whereSql}
      )
      SELECT
        COUNT(*)::int AS "totalScanEvents",
        COUNT(*) FILTER (WHERE "isFirstScan" = true)::int AS "firstScanEvents",
        COUNT(*) FILTER (WHERE COALESCE("isFirstScan", false) = false)::int AS "repeatScanEvents",
        COUNT(*) FILTER (WHERE "status" = 'BLOCKED')::int AS "blockedEvents",
        COUNT(*) FILTER (WHERE "isTrustedOwnerContext" = true)::int AS "trustedOwnerEvents",
        COUNT(*) FILTER (WHERE COALESCE("isTrustedOwnerContext", false) = false)::int AS "externalEvents",
        COUNT(*) FILTER (
          WHERE NULLIF(COALESCE("locationName", ''), '') IS NOT NULL
             OR NULLIF(COALESCE("locationCity", ''), '') IS NOT NULL
             OR NULLIF(COALESCE("locationRegion", ''), '') IS NOT NULL
             OR NULLIF(COALESCE("locationCountry", ''), '') IS NOT NULL
        )::int AS "namedLocationEvents",
        COUNT(*) FILTER (
          WHERE NULLIF(COALESCE("device", ''), '') IS NOT NULL
             OR NULLIF(COALESCE("userAgent", ''), '') IS NOT NULL
        )::int AS "knownDeviceEvents"
      FROM matching_logs
    `),
    prisma.$queryRaw<BatchEventRow[]>(Prisma.sql`
      SELECT s."batchId" AS "batchId", COUNT(*)::int AS "scanEvents"
      FROM "QrScanLog" s
      LEFT JOIN "Batch" b ON b."id" = s."batchId"
      ${whereSql}
      GROUP BY s."batchId"
    `),
    prisma.$queryRaw<TrendRow[]>(Prisma.sql`
      SELECT
        TO_CHAR(DATE_TRUNC('day', s."scannedAt"), 'Mon DD') AS "label",
        COUNT(*)::int AS "scanEvents"
      FROM "QrScanLog" s
      LEFT JOIN "Batch" b ON b."id" = s."batchId"
      ${whereSql}
      GROUP BY DATE_TRUNC('day', s."scannedAt")
      ORDER BY DATE_TRUNC('day', s."scannedAt") ASC
    `),
  ]);

  const quantityRow = quantityRows[0] || { scanEvents: 0, matchedBatches: 0 };
  const summaryRow = summaryRows[0] || emptyEventSummary();

  return {
    quantities: {
      scanEvents: Number(quantityRow.scanEvents || 0),
      matchedBatches: Number(quantityRow.matchedBatches || 0),
    },
    summary: {
      totalScanEvents: Number(summaryRow.totalScanEvents || 0),
      firstScanEvents: Number(summaryRow.firstScanEvents || 0),
      repeatScanEvents: Number(summaryRow.repeatScanEvents || 0),
      blockedEvents: Number(summaryRow.blockedEvents || 0),
      trustedOwnerEvents: Number(summaryRow.trustedOwnerEvents || 0),
      externalEvents: Number(summaryRow.externalEvents || 0),
      namedLocationEvents: Number(summaryRow.namedLocationEvents || 0),
      knownDeviceEvents: Number(summaryRow.knownDeviceEvents || 0),
    },
    batchEventCountMap: new Map(
      batchRows
        .filter((row) => Boolean(row.batchId))
        .map((row) => [String(row.batchId), Number(row.scanEvents || 0)])
    ),
    trendMap: new Map(trendRows.map((row) => [row.label, Number(row.scanEvents || 0)])),
  };
};

const enrichLogs = async (logs: any[]) => {
  let geocodeBudget = 40;
  return Promise.all(
    logs.map(async (log) => {
      let fallback: Awaited<ReturnType<typeof reverseGeocode>> | null = null;
      const hasNamedLocation =
        Boolean(log.locationName) ||
        Boolean(log.locationCity) ||
        Boolean(log.locationRegion) ||
        Boolean(log.locationCountry);

      if (!hasNamedLocation && geocodeBudget > 0 && log.latitude != null && log.longitude != null) {
        geocodeBudget -= 1;
        fallback = await reverseGeocode(log.latitude ?? null, log.longitude ?? null);
      }

      return {
        ...log,
        locationName:
          log.locationName ||
          [log.locationCity, log.locationRegion, log.locationCountry].filter(Boolean).join(", ") ||
          fallback?.name ||
          null,
        deviceLabel: compactDeviceLabel(log.userAgent || log.device || null),
      };
    })
  );
};

const loadLogs = async (filters: TrackingAnalyticsFilters) => {
  const where = buildLogWhereObject(filters);
  const [logs, total] = await Promise.all([
    prisma.qrScanLog.findMany({
      where,
      orderBy: { scannedAt: "desc" },
      take: filters.limit,
      skip: filters.offset,
      include: {
        licensee: { select: { id: true, name: true, prefix: true } },
        qrCode: { select: { id: true, code: true, status: true } },
      },
    }),
    prisma.qrScanLog.count({ where }),
  ]);

  return {
    logs: await enrichLogs(logs),
    total,
  };
};

const buildInventoryAnalytics = async (filters: TrackingAnalyticsFilters) => {
  const qrWhere = buildInventoryQrWhere(filters);
  const [grouped, eventMetrics] = await Promise.all([
    prisma.qRCode.groupBy({
      by: ["batchId", "status"],
      where: qrWhere,
      _count: { _all: true },
    }),
    loadEventMetrics(filters),
  ]);

  const batchIds = Array.from(new Set(grouped.map((row) => row.batchId).filter(Boolean))) as string[];
  const batches = batchIds.length
    ? await prisma.batch.findMany({
        where: { id: { in: batchIds } },
        select: {
          id: true,
          name: true,
          licenseeId: true,
          startCode: true,
          endCode: true,
          totalCodes: true,
          createdAt: true,
        },
        orderBy: { createdAt: "desc" },
      })
    : [];

  const groupedMap = new Map<string, Record<string, number>>();
  for (const row of grouped) {
    if (!row.batchId) continue;
    const current = groupedMap.get(row.batchId) || {};
    current[row.status] = row._count?._all || 0;
    groupedMap.set(row.batchId, current);
  }

  const batchRows: TrackingAnalyticsBatchRow[] = batches.map((batch) => {
    const counts = groupedMap.get(batch.id) || {};
    const scopeCodeCount = Object.values(counts).reduce((acc, value) => acc + Number(value || 0), 0);
    return {
      ...batch,
      createdAt: batch.createdAt.toISOString(),
      batchInventoryTotal: batch.totalCodes,
      scopeCodeCount,
      scanEventCount: eventMetrics.batchEventCountMap.get(batch.id) || 0,
      counts,
    };
  });

  const totals = buildTotalsFromRows(batchRows);
  const byDay = new Map<string, TrackingAnalyticsTrendPoint>();
  for (const row of batchRows) {
    const label = row.createdAt ? new Date(row.createdAt).toLocaleDateString(undefined, { month: "short", day: "numeric" }) : "Unknown";
    const current =
      byDay.get(label) ||
      ({ label, total: 0, dormant: 0, allocated: 0, printed: 0, redeemed: 0, blocked: 0, scanEvents: 0 } satisfies TrackingAnalyticsTrendPoint);
    current.total += row.scopeCodeCount;
    current.dormant += countDormantInventory(row.counts);
    current.allocated += countAllocatedInventory(row.counts);
    current.printed += countPrintedInventory(row.counts);
    current.redeemed += countRedeemedInventory(row.counts);
    current.blocked += countBlockedInventory(row.counts);
    byDay.set(label, current);
  }

  for (const [label, scanEvents] of eventMetrics.trendMap.entries()) {
    const current =
      byDay.get(label) ||
      ({ label, total: 0, dormant: 0, allocated: 0, printed: 0, redeemed: 0, blocked: 0, scanEvents: 0 } satisfies TrackingAnalyticsTrendPoint);
    current.scanEvents = scanEvents;
    byDay.set(label, current);
  }

  return {
    scopeMode: "inventory" as const,
    totals,
    trend: collapseTrendRows(Array.from(byDay.values())),
    batches: batchRows,
    quantities: {
      distinctCodes: totals.total,
      scanEvents: eventMetrics.quantities.scanEvents,
      matchedBatches: batchRows.length,
    },
    eventSummary: eventMetrics.summary,
  };
};

const buildActivityAnalytics = async (filters: TrackingAnalyticsFilters) => {
  const whereSql = buildMatchingLogWhereSql(filters);

  type CountRow = { batchId: string | null; status: string; count: number };
  type QuantityRow = { distinctCodes: number; scanEvents: number; matchedBatches: number };
  type TrendRow = {
    label: string;
    total: number;
    dormant: number;
    allocated: number;
    printed: number;
    redeemed: number;
    blocked: number;
    scanEvents: number;
  };
  type BatchMetaRow = {
    id: string;
    name: string;
    licenseeId: string;
    startCode: string;
    endCode: string;
    totalCodes: number;
    createdAt: Date;
  };
  type EventCountRow = { batchId: string | null; scanEvents: number };

  const [latestStatusCounts, eventMetrics] = await Promise.all([
    prisma.$queryRaw<CountRow[]>(Prisma.sql`
      WITH matching_logs AS (
        SELECT s."id", s."qrCodeId", s."batchId", s."status", s."scannedAt"
        FROM "QrScanLog" s
        LEFT JOIN "Batch" b ON b."id" = s."batchId"
        ${whereSql}
      ),
      ranked AS (
        SELECT ml.*, ROW_NUMBER() OVER (PARTITION BY ml."qrCodeId" ORDER BY ml."scannedAt" DESC, ml."id" DESC) AS rn
        FROM matching_logs ml
      ),
      latest_per_code AS (
        SELECT *
        FROM ranked
        WHERE rn = 1
      )
      SELECT l."batchId" AS "batchId", l."status"::text AS "status", COUNT(*)::int AS "count"
      FROM latest_per_code l
      GROUP BY l."batchId", l."status"
    `),
    loadEventMetrics(filters),
  ]);

  const quantities = await prisma.$queryRaw<QuantityRow[]>(Prisma.sql`
    WITH matching_logs AS (
      SELECT s."id", s."qrCodeId", s."batchId", s."scannedAt"
      FROM "QrScanLog" s
      LEFT JOIN "Batch" b ON b."id" = s."batchId"
      ${whereSql}
    ),
    ranked AS (
      SELECT ml.*, ROW_NUMBER() OVER (PARTITION BY ml."qrCodeId" ORDER BY ml."scannedAt" DESC, ml."id" DESC) AS rn
      FROM matching_logs ml
    ),
    latest_per_code AS (
      SELECT * FROM ranked WHERE rn = 1
    )
    SELECT
      (SELECT COUNT(*) FROM latest_per_code)::int AS "distinctCodes",
      (SELECT COUNT(*) FROM matching_logs)::int AS "scanEvents",
      (SELECT COUNT(DISTINCT "batchId") FROM latest_per_code WHERE "batchId" IS NOT NULL)::int AS "matchedBatches"
  `);

  const trend = await prisma.$queryRaw<TrendRow[]>(Prisma.sql`
    WITH matching_logs AS (
      SELECT s."id", s."qrCodeId", s."status", s."scannedAt"
      FROM "QrScanLog" s
      LEFT JOIN "Batch" b ON b."id" = s."batchId"
      ${whereSql}
    )
    SELECT
      TO_CHAR(DATE_TRUNC('day', ml."scannedAt"), 'Mon DD') AS "label",
      COUNT(DISTINCT ml."qrCodeId")::int AS "total",
      COUNT(DISTINCT CASE WHEN ml."status" IN ('DORMANT', 'ACTIVE') THEN ml."qrCodeId" END)::int AS "dormant",
      COUNT(DISTINCT CASE WHEN ml."status" IN ('ALLOCATED', 'ACTIVATED') THEN ml."qrCodeId" END)::int AS "allocated",
      COUNT(DISTINCT CASE WHEN ml."status" = 'PRINTED' THEN ml."qrCodeId" END)::int AS "printed",
      COUNT(DISTINCT CASE WHEN ml."status" IN ('REDEEMED', 'SCANNED') THEN ml."qrCodeId" END)::int AS "redeemed",
      COUNT(DISTINCT CASE WHEN ml."status" = 'BLOCKED' THEN ml."qrCodeId" END)::int AS "blocked",
      COUNT(*)::int AS "scanEvents"
    FROM matching_logs ml
    GROUP BY DATE_TRUNC('day', ml."scannedAt")
    ORDER BY DATE_TRUNC('day', ml."scannedAt") ASC
  `);

  const batchIds = Array.from(new Set(latestStatusCounts.map((row) => row.batchId).filter(Boolean))) as string[];
  const batchMeta = batchIds.length
    ? await prisma.batch.findMany({
        where: { id: { in: batchIds } },
        select: {
          id: true,
          name: true,
          licenseeId: true,
          startCode: true,
          endCode: true,
          totalCodes: true,
          createdAt: true,
        },
      })
    : [];
  const batchMetaMap = new Map(batchMeta.map((batch) => [batch.id, batch]));

  const batchCountsMap = new Map<string, Record<string, number>>();
  for (const row of latestStatusCounts) {
    if (!row.batchId) continue;
    const current = batchCountsMap.get(row.batchId) || {};
    current[row.status] = Number(row.count || 0);
    batchCountsMap.set(row.batchId, current);
  }

  const eventCounts = await prisma.$queryRaw<EventCountRow[]>(Prisma.sql`
    SELECT s."batchId" AS "batchId", COUNT(*)::int AS "scanEvents"
    FROM "QrScanLog" s
    LEFT JOIN "Batch" b ON b."id" = s."batchId"
    ${whereSql}
    GROUP BY s."batchId"
  `);
  const eventCountMap = new Map<string, number>();
  for (const row of eventCounts) {
    if (!row.batchId) continue;
    eventCountMap.set(row.batchId, Number(row.scanEvents || 0));
  }

  const batchRows: TrackingAnalyticsBatchRow[] = batchIds
    .map((batchId) => {
      const meta = batchMetaMap.get(batchId) as BatchMetaRow | undefined;
      if (!meta) return null;
      const counts = batchCountsMap.get(batchId) || {};
      const scopeCodeCount = Object.values(counts).reduce((acc, value) => acc + Number(value || 0), 0);
      return {
        id: meta.id,
        name: meta.name,
        licenseeId: meta.licenseeId,
        startCode: meta.startCode,
        endCode: meta.endCode,
        totalCodes: scopeCodeCount,
        batchInventoryTotal: meta.totalCodes,
        scopeCodeCount,
        scanEventCount: eventCountMap.get(batchId) || eventMetrics.batchEventCountMap.get(batchId) || 0,
        createdAt: meta.createdAt.toISOString(),
        counts,
      };
    })
    .filter(Boolean)
    .sort((a, b) => new Date(b!.createdAt).getTime() - new Date(a!.createdAt).getTime()) as TrackingAnalyticsBatchRow[];

  const totals = buildTotalsFromRows(batchRows);
  const quantityRow = quantities[0] || { distinctCodes: 0, scanEvents: 0, matchedBatches: 0 };

  return {
    scopeMode: "activity" as const,
    totals,
    trend: collapseTrendRows(
      trend.map((row) => ({
        label: row.label,
        total: Number(row.total || 0),
        dormant: Number(row.dormant || 0),
        allocated: Number(row.allocated || 0),
        printed: Number(row.printed || 0),
        redeemed: Number(row.redeemed || 0),
        blocked: Number(row.blocked || 0),
        scanEvents: Number(row.scanEvents || 0),
      }))
    ),
    batches: batchRows,
    quantities: {
      distinctCodes: Number(quantityRow.distinctCodes || 0),
      scanEvents: Number(quantityRow.scanEvents || eventMetrics.quantities.scanEvents || 0),
      matchedBatches: Number(quantityRow.matchedBatches || 0),
    },
    eventSummary: eventMetrics.summary,
  };
};

export const getQrTrackingAnalytics = async (filters: TrackingAnalyticsFilters) => {
  const scopeMode: TrackingAnalyticsScopeMode = filters.from || filters.to || typeof filters.firstScan === "boolean" ? "activity" : "inventory";
  const [analytics, logsPayload] = await Promise.all([
    scopeMode === "activity" ? buildActivityAnalytics(filters) : buildInventoryAnalytics(filters),
    loadLogs(filters),
  ]);

  return {
    scope: {
      mode: analytics.scopeMode,
      title: analytics.scopeMode === "activity" ? "Scan activity scope" : "Inventory scope",
      description:
        analytics.scopeMode === "activity"
          ? "Totals, trend, and batch rows reflect distinct QR codes matched by the scan activity filters. Scan event quantity is tracked separately."
          : "Totals, trend, and batch rows reflect current QR inventory matched by the selected batch, code, and status filters.",
      quantities: analytics.quantities,
    },
    totals: analytics.totals,
    eventSummary: analytics.eventSummary || emptyEventSummary(),
    trend: analytics.trend,
    batches: analytics.batches,
    logs: logsPayload.logs,
    pagination: {
      total: logsPayload.total,
      limit: filters.limit,
      offset: filters.offset,
    },
    supportedStatuses: TRACKING_STATUSES,
  };
};

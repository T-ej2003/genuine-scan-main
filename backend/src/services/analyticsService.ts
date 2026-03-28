import { SecurityPolicy } from "@prisma/client";
import prisma from "../config/database";
import { getOrCreateSecurityPolicy } from "./policyEngineService";

const EARTH_RADIUS_KM = 6371;

const toRadians = (deg: number) => (deg * Math.PI) / 180;

const geoDistanceKm = (aLat: number, aLon: number, bLat: number, bLon: number) => {
  const dLat = toRadians(bLat - aLat);
  const dLon = toRadians(bLon - aLon);
  const lat1 = toRadians(aLat);
  const lat2 = toRadians(bLat);
  const h =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  return EARTH_RADIUS_KM * c;
};

const average = (values: number[]) => {
  if (!values.length) return null;
  const total = values.reduce((acc, v) => acc + v, 0);
  return Math.round((total / values.length) * 10) / 10;
};

const scoreToLevel = (score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" => {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
};

const defaultPolicy: Pick<
  SecurityPolicy,
  "multiScanThreshold" | "geoDriftThresholdKm" | "velocitySpikeThresholdPerMin" | "stuckBatchHours"
> = {
  multiScanThreshold: 2,
  geoDriftThresholdKm: 300,
  velocitySpikeThresholdPerMin: 80,
  stuckBatchHours: 24,
};

const loadPolicyForScope = async (licenseeId?: string) => {
  if (!licenseeId) return defaultPolicy;
  const policy = await getOrCreateSecurityPolicy(licenseeId);
  return {
    multiScanThreshold: policy.multiScanThreshold,
    geoDriftThresholdKm: policy.geoDriftThresholdKm,
    velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
    stuckBatchHours: policy.stuckBatchHours,
  };
};

type SlaStatus =
  | "PENDING_PRINT"
  | "PRINTED_PENDING_SCAN"
  | "SCANNED"
  | "STUCK_WAITING_PRINT"
  | "STUCK_WAITING_FIRST_SCAN";

export type BatchSlaRow = {
  batchId: string;
  name: string;
  licenseeId: string;
  manufacturerId: string | null;
  manufacturerName: string | null;
  createdAt: string;
  printedAt: string | null;
  firstScanAt: string | null;
  timeToPrintMinutes: number | null;
  timeToFirstScanMinutes: number | null;
  totalScans: number;
  status: SlaStatus;
  isStuck: boolean;
  stuckForHours: number | null;
};

export type BatchSlaAnalytics = {
  policy: { stuckBatchHours: number };
  summary: {
    totalBatches: number;
    printedBatches: number;
    scannedBatches: number;
    avgTimeToPrintMinutes: number | null;
    avgTimeToFirstScanMinutes: number | null;
    stuckBatches: number;
  };
  rows: BatchSlaRow[];
  stuckRows: BatchSlaRow[];
};

export const getBatchSlaAnalytics = async (opts: {
  licenseeId?: string;
  limit?: number;
  stuckBatchHours?: number;
}): Promise<BatchSlaAnalytics> => {
  const now = new Date();
  const limit = Math.max(1, Math.min(opts.limit ?? 200, 2000));
  const policy = await loadPolicyForScope(opts.licenseeId);
  const stuckHours = Math.max(1, opts.stuckBatchHours ?? policy.stuckBatchHours);

  const where: any = {};
  if (opts.licenseeId) where.licenseeId = opts.licenseeId;

  const batches = await prisma.batch.findMany({
    where,
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: limit,
    select: {
      id: true,
      name: true,
      licenseeId: true,
      manufacturerId: true,
      createdAt: true,
      printedAt: true,
      manufacturer: { select: { id: true, name: true } },
    },
  });

  if (!batches.length) {
    return {
      policy: { stuckBatchHours: stuckHours },
      summary: {
        totalBatches: 0,
        printedBatches: 0,
        scannedBatches: 0,
        avgTimeToPrintMinutes: null,
        avgTimeToFirstScanMinutes: null,
        stuckBatches: 0,
      },
      rows: [],
      stuckRows: [],
    };
  }

  const batchIds = batches.map((b) => b.id);

  const grouped = await prisma.scanMetricsHourlyRollup.groupBy({
    by: ["batchId"],
    where: { batchId: { in: batchIds } },
    _min: { firstScannedAt: true },
    _sum: { totalScanEvents: true },
  });

  const firstScanMap = new Map<string, Date>();
  const scanCountMap = new Map<string, number>();
  for (const g of grouped) {
    if (!g.batchId) continue;
    if (g._min.firstScannedAt) firstScanMap.set(g.batchId, g._min.firstScannedAt);
    scanCountMap.set(g.batchId, g._sum.totalScanEvents || 0);
  }

  const missingBatchIds = batchIds.filter((batchId) => !scanCountMap.has(batchId));
  if (missingBatchIds.length > 0) {
    const fallbackGrouped = await prisma.qrScanLog.groupBy({
      by: ["batchId"],
      where: { batchId: { in: missingBatchIds } },
      _min: { scannedAt: true },
      _count: { _all: true },
    });

    for (const group of fallbackGrouped) {
      if (!group.batchId) continue;
      if (group._min.scannedAt) firstScanMap.set(group.batchId, group._min.scannedAt);
      scanCountMap.set(group.batchId, group._count._all || 0);
    }
  }

  const rows: BatchSlaRow[] = batches.map((b) => {
    const firstScanAt = firstScanMap.get(b.id) || null;
    const timeToPrintMinutes =
      b.printedAt != null ? Math.max(0, Math.round((b.printedAt.getTime() - b.createdAt.getTime()) / 60_000)) : null;
    const timeToFirstScanMinutes =
      b.printedAt != null && firstScanAt != null
        ? Math.max(0, Math.round((firstScanAt.getTime() - b.printedAt.getTime()) / 60_000))
        : null;

    let status: SlaStatus = "PENDING_PRINT";
    let stuckForHours: number | null = null;

    if (!b.printedAt) {
      const hours = (now.getTime() - b.createdAt.getTime()) / 3_600_000;
      if (hours >= stuckHours) {
        status = "STUCK_WAITING_PRINT";
        stuckForHours = Math.round(hours * 10) / 10;
      } else {
        status = "PENDING_PRINT";
      }
    } else if (!firstScanAt) {
      const hours = (now.getTime() - b.printedAt.getTime()) / 3_600_000;
      if (hours >= stuckHours) {
        status = "STUCK_WAITING_FIRST_SCAN";
        stuckForHours = Math.round(hours * 10) / 10;
      } else {
        status = "PRINTED_PENDING_SCAN";
      }
    } else {
      status = "SCANNED";
    }

    return {
      batchId: b.id,
      name: b.name,
      licenseeId: b.licenseeId,
      manufacturerId: b.manufacturerId || null,
      manufacturerName: b.manufacturer?.name || null,
      createdAt: b.createdAt.toISOString(),
      printedAt: b.printedAt ? b.printedAt.toISOString() : null,
      firstScanAt: firstScanAt ? firstScanAt.toISOString() : null,
      timeToPrintMinutes,
      timeToFirstScanMinutes,
      totalScans: scanCountMap.get(b.id) || 0,
      status,
      isStuck: status === "STUCK_WAITING_PRINT" || status === "STUCK_WAITING_FIRST_SCAN",
      stuckForHours,
    };
  });

  const stuckRows = rows.filter((r) => r.isStuck);
  const avgToPrint = average(rows.map((r) => r.timeToPrintMinutes).filter((v): v is number => v != null));
  const avgToFirstScan = average(
    rows.map((r) => r.timeToFirstScanMinutes).filter((v): v is number => v != null)
  );

  return {
    policy: { stuckBatchHours: stuckHours },
    summary: {
      totalBatches: rows.length,
      printedBatches: rows.filter((r) => r.printedAt != null).length,
      scannedBatches: rows.filter((r) => r.firstScanAt != null).length,
      avgTimeToPrintMinutes: avgToPrint,
      avgTimeToFirstScanMinutes: avgToFirstScan,
      stuckBatches: stuckRows.length,
    },
    rows,
    stuckRows,
  };
};

export type BatchRiskRow = {
  batchId: string;
  name: string;
  licenseeId: string;
  manufacturerId: string | null;
  manufacturerName: string | null;
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  multiScanAnomalies: number;
  geoDriftAnomalies: number;
  velocitySpikeEvents: number;
  openAlerts: number;
};

export type ManufacturerRiskRow = {
  manufacturerId: string;
  manufacturerName: string;
  score: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  batches: number;
  multiScanAnomalies: number;
  geoDriftAnomalies: number;
  velocitySpikeEvents: number;
  openAlerts: number;
};

export type RiskAnalytics = {
  policy: {
    multiScanThreshold: number;
    geoDriftThresholdKm: number;
    velocitySpikeThresholdPerMin: number;
  };
  lookbackHours: number;
  summary: {
    analyzedBatches: number;
    analyzedManufacturers: number;
    highRiskBatches: number;
    highRiskManufacturers: number;
  };
  batchRisk: BatchRiskRow[];
  manufacturerRisk: ManufacturerRiskRow[];
};

export const getRiskAnalytics = async (opts: {
  licenseeId?: string;
  lookbackHours?: number;
  limit?: number;
}): Promise<RiskAnalytics> => {
  const limit = Math.max(1, Math.min(opts.limit ?? 20, 200));
  const lookbackHours = Math.max(1, Math.min(opts.lookbackHours ?? 24, 24 * 30));
  const policy = await loadPolicyForScope(opts.licenseeId);
  const since = new Date(Date.now() - lookbackHours * 3_600_000);

  const whereBatch: any = {};
  if (opts.licenseeId) whereBatch.licenseeId = opts.licenseeId;

  const batches = await prisma.batch.findMany({
    where: whereBatch,
    select: {
      id: true,
      name: true,
      licenseeId: true,
      manufacturerId: true,
      manufacturer: { select: { id: true, name: true } },
    },
  });

  if (!batches.length) {
    return {
      policy: {
        multiScanThreshold: policy.multiScanThreshold,
        geoDriftThresholdKm: policy.geoDriftThresholdKm,
        velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
      },
      lookbackHours,
      summary: {
        analyzedBatches: 0,
        analyzedManufacturers: 0,
        highRiskBatches: 0,
        highRiskManufacturers: 0,
      },
      batchRisk: [],
      manufacturerRisk: [],
    };
  }

  const batchIds = batches.map((b) => b.id);

  const qrRows = await prisma.qRCode.findMany({
    where: { batchId: { in: batchIds } },
    select: { id: true, batchId: true, scanCount: true },
  });

  const multiScanByBatch = new Map<string, number>();
  for (const qr of qrRows) {
    if (!qr.batchId) continue;
    if (qr.scanCount >= policy.multiScanThreshold) {
      multiScanByBatch.set(qr.batchId, (multiScanByBatch.get(qr.batchId) || 0) + 1);
    }
  }

  const geoLogs = await prisma.qrScanLog.findMany({
    where: {
      batchId: { in: batchIds },
      scannedAt: { gte: since },
      latitude: { not: null },
      longitude: { not: null },
    },
    orderBy: [{ qrCodeId: "asc" }, { scannedAt: "asc" }],
    select: {
      qrCodeId: true,
      batchId: true,
      latitude: true,
      longitude: true,
      scannedAt: true,
    },
  });

  const geoByQr = new Map<
    string,
    {
      batchId: string;
      firstLat: number;
      firstLon: number;
      lastLat: number;
      lastLon: number;
    }
  >();

  for (const log of geoLogs) {
    if (!log.batchId || log.latitude == null || log.longitude == null) continue;
    const existing = geoByQr.get(log.qrCodeId);
    if (!existing) {
      geoByQr.set(log.qrCodeId, {
        batchId: log.batchId,
        firstLat: log.latitude,
        firstLon: log.longitude,
        lastLat: log.latitude,
        lastLon: log.longitude,
      });
    } else {
      existing.lastLat = log.latitude;
      existing.lastLon = log.longitude;
    }
  }

  const geoDriftByBatch = new Map<string, number>();
  for (const item of geoByQr.values()) {
    const drift = geoDistanceKm(item.firstLat, item.firstLon, item.lastLat, item.lastLon);
    if (drift >= policy.geoDriftThresholdKm) {
      geoDriftByBatch.set(item.batchId, (geoDriftByBatch.get(item.batchId) || 0) + 1);
    }
  }

  const velocityLogs = await prisma.qrScanLog.findMany({
    where: {
      batchId: { in: batchIds },
      scannedAt: { gte: since },
    },
    select: { batchId: true, scannedAt: true },
  });

  const minuteBucketCounts = new Map<string, number>();
  for (const log of velocityLogs) {
    if (!log.batchId) continue;
    const d = new Date(log.scannedAt);
    const minute = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}-${String(
      d.getUTCDate()
    ).padStart(2, "0")}T${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(
      2,
      "0"
    )}`;
    const key = `${log.batchId}|${minute}`;
    minuteBucketCounts.set(key, (minuteBucketCounts.get(key) || 0) + 1);
  }

  const velocityByBatch = new Map<string, number>();
  for (const [key, count] of minuteBucketCounts.entries()) {
    if (count < policy.velocitySpikeThresholdPerMin) continue;
    const [batchId] = key.split("|");
    velocityByBatch.set(batchId, (velocityByBatch.get(batchId) || 0) + 1);
  }

  const openAlertGrouped = await prisma.policyAlert.groupBy({
    by: ["batchId"],
    where: {
      batchId: { in: batchIds },
      acknowledgedAt: null,
    },
    _count: { _all: true },
  });

  const openAlertsByBatch = new Map<string, number>();
  for (const row of openAlertGrouped) {
    if (!row.batchId) continue;
    openAlertsByBatch.set(row.batchId, row._count._all || 0);
  }

  const batchRiskAll: BatchRiskRow[] = batches.map((batch) => {
    const multi = multiScanByBatch.get(batch.id) || 0;
    const geo = geoDriftByBatch.get(batch.id) || 0;
    const velocity = velocityByBatch.get(batch.id) || 0;
    const openAlerts = openAlertsByBatch.get(batch.id) || 0;
    const score = Math.min(100, multi * 12 + geo * 22 + velocity * 28 + openAlerts * 5);
    return {
      batchId: batch.id,
      name: batch.name,
      licenseeId: batch.licenseeId,
      manufacturerId: batch.manufacturerId || null,
      manufacturerName: batch.manufacturer?.name || null,
      score,
      riskLevel: scoreToLevel(score),
      multiScanAnomalies: multi,
      geoDriftAnomalies: geo,
      velocitySpikeEvents: velocity,
      openAlerts,
    };
  });

  const manufacturerAgg = new Map<
    string,
    {
      manufacturerId: string;
      manufacturerName: string;
      batches: number;
      multiScanAnomalies: number;
      geoDriftAnomalies: number;
      velocitySpikeEvents: number;
      openAlerts: number;
    }
  >();

  for (const row of batchRiskAll) {
    if (!row.manufacturerId) continue;
    const existing = manufacturerAgg.get(row.manufacturerId);
    if (!existing) {
      manufacturerAgg.set(row.manufacturerId, {
        manufacturerId: row.manufacturerId,
        manufacturerName: row.manufacturerName || row.manufacturerId,
        batches: 1,
        multiScanAnomalies: row.multiScanAnomalies,
        geoDriftAnomalies: row.geoDriftAnomalies,
        velocitySpikeEvents: row.velocitySpikeEvents,
        openAlerts: row.openAlerts,
      });
      continue;
    }

    existing.batches += 1;
    existing.multiScanAnomalies += row.multiScanAnomalies;
    existing.geoDriftAnomalies += row.geoDriftAnomalies;
    existing.velocitySpikeEvents += row.velocitySpikeEvents;
    existing.openAlerts += row.openAlerts;
  }

  const manufacturerRiskAll: ManufacturerRiskRow[] = Array.from(manufacturerAgg.values()).map((m) => {
    const score = Math.min(
      100,
      m.multiScanAnomalies * 8 +
        m.geoDriftAnomalies * 16 +
        m.velocitySpikeEvents * 22 +
        m.openAlerts * 4 +
        m.batches * 2
    );
    return {
      manufacturerId: m.manufacturerId,
      manufacturerName: m.manufacturerName,
      score,
      riskLevel: scoreToLevel(score),
      batches: m.batches,
      multiScanAnomalies: m.multiScanAnomalies,
      geoDriftAnomalies: m.geoDriftAnomalies,
      velocitySpikeEvents: m.velocitySpikeEvents,
      openAlerts: m.openAlerts,
    };
  });

  const sortedBatchRisk = [...batchRiskAll].sort((a, b) => b.score - a.score);
  const sortedManufacturerRisk = [...manufacturerRiskAll].sort((a, b) => b.score - a.score);

  return {
    policy: {
      multiScanThreshold: policy.multiScanThreshold,
      geoDriftThresholdKm: policy.geoDriftThresholdKm,
      velocitySpikeThresholdPerMin: policy.velocitySpikeThresholdPerMin,
    },
    lookbackHours,
    summary: {
      analyzedBatches: batchRiskAll.length,
      analyzedManufacturers: manufacturerRiskAll.length,
      highRiskBatches: batchRiskAll.filter((b) => b.score >= 65).length,
      highRiskManufacturers: manufacturerRiskAll.filter((m) => m.score >= 65).length,
    },
    batchRisk: sortedBatchRisk.slice(0, limit),
    manufacturerRisk: sortedManufacturerRisk.slice(0, limit),
  };
};

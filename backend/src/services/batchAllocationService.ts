import { QRStatus } from "@prisma/client";

import prisma from "../config/database";

const LINEAGE_BACKFILL_COOLDOWN_MS = 5 * 60_000;
const lineageBackfillState = new Map<string, number>();

const UNASSIGNED_STATUSES = [QRStatus.DORMANT, QRStatus.ACTIVE] as const;
const PRINTABLE_STATUSES = [QRStatus.ALLOCATED, QRStatus.DORMANT, QRStatus.ACTIVE] as const;
const REDEEMED_STATUSES = [QRStatus.REDEEMED, QRStatus.SCANNED] as const;

export type BatchKind = "RECEIVED_PARENT" | "MANUFACTURER_CHILD";

export type BatchInventoryCounts = {
  dormant: number;
  active: number;
  activated: number;
  allocated: number;
  printed: number;
  redeemed: number;
  blocked: number;
  scanned: number;
};

type BatchWithScope = {
  id: string;
  name: string;
  licenseeId: string;
  manufacturerId: string | null;
  parentBatchId: string | null;
  rootBatchId: string | null;
  startCode: string;
  endCode: string;
  totalCodes: number;
  printedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
  licensee?: { id: string; name: string; prefix: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  _count?: { qrCodes: number };
};

export type BatchOperationalSummary = BatchWithScope & {
  batchKind: BatchKind;
  unassignedRemainingCodes: number;
  assignedCodes: number;
  printableCodes: number;
  availableCodes: number;
  remainingStartCode: string | null;
  remainingEndCode: string | null;
  inventoryCounts: BatchInventoryCounts;
  printedCodes: number;
  redeemedCodes: number;
  blockedCodes: number;
};

const emptyCounts = (): BatchInventoryCounts => ({
  dormant: 0,
  active: 0,
  activated: 0,
  allocated: 0,
  printed: 0,
  redeemed: 0,
  blocked: 0,
  scanned: 0,
});

const toCountKey = (status: QRStatus): keyof BatchInventoryCounts => {
  if (status === QRStatus.DORMANT) return "dormant";
  if (status === QRStatus.ACTIVE) return "active";
  if (status === QRStatus.ACTIVATED) return "activated";
  if (status === QRStatus.ALLOCATED) return "allocated";
  if (status === QRStatus.PRINTED) return "printed";
  if (status === QRStatus.REDEEMED) return "redeemed";
  if (status === QRStatus.BLOCKED) return "blocked";
  return "scanned";
};

const shouldBackfillLineage = (key: string, force?: boolean) => {
  if (force) return true;
  const now = Date.now();
  const last = lineageBackfillState.get(key) || 0;
  if (now - last < LINEAGE_BACKFILL_COOLDOWN_MS) return false;
  lineageBackfillState.set(key, now);
  return true;
};

export const backfillBatchLineageFromAuditLogs = async (opts?: {
  licenseeId?: string;
  limit?: number;
  force?: boolean;
}) => {
  const scopeKey = opts?.licenseeId || "__ALL__";
  if (!shouldBackfillLineage(scopeKey, opts?.force)) return;

  const logs = await prisma.auditLog.findMany({
    where: {
      action: "ALLOCATED",
      entityType: "Batch",
      ...(opts?.licenseeId ? { licenseeId: opts.licenseeId } : {}),
    },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: Math.max(100, Math.min(opts?.limit ?? 2500, 10_000)),
    select: {
      entityId: true,
      details: true,
    },
  });

  const parentRootCache = new Map<string, string>();

  for (const log of logs.reverse()) {
    const details = (log.details || {}) as Record<string, unknown>;
    const context = String(details.context || "").trim().toUpperCase();
    if (context !== "ASSIGN_MANUFACTURER_QUANTITY_CHILD") continue;

    const childBatchId = String(log.entityId || "").trim();
    const parentBatchId = String(details.parentBatchId || "").trim();
    if (!childBatchId || !parentBatchId) continue;

    let rootBatchId = parentRootCache.get(parentBatchId);
    if (!rootBatchId) {
      const parent = await prisma.batch.findUnique({
        where: { id: parentBatchId },
        select: { id: true, rootBatchId: true },
      });
      if (!parent) continue;
      rootBatchId = parent.rootBatchId || parent.id;
      parentRootCache.set(parentBatchId, rootBatchId);
    }

    await prisma.batch.updateMany({
      where: {
        id: childBatchId,
        OR: [{ parentBatchId: null }, { rootBatchId: null }],
      },
      data: {
        parentBatchId,
        rootBatchId,
      },
    });
  }
};

const buildCountMaps = async (batchIds: string[]) => {
  if (batchIds.length === 0) {
    return {
      countsMap: new Map<string, BatchInventoryCounts>(),
      unassignedRangeMap: new Map<string, { start: string | null; end: string | null }>(),
      printableRangeMap: new Map<string, { start: string | null; end: string | null }>(),
    };
  }

  const [rollups, unassignedRanges, printableRanges] = await Promise.all([
    prisma.inventoryStatusRollup.findMany({
      where: { batchId: { in: batchIds } },
      select: {
        batchId: true,
        dormant: true,
        active: true,
        activated: true,
        allocated: true,
        printed: true,
        redeemed: true,
        blocked: true,
        scanned: true,
      },
    }),
    prisma.qRCode.groupBy({
      by: ["batchId"],
      where: {
        batchId: { in: batchIds },
        status: { in: [...UNASSIGNED_STATUSES] },
      },
      _count: { _all: true },
      _min: { code: true },
      _max: { code: true },
    }),
    prisma.qRCode.groupBy({
      by: ["batchId"],
      where: {
        batchId: { in: batchIds },
        status: { in: [...PRINTABLE_STATUSES] },
      },
      _count: { _all: true },
      _min: { code: true },
      _max: { code: true },
    }),
  ]);

  const countsMap = new Map<string, BatchInventoryCounts>();
  for (const rollup of rollups) {
    countsMap.set(rollup.batchId, {
      dormant: Number(rollup.dormant || 0),
      active: Number(rollup.active || 0),
      activated: Number(rollup.activated || 0),
      allocated: Number(rollup.allocated || 0),
      printed: Number(rollup.printed || 0),
      redeemed: Number(rollup.redeemed || 0),
      blocked: Number(rollup.blocked || 0),
      scanned: Number(rollup.scanned || 0),
    });
  }

  const missingBatchIds = batchIds.filter((batchId) => !countsMap.has(batchId));
  if (missingBatchIds.length > 0) {
    const countGroups = await prisma.qRCode.groupBy({
      by: ["batchId", "status"],
      where: { batchId: { in: missingBatchIds } },
      _count: { _all: true },
    });

    for (const group of countGroups) {
      if (!group.batchId) continue;
      const current = countsMap.get(group.batchId) || emptyCounts();
      current[toCountKey(group.status)] = group._count?._all || 0;
      countsMap.set(group.batchId, current);
    }
  }

  const unassignedRangeMap = new Map<string, { start: string | null; end: string | null }>();
  for (const group of unassignedRanges) {
    if (!group.batchId) continue;
    unassignedRangeMap.set(group.batchId, {
      start: group._min?.code || null,
      end: group._max?.code || null,
    });
  }

  const printableRangeMap = new Map<string, { start: string | null; end: string | null }>();
  for (const group of printableRanges) {
    if (!group.batchId) continue;
    printableRangeMap.set(group.batchId, {
      start: group._min?.code || null,
      end: group._max?.code || null,
    });
  }

  return {
    countsMap,
    unassignedRangeMap,
    printableRangeMap,
  };
};

export const enrichBatchSummaries = async (batches: BatchWithScope[]): Promise<BatchOperationalSummary[]> => {
  if (!batches.length) return [];

  const batchIds = batches.map((batch) => batch.id);
  const { countsMap, unassignedRangeMap, printableRangeMap } = await buildCountMaps(batchIds);

  return batches.map((batch) => {
    const counts = countsMap.get(batch.id) || emptyCounts();
    const batchKind: BatchKind = batch.manufacturerId ? "MANUFACTURER_CHILD" : "RECEIVED_PARENT";
    const unassignedRemainingCodes = batchKind === "RECEIVED_PARENT" ? counts.dormant + counts.active : 0;
    const printableCodes = batchKind === "MANUFACTURER_CHILD" ? counts.allocated + counts.dormant + counts.active : 0;
    const assignedCodes = batchKind === "MANUFACTURER_CHILD" ? batch.totalCodes : 0;
    const activeRange = batchKind === "MANUFACTURER_CHILD" ? printableRangeMap.get(batch.id) : unassignedRangeMap.get(batch.id);

    return {
      ...batch,
      batchKind,
      unassignedRemainingCodes,
      assignedCodes,
      printableCodes,
      availableCodes: batchKind === "MANUFACTURER_CHILD" ? printableCodes : unassignedRemainingCodes,
      remainingStartCode: activeRange?.start || null,
      remainingEndCode: activeRange?.end || null,
      inventoryCounts: counts,
      printedCodes: counts.printed,
      redeemedCodes: counts.redeemed + counts.scanned,
      blockedCodes: counts.blocked,
    };
  });
};

export const getBatchAllocationMap = async (batchId: string, opts?: { licenseeId?: string }) => {
  const focusBatch = await prisma.batch.findFirst({
    where: {
      id: batchId,
      ...(opts?.licenseeId ? { licenseeId: opts.licenseeId } : {}),
    },
    include: {
      licensee: { select: { id: true, name: true, prefix: true } },
      manufacturer: { select: { id: true, name: true, email: true } },
      _count: { select: { qrCodes: true } },
    },
  });

  if (!focusBatch) return null;

  const sourceBatchId = focusBatch.rootBatchId || focusBatch.parentBatchId || focusBatch.id;
  const relatedBatches = await prisma.batch.findMany({
    where: {
      licenseeId: focusBatch.licenseeId,
      OR: [
        { id: sourceBatchId },
        { parentBatchId: sourceBatchId },
        { rootBatchId: sourceBatchId },
      ],
    },
    orderBy: [{ createdAt: "asc" }, { id: "asc" }],
    include: {
      licensee: { select: { id: true, name: true, prefix: true } },
      manufacturer: { select: { id: true, name: true, email: true } },
      _count: { select: { qrCodes: true } },
    },
  });

  const enriched = await enrichBatchSummaries(relatedBatches as BatchWithScope[]);
  const sourceBatch = enriched.find((batch) => batch.id === sourceBatchId) || null;
  const selectedBatch = enriched.find((batch) => batch.id === focusBatch.id) || null;
  const allocationBatches = enriched.filter((batch) => batch.id !== sourceBatchId);

  const totalDistributedCodes = allocationBatches.reduce((acc, batch) => acc + batch.totalCodes, 0);
  const pendingPrintableCodes = allocationBatches.reduce((acc, batch) => acc + batch.printableCodes, 0);
  const printedCodes = allocationBatches.reduce((acc, batch) => acc + batch.printedCodes + batch.redeemedCodes, 0);

  return {
    sourceBatchId,
    focusBatchId: focusBatch.id,
    sourceBatch,
    selectedBatch,
    allocations: allocationBatches,
    totals: {
      totalDistributedCodes,
      sourceRemainingCodes: sourceBatch?.unassignedRemainingCodes || 0,
      pendingPrintableCodes,
      printedCodes,
    },
  };
};

export const buildLineageSuccessMessage = (params: {
  sourceBatchName: string;
  sourceBatchId: string;
  allocatedBatchName: string;
  allocatedBatchId: string;
  sourceRemainingCodes: number;
}) => {
  return {
    title: `Allocated ${params.allocatedBatchName}`,
    body: `The remaining unassigned inventory stays in ${params.sourceBatchName} (${params.sourceBatchId}). The allocated portion is now ${params.allocatedBatchName} (${params.allocatedBatchId}). ${params.sourceRemainingCodes.toLocaleString()} codes remain ready for later allocation in the source batch.`,
  };
};

export const readableStatusCount = (counts: BatchInventoryCounts) => ({
  dormant: counts.dormant,
  active: counts.active,
  allocated: counts.allocated,
  printed: counts.printed,
  redeemed: counts.redeemed + counts.scanned,
  blocked: counts.blocked,
});

export const isPrintableStatus = (status: QRStatus) => PRINTABLE_STATUSES.includes(status as (typeof PRINTABLE_STATUSES)[number]);
export const isUnassignedStatus = (status: QRStatus) => UNASSIGNED_STATUSES.includes(status as (typeof UNASSIGNED_STATUSES)[number]);
export const isRedeemedStatus = (status: QRStatus) => REDEEMED_STATUSES.includes(status as (typeof REDEEMED_STATUSES)[number]);

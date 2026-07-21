import { BatchLifecycleState, Prisma, QRStatus } from "@prisma/client";

import prisma from "../config/database";
import { CanonicalTransactionClient } from "../lib/canonicalDbContext";
import { listReservableQrCodeSummaries } from "./printReservationService";
import {
  buildBatchPrintReadinessFromSummary,
  type BatchPrintReadiness,
} from "./batchPrintLifecycleReconciliationService";

const LINEAGE_BACKFILL_COOLDOWN_MS = 5 * 60_000;
const lineageBackfillState = new Map<string, number>();

export type BatchOperationalRepositoryBoundary = {
  auditId: string;
  requestedLicenseeId: string | null;
  routeSurface: "GET /api/qr/batches" | "GET /api/qr/batches/:id/allocation-map";
  focusBatchId: string | null;
};

export type AuthorizedBatchOperationalRepositoryBoundary = BatchOperationalRepositoryBoundary & {
  scopeFingerprint: string;
};

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
  lifecycleState?: BatchLifecycleState | null;
  releasedAt?: Date | null;
  releasedByUserId?: string | null;
  sampleScanPolicy?: Prisma.JsonValue | null;
  metadata?: Prisma.JsonValue | null;
  createdAt: Date;
  updatedAt: Date;
  suspendedAt?: Date | null;
  suspendedReason?: string | null;
  printPackDownloadedAt?: Date | null;
  printPackDownloadedByUserId?: string | null;
  licensee?: { id: string; name: string; prefix: string } | null;
  manufacturer?: { id: string; name: string; email: string } | null;
  parentBatch?: { id: string; name: string } | null;
  rootBatch?: { id: string; name: string } | null;
  _count?: { qrCodes: number };
};

type JsonRecord = Record<string, Prisma.JsonValue | undefined>;

const jsonRecord = (value: Prisma.JsonValue, field: string): JsonRecord => {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Batch operational function returned invalid ${field}`);
  }
  return value as JsonRecord;
};

const fieldValue = (row: JsonRecord, field: string) => {
  if (!Object.prototype.hasOwnProperty.call(row, field)) {
    throw new Error(`Batch operational function omitted ${field}`);
  }
  return row[field] as Prisma.JsonValue;
};

const requiredString = (row: JsonRecord, field: string) => {
  const value = fieldValue(row, field);
  if (typeof value !== "string" || !value) throw new Error(`Batch operational function returned invalid ${field}`);
  return value;
};

const nullableString = (row: JsonRecord, field: string) => {
  const value = fieldValue(row, field);
  if (value == null) return null;
  if (typeof value !== "string") throw new Error(`Batch operational function returned invalid ${field}`);
  return value;
};

const safeCount = (value: unknown, field: string) => {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized < 0) {
    throw new Error(`Batch operational function returned invalid ${field}`);
  }
  return normalized;
};

const dateValue = (row: JsonRecord, field: string, required = false) => {
  const value = fieldValue(row, field);
  if (value == null && !required) return null;
  const date = new Date(String(value || ""));
  if (!Number.isFinite(date.getTime())) throw new Error(`Batch operational function returned invalid ${field}`);
  return date;
};

const namedRelation = (value: Prisma.JsonValue | undefined, field: string, includePrefix = false) => {
  if (value == null) return null;
  const row = jsonRecord(value, field);
  return {
    id: requiredString(row, "id"),
    name: requiredString(row, "name"),
    ...(includePrefix ? { prefix: requiredString(row, "prefix") } : {}),
  };
};

const batchFromFunction = (value: Prisma.JsonValue, includeLineageRelations: boolean): BatchWithScope => {
  const row = jsonRecord(value, "row_data");
  const manufacturerValue = fieldValue(row, "manufacturer");
  const manufacturer = manufacturerValue == null ? null : jsonRecord(manufacturerValue, "manufacturer");
  const countRow = jsonRecord(fieldValue(row, "_count"), "_count");
  const licensee = namedRelation(fieldValue(row, "licensee"), "licensee", true);
  if (!licensee || !("prefix" in licensee)) throw new Error("Batch operational function returned invalid licensee");
  return {
    id: requiredString(row, "id"),
    name: requiredString(row, "name"),
    licenseeId: requiredString(row, "licenseeId"),
    manufacturerId: nullableString(row, "manufacturerId"),
    parentBatchId: nullableString(row, "parentBatchId"),
    rootBatchId: nullableString(row, "rootBatchId"),
    startCode: requiredString(row, "startCode"),
    endCode: requiredString(row, "endCode"),
    totalCodes: safeCount(row.totalCodes, "totalCodes"),
    lifecycleState: requiredString(row, "lifecycleState") as BatchLifecycleState,
    sampleScanPolicy: fieldValue(row, "sampleScanPolicy"),
    metadata: fieldValue(row, "metadata"),
    releasedAt: dateValue(row, "releasedAt"),
    releasedByUserId: nullableString(row, "releasedByUserId"),
    printedAt: dateValue(row, "printedAt"),
    suspendedAt: dateValue(row, "suspendedAt"),
    suspendedReason: nullableString(row, "suspendedReason"),
    printPackDownloadedAt: dateValue(row, "printPackDownloadedAt"),
    printPackDownloadedByUserId: nullableString(row, "printPackDownloadedByUserId"),
    createdAt: dateValue(row, "createdAt", true)!,
    updatedAt: dateValue(row, "updatedAt", true)!,
    licensee: licensee as BatchWithScope["licensee"],
    manufacturer: manufacturer
      ? {
          id: requiredString(manufacturer, "id"),
          name: requiredString(manufacturer, "name"),
          email: requiredString(manufacturer, "email"),
        }
      : null,
    ...(includeLineageRelations ? {
      parentBatch: namedRelation(fieldValue(row, "parentBatch"), "parentBatch") as BatchWithScope["parentBatch"],
      rootBatch: namedRelation(fieldValue(row, "rootBatch"), "rootBatch") as BatchWithScope["rootBatch"],
    } : {}),
    _count: { qrCodes: safeCount(countRow.qrCodes, "_count.qrCodes") },
  };
};

const fingerprint = (value: unknown) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!/^(?:[0-9a-f]{32}|[0-9a-f]{64})$/.test(normalized)) {
    throw new Error("Batch operational function returned invalid scope fingerprint");
  }
  return normalized;
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
  printReadiness: BatchPrintReadiness;
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

const buildCountMaps = async (
  batchIds: string[],
  db: CanonicalTransactionClient,
  boundary: AuthorizedBatchOperationalRepositoryBoundary
) => {
  if (batchIds.length === 0) {
    return {
      countsMap: new Map<string, BatchInventoryCounts>(),
      unassignedRangeMap: new Map<string, { start: string | null; end: string | null }>(),
      printableRangeMap: new Map<string, { start: string | null; end: string | null }>(),
      reservableCountMap: new Map<string, number>(),
    };
  }

  const readRollups = (ids: string[]) =>
    db.$queryRaw<Array<{
      batch_id: string;
      dormant: bigint | number | string;
      active: bigint | number | string;
      activated: bigint | number | string;
      allocated: bigint | number | string;
      printed: bigint | number | string;
      redeemed: bigint | number | string;
      blocked: bigint | number | string;
      scanned: bigint | number | string;
    }>>`
      SELECT batch_id, dormant, active, activated, allocated, printed, redeemed, blocked, scanned
      FROM app_rls.batch_inventory_rollups(
        ${boundary.auditId},
        ${boundary.requestedLicenseeId},
        ${boundary.routeSurface},
        ${boundary.focusBatchId},
        ${boundary.scopeFingerprint},
        ARRAY[${Prisma.join(ids)}]::text[]
      )
    `;
  const readUnassignedRanges = (ids: string[]) =>
    db.$queryRaw<Array<{
      batch_id: string;
      start_code: string | null;
      end_code: string | null;
    }>>`
      SELECT batch_id, start_code, end_code
      FROM app_rls.batch_unassigned_ranges(
        ${boundary.auditId},
        ${boundary.requestedLicenseeId},
        ${boundary.routeSurface},
        ${boundary.focusBatchId},
        ${boundary.scopeFingerprint},
        ARRAY[${Prisma.join(ids)}]::text[]
      )
    `;
  const readReservableSummaries = (ids: string[]) =>
    listReservableQrCodeSummaries(db, ids, boundary);

  const chunks = Array.from({ length: Math.ceil(batchIds.length / 500) }, (_, index) =>
    batchIds.slice(index * 500, (index + 1) * 500)
  );
  const rollups = [] as Awaited<ReturnType<typeof readRollups>>;
  const unassignedRanges = [] as Awaited<ReturnType<typeof readUnassignedRanges>>;
  const reservableSummaryMap = new Map<string, { count: number; startCode: string | null; endCode: string | null }>();
  for (const ids of chunks) {
    rollups.push(...await readRollups(ids));
    unassignedRanges.push(...await readUnassignedRanges(ids));
    for (const [batchId, summary] of await readReservableSummaries(ids)) {
      reservableSummaryMap.set(batchId, summary);
    }
  }

  const countsMap = new Map<string, BatchInventoryCounts>();
  for (const rollup of rollups) {
    countsMap.set(rollup.batch_id, {
      dormant: safeCount(rollup.dormant, "dormant"),
      active: safeCount(rollup.active, "active"),
      activated: safeCount(rollup.activated, "activated"),
      allocated: safeCount(rollup.allocated, "allocated"),
      printed: safeCount(rollup.printed, "printed"),
      redeemed: safeCount(rollup.redeemed, "redeemed"),
      blocked: safeCount(rollup.blocked, "blocked"),
      scanned: safeCount(rollup.scanned, "scanned"),
    });
  }

  const missingBatchIds = batchIds.filter((batchId) => !countsMap.has(batchId));
  if (missingBatchIds.length > 0) {
    const countGroups: Array<{ batch_id: string; status: QRStatus; count: bigint | number | string }> = [];
    for (let offset = 0; offset < missingBatchIds.length; offset += 500) {
      const ids = missingBatchIds.slice(offset, offset + 500);
      countGroups.push(...await db.$queryRaw<typeof countGroups>`
        SELECT batch_id, status, item_count AS count
        FROM app_rls.batch_status_fallback(
          ${boundary.auditId},
          ${boundary.requestedLicenseeId},
          ${boundary.routeSurface},
          ${boundary.focusBatchId},
          ${boundary.scopeFingerprint},
          ARRAY[${Prisma.join(ids)}]::text[]
        )
      `);
    }

    for (const group of countGroups) {
      if (!group.batch_id || !Object.values(QRStatus).includes(group.status)) {
        throw new Error("Batch operational function returned invalid status fallback");
      }
      const current = countsMap.get(group.batch_id) || emptyCounts();
      current[toCountKey(group.status)] = safeCount(group.count, "status count");
      countsMap.set(group.batch_id, current);
    }
  }

  const unassignedRangeMap = new Map<string, { start: string | null; end: string | null }>();
  for (const group of unassignedRanges) {
    if (!group.batch_id) throw new Error("Batch operational function returned invalid unassigned range");
    unassignedRangeMap.set(group.batch_id, {
      start: group.start_code || null,
      end: group.end_code || null,
    });
  }

  return {
    countsMap,
    unassignedRangeMap,
    printableRangeMap: new Map(
      [...reservableSummaryMap.entries()].map(([batchId, summary]) => [
        batchId,
        { start: summary.startCode, end: summary.endCode },
      ])
    ),
    reservableCountMap: new Map([...reservableSummaryMap.entries()].map(([batchId, summary]) => [batchId, summary.count])),
  };
};

export const enrichBatchSummaries = async (
  batches: BatchWithScope[],
  db: CanonicalTransactionClient,
  boundary: AuthorizedBatchOperationalRepositoryBoundary
): Promise<BatchOperationalSummary[]> => {
  if (!batches.length) return [];

  const batchIds = batches.map((batch) => batch.id);
  const { countsMap, unassignedRangeMap, printableRangeMap, reservableCountMap } = await buildCountMaps(
    batchIds,
    db,
    boundary
  );

  return batches.map((batch) => {
    const counts = countsMap.get(batch.id) || emptyCounts();
    const batchKind: BatchKind = batch.manufacturerId ? "MANUFACTURER_CHILD" : "RECEIVED_PARENT";
    const unassignedRemainingCodes = batchKind === "RECEIVED_PARENT" ? counts.dormant + counts.active : 0;
    const printableCodes = batchKind === "MANUFACTURER_CHILD" ? reservableCountMap.get(batch.id) || 0 : 0;
    const assignedCodes = batchKind === "MANUFACTURER_CHILD" ? batch.totalCodes : 0;
    const activeRange = batchKind === "MANUFACTURER_CHILD" ? printableRangeMap.get(batch.id) : unassignedRangeMap.get(batch.id);
    const printReadiness = buildBatchPrintReadinessFromSummary({
      batchId: batch.id,
      lifecycleState: batch.lifecycleState || BatchLifecycleState.DRAFT,
      releasedAt: batch.releasedAt || null,
      availableToPrint: batchKind === "MANUFACTURER_CHILD" ? printableCodes : 0,
      printedAt: batch.printedAt,
      printedCodes: counts.printed + counts.redeemed + counts.scanned,
      allocatedCodes: counts.allocated,
      manufacturerId: batch.manufacturerId,
      parentBatchId: batch.parentBatchId,
      rootBatchId: batch.rootBatchId,
    });

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
      printReadiness,
      printedCodes: counts.printed,
      redeemedCodes: counts.redeemed + counts.scanned,
      blockedCodes: counts.blocked,
    };
  });
};

export const listBatchOperationalSummaries = async (params: {
  boundary: BatchOperationalRepositoryBoundary;
  limit: number;
  offset: number;
  db: CanonicalTransactionClient;
}) => {
  if (
    params.boundary.routeSurface !== "GET /api/qr/batches" ||
    params.boundary.focusBatchId ||
    !Number.isInteger(params.limit) ||
    params.limit < 1 ||
    params.limit > 500 ||
    !Number.isInteger(params.offset) ||
    params.offset < 0
  ) {
    throw new Error("Invalid batch operational list boundary");
  }

  let scopeFingerprint = "";
  const readBatches = async () => {
    const [scope] = await params.db.$queryRaw<Array<{ scope_fingerprint: string }>>`
      SELECT scope_fingerprint
      FROM app_rls.batch_operational_scope(
        ${params.boundary.auditId},
        ${params.boundary.requestedLicenseeId},
        ${params.boundary.routeSurface},
        ${params.boundary.focusBatchId}
      )
    `;
    scopeFingerprint = fingerprint(scope?.scope_fingerprint);
    const rows = await params.db.$queryRaw<Array<{ row_data: Prisma.JsonValue }>>`
      SELECT row_data
      FROM app_rls.batch_operational_rows(
        ${params.boundary.auditId},
        ${params.boundary.requestedLicenseeId},
        ${params.boundary.routeSurface},
        ${params.boundary.focusBatchId},
        ${scopeFingerprint},
        CAST(${params.limit} AS integer),
        CAST(${params.offset} AS integer)
      )
    `;
    return rows.map((row) => batchFromFunction(row.row_data, true));
  };
  const readTotal = async () => {
    const [row] = await params.db.$queryRaw<Array<{ total: bigint | number | string }>>`
      SELECT total
      FROM app_rls.batch_operational_total(
        ${params.boundary.auditId},
        ${params.boundary.requestedLicenseeId},
        ${params.boundary.routeSurface},
        ${params.boundary.focusBatchId},
        ${scopeFingerprint}
      )
    `;
    return safeCount(row?.total, "total");
  };
  const batches = await readBatches();
  const total = await readTotal();
  const authorizedBoundary = { ...params.boundary, scopeFingerprint };
  return {
    rows: batches.length ? await enrichBatchSummaries(batches, params.db, authorizedBoundary) : batches,
    total,
  };
};

export const getBatchAllocationMap = async (
  batchId: string,
  opts: { boundary: BatchOperationalRepositoryBoundary; db: CanonicalTransactionClient }
) => {
  if (
    opts.boundary.routeSurface !== "GET /api/qr/batches/:id/allocation-map" ||
    opts.boundary.focusBatchId !== batchId
  ) {
    throw new Error("Invalid batch allocation-map boundary");
  }
  const [scope] = await opts.db.$queryRaw<Array<{ scope_fingerprint: string }>>`
    SELECT scope_fingerprint
    FROM app_rls.batch_operational_scope(
      ${opts.boundary.auditId},
      ${opts.boundary.requestedLicenseeId},
      ${opts.boundary.routeSurface},
      ${batchId}
    )
  `;
  const scopeFingerprint = fingerprint(scope?.scope_fingerprint);
  const rows = await opts.db.$queryRaw<Array<{ row_data: Prisma.JsonValue }>>`
    SELECT row_data
    FROM app_rls.batch_operational_rows(
      ${opts.boundary.auditId},
      ${opts.boundary.requestedLicenseeId},
      ${opts.boundary.routeSurface},
      ${batchId},
      ${scopeFingerprint},
      CAST(${0} AS integer),
      CAST(${0} AS integer)
    )
  `;
  const relatedBatches = rows.map((row) => batchFromFunction(row.row_data, false));
  const focusBatch = relatedBatches.find((batch) => batch.id === batchId) || null;
  if (!focusBatch) return null;

  const sourceBatchId = focusBatch.rootBatchId || focusBatch.parentBatchId || focusBatch.id;
  const enriched = await enrichBatchSummaries(
    relatedBatches,
    opts.db,
    { ...opts.boundary, scopeFingerprint }
  );
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

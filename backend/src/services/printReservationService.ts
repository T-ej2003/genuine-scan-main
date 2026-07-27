import {
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintSessionStatus,
  Prisma,
  QRStatus,
} from "@prisma/client";

import type { CanonicalTransactionClient } from "../lib/canonicalDbContext";
import type { AuthorizedBatchOperationalRepositoryBoundary } from "./batchAllocationService";

const REUSABLE_DEAD_LETTER_REASONS = new Set([
  "operator_abandoned_unconfirmed_run",
  "pre_dispatch_failure",
  "connector_payload_validation_failed_before_dispatch",
  "printer_agent_payload_failed_before_dispatch",
]);

const REUSABLE_FAILURE_PATTERNS = [
  /operator closed unconfirmed failed print run/i,
  /operator abandoned unconfirmed print run/i,
  /before any printer acknowledgement/i,
  /pre[- ]dispatch/i,
];

type EvidenceFields = {
  agentAckedAt?: Date | string | null;
  dispatchedAt?: Date | string | null;
  printConfirmedAt?: Date | string | null;
  confirmationEvidence?: unknown;
  deviceJobRef?: string | null;
};

export type ReusablePrintItemCandidate = EvidenceFields & {
  state?: PrintItemState | string | null;
  failureReason?: string | null;
  deadLetterReason?: string | null;
  printSession?: { status?: PrintSessionStatus | string | null; printJob?: { status?: PrintJobStatus | string | null } | null } | null;
};

export type ReservableQrCodeRow = {
  id: string;
  code: string;
  displayCode: string | null;
  licenseeId: string;
  batchId: string | null;
  replayEpoch: number | null;
  reusablePrintItemId: string | null;
  previousPrintSessionId: string | null;
  previousPrintJobId: string | null;
  previousPrintItemState: PrintItemState | null;
  previousAttemptCount: number | null;
};

export type ReservableQrCodeSummary = {
  count: number;
  startCode: string | null;
  endCode: string | null;
};

export type UnresolvedRecoveryRange = {
  count: number;
  startCode: string;
  endCode: string;
  printSessionId: string | null;
  printJobId: string | null;
};

const hasNonEmptyJsonEvidence = (value: unknown) => {
  if (value === null || value === undefined) return false;
  if (typeof value === "object" && !Array.isArray(value)) return Object.keys(value as Record<string, unknown>).length > 0;
  return true;
};

export const hasPrintItemPhysicalEvidence = (item: EvidenceFields) =>
  Boolean(
    item.agentAckedAt ||
      item.dispatchedAt ||
      item.printConfirmedAt ||
      item.deviceJobRef ||
      hasNonEmptyJsonEvidence(item.confirmationEvidence)
  );

const hasReusableReason = (item: ReusablePrintItemCandidate) => {
  const deadLetterReason = String(item.deadLetterReason || "").trim();
  if (REUSABLE_DEAD_LETTER_REASONS.has(deadLetterReason)) return true;

  const failureReason = String(item.failureReason || "").trim();
  return REUSABLE_FAILURE_PATTERNS.some((pattern) => pattern.test(failureReason));
};

export const isZeroEvidencePrintItemReusable = (item: ReusablePrintItemCandidate) => {
  const itemState = String(item.state || "").trim();
  const sessionStatus = String(item.printSession?.status || "").trim();
  const jobStatus = String(item.printSession?.printJob?.status || "").trim();

  const stoppedUnconfirmedRecovery =
    itemState === PrintItemState.CANCELLED &&
    sessionStatus === PrintSessionStatus.STOPPED &&
    (jobStatus === PrintJobStatus.STOPPED || jobStatus === PrintJobStatus.PARTIALLY_COMPLETED) &&
    !item.printConfirmedAt &&
    !hasNonEmptyJsonEvidence(item.confirmationEvidence);
  if (stoppedUnconfirmedRecovery) return true;

  if (hasPrintItemPhysicalEvidence(item)) return false;
  if (!hasReusableReason(item)) return false;

  if (itemState !== PrintItemState.FAILED && itemState !== PrintItemState.FROZEN) return false;
  if (sessionStatus !== PrintSessionStatus.CANCELLED && sessionStatus !== PrintSessionStatus.FAILED) return false;
  return jobStatus === PrintJobStatus.CANCELLED || jobStatus === PrintJobStatus.FAILED;
};

const reusablePrintItemSql = Prisma.sql`
  pi."id" IS NOT NULL
  AND pi."printConfirmedAt" IS NULL
  AND (
    pi."confirmationEvidence" IS NULL
    OR pi."confirmationEvidence"::text IN ('null', '{}')
  )
  AND (
    (
      pi."state" IN (CAST(${PrintItemState.FAILED} AS "PrintItemState"), CAST(${PrintItemState.FROZEN} AS "PrintItemState"))
      AND pi."agentAckedAt" IS NULL
      AND pi."dispatchedAt" IS NULL
      AND pi."deviceJobRef" IS NULL
      AND (
        pi."deadLetterReason" IN (${Prisma.join([...REUSABLE_DEAD_LETTER_REASONS])})
        OR pi."failureReason" ILIKE '%operator closed unconfirmed failed print run%'
        OR pi."failureReason" ILIKE '%operator abandoned unconfirmed print run%'
        OR pi."failureReason" ILIKE '%before any printer acknowledgement%'
        OR pi."failureReason" ILIKE '%pre-dispatch%'
        OR pi."failureReason" ILIKE '%pre dispatch%'
      )
      AND ps."status" IN (CAST(${PrintSessionStatus.CANCELLED} AS "PrintSessionStatus"), CAST(${PrintSessionStatus.FAILED} AS "PrintSessionStatus"))
      AND pj."status" IN (CAST(${PrintJobStatus.CANCELLED} AS "PrintJobStatus"), CAST(${PrintJobStatus.FAILED} AS "PrintJobStatus"))
    )
    OR (
      pi."state" = CAST(${PrintItemState.CANCELLED} AS "PrintItemState")
      AND ps."status" = CAST(${PrintSessionStatus.STOPPED} AS "PrintSessionStatus")
      AND pj."status" IN (CAST(${PrintJobStatus.STOPPED} AS "PrintJobStatus"), CAST(${PrintJobStatus.PARTIALLY_COMPLETED} AS "PrintJobStatus"))
    )
  )
`;

const reservableQrWhereSql = (params: {
  batchIdSql: Prisma.Sql;
  rangeStart?: string | null;
  rangeEnd?: string | null;
}) => {
  const rangeFilter =
    params.rangeStart && params.rangeEnd
      ? Prisma.sql`AND COALESCE(q."displayCode", q."code") >= ${params.rangeStart} AND COALESCE(q."displayCode", q."code") <= ${params.rangeEnd}`
      : Prisma.empty;

  return Prisma.sql`
    q."batchId" ${params.batchIdSql}
    AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
    AND q."printJobId" IS NULL
    ${rangeFilter}
    AND (
      pi."id" IS NULL
      OR (${reusablePrintItemSql})
    )
  `;
};

export const selectReservableQrCodesForPrint = async (
  tx: Prisma.TransactionClient,
  params: { batchId: string; quantity: number; rangeStart?: string | null; rangeEnd?: string | null }
) =>
  tx.$queryRaw<ReservableQrCodeRow[]>(Prisma.sql`
    SELECT
      q."id",
      q."code",
      q."displayCode",
      q."licenseeId",
      q."batchId",
      q."replayEpoch",
      pi."id" AS "reusablePrintItemId",
      pi."printSessionId" AS "previousPrintSessionId",
      ps."printJobId" AS "previousPrintJobId",
      pi."state" AS "previousPrintItemState",
      pi."attemptCount" AS "previousAttemptCount"
    FROM "QRCode" q
    LEFT JOIN "PrintItem" pi ON pi."qrCodeId" = q."id"
    LEFT JOIN "PrintSession" ps ON ps."id" = pi."printSessionId"
    LEFT JOIN "PrintJob" pj ON pj."id" = ps."printJobId"
    WHERE ${reservableQrWhereSql({
      batchIdSql: Prisma.sql`= ${params.batchId}`,
      rangeStart: params.rangeStart,
      rangeEnd: params.rangeEnd,
    })}
    ORDER BY COALESCE(q."displayCode", q."code") ASC, q."createdAt" ASC
    FOR UPDATE OF q SKIP LOCKED
    LIMIT ${params.quantity};
  `);

export const countReservableQrCodesForPrint = async (
  client: Prisma.TransactionClient,
  params: { batchId: string; rangeStart?: string | null; rangeEnd?: string | null }
) => {
  const rows = await client.$queryRaw<Array<{ count: bigint | number }>>(Prisma.sql`
    SELECT COUNT(*)::int AS "count"
    FROM "QRCode" q
    LEFT JOIN "PrintItem" pi ON pi."qrCodeId" = q."id"
    LEFT JOIN "PrintSession" ps ON ps."id" = pi."printSessionId"
    LEFT JOIN "PrintJob" pj ON pj."id" = ps."printJobId"
    WHERE ${reservableQrWhereSql({
      batchIdSql: Prisma.sql`= ${params.batchId}`,
      rangeStart: params.rangeStart,
      rangeEnd: params.rangeEnd,
    })};
  `);
  return Number(rows[0]?.count || 0);
};

export const countBlockedQrCodesForPrint = async (
  client: Prisma.TransactionClient,
  params: { batchId: string; rangeStart?: string | null; rangeEnd?: string | null }
) => {
  const rangeFilter =
    params.rangeStart && params.rangeEnd
      ? Prisma.sql`AND COALESCE(q."displayCode", q."code") >= ${params.rangeStart} AND COALESCE(q."displayCode", q."code") <= ${params.rangeEnd}`
      : Prisma.empty;
  const rows = await client.$queryRaw<Array<{ count: bigint | number }>>(Prisma.sql`
    SELECT COUNT(*)::int AS "count"
    FROM "QRCode" q
    JOIN "PrintItem" pi ON pi."qrCodeId" = q."id"
    LEFT JOIN "PrintSession" ps ON ps."id" = pi."printSessionId"
    LEFT JOIN "PrintJob" pj ON pj."id" = ps."printJobId"
    WHERE q."batchId" = ${params.batchId}
      AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
      AND q."printJobId" IS NULL
      ${rangeFilter}
      AND NOT (${reusablePrintItemSql});
  `);
  return Number(rows[0]?.count || 0);
};

export const requestedRangeSkipsRecovery = (params: {
  recoveryStartCode?: string | null;
  rangeStart?: string | null;
  rangeEnd?: string | null;
}) => {
  const recoveryStart = String(params.recoveryStartCode || "").trim();
  if (!recoveryStart) return false;
  const rangeStart = String(params.rangeStart || "").trim();
  const rangeEnd = String(params.rangeEnd || "").trim();
  if (!rangeStart && !rangeEnd) return false;
  if (rangeStart && rangeStart > recoveryStart) return true;
  if (rangeEnd && rangeEnd < recoveryStart) return true;
  return false;
};

export const findUnresolvedRecoveryRangeForBatch = async (
  client: Prisma.TransactionClient,
  params: { batchId: string }
): Promise<UnresolvedRecoveryRange | null> => {
  const rows = await client.$queryRaw<
    Array<{
      count: bigint | number;
      startCode: string | null;
      endCode: string | null;
      printSessionId: string | null;
      printJobId: string | null;
    }>
  >(Prisma.sql`
    SELECT
      COUNT(*)::int AS "count",
      MIN(COALESCE(q."displayCode", q."code")) AS "startCode",
      MAX(COALESCE(q."displayCode", q."code")) AS "endCode",
      MIN(ps."id") AS "printSessionId",
      MIN(pj."id") AS "printJobId"
    FROM "QRCode" q
    JOIN "PrintItem" pi ON pi."qrCodeId" = q."id"
    JOIN "PrintSession" ps ON ps."id" = pi."printSessionId"
    JOIN "PrintJob" pj ON pj."id" = ps."printJobId"
    WHERE q."batchId" = ${params.batchId}
      AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
      AND q."printJobId" IS NULL
      AND ${reusablePrintItemSql}
      AND pi."state" = CAST(${PrintItemState.CANCELLED} AS "PrintItemState")
      AND ps."status" = CAST(${PrintSessionStatus.STOPPED} AS "PrintSessionStatus");
  `);
  const row = rows[0];
  const count = Number(row?.count || 0);
  if (!row || count <= 0 || !row.startCode || !row.endCode) return null;
  return {
    count,
    startCode: row.startCode,
    endCode: row.endCode,
    printSessionId: row.printSessionId || null,
    printJobId: row.printJobId || null,
  };
};

export const listReservableQrCodeSummaries = async (
  client: CanonicalTransactionClient,
  batchIds: string[],
  boundary: AuthorizedBatchOperationalRepositoryBoundary
): Promise<Map<string, ReservableQrCodeSummary>> => {
  if (batchIds.length === 0) return new Map();

  const rows = await client.$queryRaw<
    Array<{ batch_id: string; count: bigint | number | string; start_code: string | null; end_code: string | null }>
  >`
    SELECT
      batch_id,
      item_count AS count,
      start_code,
      end_code
    FROM app_rls.batch_reservable_qr_summaries(
      ${boundary.databaseSessionCapability}, ${boundary.purpose}, ${boundary.requestId},
      ${boundary.auditId},
      ${boundary.requestedLicenseeId},
      ${boundary.routeSurface},
      ${boundary.focusBatchId},
      ${boundary.scopeFingerprint},
      ARRAY[${Prisma.join(batchIds)}]::text[]
    )
  `;

  return rows.reduce<Map<string, ReservableQrCodeSummary>>((acc, row) => {
    const count = Number(row.count);
    if (!row.batch_id || !Number.isSafeInteger(count) || count < 0) {
      throw new Error("Batch operational function returned invalid reservable summary");
    }
    acc.set(row.batch_id, {
      count,
      startCode: row.start_code || null,
      endCode: row.end_code || null,
    });
    return acc;
  }, new Map());
};

export const buildReusablePrintItemResetData = (now: Date): Prisma.PrintItemUpdateManyMutationInput => ({
  state: PrintItemState.RESERVED,
  pipelineState: PrintPipelineState.QUEUED,
  issueSequence: null,
  attemptCount: { increment: 1 },
  currentRenderTokenHash: null,
  deviceJobRef: null,
  dispatchMetadata: Prisma.JsonNull,
  confirmationEvidence: Prisma.JsonNull,
  issuedAt: null,
  dispatchedAt: null,
  agentAckedAt: null,
  confirmationDeadlineAt: null,
  printConfirmedAt: null,
  closedAt: null,
  frozenAt: null,
  failedAt: null,
  failureReason: null,
  deadLetterReason: null,
  updatedAt: now,
});

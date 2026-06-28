import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintSessionStatus,
  Prisma,
  QRStatus,
  ReissueRequestStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { createAuditLog } from "./auditService";
import { createUserNotification } from "./notificationService";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "./qrTokenService";
import { startNetworkDirectDispatch } from "./networkDirectPrintService";
import { startNetworkIppDispatch } from "./networkIppPrintService";
import { ensureSelectedPrinterReady, generatePrintJobNumber } from "../controllers/print-job/shared";
import { buildScopedPrintJobWhere, type PrintJobScope } from "./printJobScopeService";
import { materializeReplacementChainsForReissue } from "./replacementChainService";
import {
  buildReusablePrintItemResetData,
  findUnresolvedRecoveryRangeForBatch,
  selectReservableQrCodesForPrint,
  type ReservableQrCodeRow,
} from "./printReservationService";

const BLOCKING_REISSUE_STATUSES = new Set<PrintJobStatus>([PrintJobStatus.PENDING, PrintJobStatus.SENT]);
const RECOVERABLE_ORIGINAL_JOB_STATUSES = new Set<PrintJobStatus>([
  PrintJobStatus.CONFIRMED,
  PrintJobStatus.PARTIALLY_COMPLETED,
  PrintJobStatus.STOPPED,
  PrintJobStatus.FAILED,
  PrintJobStatus.CANCELLED,
]);
const RECOVERABLE_ORIGINAL_SESSION_STATUSES = new Set<PrintSessionStatus>([
  PrintSessionStatus.COMPLETED,
  PrintSessionStatus.STOPPED,
  PrintSessionStatus.FAILED,
  PrintSessionStatus.CANCELLED,
]);

type PrintItemRangeRow = {
  code?: string | null;
  state?: PrintItemState | string | null;
  printConfirmedAt?: Date | string | null;
  confirmationEvidence?: unknown;
  qrCode?: { displayCode?: string | null } | null;
};

type ReissueRangeSummary = {
  startCode: string | null;
  endCode: string | null;
  count: number;
};

type OriginalReissueContext = {
  requestedRange: ReissueRangeSummary;
  confirmedRange: ReissueRangeSummary;
  recoveryRange: ReissueRangeSummary;
  failedRange: ReissueRangeSummary;
  requestedCount: number;
  confirmedCount: number;
  pendingCount: number;
  failedCount: number;
  recoveryStartLabel: string | null;
  recoveryEndLabel: string | null;
};

export type PrintJobReissueProjection = {
  printJobId: string;
  requestedCount: number;
  requestedRangeStart: string | null;
  requestedRangeEnd: string | null;
  confirmedCount: number;
  pendingCount: number;
  failedCount: number;
  recoveryStartLabel: string | null;
  recoveryEndLabel: string | null;
};

const hasNonEmptyJsonEvidence = (value: unknown) => {
  if (value === null || value === undefined) return false;
  if (typeof value === "object" && !Array.isArray(value)) return Object.keys(value as Record<string, unknown>).length > 0;
  return true;
};

const displayLabelCode = (row: PrintItemRangeRow) => {
  const displayCode = String(row.qrCode?.displayCode || "").trim();
  return displayCode || String(row.code || "").trim();
};

const buildRangeSummary = (codes: Array<string | null | undefined>): ReissueRangeSummary => {
  const sorted = codes.map((code) => String(code || "").trim()).filter(Boolean).sort();
  return {
    startCode: sorted[0] || null,
    endCode: sorted[sorted.length - 1] || null,
    count: sorted.length,
  };
};

const isConfirmedPrintItem = (row: PrintItemRangeRow) =>
  Boolean(
    row.printConfirmedAt ||
      row.state === PrintItemState.PRINT_CONFIRMED ||
      row.state === PrintItemState.CLOSED ||
      hasNonEmptyJsonEvidence(row.confirmationEvidence)
  );

const isFailedPrintItem = (row: PrintItemRangeRow) =>
  row.state === PrintItemState.FAILED || row.state === PrintItemState.FROZEN;

const buildOriginalReissueContext = (originalJob: any): OriginalReissueContext => {
  const itemRows: PrintItemRangeRow[] = Array.isArray(originalJob?.printSession?.items)
    ? originalJob.printSession.items
    : [];
  const requestedFallbackCount = Number(originalJob?.itemCount || originalJob?.quantity || 0);
  if (itemRows.length === 0) {
    const range = buildRangeSummary([originalJob?.rangeStart, originalJob?.rangeEnd].filter(Boolean));
    const requestedCount = requestedFallbackCount || range.count;
    return {
      requestedRange: { ...range, count: requestedCount || range.count },
      confirmedRange: originalJob?.confirmedAt ? { ...range, count: requestedCount || range.count } : { startCode: null, endCode: null, count: 0 },
      recoveryRange: { startCode: null, endCode: null, count: 0 },
      failedRange: { startCode: null, endCode: null, count: 0 },
      requestedCount,
      confirmedCount: originalJob?.confirmedAt ? requestedCount : 0,
      pendingCount: originalJob?.confirmedAt ? 0 : requestedCount,
      failedCount: 0,
      recoveryStartLabel: null,
      recoveryEndLabel: null,
    };
  }

  const confirmedRows = itemRows.filter(isConfirmedPrintItem);
  const failedRows = itemRows.filter(isFailedPrintItem);
  const recoveryRows = itemRows.filter((row) => !isConfirmedPrintItem(row));
  const recoveryRange = buildRangeSummary(recoveryRows.map(displayLabelCode));

  return {
    requestedRange: buildRangeSummary(itemRows.map(displayLabelCode)),
    confirmedRange: buildRangeSummary(confirmedRows.map(displayLabelCode)),
    recoveryRange,
    failedRange: buildRangeSummary(failedRows.map(displayLabelCode)),
    requestedCount: itemRows.length,
    confirmedCount: confirmedRows.length,
    pendingCount: recoveryRows.length,
    failedCount: failedRows.length,
    recoveryStartLabel: recoveryRange.startCode,
    recoveryEndLabel: recoveryRange.endCode,
  };
};

export const describeOriginalPrintJobForReissue = (originalJob: any, projection?: PrintJobReissueProjection | null) => {
  if (projection) {
    const requestedCount = projection.pendingCount > 0 ? projection.pendingCount : projection.requestedCount;
    return {
      requestedCount: requestedCount || Number(originalJob?.itemCount || originalJob?.quantity || 0),
      requestedRangeStart:
        projection.recoveryStartLabel ||
        projection.requestedRangeStart ||
        originalJob?.rangeStart ||
        null,
      requestedRangeEnd:
        projection.recoveryEndLabel ||
        projection.requestedRangeEnd ||
        originalJob?.rangeEnd ||
        null,
      originalPrintJobId: originalJob?.id || projection.printJobId || null,
      originalPrintJobNumber: originalJob?.jobNumber || null,
      originalRequestedRange: {
        startCode: projection.requestedRangeStart || originalJob?.rangeStart || null,
        endCode: projection.requestedRangeEnd || originalJob?.rangeEnd || null,
        count: projection.requestedCount || Number(originalJob?.itemCount || originalJob?.quantity || 0),
      },
      originalConfirmedCount: projection.confirmedCount,
      originalPendingCount: projection.pendingCount,
      originalFailedCount: projection.failedCount,
      recoveryStartLabel: projection.recoveryStartLabel,
      recoveryEndLabel: projection.recoveryEndLabel,
    };
  }

  const context = buildOriginalReissueContext(originalJob);
  return {
    requestedCount: context.recoveryRange.count || Number(originalJob?.itemCount || originalJob?.quantity || context.requestedCount || 0),
    requestedRangeStart: context.recoveryRange.startCode || context.requestedRange.startCode || originalJob?.rangeStart || null,
    requestedRangeEnd: context.recoveryRange.endCode || context.requestedRange.endCode || originalJob?.rangeEnd || null,
    originalPrintJobId: originalJob?.id || null,
    originalPrintJobNumber: originalJob?.jobNumber || null,
    originalRequestedRange: {
      startCode: context.requestedRange.startCode || originalJob?.rangeStart || null,
      endCode: context.requestedRange.endCode || originalJob?.rangeEnd || null,
      count: context.requestedCount || Number(originalJob?.itemCount || originalJob?.quantity || 0),
    },
    originalConfirmedCount: context.confirmedCount,
    originalPendingCount: context.pendingCount,
    originalFailedCount: context.failedCount,
    recoveryStartLabel: context.recoveryStartLabel,
    recoveryEndLabel: context.recoveryEndLabel,
  };
};

const buildReissueBusinessError = (message: string, code: string, statusCode: number, details?: Record<string, unknown>) =>
  Object.assign(new Error(message), { code, statusCode, details });

const isOriginalRecoverable = (originalJob: any, context: OriginalReissueContext) => {
  if (!RECOVERABLE_ORIGINAL_JOB_STATUSES.has(originalJob.status)) return false;
  if (
    originalJob.status === PrintJobStatus.CONFIRMED ||
    originalJob.pipelineState === PrintPipelineState.LOCKED ||
    originalJob.pipelineState === PrintPipelineState.PRINT_CONFIRMED
  ) {
    return true;
  }
  if (!originalJob.printSession) return false;
  if (!RECOVERABLE_ORIGINAL_SESSION_STATUSES.has(originalJob.printSession.status)) return false;
  return context.pendingCount > 0;
};

export const projectPrintJobReissueSummaries = async (
  client: Prisma.TransactionClient | typeof prisma,
  printJobIds: string[]
): Promise<Map<string, PrintJobReissueProjection>> => {
  const ids = Array.from(new Set(printJobIds.map((id) => String(id || "").trim()).filter(Boolean)));
  if (ids.length === 0) return new Map();

  const confirmedSql = Prisma.sql`(
    pi."printConfirmedAt" IS NOT NULL
    OR pi."state" IN (CAST(${PrintItemState.PRINT_CONFIRMED} AS "PrintItemState"), CAST(${PrintItemState.CLOSED} AS "PrintItemState"))
    OR (
      pi."confirmationEvidence" IS NOT NULL
      AND pi."confirmationEvidence"::text NOT IN ('null', '{}')
    )
  )`;
  const labelSql = Prisma.sql`COALESCE(q."displayCode", pi."code")`;

  const rows = await client.$queryRaw<
    Array<{
      printJobId: string;
      requestedCount: bigint | number;
      requestedRangeStart: string | null;
      requestedRangeEnd: string | null;
      confirmedCount: bigint | number;
      pendingCount: bigint | number;
      failedCount: bigint | number;
      recoveryStartLabel: string | null;
      recoveryEndLabel: string | null;
    }>
  >(Prisma.sql`
    SELECT
      pj."id" AS "printJobId",
      COUNT(pi."id")::int AS "requestedCount",
      MIN(${labelSql}) AS "requestedRangeStart",
      MAX(${labelSql}) AS "requestedRangeEnd",
      COALESCE(SUM(CASE WHEN ${confirmedSql} THEN 1 ELSE 0 END), 0)::int AS "confirmedCount",
      COALESCE(SUM(CASE WHEN NOT ${confirmedSql} THEN 1 ELSE 0 END), 0)::int AS "pendingCount",
      COALESCE(SUM(CASE WHEN pi."state" IN (CAST(${PrintItemState.FAILED} AS "PrintItemState"), CAST(${PrintItemState.FROZEN} AS "PrintItemState")) THEN 1 ELSE 0 END), 0)::int AS "failedCount",
      MIN(CASE WHEN NOT ${confirmedSql} THEN ${labelSql} ELSE NULL END) AS "recoveryStartLabel",
      MAX(CASE WHEN NOT ${confirmedSql} THEN ${labelSql} ELSE NULL END) AS "recoveryEndLabel"
    FROM "PrintJob" pj
    LEFT JOIN "PrintSession" ps ON ps."printJobId" = pj."id"
    LEFT JOIN "PrintItem" pi ON pi."printSessionId" = ps."id"
    LEFT JOIN "QRCode" q ON q."id" = pi."qrCodeId"
    WHERE pj."id" IN (${Prisma.join(ids)})
    GROUP BY pj."id";
  `);

  return rows.reduce<Map<string, PrintJobReissueProjection>>((acc, row) => {
    acc.set(row.printJobId, {
      printJobId: row.printJobId,
      requestedCount: Number(row.requestedCount || 0),
      requestedRangeStart: row.requestedRangeStart || null,
      requestedRangeEnd: row.requestedRangeEnd || null,
      confirmedCount: Number(row.confirmedCount || 0),
      pendingCount: Number(row.pendingCount || 0),
      failedCount: Number(row.failedCount || 0),
      recoveryStartLabel: row.recoveryStartLabel || null,
      recoveryEndLabel: row.recoveryEndLabel || null,
    });
    return acc;
  }, new Map());
};

export const createAuthorizedPrintReissue = async (params: {
  scope: PrintJobScope;
  originalPrintJobId: string;
  reason: string;
  quantity?: number | null;
  approvedReissueRequestId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
}) => {
  const originalJob = await prisma.printJob.findFirst({
    where: buildScopedPrintJobWhere(params.scope, { id: params.originalPrintJobId }),
    include: {
      batch: {
        select: {
          id: true,
          name: true,
          licenseeId: true,
        },
      },
      printer: true,
      reprintJobs: {
        select: {
          id: true,
          status: true,
          createdAt: true,
        },
        orderBy: [{ createdAt: "desc" }],
        take: 5,
      },
      printSession: {
        select: {
          id: true,
          status: true,
          items: {
            orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
            select: {
              code: true,
              state: true,
              printConfirmedAt: true,
              confirmationEvidence: true,
              qrCode: { select: { displayCode: true } },
            },
          },
        },
      },
    },
  });

  if (!originalJob || !originalJob.printer || !originalJob.printerId) {
    throw Object.assign(new Error("PRINT_JOB_NOT_FOUND"), { statusCode: 404 });
  }

  const originalContext = buildOriginalReissueContext(originalJob);
  if (!isOriginalRecoverable(originalJob, originalContext)) {
    throw buildReissueBusinessError(
      "This print run is not ready for controlled replacement printing.",
      "PRINT_REISSUE_ORIGINAL_NOT_RECOVERABLE",
      409,
      {
        originalPrintJobId: originalJob.id,
        status: originalJob.status,
        pipelineState: originalJob.pipelineState,
        pendingCount: originalContext.pendingCount,
      }
    );
  }

  if (originalJob.reprintJobs.some((job) => BLOCKING_REISSUE_STATUSES.has(job.status))) {
    throw Object.assign(new Error("PRINT_REISSUE_ALREADY_IN_PROGRESS"), { statusCode: 409 });
  }

  const recoveryRange =
    originalContext.pendingCount > 0 && originalContext.recoveryRange.startCode && originalContext.recoveryRange.endCode
      ? originalContext.recoveryRange
      : null;
  const requestedReplacementCount = Number(params.quantity || originalJob.itemCount || originalJob.quantity || 1);
  const quantity = recoveryRange
    ? recoveryRange.count
    : Math.max(1, Math.min(Number(originalJob.itemCount || originalJob.quantity || 1), requestedReplacementCount));
  const replacementRangeStart = recoveryRange?.startCode || null;
  const replacementRangeEnd = recoveryRange?.endCode || null;

  const now = new Date();
  const expAt = getQrTokenExpiryDate(now);
  const printerSelection = await ensureSelectedPrinterReady({
    printerId: originalJob.printerId,
    userId: originalJob.manufacturerId,
    orgId: originalJob.printer.orgId || null,
    licenseeId: originalJob.batch.licenseeId || null,
  });

  const created = await prisma.$transaction(
    async (tx) => {
      const unresolvedRecovery = await findUnresolvedRecoveryRangeForBatch(tx, { batchId: originalJob.batch.id });
      if (unresolvedRecovery?.printJobId && unresolvedRecovery.printJobId !== originalJob.id) {
        throw buildReissueBusinessError(
          `Recover unconfirmed label range ${unresolvedRecovery.startCode} to ${unresolvedRecovery.endCode} before starting a later print run.`,
          "RECOVERY_REQUIRED_BEFORE_NEW_PRINT",
          409,
          {
            batchId: originalJob.batch.id,
            recoveryRange: unresolvedRecovery,
            recoveryAction: `Continue from label ${unresolvedRecovery.startCode}. Recover unconfirmed label range ${unresolvedRecovery.startCode} to ${unresolvedRecovery.endCode}.`,
            userMessage: `Continue from label ${unresolvedRecovery.startCode} before starting a later range.`,
            canRetry: true,
          }
        );
      }

      const reservedRows = await selectReservableQrCodesForPrint(tx, {
        batchId: originalJob.batch.id,
        quantity,
        rangeStart: replacementRangeStart,
        rangeEnd: replacementRangeEnd,
      });

      if (reservedRows.length < quantity) {
        throw buildReissueBusinessError(
          "Not enough recoverable labels remain for this approved replacement request.",
          "NOT_ENOUGH_RECOVERABLE_LABELS",
          422,
          {
            requestedQuantity: quantity,
            selectedQuantity: reservedRows.length,
            rangeStart: replacementRangeStart,
            rangeEnd: replacementRangeEnd,
          }
        );
      }

      const prepared = reservedRows.map((qr: ReservableQrCodeRow) => {
        const nonce = randomNonce();
        const payload = {
          qr_id: qr.id,
          batch_id: qr.batchId,
          licensee_id: qr.licenseeId,
          manufacturer_id: originalJob.manufacturerId,
          epoch: Number(qr.replayEpoch || 1),
          iat: Math.floor(now.getTime() / 1000),
          exp: Math.floor(expAt.getTime() / 1000),
          nonce,
        };
        const token = signQrPayload(payload);
        return {
          qr,
          nonce,
          tokenHash: hashToken(token),
        };
      });

      const replacementJob = await tx.printJob.create({
        data: {
          jobNumber: generatePrintJobNumber(),
          batchId: originalJob.batch.id,
          manufacturerId: originalJob.manufacturerId,
          printerId: originalJob.printerId,
          quantity,
          itemCount: prepared.length,
          rangeStart: replacementRangeStart,
          rangeEnd: replacementRangeEnd,
          printMode: printerSelection.printMode,
          payloadType: printerSelection.payloadType,
          reprintOfJobId: originalJob.id,
          approvedByUserId: params.scope.userId,
          reprintReason: params.reason,
          status: PrintJobStatus.PENDING,
          pipelineState:
            printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
              ? PrintPipelineState.QUEUED
              : PrintPipelineState.PREFLIGHT_OK,
        },
      });

      let reissueRequest: any;
      if (params.approvedReissueRequestId) {
        const claimed = await tx.printReissueRequest.updateMany({
          where: {
            id: params.approvedReissueRequestId,
            originalPrintJobId: originalJob.id,
            status: ReissueRequestStatus.APPROVED,
            replacementPrintJobId: null,
          },
          data: {
            status: ReissueRequestStatus.EXECUTED,
            executedAt: now,
          },
        });
        if (claimed.count !== 1) {
          throw Object.assign(new Error("Replacement labels were already allocated for this reissue request."), {
            code: "REPLACEMENT_ALREADY_ALLOCATED",
            statusCode: 409,
          });
        }
      }

      const values = prepared.map((item) =>
        Prisma.sql`(${item.qr.id}, ${item.nonce}, ${item.tokenHash}, ${now}, ${expAt})`
      );

      const updatedCount = await tx.$executeRaw(Prisma.sql`
        UPDATE "QRCode" AS q
        SET
          "status" = CAST(${QRStatus.ACTIVATED} AS "QRStatus"),
          "tokenNonce" = v."tokenNonce",
          "tokenIssuedAt" = v."tokenIssuedAt",
          "tokenExpiresAt" = v."tokenExpiresAt",
          "tokenHash" = v."tokenHash",
          "printJobId" = ${replacementJob.id},
          "issuanceMode" = 'GOVERNED_PRINT'
        FROM (
          VALUES ${Prisma.join(values)}
        ) AS v("id", "tokenNonce", "tokenHash", "tokenIssuedAt", "tokenExpiresAt")
        WHERE q."id" = v."id"
          AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
          AND q."printJobId" IS NULL;
      `);

      if (Number(updatedCount) !== prepared.length) {
        throw new Error("BATCH_BUSY");
      }

      const session = await tx.printSession.create({
        data: {
          printJobId: replacementJob.id,
          batchId: originalJob.batch.id,
          manufacturerId: originalJob.manufacturerId,
          printerRegistrationId:
            printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
              ? printerSelection.printer.printerRegistrationId ||
                printerSelection.printerStatus?.registrationId ||
                null
              : null,
          printerId: originalJob.printerId,
          status: "ACTIVE",
          totalItems: prepared.length,
        },
      });

      const newPreparedItems = prepared.filter((item) => !item.qr.reusablePrintItemId);
      const reusablePreparedItems = prepared.filter((item) => item.qr.reusablePrintItemId);
      if (newPreparedItems.length > 0) {
        await tx.printItem.createMany({
          data: newPreparedItems.map((item) => ({
            printSessionId: session.id,
            qrCodeId: item.qr.id,
            code: item.qr.code,
            state: "RESERVED",
            pipelineState: PrintPipelineState.QUEUED,
          })),
        });
      }
      for (const item of reusablePreparedItems) {
        const reusablePrintItemId = item.qr.reusablePrintItemId;
        if (!reusablePrintItemId) continue;
        const updated = await tx.printItem.updateMany({
          where: {
            id: reusablePrintItemId,
            qrCodeId: item.qr.id,
            printConfirmedAt: null,
            state: { in: [PrintItemState.FAILED, PrintItemState.FROZEN, PrintItemState.CANCELLED] },
          },
          data: buildReusablePrintItemResetData(now),
        });
        if (updated.count !== 1) throw new Error("BATCH_BUSY");
        await tx.printItem.update({
          where: { id: reusablePrintItemId },
          data: { printSession: { connect: { id: session.id } } },
        });
        await tx.printItemEvent.create({
          data: {
            printItemId: reusablePrintItemId,
            eventType: PrintItemEventType.RESERVED,
            previousState: item.qr.previousPrintItemState || PrintItemState.FAILED,
            nextState: PrintItemState.RESERVED,
            actorUserId: params.scope.userId,
            details: {
              action: "zero_evidence_print_item_reused",
              previousPrintSessionId: item.qr.previousPrintSessionId,
              previousPrintJobId: item.qr.previousPrintJobId,
              newPrintSessionId: session.id,
              newPrintJobId: replacementJob.id,
              qrCodeId: item.qr.id,
              code: item.qr.code,
              previousAttemptCount: item.qr.previousAttemptCount || 0,
              nextAttemptCount: Number(item.qr.previousAttemptCount || 0) + 1,
              context: "print_reissue",
            },
          },
        });
      }

      if (params.approvedReissueRequestId) {
        reissueRequest = await tx.printReissueRequest.update({
          where: { id: params.approvedReissueRequestId },
          data: {
            replacementPrintJobId: replacementJob.id,
            executedAt: now,
          },
        });
      } else {
        reissueRequest = await tx.printReissueRequest.create({
          data: {
            originalPrintJobId: originalJob.id,
            replacementPrintJobId: replacementJob.id,
            requestedByUserId: params.scope.userId,
            approvedByUserId: params.scope.userId,
            status: ReissueRequestStatus.EXECUTED,
            reason: params.reason,
            approvedAt: now,
            executedAt: now,
          },
        });
      }

      await materializeReplacementChainsForReissue({
        tx,
        originalPrintJobId: originalJob.id,
        replacementPrintJobId: replacementJob.id,
        reissueRequestId: reissueRequest.id,
        reason: params.reason,
      });

      return { replacementJob, session, reissueRequest };
    },
    { timeout: 30000, maxWait: 10000 }
  );

  await createAuditLog({
    userId: params.scope.userId,
    licenseeId: originalJob.batch.licenseeId || undefined,
    action: "PRINT_REISSUE_EXECUTED",
    entityType: "PrintJob",
    entityId: created.replacementJob.id,
    details: {
      originalPrintJobId: originalJob.id,
      replacementPrintJobId: created.replacementJob.id,
      reissueRequestId: created.reissueRequest.id,
      reason: params.reason,
      quantity,
      rangeStart: replacementRangeStart,
      rangeEnd: replacementRangeEnd,
      printerId: originalJob.printerId,
      manufacturerId: originalJob.manufacturerId,
      batchId: originalJob.batch.id,
      originalConfirmedCount: originalContext.confirmedCount,
      originalPendingCount: originalContext.pendingCount,
      originalFailedCount: originalContext.failedCount,
    },
    ipAddress: params.ipAddress || undefined,
    userAgent: params.userAgent || undefined,
  });

  await Promise.allSettled([
    createUserNotification({
      userId: originalJob.manufacturerId,
      licenseeId: originalJob.batch.licenseeId,
      type: "authorized_print_reissue_created",
      title: "Authorized reissue created",
      body: `A controlled reissue was authorized for ${originalJob.batch.name}.`,
      data: {
        entityType: "replacement_allocation",
        entityId: created.replacementJob.id,
        originalPrintJobId: originalJob.id,
        replacementPrintJobId: created.replacementJob.id,
        reissueRequestId: created.reissueRequest.id,
        printSessionId: created.session.id,
        batchId: originalJob.batch.id,
        licenseeId: originalJob.batch.licenseeId,
        manufacturerId: originalJob.manufacturerId,
        quantity,
        rangeStart: replacementRangeStart,
        rangeEnd: replacementRangeEnd,
        preferredTab: "reissue",
        preferredSection: "replacement-ready",
        targetRoute: `/batches?batchId=${encodeURIComponent(originalJob.batch.id)}&tab=reissue&reissueRequestId=${encodeURIComponent(created.reissueRequest.id)}&printJobId=${encodeURIComponent(created.replacementJob.id)}`,
      },
    }),
  ]);

  if (printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT) {
    await startNetworkDirectDispatch({
      jobId: created.replacementJob.id,
      actorUserId: originalJob.manufacturerId,
    });
  } else if (printerSelection.printMode === PrintDispatchMode.NETWORK_IPP) {
    await startNetworkIppDispatch({
      jobId: created.replacementJob.id,
      actorUserId: originalJob.manufacturerId,
    });
  }

  return {
    reissueRequestId: created.reissueRequest.id,
    replacementPrintJobId: created.replacementJob.id,
    printSessionId: created.session.id,
    quantity,
    requestedRangeStart: replacementRangeStart,
    requestedRangeEnd: replacementRangeEnd,
    recoveryStartLabel: originalContext.recoveryStartLabel,
    recoveryEndLabel: originalContext.recoveryEndLabel,
    originalRequestedRange: {
      startCode: originalContext.requestedRange.startCode || originalJob.rangeStart || null,
      endCode: originalContext.requestedRange.endCode || originalJob.rangeEnd || null,
      count: originalContext.requestedCount,
    },
    originalConfirmedCount: originalContext.confirmedCount,
    originalPendingCount: originalContext.pendingCount,
    originalFailedCount: originalContext.failedCount,
    mode: printerSelection.printMode,
    pipelineState:
      printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
        ? PrintPipelineState.QUEUED
        : PrintPipelineState.PREFLIGHT_OK,
  };
};

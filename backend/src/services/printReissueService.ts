import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
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
  selectReservableQrCodesForPrint,
  type ReservableQrCodeRow,
} from "./printReservationService";

const BLOCKING_REISSUE_STATUSES = new Set<PrintJobStatus>([PrintJobStatus.PENDING, PrintJobStatus.SENT]);

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
    },
  });

  if (!originalJob || !originalJob.printer || !originalJob.printerId) {
    throw Object.assign(new Error("PRINT_JOB_NOT_FOUND"), { statusCode: 404 });
  }

  if (
    originalJob.status !== PrintJobStatus.CONFIRMED &&
    originalJob.pipelineState !== PrintPipelineState.LOCKED &&
    originalJob.pipelineState !== PrintPipelineState.PRINT_CONFIRMED
  ) {
    throw Object.assign(new Error("PRINT_JOB_NOT_LOCKED"), { statusCode: 409 });
  }

  if (originalJob.reprintJobs.some((job) => BLOCKING_REISSUE_STATUSES.has(job.status))) {
    throw Object.assign(new Error("PRINT_REISSUE_ALREADY_IN_PROGRESS"), { statusCode: 409 });
  }

  const quantity = Math.max(
    1,
    Math.min(
      Number(originalJob.itemCount || originalJob.quantity || 1),
      Number(params.quantity || originalJob.itemCount || originalJob.quantity || 1)
    )
  );

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
      const reservedRows = await selectReservableQrCodesForPrint(tx, {
        batchId: originalJob.batch.id,
        quantity,
      });

      if (reservedRows.length < quantity) {
        throw new Error(`NOT_ENOUGH_CODES:${reservedRows.length}`);
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
          throw Object.assign(new Error("PRINT_REISSUE_ALREADY_EXECUTED"), { statusCode: 409 });
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
            agentAckedAt: null,
            dispatchedAt: null,
            printConfirmedAt: null,
            deviceJobRef: null,
            state: { in: [PrintItemState.FAILED, PrintItemState.FROZEN] },
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
      printerId: originalJob.printerId,
      manufacturerId: originalJob.manufacturerId,
      batchId: originalJob.batch.id,
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
        originalPrintJobId: originalJob.id,
        replacementPrintJobId: created.replacementJob.id,
        printSessionId: created.session.id,
        batchId: originalJob.batch.id,
        quantity,
        targetRoute: "/batches",
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
    mode: printerSelection.printMode,
    pipelineState:
      printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
        ? PrintPipelineState.QUEUED
        : PrintPipelineState.PREFLIGHT_OK,
  };
};

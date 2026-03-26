import {
  PrintDispatchMode,
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

const BLOCKING_REISSUE_STATUSES = new Set<PrintJobStatus>([PrintJobStatus.PENDING, PrintJobStatus.SENT]);

export const createAuthorizedPrintReissue = async (params: {
  scope: PrintJobScope;
  originalPrintJobId: string;
  reason: string;
  quantity?: number | null;
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
      const reservedRows = await tx.$queryRaw<
        Array<{ id: string; code: string; licenseeId: string; batchId: string | null }>
      >(Prisma.sql`
        SELECT q."id", q."code", q."licenseeId", q."batchId"
        FROM "QRCode" q
        WHERE q."batchId" = ${originalJob.batch.id}
          AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
          AND q."printJobId" IS NULL
        ORDER BY q."code" ASC
        FOR UPDATE SKIP LOCKED
        LIMIT ${quantity};
      `);

      if (reservedRows.length < quantity) {
        throw new Error(`NOT_ENOUGH_CODES:${reservedRows.length}`);
      }

      const prepared = reservedRows.map((qr) => {
        const nonce = randomNonce();
        const payload = {
          qr_id: qr.id,
          batch_id: qr.batchId,
          licensee_id: qr.licenseeId,
          manufacturer_id: originalJob.manufacturerId,
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
          "printJobId" = ${replacementJob.id}
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

      await tx.printItem.createMany({
        data: prepared.map((item) => ({
          printSessionId: session.id,
          qrCodeId: item.qr.id,
          code: item.qr.code,
          state: "RESERVED",
          pipelineState: PrintPipelineState.QUEUED,
        })),
      });

      const reissueRequest = await tx.printReissueRequest.create({
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

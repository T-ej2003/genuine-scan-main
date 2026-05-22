import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  Prisma,
  QRStatus,
} from "@prisma/client";

import prisma from "../config/database";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "./qrTokenService";
import { generatePrintJobNumber, type ensureSelectedPrinterReady } from "../controllers/print-job/shared";
import {
  buildReusablePrintItemResetData,
  countBlockedQrCodesForPrint,
  selectReservableQrCodesForPrint,
  type ReservableQrCodeRow,
} from "./printReservationService";

type PrinterSelection = Awaited<ReturnType<typeof ensureSelectedPrinterReady>>;

type PrintJobBatch = {
  id: string;
  manufacturerId: string | null;
};

type TransactionEventLogger = (event: string, data: Record<string, unknown>) => void;
type TransactionStageLogger = (stage: string, event: string, data?: Record<string, unknown>) => void;

export const createPrintJobRecords = async (params: {
  batch: PrintJobBatch;
  userId: string;
  printerSelection: PrinterSelection;
  quantity: number;
  rangeStart?: string | null;
  rangeEnd?: string | null;
  printLockTokenHash?: string | null;
  onEvent: TransactionEventLogger;
  onStage: TransactionStageLogger;
}) => {
  const { batch, userId, printerSelection, quantity, rangeStart, rangeEnd, printLockTokenHash, onEvent, onStage } =
    params;
  const now = new Date();
  const expAt = getQrTokenExpiryDate(now);

  return prisma.$transaction(
    async (tx) => {
      onStage("reservation_started", "reservation_started", {
        batchId: batch.id,
        quantity,
        rangeStart: rangeStart || null,
        rangeEnd: rangeEnd || null,
      });
      const reservedRows = await selectReservableQrCodesForPrint(tx, {
        batchId: batch.id,
        quantity,
        rangeStart,
        rangeEnd,
      });

      if (reservedRows.length < quantity) {
        const blockedCount = await countBlockedQrCodesForPrint(tx, { batchId: batch.id, rangeStart, rangeEnd });
        onEvent("print_item_reservation_shortfall", {
          batchId: batch.id,
          requestedQuantity: quantity,
          reservableSelectedCount: reservedRows.length,
          blockedByPrintItemEvidenceCount: blockedCount,
        });
        throw new Error(`NOT_ENOUGH_CODES:${reservedRows.length}`);
      }
      const reusableRows = reservedRows.filter((row) => row.reusablePrintItemId);
      if (reusableRows.length > 0) {
        onEvent("print_item_zero_evidence_reuse_selected", {
          batchId: batch.id,
          reusableCount: reusableRows.length,
          qrCodeIds: reusableRows.map((row) => row.id),
          printItemIds: reusableRows.map((row) => row.reusablePrintItemId),
        });
      }

      onStage("print_job_prepare_tokens", "print_job_prepare_tokens");
      let cryptoMetadataLogged = false;
      const prepared = reservedRows.map((qr: ReservableQrCodeRow) => {
        const nonce = randomNonce();
        const payload = {
          qr_id: qr.id,
          batch_id: qr.batchId,
          licensee_id: qr.licenseeId,
          manufacturer_id: batch.manufacturerId || null,
          epoch: Number(qr.replayEpoch || 1),
          iat: Math.floor(now.getTime() / 1000),
          exp: Math.floor(expAt.getTime() / 1000),
          nonce,
        };
        const token = signQrPayload(payload, {
          onCryptoMetadata: (metadata) => {
            if (cryptoMetadataLogged) return;
            cryptoMetadataLogged = true;
            onEvent("crypto_metadata", {
              transactionStage: "print_job_prepare_tokens",
              ...metadata,
            });
          },
        });
        const tokenHash = hashToken(token);
        return { qr, nonce, tokenHash };
      });

      onStage("print_job_created", "print_job_created");
      const createdJob = await tx.printJob.create({
        data: {
          jobNumber: generatePrintJobNumber(),
          batchId: batch.id,
          manufacturerId: userId,
          printerId: printerSelection.printer.id,
          quantity,
          itemCount: prepared.length,
          printMode: printerSelection.printMode,
          payloadType: printerSelection.payloadType,
          rangeStart: rangeStart || null,
          rangeEnd: rangeEnd || null,
          reprintOfJobId: null,
          reprintReason: null,
          ...(printLockTokenHash ? { printLockTokenHash } : {}),
          status: PrintJobStatus.PENDING,
          pipelineState:
            printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
              ? PrintPipelineState.QUEUED
              : PrintPipelineState.PREFLIGHT_OK,
        },
      });
      onEvent("print_job_created", {
        printJobId: createdJob.id,
        itemCount: prepared.length,
        printMode: printerSelection.printMode,
      });

      onStage("qr_codes_activated", "qr_codes_activated");
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
          "printJobId" = ${createdJob.id},
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

      onStage("print_session_created", "print_session_created");
      const session = await tx.printSession.create({
        data: {
          printJobId: createdJob.id,
          batchId: batch.id,
          manufacturerId: userId,
          printerRegistrationId:
            printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
              ? printerSelection.printer.printerRegistrationId || printerSelection.printerStatus?.registrationId || null
              : null,
          printerId: printerSelection.printer.id,
          status: "ACTIVE",
          totalItems: prepared.length,
        },
      });
      onEvent("print_session_created", {
        printJobId: createdJob.id,
        printSessionId: session.id,
        totalItems: prepared.length,
      });

      onStage("print_items_created", "print_items_created");
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

        if (updated.count !== 1) {
          throw new Error("BATCH_BUSY");
        }
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
            actorUserId: userId,
            details: {
              action: "zero_evidence_print_item_reused",
              previousPrintSessionId: item.qr.previousPrintSessionId,
              previousPrintJobId: item.qr.previousPrintJobId,
              newPrintSessionId: session.id,
              newPrintJobId: createdJob.id,
              qrCodeId: item.qr.id,
              code: item.qr.code,
              previousAttemptCount: item.qr.previousAttemptCount || 0,
              nextAttemptCount: Number(item.qr.previousAttemptCount || 0) + 1,
            },
          },
        });
      }

      onEvent("print_item_reservation_finalized", {
        printJobId: createdJob.id,
        printSessionId: session.id,
        createdItemCount: newPreparedItems.length,
        reusedItemCount: reusablePreparedItems.length,
      });
      onEvent("print_items_created", {
        printJobId: createdJob.id,
        printSessionId: session.id,
        itemCount: prepared.length,
        createdItemCount: newPreparedItems.length,
        reusedItemCount: reusablePreparedItems.length,
      });

      return {
        job: createdJob,
        session,
        preparedCount: prepared.length,
      };
    },
    { timeout: 30000, maxWait: 10000 }
  );
};

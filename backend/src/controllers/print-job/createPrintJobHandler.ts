import { randomBytes } from "crypto";
import { PrintDispatchMode, PrintJobStatus, PrintPipelineState, QRStatus } from "@prisma/client";
import { Prisma } from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "../../services/qrTokenService";
import { createAuditLog } from "../../services/auditService";
import { createUserNotification } from "../../services/notificationService";
import {
  supportsNetworkDirectPayloadType,
} from "../../services/printPayloadService";
import { startNetworkDirectDispatch } from "../../services/networkDirectPrintService";
import { startNetworkIppDispatch } from "../../services/networkIppPrintService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import {
  buildPrintJobErrorPayload,
  sendPrintJobCreateErrorResponse,
} from "./errorResponses";
import {
  beginPrintActionIdempotency,
  createPrintJobSchema,
  describePrintDispatchMode,
  ensureManufacturerUser,
  ensureSelectedPrinterReady,
  generatePrintJobNumber,
  getLockExpiresAt,
  handleIdempotencyError,
  hashLockToken,
  notifySystemPrintEvent,
  replayIdempotentResponseIfAny,
} from "./shared";

export const createPrintJob = async (req: AuthRequest, res: any) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = createPrintJobSchema.safeParse(req.body);
    if (!parsed.success) {
      const missingFields = parsed.error.errors
        .map((issue) => String(issue.path[0] || "").trim())
        .filter(Boolean);
      return res.status(400).json(
        buildPrintJobErrorPayload({
          code: "INVALID_PRINT_JOB_REQUEST",
          message: "The print job request is missing required information.",
          details: missingFields.length > 0 ? { missingFields } : undefined,
        })
      );
    }

    let idempotency;
    try {
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_create",
        scope: `user:${user.userId}:batch:${parsed.data.batchId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const { batchId, printerId, quantity, rangeStart, rangeEnd } = parsed.data;
    const batch = await prisma.batch.findFirst({
      where: { id: batchId, manufacturerId: user.userId },
      select: { id: true, name: true, licenseeId: true, manufacturerId: true },
    });
    if (!batch) {
      return res.status(404).json(
        buildPrintJobErrorPayload({
          code: "BATCH_NOT_FOUND",
          message: "Batch not found or not assigned to you.",
        })
      );
    }

    const activeJob = await prisma.printJob.findFirst({
      where: {
        batchId: batch.id,
        manufacturerId: user.userId,
        status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
        printSession: {
          is: {
            status: "ACTIVE",
          },
        },
      },
      orderBy: [{ createdAt: "desc" }],
      select: {
        id: true,
        status: true,
        pipelineState: true,
        printMode: true,
        quantity: true,
        itemCount: true,
        printer: {
          select: {
            id: true,
            name: true,
            connectionType: true,
            commandLanguage: true,
            deliveryMode: true,
          },
        },
        printSession: {
          select: {
            id: true,
            status: true,
            totalItems: true,
            confirmedItems: true,
            frozenItems: true,
          },
        },
      },
    });
    if (activeJob) {
      return res.status(409).json({
        ...buildPrintJobErrorPayload({
          code: "ACTIVE_PRINT_JOB_EXISTS",
          message: "An active print run already exists for this batch. Resume the current job instead of starting a duplicate run.",
        }),
        data: {
          activePrintJobId: activeJob.id,
          activePrintSessionId: activeJob.printSession?.id || null,
          job: {
            id: activeJob.id,
            status: activeJob.status,
            pipelineState: activeJob.pipelineState,
            printMode: activeJob.printMode,
            quantity: activeJob.quantity,
            itemCount: activeJob.itemCount,
            printer: activeJob.printer,
            session: activeJob.printSession,
          },
        },
      });
    }

    const printerSelection = await ensureSelectedPrinterReady({
      printerId,
      userId: user.userId,
      orgId: user.orgId || null,
      licenseeId: batch.licenseeId || null,
    });
    if (
      printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT &&
      !supportsNetworkDirectPayloadType(printerSelection.payloadType)
    ) {
      return res.status(409).json(
        buildPrintJobErrorPayload({
          code: "PRINTER_NETWORK_LANGUAGE_UNSUPPORTED",
          message:
            "Network-direct printing currently supports certified industrial printer profiles only when the live language and transport are approved.",
        })
      );
    }

    const printLockToken =
      printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT ? randomBytes(24).toString("base64url") : null;
    const printLockTokenHash = printLockToken ? hashLockToken(printLockToken) : null;
    const now = new Date();
    const expAt = getQrTokenExpiryDate(now);

    const created = await prisma.$transaction(
      async (tx) => {
        const rangeFilter =
          rangeStart && rangeEnd
            ? Prisma.sql`AND q."code" >= ${rangeStart} AND q."code" <= ${rangeEnd}`
            : Prisma.empty;

        const reservedRows = await tx.$queryRaw<
          Array<{ id: string; code: string; licenseeId: string; batchId: string | null; replayEpoch: number | null }>
        >(Prisma.sql`
          SELECT q."id", q."code", q."licenseeId", q."batchId", q."replayEpoch"
          FROM "QRCode" q
          WHERE q."batchId" = ${batch.id}
            AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
            AND q."printJobId" IS NULL
            ${rangeFilter}
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
            manufacturer_id: batch.manufacturerId || null,
            epoch: Number(qr.replayEpoch || 1),
            iat: Math.floor(now.getTime() / 1000),
            exp: Math.floor(expAt.getTime() / 1000),
            nonce,
          };
          const token = signQrPayload(payload);
          const tokenHash = hashToken(token);
          return { qr, nonce, tokenHash };
        });

        const createdJob = await tx.printJob.create({
          data: {
            jobNumber: generatePrintJobNumber(),
            batchId: batch.id,
            manufacturerId: user.userId,
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

        const session = await tx.printSession.create({
          data: {
            printJobId: createdJob.id,
            batchId: batch.id,
            manufacturerId: user.userId,
            printerRegistrationId:
              printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
                ? printerSelection.printer.printerRegistrationId || printerSelection.printerStatus?.registrationId || null
                : null,
            printerId: printerSelection.printer.id,
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

        return {
          job: createdJob,
          session,
          preparedCount: prepared.length,
        };
      },
      { timeout: 30000, maxWait: 10000 }
    );

    await createAuditLog({
      userId: user.userId,
      licenseeId: batch.licenseeId,
      action: "CREATED",
      entityType: "PrintJob",
      entityId: created.job.id,
      details: {
        batchId: batch.id,
        quantity,
        rangeStart: rangeStart || null,
        rangeEnd: rangeEnd || null,
        mode: printerSelection.printMode,
        printerId: printerSelection.printer.id,
        printerName: printerSelection.printer.name,
        printSessionId: created.session.id,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    const responsePayload = {
      success: true,
      data: {
        printJobId: created.job.id,
        printSessionId: created.session.id,
        printLockToken: null,
        quantity,
        tokenCount: created.preparedCount,
        mode: printerSelection.printMode,
        pipelineState:
          printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
            ? PrintPipelineState.QUEUED
            : PrintPipelineState.PREFLIGHT_OK,
        lockExpiresAt: getLockExpiresAt(created.job.createdAt).toISOString(),
        printer: {
          id: printerSelection.printer.id,
          name: printerSelection.printer.name,
          connectionType: printerSelection.printer.connectionType,
          commandLanguage: printerSelection.printer.commandLanguage,
          ipAddress: printerSelection.printer.ipAddress,
          host: (printerSelection.printer as any).host || null,
          port: printerSelection.printer.port,
          resourcePath: (printerSelection.printer as any).resourcePath || null,
          tlsEnabled: (printerSelection.printer as any).tlsEnabled ?? null,
          printerUri: (printerSelection.printer as any).printerUri || null,
          deliveryMode: (printerSelection.printer as any).deliveryMode || null,
          gatewayId: (printerSelection.printer as any).gatewayId || null,
          nativePrinterId: printerSelection.printer.nativePrinterId,
        },
        printerStatus: printerSelection.printerStatus,
      },
    };

    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 201,
      responsePayload,
    });

    try {
      await createUserNotification({
        userId: user.userId,
        licenseeId: batch.licenseeId,
        type: "manufacturer_print_job_created",
        title:
          printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT
            ? "Network-direct job prepared"
            : printerSelection.printMode === PrintDispatchMode.NETWORK_IPP
              ? "Network IPP job prepared"
              : "Direct-print job prepared",
        body: `${describePrintDispatchMode(printerSelection.printMode)} session ready for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
      await notifySystemPrintEvent({
        licenseeId: batch.licenseeId,
        orgId: user.orgId || null,
        type: "system_print_job_created",
        title: "System print job created",
        body: `${describePrintDispatchMode(printerSelection.printMode)} print job created for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
    } catch (notifyError) {
      console.error("createPrintJob notification error:", notifyError);
    }

    if (printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT) {
      void startNetworkDirectDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      }).catch((error) => {
        console.error("startNetworkDirectDispatch error:", error);
      });
    } else if (printerSelection.printMode === PrintDispatchMode.NETWORK_IPP) {
      void startNetworkIppDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      }).catch((error) => {
        console.error("startNetworkIppDispatch error:", error);
      });
    }

    return res.status(201).json(responsePayload);
  } catch (e: any) {
    console.error("createPrintJob error:", e);
    return sendPrintJobCreateErrorResponse(e, res);
  }
};

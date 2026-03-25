import { Response } from "express";
import {
  PrintItemEventType,
  PrintItemState,
  PrintSessionStatus,
  QRStatus,
} from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { createAuditLog } from "../../services/auditService";
import { createUserNotification } from "../../services/notificationService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import {
  finalizePrintSessionIfReady,
  getOrCreatePrintSession,
  OPEN_PRINT_STATES,
} from "../../services/printLifecycleService";
import {
  beginPrintActionIdempotency,
  confirmDirectPrintItemSchema,
  confirmSchema,
  ensureManufacturerUser,
  getManufacturerPrintJob,
  handleIdempotencyError,
  hashLockToken,
  isLockExpired,
  notifySystemPrintEvent,
  printJobIdParamSchema,
  replayIdempotentResponseIfAny,
} from "./shared";

export const confirmDirectPrintItem = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = confirmDirectPrintItemSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = printJobIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid print job id" });
    }
    const jobId = paramsParsed.data.id;

    let idempotency;
    try {
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_confirm_item",
        scope: `job:${jobId}:item:${parsed.data.printItemId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const job = await getManufacturerPrintJob(jobId, user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

    const now = new Date();
    if (isLockExpired(job.createdAt, now)) {
      return res.status(410).json({
        success: false,
        error: "Print lock token expired. Create a new print job to continue secure direct printing.",
      });
    }

    const tokenHash = hashLockToken(parsed.data.printLockToken);
    if (tokenHash !== job.printLockTokenHash) {
      return res.status(403).json({ success: false, error: "Invalid print lock token" });
    }

    const session = await getOrCreatePrintSession({
      id: job.id,
      batchId: job.batchId,
      manufacturerId: job.manufacturerId,
      quantity: job.quantity,
      status: job.status,
      printerRegistrationId: job.printSession?.printerRegistrationId || null,
      printerId: job.printerId || null,
    });

    if (session.status !== PrintSessionStatus.ACTIVE && session.status !== PrintSessionStatus.COMPLETED) {
      return res.status(409).json({ success: false, error: `Print session is ${session.status}` });
    }

    const printItem = await prisma.printItem.findFirst({
      where: {
        id: parsed.data.printItemId,
        printSessionId: session.id,
      },
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            status: true,
            printJobId: true,
          },
        },
      },
    });

    if (!printItem) {
      return res.status(404).json({ success: false, error: "Print item not found for this session" });
    }

    if (printItem.state === PrintItemState.CLOSED) {
      const responsePayload = {
        success: true,
        data: {
          printJobId: job.id,
          printSessionId: session.id,
          printItemId: printItem.id,
          qrId: printItem.qrCodeId,
          code: printItem.code,
          printConfirmedAt: printItem.printConfirmedAt?.toISOString?.() || null,
          remainingToPrint: 0,
          jobConfirmed: true,
          confirmedAt: job.confirmedAt ? job.confirmedAt.toISOString() : null,
        },
      };

      await completeIdempotentAction({
        keyHash: idempotency.keyHash,
        statusCode: 200,
        responsePayload,
      });

      return res.json(responsePayload);
    }

    if (printItem.state !== PrintItemState.AGENT_ACKED) {
      return res.status(409).json({ success: false, error: `Print item is ${printItem.state}, expected AGENT_ACKED` });
    }

    const txResult = await prisma.$transaction(async (tx) => {
      const markConfirmed = await tx.printItem.updateMany({
        where: {
          id: printItem.id,
          state: PrintItemState.AGENT_ACKED,
        },
        data: {
          state: PrintItemState.PRINT_CONFIRMED,
          printConfirmedAt: now,
        },
      });

      if (markConfirmed.count === 0) {
        throw new Error("PRINT_ITEM_CONFIRM_CONFLICT");
      }

      await tx.printItemEvent.create({
        data: {
          printItemId: printItem.id,
          eventType: PrintItemEventType.PRINT_CONFIRMED,
          previousState: PrintItemState.AGENT_ACKED,
          nextState: PrintItemState.PRINT_CONFIRMED,
          actorUserId: user.userId,
          details: {
            agentMetadata: parsed.data.agentMetadata ?? null,
          },
        },
      });

      const qrUpdated = await tx.qRCode.updateMany({
        where: {
          id: printItem.qrCodeId,
          printJobId: job.id,
          status: QRStatus.ACTIVATED,
        },
        data: {
          status: QRStatus.PRINTED,
          printedAt: now,
          printedByUserId: user.userId,
        },
      });

      if (qrUpdated.count === 0 && printItem.qrCode.status !== QRStatus.PRINTED) {
        throw new Error("QR_NOT_PRINTABLE");
      }

      await tx.printSession.update({
        where: { id: session.id },
        data: {
          confirmedItems: { increment: 1 },
        },
      });

      const finalize = await finalizePrintSessionIfReady({
        tx,
        printSessionId: session.id,
        printJobId: job.id,
        batchId: job.batchId,
        now,
        actorUserId: user.userId,
      });

      return finalize;
    });

    await createAuditLog({
      userId: user.userId,
      licenseeId: job.batch.licenseeId,
      action: "DIRECT_PRINT_ITEM_CONFIRMED",
      entityType: "PrintItem",
      entityId: printItem.id,
      details: {
        printJobId: job.id,
        printSessionId: session.id,
        qrId: printItem.qrCodeId,
        code: printItem.code,
        remainingToPrint: txResult.remainingToPrint,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    if (txResult.jobConfirmed) {
      try {
        await createUserNotification({
          userId: user.userId,
          licenseeId: job.batch.licenseeId,
          type: "manufacturer_print_job_confirmed",
          title: "Direct-print job confirmed",
          body: `All secure direct-print items were confirmed for ${job.batch.name}.`,
          data: {
            printJobId: job.id,
            printSessionId: session.id,
            batchId: job.batch.id,
            batchName: job.batch.name,
            printedCodes: job.quantity,
            mode: "DIRECT_PRINT",
            targetRoute: "/batches",
          },
        });

        await notifySystemPrintEvent({
          licenseeId: job.batch.licenseeId,
          orgId: user.orgId || null,
          type: "system_print_job_completed",
          title: "System print job completed",
          body: `Direct-print job completed for ${job.batch.name}.`,
          data: {
            printJobId: job.id,
            printSessionId: session.id,
            batchId: job.batch.id,
            batchName: job.batch.name,
            printedCodes: job.quantity,
            mode: "DIRECT_PRINT",
            targetRoute: "/batches",
          },
        });
      } catch (notifyError) {
        console.error("confirmDirectPrintItem notification error:", notifyError);
      }
    }

    const responsePayload = {
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: session.id,
        printItemId: printItem.id,
        qrId: printItem.qrCodeId,
        code: printItem.code,
        printConfirmedAt: now.toISOString(),
        remainingToPrint: txResult.remainingToPrint,
        jobConfirmed: txResult.jobConfirmed,
        confirmedAt: txResult.confirmedAt ? txResult.confirmedAt.toISOString() : null,
      },
    };

    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 200,
      responsePayload,
    });

    return res.json(responsePayload);
  } catch (e: any) {
    const msg = String(e?.message || "");
    if (msg.includes("PRINT_ITEM_CONFIRM_CONFLICT")) {
      return res.status(409).json({ success: false, error: "Print item confirmation conflict" });
    }
    if (msg.includes("QR_NOT_PRINTABLE")) {
      return res.status(409).json({ success: false, error: "QR is not in printable state" });
    }
    console.error("confirmDirectPrintItem error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const confirmPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = confirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const paramsParsed = printJobIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid print job id" });
    }
    const jobId = paramsParsed.data.id;

    const job = await getManufacturerPrintJob(jobId, user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

    const tokenHash = hashLockToken(parsed.data.printLockToken);
    if (tokenHash !== job.printLockTokenHash) {
      return res.status(403).json({ success: false, error: "Invalid print lock token" });
    }

    const session = await getOrCreatePrintSession({
      id: job.id,
      batchId: job.batchId,
      manufacturerId: job.manufacturerId,
      quantity: job.quantity,
      status: job.status,
      printerRegistrationId: job.printSession?.printerRegistrationId || null,
      printerId: job.printerId || null,
    });

    const remainingToPrint = await prisma.printItem.count({
      where: {
        printSessionId: session.id,
        state: { in: OPEN_PRINT_STATES },
      },
    });

    if (remainingToPrint > 0) {
      return res.status(409).json({
        success: false,
        error: `Cannot confirm job while ${remainingToPrint} items are not print-confirmed. Use per-item confirm or fail-stop.`,
      });
    }

    const now = new Date();
    const finalize = await prisma.$transaction((tx) =>
      finalizePrintSessionIfReady({
        tx,
        printSessionId: session.id,
        printJobId: job.id,
        batchId: job.batchId,
        now,
        actorUserId: user.userId,
      })
    );

    await createAuditLog({
      userId: user.userId,
      licenseeId: job.batch.licenseeId,
      action: "PRINT_CONFIRMED",
      entityType: "PrintJob",
      entityId: job.id,
      details: {
        printSessionId: session.id,
        remainingToPrint: finalize.remainingToPrint,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: session.id,
        confirmedAt: finalize.confirmedAt,
        remainingToPrint: finalize.remainingToPrint,
        jobConfirmed: finalize.jobConfirmed,
      },
    });
  } catch (e: any) {
    console.error("confirmPrintJob error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

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
  return res.status(410).json({
    success: false,
    error:
      "Browser-mediated direct printing has been disabled. The MSCQR connector now confirms printed labels directly with the server.",
  });
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

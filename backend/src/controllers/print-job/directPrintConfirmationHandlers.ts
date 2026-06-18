import { Response } from "express";
import {
  PrintDispatchMode,
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
import { recordPrintJobSampleScan } from "../../services/printSampleScanService";
import { assertBatchTransitionAllowedFromDb } from "../../services/batchStateMachineService";
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
  sampleScanSchema,
} from "./shared";

export const confirmDirectPrintItem = async (req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Browser-mediated direct printing has been disabled. The MSCQR connector now confirms printed labels directly with the server.",
  });
};

const errorMessage = (error: unknown, fallback: string) =>
  error instanceof Error ? error.message : fallback;

const errorStatusCode = (error: unknown, fallback = 400) => {
  if (error && typeof error === "object" && "statusCode" in error) {
    const statusCode = Number((error as { statusCode?: unknown }).statusCode);
    if (Number.isFinite(statusCode)) return statusCode;
  }
  return fallback;
};

const actionableTransitionPayload = (error: unknown, fallback: string) => {
  const code = typeof (error as { code?: unknown })?.code === "string" ? String((error as { code: string }).code) : undefined;
  const message = errorMessage(error, fallback);
  const recoveryByCode: Record<string, string> = {
    PHYSICAL_CONFIRMATION_REQUIRED: "confirm_physical_print",
    SAMPLE_SCAN_REQUIRED: "scan_sample_label",
    APPROVAL_REQUIRED: "request_checker_approval",
    CHECKER_REQUIRED: "use_different_checker",
    MAKER_CANNOT_APPROVE: "use_different_checker",
    QR_NOT_IN_PRINT_JOB: "scan_label_from_this_print_job",
    QR_VERIFY_TOKEN_REQUIRED: "scan_printed_verify_qr",
    PRINT_JOB_NOT_CONFIRMED: "confirm_physical_print",
    INVALID_STATE_TRANSITION: "complete_previous_step",
  };
  const requiredStepByCode: Record<string, string> = {
    PHYSICAL_CONFIRMATION_REQUIRED: "Confirm physical printing",
    SAMPLE_SCAN_REQUIRED: "Scan one printed label",
    APPROVAL_REQUIRED: "Get checker approval",
    CHECKER_REQUIRED: "Use a different authorized checker",
    MAKER_CANNOT_APPROVE: "Use a different authorized checker",
    QR_NOT_IN_PRINT_JOB: "Scan a label from this print job",
    QR_VERIFY_TOKEN_REQUIRED: "Scan the printed verify QR",
    PRINT_JOB_NOT_CONFIRMED: "Confirm physical printing",
    INVALID_STATE_TRANSITION: "Complete the previous batch step",
  };
  return {
    success: false,
    error: message,
    message,
    ...(code ? { code, errorCode: code } : {}),
    ...(code ? { userMessage: message, requiredPreviousStep: requiredStepByCode[code] || null, recoveryAction: recoveryByCode[code] || "refresh_and_retry" } : {}),
    canRetry: code ? !["MAKER_CANNOT_APPROVE", "CHECKER_REQUIRED"].includes(code) : undefined,
  };
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

    const requiresLockToken = job.printMode === PrintDispatchMode.LOCAL_AGENT || Boolean(job.printLockTokenHash);
    if (requiresLockToken && !parsed.data.printLockToken) {
      return res.status(400).json({ success: false, error: "Print lock token is required for this print job." });
    }
    const tokenHash = parsed.data.printLockToken ? hashLockToken(parsed.data.printLockToken) : null;
    if (requiresLockToken && tokenHash !== job.printLockTokenHash) {
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

    await assertBatchTransitionAllowedFromDb({
      batchId: job.batchId,
      printJobId: job.id,
      toStatus: "PHYSICAL_PRINT_CONFIRMED",
      actor: { userId: user.userId },
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
        error: `Cannot confirm job while ${remainingToPrint} items are waiting for connector physical confirmation.`,
        message: `Cannot confirm job while ${remainingToPrint} items are waiting for connector physical confirmation.`,
        code: "PHYSICAL_CONFIRMATION_REQUIRED",
        errorCode: "PHYSICAL_CONFIRMATION_REQUIRED",
        recoveryAction: "wait_for_connector_confirmation_or_stop_recover",
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
        operatorNote: parsed.data.operatorNote || null,
        sampleScanStatus: "pending_sample_scan",
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
  } catch (e: unknown) {
    console.error("confirmPrintJob error:", e);
    return res.status(errorStatusCode(e)).json(actionableTransitionPayload(e, "Bad request"));
  }
};

export const capturePrintJobSampleScan = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const paramsParsed = printJobIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid print job id" });
    }

    const parsed = sampleScanSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid sample scan payload" });
    }

    const job = await getManufacturerPrintJob(paramsParsed.data.id, user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

    const result = await recordPrintJobSampleScan({
      printJobId: job.id,
      actorId: user.userId,
      scannedValue: parsed.data.publicCode,
    });

    return res.json({ success: true, data: result });
  } catch (error: unknown) {
    const statusCode = errorStatusCode(error);
    return res.status(statusCode).json(actionableTransitionPayload(error, "Sample scan could not be verified."));
  }
};

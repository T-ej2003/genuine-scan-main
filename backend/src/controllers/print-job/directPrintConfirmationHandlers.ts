import { Response } from "express";
import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintSessionStatus,
  PrintPayloadType,
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
import { confirmPrintItemDispatch } from "../../services/printConfirmationService";
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

const toPayloadType = (value: unknown) => {
  const normalized = String(value || "").trim().toUpperCase();
  return (Object.values(PrintPayloadType) as string[]).includes(normalized) ? (normalized as PrintPayloadType) : null;
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

    if (job.printMode === PrintDispatchMode.NETWORK_DIRECT || job.printMode === PrintDispatchMode.NETWORK_IPP) {
      const acknowledgedItems = await prisma.printItem.findMany({
        where: {
          printSessionId: session.id,
          state: PrintItemState.AGENT_ACKED,
        },
        orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
        select: {
          id: true,
          dispatchMetadata: true,
          deviceJobRef: true,
        },
      });

      if (acknowledgedItems.length > 0) {
        for (const item of acknowledgedItems) {
          const metadata =
            item.dispatchMetadata && typeof item.dispatchMetadata === "object" && !Array.isArray(item.dispatchMetadata)
              ? (item.dispatchMetadata as Record<string, unknown>)
              : {};
          await confirmPrintItemDispatch({
            printSessionId: session.id,
            printJobId: job.id,
            batchId: job.batchId,
            printItemId: item.id,
            actorUserId: user.userId,
            dispatchMode: job.printMode,
            payloadType: toPayloadType(metadata.payloadType) || job.payloadType || null,
            payloadHash: typeof metadata.payloadHash === "string" ? metadata.payloadHash : job.payloadHash || null,
            bytesWritten: Number.isFinite(Number(metadata.bytesWritten)) ? Number(metadata.bytesWritten) : null,
            deviceJobRef: item.deviceJobRef || null,
            dispatchMetadata: {
              ...metadata,
              operatorConfirmedAt: new Date().toISOString(),
              operatorNote: parsed.data.operatorNote || null,
              sampleScanStatus: "pending_sample_scan",
              confirmationSource: "operator_physical_confirmation",
            },
            confirmationMode: "LOCAL_QUEUE",
            confirmationEvidence: {
              operatorConfirmed: true,
              operatorNote: parsed.data.operatorNote || null,
              sampleScanStatus: "pending_sample_scan",
            },
          });
        }
      }
    }

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
    return res.status(errorStatusCode(e)).json({
      success: false,
      error: errorMessage(e, "Bad request"),
      code: typeof (e as { code?: unknown })?.code === "string" ? (e as { code: string }).code : undefined,
    });
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
    return res.status(statusCode).json({
      success: false,
      error: errorMessage(error, "Sample scan could not be verified."),
      code: typeof (error as { code?: unknown })?.code === "string" ? (error as { code: string }).code : undefined,
    });
  }
};

import { Response } from "express";
import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintSessionStatus,
  QRStatus,
} from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { createAuditLog } from "../../services/auditService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import { countRemainingToPrint, getOrCreatePrintSession } from "../../services/printLifecycleService";
import { buildApprovedPrintPayload } from "../../services/printPayloadService";
import { hashToken } from "../../services/qrTokenService";
import {
  beginPrintActionIdempotency,
  ensureManufacturerUser,
  ensureSelectedPrinterReady,
  getManufacturerPrintJob,
  handleIdempotencyError,
  hashLockToken,
  isLockExpired,
  printJobIdParamSchema,
  replayIdempotentResponseIfAny,
  resolveDirectPrintTokenSchema,
} from "./shared";

export const resolveDirectPrintToken = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = resolveDirectPrintTokenSchema.safeParse(req.body || {});
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
        action: "print_job_resolve_token",
        scope: `job:${jobId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const job = await getManufacturerPrintJob(jobId, user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });
    if (job.printMode !== PrintDispatchMode.LOCAL_AGENT) {
      return res
        .status(409)
        .json({ success: false, error: "This print job is not configured for local-agent dispatch." });
    }
    if (!job.printer) {
      return res.status(409).json({ success: false, error: "Registered printer metadata is missing for this job." });
    }
    const printer = job.printer;

    const session = await getOrCreatePrintSession({
      id: job.id,
      batchId: job.batchId,
      manufacturerId: job.manufacturerId,
      quantity: job.quantity,
      status: job.status,
      printerRegistrationId: job.printSession?.printerRegistrationId || null,
      printerId: job.printerId || null,
    });

    if (session.status !== PrintSessionStatus.ACTIVE) {
      return res.status(409).json({ success: false, error: `Print session is ${session.status}` });
    }

    const now = new Date();
    if (isLockExpired(job.createdAt, now)) {
      return res.status(410).json({
        success: false,
        error: "Print lock token expired. Create a new print job to continue secure direct printing.",
      });
    }

    const lockHash = hashLockToken(parsed.data.printLockToken);
    if (lockHash !== job.printLockTokenHash) {
      return res.status(403).json({ success: false, error: "Invalid print lock token" });
    }

    await ensureSelectedPrinterReady({
      printerId: job.printerId || "",
      userId: user.userId,
      orgId: user.orgId || null,
      licenseeId: job.batch.licenseeId || null,
    });

    const renderTokenHash = hashToken(parsed.data.renderToken);
    const renderTokenRow = await prisma.printRenderToken.findUnique({
      where: { tokenHash: renderTokenHash },
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            status: true,
            batchId: true,
            licenseeId: true,
            printJobId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
          },
        },
      },
    });

    if (!renderTokenRow || renderTokenRow.printJobId !== job.id) {
      return res.status(404).json({ success: false, error: "Render token not found for this print job" });
    }
    if (renderTokenRow.usedAt) {
      return res.status(409).json({ success: false, error: "Render token already used" });
    }
    if (renderTokenRow.expiresAt.getTime() <= now.getTime()) {
      return res.status(410).json({ success: false, error: "Render token expired" });
    }

    const qr = renderTokenRow.qrCode;
    if (!qr || qr.printJobId !== job.id) {
      return res.status(409).json({ success: false, error: "QR code is not bound to this print job" });
    }
    if (qr.status !== QRStatus.ACTIVATED) {
      return res.status(409).json({ success: false, error: "QR code is not ready for direct-print rendering" });
    }
    if (!qr.tokenNonce || !qr.tokenIssuedAt || !qr.tokenExpiresAt) {
      return res.status(409).json({
        success: false,
        error: "QR token metadata missing. Regenerate print job to re-initialize secure token state.",
      });
    }

    const printItem = await prisma.printItem.findUnique({
      where: { qrCodeId: qr.id },
      select: { id: true, printSessionId: true, state: true, currentRenderTokenHash: true },
    });

    if (!printItem || printItem.printSessionId !== session.id) {
      return res.status(409).json({ success: false, error: "Print item not found for this session" });
    }
    if (printItem.state !== PrintItemState.ISSUED) {
      return res.status(409).json({ success: false, error: `Print item is ${printItem.state}, expected ISSUED` });
    }
    if (printItem.currentRenderTokenHash && printItem.currentRenderTokenHash !== renderTokenHash) {
      return res.status(409).json({ success: false, error: "Render token no longer valid for this print item" });
    }

    let approvedPayload;
    try {
      approvedPayload = buildApprovedPrintPayload({
        printer: {
          id: printer.id,
          name: printer.name,
          connectionType: printer.connectionType,
          commandLanguage: printer.commandLanguage,
          nativePrinterId: printer.nativePrinterId,
          ipAddress: printer.ipAddress,
          port: printer.port,
          calibrationProfile: (printer.calibrationProfile as Record<string, unknown> | null) || null,
          capabilitySummary: (printer.capabilitySummary as Record<string, unknown> | null) || null,
          metadata: (printer.metadata as Record<string, unknown> | null) || null,
        },
        qr,
        manufacturerId: job.manufacturerId,
        printJobId: job.id,
        printItemId: printItem.id,
        jobNumber: job.jobNumber,
        reprintOfJobId: job.reprintOfJobId,
      });
    } catch (error: any) {
      return res.status(409).json({
        success: false,
        error: error?.message || "Failed to build approved print payload for this label.",
      });
    }

    const txResult = await prisma.$transaction(async (tx) => {
      const markRenderTokenUsed = await tx.printRenderToken.updateMany({
        where: {
          id: renderTokenRow.id,
          usedAt: null,
          expiresAt: { gt: now },
        },
        data: { usedAt: now },
      });
      if (markRenderTokenUsed.count === 0) {
        throw new Error("RENDER_TOKEN_ALREADY_USED");
      }

      const markAcked = await tx.printItem.updateMany({
        where: {
          id: printItem.id,
          state: PrintItemState.ISSUED,
        },
        data: {
          state: PrintItemState.AGENT_ACKED,
          agentAckedAt: now,
          attemptCount: { increment: 1 },
        },
      });
      if (markAcked.count === 0) {
        throw new Error("PRINT_ITEM_ALREADY_ACKED");
      }

      await tx.printItemEvent.create({
        data: {
          printItemId: printItem.id,
          eventType: PrintItemEventType.AGENT_ACKED,
          previousState: PrintItemState.ISSUED,
          nextState: PrintItemState.AGENT_ACKED,
          actorUserId: user.userId,
          details: {
            renderTokenId: renderTokenRow.id,
          },
        },
      });

      const remainingToPrint = await countRemainingToPrint(tx, session.id);
      return { remainingToPrint };
    });

    await createAuditLog({
      userId: user.userId,
      licenseeId: job.batch.licenseeId,
      action: "DIRECT_PRINT_ITEM_ACKED",
      entityType: "PrintItem",
      entityId: printItem.id,
      details: {
        mode: "DIRECT_PRINT",
        printJobId: job.id,
        printSessionId: session.id,
        code: qr.code,
        remainingToPrint: txResult.remainingToPrint,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    const responsePayload = {
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: session.id,
        printItemId: printItem.id,
        qrId: qr.id,
        code: qr.code,
        renderResolvedAt: now.toISOString(),
        remainingToPrint: txResult.remainingToPrint,
        jobConfirmed: false,
        confirmedAt: null,
        printMode: job.printMode,
        payloadType: approvedPayload.payloadType,
        payloadContent: approvedPayload.payloadContent,
        payloadHash: approvedPayload.payloadHash,
        previewLabel: approvedPayload.previewLabel,
        commandLanguage: approvedPayload.commandLanguage,
        scanToken: approvedPayload.scanToken,
        scanUrl: approvedPayload.scanUrl,
        printer: {
          id: printer.id,
          name: printer.name,
          connectionType: printer.connectionType,
          commandLanguage: printer.commandLanguage,
          nativePrinterId: printer.nativePrinterId,
        },
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
    if (msg.includes("RENDER_TOKEN_ALREADY_USED")) {
      return res.status(409).json({ success: false, error: "Render token already used" });
    }
    if (msg.includes("PRINT_ITEM_ALREADY_ACKED")) {
      return res.status(409).json({ success: false, error: "Print item already acknowledged" });
    }
    console.error("resolveDirectPrintToken error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

import { randomBytes } from "crypto";
import { Response } from "express";
import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintSessionStatus,
} from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { createAuditLog } from "../../services/auditService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import { countRemainingToPrint, getOrCreatePrintSession } from "../../services/printLifecycleService";
import { hashToken } from "../../services/qrTokenService";
import {
  beginPrintActionIdempotency,
  DIRECT_PRINT_MAX_BATCH,
  DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS,
  ensureManufacturerUser,
  ensureSelectedPrinterReady,
  getLockExpiresAt,
  getManufacturerPrintJob,
  handleIdempotencyError,
  hashLockToken,
  isLockExpired,
  issueDirectPrintTokensSchema,
  replayIdempotentResponseIfAny,
} from "./shared";

export const issueDirectPrintTokens = async (req: AuthRequest, res: Response) => {
  try {
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = issueDirectPrintTokensSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const jobId = String(req.params.id || "").trim();
    if (!jobId) {
      return res.status(400).json({ success: false, error: "Missing print job id" });
    }

    let idempotency;
    try {
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_issue_tokens",
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
    if (job.status === PrintJobStatus.CONFIRMED) {
      return res.status(409).json({ success: false, error: "Print job already confirmed" });
    }

    await ensureSelectedPrinterReady({
      printerId: job.printerId || "",
      userId: user.userId,
      orgId: user.orgId || null,
      licenseeId: job.batch.licenseeId || null,
    });

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

    if (session.status !== PrintSessionStatus.ACTIVE) {
      return res.status(409).json({
        success: false,
        error: `Print session is not active (${session.status}).`,
      });
    }

    const requestedCount = Math.max(1, Math.min(DIRECT_PRINT_MAX_BATCH, parsed.data.count || 1));
    const renderTokenExpiresAt = new Date(now.getTime() + DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS * 1000);

    const txResult = await prisma.$transaction(async (tx) => {
      const reservedItems = await tx.printItem.findMany({
        where: {
          printSessionId: session.id,
          state: PrintItemState.RESERVED,
        },
        orderBy: { code: "asc" },
        take: requestedCount,
        select: { id: true, qrCodeId: true, code: true },
      });

      if (reservedItems.length === 0) {
        const remainingToPrint = await countRemainingToPrint(tx, session.id);
        return {
          items: [] as Array<{
            printItemId: string;
            qrId: string;
            code: string;
            renderToken: string;
            tokenHash: string;
          }>,
          remainingToPrint,
        };
      }

      const rowsWithTokens = reservedItems.map((row, index) => {
        const renderToken = randomBytes(24).toString("base64url");
        return {
          printItemId: row.id,
          qrId: row.qrCodeId,
          code: row.code,
          renderToken,
          tokenHash: hashToken(renderToken),
          issueSequence: session.issuedItems + index + 1,
        };
      });

      await tx.printRenderToken.deleteMany({
        where: {
          printJobId: job.id,
          qrCodeId: { in: rowsWithTokens.map((item) => item.qrId) },
          usedAt: null,
        },
      });

      await tx.printRenderToken.createMany({
        data: rowsWithTokens.map((item) => ({
          tokenHash: item.tokenHash,
          printJobId: job.id,
          qrCodeId: item.qrId,
          expiresAt: renderTokenExpiresAt,
        })),
      });

      for (const item of rowsWithTokens) {
        const updated = await tx.printItem.updateMany({
          where: {
            id: item.printItemId,
            state: PrintItemState.RESERVED,
          },
          data: {
            state: PrintItemState.ISSUED,
            issuedAt: now,
            issueSequence: item.issueSequence,
            currentRenderTokenHash: item.tokenHash,
          },
        });

        if (updated.count === 0) {
          throw new Error("PRINT_ITEM_STATE_CONFLICT");
        }
      }

      await tx.printItemEvent.createMany({
        data: rowsWithTokens.map((item) => ({
          printItemId: item.printItemId,
          eventType: PrintItemEventType.ISSUED,
          previousState: PrintItemState.RESERVED,
          nextState: PrintItemState.ISSUED,
          actorUserId: user.userId,
          details: {
            expiresAt: renderTokenExpiresAt.toISOString(),
          },
        })),
      });

      await tx.printSession.update({
        where: { id: session.id },
        data: {
          issuedItems: { increment: rowsWithTokens.length },
        },
      });

      await tx.printJob.updateMany({
        where: { id: job.id, status: PrintJobStatus.PENDING },
        data: { status: PrintJobStatus.SENT, sentAt: now },
      });

      const remainingToPrint = await countRemainingToPrint(tx, session.id);
      return {
        items: rowsWithTokens,
        remainingToPrint,
      };
    });

    await createAuditLog({
      userId: user.userId,
      licenseeId: job.batch.licenseeId,
      action: "DIRECT_PRINT_TOKEN_ISSUED",
      entityType: "PrintSession",
      entityId: session.id,
      details: {
        printJobId: job.id,
        issuedCount: txResult.items.length,
        expiresAt: renderTokenExpiresAt.toISOString(),
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    const responsePayload = {
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: session.id,
        lockExpiresAt: getLockExpiresAt(job.createdAt).toISOString(),
        directPrintTokenExpiresAt: renderTokenExpiresAt.toISOString(),
        remainingToPrint: txResult.remainingToPrint,
        items: txResult.items.map((item) => ({
          printItemId: item.printItemId,
          qrId: item.qrId,
          code: item.code,
          renderToken: item.renderToken,
          expiresAt: renderTokenExpiresAt.toISOString(),
        })),
      },
    };

    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 200,
      responsePayload,
    });

    return res.json(responsePayload);
  } catch (e: any) {
    console.error("issueDirectPrintTokens error:", e);
    const msg = String(e?.message || "");
    if (msg.includes("PRINT_ITEM_STATE_CONFLICT")) {
      return res.status(409).json({ success: false, error: "Print item state conflict. Retry token issuance." });
    }
    if (msg.includes("PRINTER_NOT_TRUSTED")) {
      const printerStatus = (e as { printerStatus?: unknown })?.printerStatus || null;
      return res.status(409).json({
        success: false,
        error: "Printer readiness validation failed. Token issuance blocked until printer is eligible for printing.",
        data: { printerStatus },
      });
    }
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

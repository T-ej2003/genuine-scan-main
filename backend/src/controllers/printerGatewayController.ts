import { PrintDispatchMode, PrintItemEventType, PrintItemState, PrintPayloadType, QRStatus } from "@prisma/client";
import { Request, Response } from "express";

import prisma from "../config/database";
import { buildApprovedPrintContext } from "../services/printPayloadService";
import { failStopPrintSession, finalizePrintSessionIfReady } from "../services/printLifecycleService";
import { hashGatewaySecret } from "../services/printerRegistryService";

const gatewayIdFrom = (req: Request) => String(req.get("x-printer-gateway-id") || req.body?.gatewayId || "").trim();
const gatewaySecretFrom = (req: Request) => String(req.get("x-printer-gateway-secret") || req.body?.gatewaySecret || "").trim();

const reserveGatewayItem = async (params: { printSessionId: string; actorUserId: string }) => {
  const now = new Date();
  return prisma.$transaction(async (tx) => {
    const row = await tx.printItem.findFirst({
      where: {
        printSessionId: params.printSessionId,
        state: PrintItemState.RESERVED,
      },
      orderBy: { code: "asc" },
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            batchId: true,
            licenseeId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
            status: true,
          },
        },
      },
    });
    if (!row) return null;

    const session = await tx.printSession.findUnique({ where: { id: params.printSessionId }, select: { issuedItems: true } });
    const updated = await tx.printItem.updateMany({
      where: {
        id: row.id,
        state: PrintItemState.RESERVED,
      },
      data: {
        state: PrintItemState.ISSUED,
        issuedAt: now,
        issueSequence: Number(session?.issuedItems || 0) + 1,
      },
    });
    if (updated.count === 0) return null;

    await tx.printItemEvent.create({
      data: {
        printItemId: row.id,
        eventType: PrintItemEventType.ISSUED,
        previousState: PrintItemState.RESERVED,
        nextState: PrintItemState.ISSUED,
        actorUserId: params.actorUserId,
        details: {
          dispatchMode: PrintDispatchMode.NETWORK_IPP,
          deliveryMode: "SITE_GATEWAY",
        },
      },
    });

    await tx.printSession.update({
      where: { id: params.printSessionId },
      data: {
        issuedItems: { increment: 1 },
      },
    });

    return row;
  });
};

const authenticateGatewayPrinter = async (req: Request) => {
  const gatewayId = gatewayIdFrom(req);
  const gatewaySecret = gatewaySecretFrom(req);
  if (!gatewayId || !gatewaySecret) return null;

  const printer = await prisma.printer.findFirst({
    where: {
      gatewayId,
      connectionType: "NETWORK_IPP",
      deliveryMode: "SITE_GATEWAY",
      isActive: true,
    },
  });
  if (!printer || !printer.gatewaySecretHash) return null;
  if (hashGatewaySecret(gatewaySecret) !== printer.gatewaySecretHash) return null;
  return printer;
};

export const gatewayHeartbeat = async (req: Request, res: Response) => {
  try {
    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const gatewayError = String(req.body?.error || "").trim() || null;
    const status = gatewayError ? "ERROR" : "ONLINE";
    await prisma.printer.update({
      where: { id: printer.id },
      data: {
        gatewayLastSeenAt: new Date(),
        gatewayStatus: status,
        gatewayLastError: gatewayError,
      },
    });

    return res.json({
      success: true,
      data: {
        gatewayId: printer.gatewayId,
        printerId: printer.id,
        status,
      },
    });
  } catch (error: any) {
    console.error("gatewayHeartbeat error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const claimGatewayIppJob = async (req: Request, res: Response) => {
  try {
    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    await prisma.printer.update({
      where: { id: printer.id },
      data: {
        gatewayLastSeenAt: new Date(),
        gatewayStatus: "ONLINE",
        gatewayLastError: null,
      },
    });

    const job = await prisma.printJob.findFirst({
      where: {
        printerId: printer.id,
        printMode: PrintDispatchMode.NETWORK_IPP,
        status: { in: ["PENDING", "SENT"] },
        printSession: {
          is: {
            status: "ACTIVE",
          },
        },
      },
      include: {
        batch: {
          select: {
            id: true,
            name: true,
            licenseeId: true,
          },
        },
        printSession: true,
      },
      orderBy: [{ createdAt: "asc" }],
    });

    if (!job || !job.printSession) {
      return res.json({ success: true, data: null });
    }

    if (job.status === "PENDING") {
      await prisma.printJob.update({
        where: { id: job.id },
        data: { status: "SENT", sentAt: new Date() },
      });
    }

    const item = await reserveGatewayItem({
      printSessionId: job.printSession.id,
      actorUserId: job.manufacturerId,
    });

    if (!item) {
      return res.json({ success: true, data: null });
    }

    if (item.qrCode.status !== QRStatus.ACTIVATED) {
      await failStopPrintSession({
        printSessionId: job.printSession.id,
        printJobId: job.id,
        batchId: job.batchId,
        licenseeId: job.batch.licenseeId || null,
        actorUserId: job.manufacturerId,
        reason: `QR ${item.code} is not in ACTIVATED state for gateway-backed IPP printing.`,
        printItemId: item.id,
        metadata: {
          dispatchMode: PrintDispatchMode.NETWORK_IPP,
          deliveryMode: "SITE_GATEWAY",
        },
      });
      return res.status(409).json({ success: false, error: "Reserved QR code is not printable anymore." });
    }

    const context = buildApprovedPrintContext({
      qr: item.qrCode,
      manufacturerId: job.manufacturerId,
      reprintOfJobId: job.reprintOfJobId,
    });

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: job.printSession.id,
        printItemId: item.id,
        code: item.code,
        scanUrl: context.scanUrl,
        previewLabel: context.previewLabel,
        printer: {
          id: printer.id,
          name: printer.name,
          host: printer.host,
          port: printer.port,
          resourcePath: printer.resourcePath,
          tlsEnabled: printer.tlsEnabled,
          printerUri: printer.printerUri,
        },
        calibrationProfile: (printer.calibrationProfile as Record<string, unknown> | null) || null,
        jobNumber: job.jobNumber,
      },
    });
  } catch (error: any) {
    console.error("claimGatewayIppJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const confirmGatewayIppJob = async (req: Request, res: Response) => {
  try {
    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const printJobId = String(req.body?.printJobId || "").trim();
    const printItemId = String(req.body?.printItemId || "").trim();
    if (!printJobId || !printItemId) {
      return res.status(400).json({ success: false, error: "printJobId and printItemId are required" });
    }

    const job = await prisma.printJob.findFirst({
      where: {
        id: printJobId,
        printerId: printer.id,
        printMode: PrintDispatchMode.NETWORK_IPP,
      },
      include: {
        batch: { select: { id: true, licenseeId: true } },
        printSession: true,
        printer: true,
      },
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const item = await prisma.printItem.findFirst({
      where: {
        id: printItemId,
        printSessionId: job.printSession.id,
      },
      include: {
        qrCode: {
          select: {
            status: true,
          },
        },
      },
    });
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(req.body?.payloadHash || "").trim();
    const bytesWritten = Math.max(1, Number(req.body?.bytesWritten || 1) || 1);
    const ippJobId = Number(req.body?.ippJobId || 0) || null;
    const now = new Date();

    const finalize = await prisma.$transaction(async (tx) => {
      const acked = await tx.printItem.updateMany({
        where: { id: item.id, state: PrintItemState.ISSUED },
        data: {
          state: PrintItemState.AGENT_ACKED,
          agentAckedAt: now,
          attemptCount: { increment: 1 },
        },
      });
      if (acked.count === 0) throw new Error("GATEWAY_IPP_ACK_CONFLICT");

      await tx.printItemEvent.create({
        data: {
          printItemId: item.id,
          eventType: PrintItemEventType.AGENT_ACKED,
          previousState: PrintItemState.ISSUED,
          nextState: PrintItemState.AGENT_ACKED,
          actorUserId: job.manufacturerId,
          details: {
            dispatchMode: PrintDispatchMode.NETWORK_IPP,
            deliveryMode: "SITE_GATEWAY",
            payloadType: PrintPayloadType.PDF,
            payloadHash: payloadHash || null,
            bytesWritten,
            ippJobId,
          },
        },
      });

      const confirmed = await tx.printItem.updateMany({
        where: { id: item.id, state: PrintItemState.AGENT_ACKED },
        data: {
          state: PrintItemState.PRINT_CONFIRMED,
          printConfirmedAt: now,
        },
      });
      if (confirmed.count === 0) throw new Error("GATEWAY_IPP_CONFIRM_CONFLICT");

      await tx.printItemEvent.create({
        data: {
          printItemId: item.id,
          eventType: PrintItemEventType.PRINT_CONFIRMED,
          previousState: PrintItemState.AGENT_ACKED,
          nextState: PrintItemState.PRINT_CONFIRMED,
          actorUserId: job.manufacturerId,
          details: {
            dispatchMode: PrintDispatchMode.NETWORK_IPP,
            deliveryMode: "SITE_GATEWAY",
            payloadType: PrintPayloadType.PDF,
            payloadHash: payloadHash || null,
            bytesWritten,
            ippJobId,
          },
        },
      });

      await tx.qRCode.updateMany({
        where: {
          id: item.qrCodeId,
          printJobId: job.id,
          status: QRStatus.ACTIVATED,
        },
        data: {
          status: QRStatus.PRINTED,
          printedAt: now,
          printedByUserId: job.manufacturerId,
        },
      });

      await tx.printSession.update({
        where: { id: job.printSession!.id },
        data: {
          confirmedItems: { increment: 1 },
        },
      });

      return finalizePrintSessionIfReady({
        tx,
        printSessionId: job.printSession!.id,
        printJobId: job.id,
        batchId: job.batchId,
        now,
        actorUserId: job.manufacturerId,
      });
    });

    await prisma.printer.update({
      where: { id: printer.id },
      data: {
        gatewayLastSeenAt: new Date(),
        gatewayStatus: "ONLINE",
        gatewayLastError: null,
      },
    });

    return res.json({
      success: true,
      data: {
        remainingToPrint: finalize.remainingToPrint,
        jobConfirmed: finalize.jobConfirmed,
        confirmedAt: finalize.confirmedAt,
      },
    });
  } catch (error: any) {
    console.error("confirmGatewayIppJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const failGatewayIppJob = async (req: Request, res: Response) => {
  try {
    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const printJobId = String(req.body?.printJobId || "").trim();
    const printItemId = String(req.body?.printItemId || "").trim();
    const reason = String(req.body?.reason || "").trim();
    if (!printJobId || !printItemId || !reason) {
      return res.status(400).json({ success: false, error: "printJobId, printItemId, and reason are required" });
    }

    const job = await prisma.printJob.findFirst({
      where: {
        id: printJobId,
        printerId: printer.id,
        printMode: PrintDispatchMode.NETWORK_IPP,
      },
      include: {
        batch: { select: { id: true, licenseeId: true } },
        printSession: true,
      },
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const result = await failStopPrintSession({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      licenseeId: job.batch.licenseeId || null,
      actorUserId: job.manufacturerId,
      reason,
      printItemId,
      metadata: {
        dispatchMode: PrintDispatchMode.NETWORK_IPP,
        deliveryMode: "SITE_GATEWAY",
      },
    });

    await prisma.printer.update({
      where: { id: printer.id },
      data: {
        gatewayLastSeenAt: new Date(),
        gatewayStatus: "ERROR",
        gatewayLastError: reason,
      },
    });

    return res.json({
      success: true,
      data: result,
    });
  } catch (error: any) {
    console.error("failGatewayIppJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

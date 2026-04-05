import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintPayloadType,
  PrinterConnectionType,
  QRStatus,
} from "@prisma/client";
import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import { buildApprovedPrintContext, buildApprovedPrintPayload } from "../services/printPayloadService";
import { failStopPrintSession } from "../services/printLifecycleService";
import { hashGatewaySecret } from "../services/printerRegistryService";
import {
  acknowledgePrintItemDispatch,
  confirmPrintItemDispatch,
  resolvePrinterConfirmationMode,
} from "../services/printConfirmationService";
import {
  acknowledgeGatewayPrinterTestJob,
  claimGatewayPrinterTestJob,
  confirmGatewayPrinterTestJob,
  failGatewayPrinterTestJob,
} from "../services/printerTestLabelService";

const gatewayIdFrom = (req: Request) => String(req.get("x-printer-gateway-id") || req.body?.gatewayId || "").trim();
const gatewaySecretFrom = (req: Request) => String(req.get("x-printer-gateway-secret") || req.body?.gatewaySecret || "").trim();

const gatewayCredentialsSchema = z.object({
  gatewayId: z.string().trim().min(3).max(180).optional(),
  gatewaySecret: z.string().trim().min(8).max(512).optional(),
});

const gatewayHeartbeatSchema = gatewayCredentialsSchema
  .extend({
    error: z.string().trim().max(500).optional().or(z.literal("")),
  })
  .strict();

const gatewayClaimSchema = gatewayCredentialsSchema.strict();

const gatewayAckSchema = gatewayCredentialsSchema
  .extend({
    printJobId: z.string().trim().min(1).max(120),
    printItemId: z.string().trim().min(1).max(120),
    payloadHash: z.string().trim().max(256).optional().or(z.literal("")),
    bytesWritten: z.coerce.number().int().min(1).max(50_000_000).optional(),
    deviceJobRef: z.string().trim().max(240).optional().or(z.literal("")),
    payloadType: z.string().trim().max(64).optional().or(z.literal("")),
    ippJobId: z.coerce.number().int().min(1).max(2_147_483_647).optional(),
    gatewayMetadata: z.any().optional(),
  })
  .strict();

const gatewayConfirmSchema = gatewayAckSchema;

const gatewayFailureSchema = gatewayCredentialsSchema
  .extend({
    printJobId: z.string().trim().min(1).max(120),
    printItemId: z.string().trim().min(1).max(120),
    reason: z.string().trim().min(2).max(1000),
    gatewayMetadata: z.any().optional(),
  })
  .strict();

const gatewayTestAckSchema = gatewayCredentialsSchema
  .extend({
    testJobId: z.string().trim().min(1).max(120),
    payloadHash: z.string().trim().max(256).optional().or(z.literal("")),
    bytesWritten: z.coerce.number().int().min(1).max(50_000_000).optional(),
    deviceJobRef: z.string().trim().max(240).optional().or(z.literal("")),
    payloadType: z.string().trim().max(64).optional().or(z.literal("")),
    ippJobId: z.coerce.number().int().min(1).max(2_147_483_647).optional(),
    gatewayMetadata: z.any().optional(),
  })
  .strict();

const gatewayTestConfirmSchema = gatewayTestAckSchema;

const gatewayTestFailureSchema = gatewayCredentialsSchema
  .extend({
    testJobId: z.string().trim().min(1).max(120),
    reason: z.string().trim().min(2).max(1000),
    gatewayMetadata: z.any().optional(),
  })
  .strict();

const toPayloadType = (value: unknown, fallback?: PrintPayloadType | null) => {
  const normalized = String(value || "").trim().toUpperCase();
  return (Object.values(PrintPayloadType) as string[]).includes(normalized)
    ? (normalized as PrintPayloadType)
    : fallback || null;
};

const reserveGatewayItem = async (params: {
  printSessionId: string;
  actorUserId: string;
  dispatchMode: PrintDispatchMode;
}) => {
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
        pipelineState: PrintPipelineState.SENT_TO_PRINTER,
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
          dispatchMode: params.dispatchMode,
          deliveryMode: "SITE_GATEWAY",
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
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

const authenticateGatewayPrinter = async (req: Request, connectionType?: PrinterConnectionType) => {
  const gatewayId = gatewayIdFrom(req);
  const gatewaySecret = gatewaySecretFrom(req);
  if (!gatewayId || !gatewaySecret) return null;

  const printer = await prisma.printer.findFirst({
    where: {
      gatewayId,
      deliveryMode: "SITE_GATEWAY",
      isActive: true,
      ...(connectionType ? { connectionType } : {}),
    },
  });
  if (!printer || !printer.gatewaySecretHash) return null;
  if (hashGatewaySecret(gatewaySecret) !== printer.gatewaySecretHash) return null;
  return printer;
};

const markGatewaySeen = async (printerId: string, status: "ONLINE" | "ERROR" = "ONLINE", error?: string | null) =>
  prisma.printer.update({
    where: { id: printerId },
    data: {
      gatewayLastSeenAt: new Date(),
      gatewayStatus: status,
      gatewayLastError: error || null,
    },
  });

const loadGatewayJob = async (params: {
  printerId: string;
  printJobId: string;
  printMode: PrintDispatchMode;
}) =>
  prisma.printJob.findFirst({
    where: {
      id: params.printJobId,
      printerId: params.printerId,
      printMode: params.printMode,
    },
    include: {
      batch: { select: { id: true, licenseeId: true } },
      printSession: true,
      printer: true,
    },
  });

const loadGatewayItem = async (printSessionId: string, printItemId: string) =>
  prisma.printItem.findFirst({
    where: {
      id: printItemId,
      printSessionId,
    },
    include: {
      qrCode: {
        select: {
          id: true,
          code: true,
          status: true,
        },
      },
    },
  });

const failGatewayJob = async (params: {
  printerId: string;
  printJobId: string;
  printItemId: string;
  printMode: PrintDispatchMode;
  reason: string;
  gatewayMetadata?: unknown;
}) => {
  const job = await loadGatewayJob({
    printerId: params.printerId,
    printJobId: params.printJobId,
    printMode: params.printMode,
  });
  if (!job || !job.printSession) {
    throw new Error("Print job not found for this gateway.");
  }

  const result = await failStopPrintSession({
    printSessionId: job.printSession.id,
    printJobId: job.id,
    batchId: job.batchId,
    licenseeId: job.batch.licenseeId || null,
    actorUserId: job.manufacturerId,
    reason: params.reason,
    printItemId: params.printItemId,
    metadata: {
      dispatchMode: params.printMode,
      deliveryMode: "SITE_GATEWAY",
      gatewayMetadata: params.gatewayMetadata || null,
    },
  });

  await prisma.printJob.update({
    where: { id: job.id },
    data: {
      status: PrintJobStatus.FAILED,
      pipelineState: PrintPipelineState.FAILED,
      failureReason: params.reason,
    },
  });

  return { job, result };
};

export const gatewayHeartbeat = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayHeartbeatSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid heartbeat payload" });
    }

    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const gatewayError = String(parsed.data.error || "").trim() || null;
    const status = gatewayError ? "ERROR" : "ONLINE";
    await markGatewaySeen(printer.id, status, gatewayError);

    return res.json({
      success: true,
      data: {
        gatewayId: printer.gatewayId,
        printerId: printer.id,
        connectionType: printer.connectionType,
        deliveryMode: printer.deliveryMode,
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
    const parsed = gatewayClaimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway request" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_IPP);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    await markGatewaySeen(printer.id);

    const job = await prisma.printJob.findFirst({
      where: {
        printerId: printer.id,
        printMode: PrintDispatchMode.NETWORK_IPP,
        status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
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

    if (job.status === PrintJobStatus.PENDING) {
      await prisma.printJob.update({
        where: { id: job.id },
        data: {
          status: PrintJobStatus.SENT,
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
          sentAt: new Date(),
        },
      });
    }

    const item = await reserveGatewayItem({
      printSessionId: job.printSession.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_IPP,
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
        connectionType: PrinterConnectionType.NETWORK_IPP,
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

export const claimGatewayDirectJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayClaimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway request" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_DIRECT);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }
    if (resolvePrinterConfirmationMode(printer) !== "ZEBRA_ODOMETER") {
      return res.status(409).json({
        success: false,
        error: "This gateway-backed raw printer is not yet certified for strict terminal completion confirmation.",
      });
    }

    await markGatewaySeen(printer.id);

    const job = await prisma.printJob.findFirst({
      where: {
        printerId: printer.id,
        printMode: PrintDispatchMode.NETWORK_DIRECT,
        status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
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

    if (job.status === PrintJobStatus.PENDING) {
      await prisma.printJob.update({
        where: { id: job.id },
        data: {
          status: PrintJobStatus.SENT,
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
          sentAt: new Date(),
        },
      });
    }

    const item = await reserveGatewayItem({
      printSessionId: job.printSession.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
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
        reason: `QR ${item.code} is not in ACTIVATED state for gateway-backed network direct printing.`,
        printItemId: item.id,
        metadata: {
          dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
          deliveryMode: "SITE_GATEWAY",
        },
      });
      return res.status(409).json({ success: false, error: "Reserved QR code is not printable anymore." });
    }

    const approvedPayload = buildApprovedPrintPayload({
      printer: {
        id: printer.id,
        name: printer.name,
        connectionType: printer.connectionType,
        commandLanguage: printer.commandLanguage,
        ipAddress: printer.ipAddress,
        port: printer.port,
        calibrationProfile: (printer.calibrationProfile as Record<string, unknown> | null) || null,
        capabilitySummary: (printer.capabilitySummary as Record<string, unknown> | null) || null,
        metadata: (printer.metadata as Record<string, unknown> | null) || null,
      },
      qr: item.qrCode,
      manufacturerId: job.manufacturerId,
      printJobId: job.id,
      printItemId: item.id,
      jobNumber: job.jobNumber,
      reprintOfJobId: job.reprintOfJobId,
    });

    return res.json({
      success: true,
      data: {
        connectionType: PrinterConnectionType.NETWORK_DIRECT,
        printJobId: job.id,
        printSessionId: job.printSession.id,
        printItemId: item.id,
        code: item.code,
        payloadType: approvedPayload.payloadType,
        payloadContent: approvedPayload.payloadContent,
        payloadHash: approvedPayload.payloadHash,
        previewLabel: approvedPayload.previewLabel,
        commandLanguage: approvedPayload.commandLanguage,
        scanUrl: approvedPayload.scanUrl,
        printer: {
          id: printer.id,
          name: printer.name,
          ipAddress: printer.ipAddress,
          port: printer.port,
        },
        calibrationProfile: (printer.calibrationProfile as Record<string, unknown> | null) || null,
        jobNumber: job.jobNumber,
      },
    });
  } catch (error: any) {
    console.error("claimGatewayDirectJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const claimGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayClaimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway request" });
    }

    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }
    if (
      printer.connectionType !== PrinterConnectionType.NETWORK_DIRECT &&
      printer.connectionType !== PrinterConnectionType.NETWORK_IPP
    ) {
      return res.json({ success: true, data: null });
    }

    await markGatewaySeen(printer.id);

    const claim = claimGatewayPrinterTestJob({
      printerId: printer.id,
      connectionType: printer.connectionType as "NETWORK_DIRECT" | "NETWORK_IPP",
    });
    return res.json({ success: true, data: claim });
  } catch (error: any) {
    console.error("claimGatewayTestJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const ackGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayTestAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway test ack payload" });
    }

    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const acknowledged = acknowledgeGatewayPrinterTestJob({
      printerId: printer.id,
      testJobId: parsed.data.testJobId,
      metadata: {
        payloadHash: String(parsed.data.payloadHash || "").trim() || null,
        bytesWritten: parsed.data.bytesWritten || null,
        deviceJobRef: String(parsed.data.deviceJobRef || parsed.data.ippJobId || "").trim() || null,
        payloadType: toPayloadType(parsed.data.payloadType),
        ippJobId: parsed.data.ippJobId || null,
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
    });
    if (!acknowledged) {
      return res.status(404).json({ success: false, error: "Printer test job not found." });
    }

    await markGatewaySeen(printer.id);
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, acknowledged: true } });
  } catch (error: any) {
    console.error("ackGatewayTestJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const confirmGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayTestConfirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway test confirm payload" });
    }

    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const confirmed = confirmGatewayPrinterTestJob({
      printerId: printer.id,
      testJobId: parsed.data.testJobId,
      payloadType: toPayloadType(parsed.data.payloadType),
      deviceJobRef: String(parsed.data.deviceJobRef || parsed.data.ippJobId || "").trim() || null,
      confirmationMode: resolvePrinterConfirmationMode(printer),
      metadata: {
        payloadHash: String(parsed.data.payloadHash || "").trim() || null,
        bytesWritten: parsed.data.bytesWritten || null,
        ippJobId: parsed.data.ippJobId || null,
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
    });
    if (!confirmed) {
      return res.status(404).json({ success: false, error: "Printer test job not found." });
    }

    await markGatewaySeen(printer.id);
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, confirmed: true } });
  } catch (error: any) {
    console.error("confirmGatewayTestJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const failGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayTestFailureSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway test failure payload" });
    }

    const printer = await authenticateGatewayPrinter(req);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const failed = failGatewayPrinterTestJob({
      printerId: printer.id,
      testJobId: parsed.data.testJobId,
      reason: parsed.data.reason,
    });
    if (!failed) {
      return res.status(404).json({ success: false, error: "Printer test job not found." });
    }

    await markGatewaySeen(printer.id, "ERROR", parsed.data.reason);
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, failed: true } });
  } catch (error: any) {
    console.error("failGatewayTestJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const ackGatewayIppJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway ack payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_IPP);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const job = await loadGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printMode: PrintDispatchMode.NETWORK_IPP,
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const item = await loadGatewayItem(job.printSession.id, parsed.data.printItemId);
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const deviceJobRef = String(parsed.data.deviceJobRef || parsed.data.ippJobId || "").trim();

    await acknowledgePrintItemDispatch({
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_IPP,
      payloadType: PrintPayloadType.PDF,
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: deviceJobRef || null,
      dispatchMetadata: {
        deliveryMode: "SITE_GATEWAY",
        ippJobId: parsed.data.ippJobId || null,
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
      confirmationMode: resolvePrinterConfirmationMode(printer),
    });

    await markGatewaySeen(printer.id);

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printItemId: item.id,
        acknowledged: true,
      },
    });
  } catch (error: any) {
    console.error("ackGatewayIppJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const confirmGatewayIppJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayConfirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway confirm payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_IPP);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const job = await loadGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printMode: PrintDispatchMode.NETWORK_IPP,
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const item = await loadGatewayItem(job.printSession.id, parsed.data.printItemId);
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const deviceJobRef = String(parsed.data.deviceJobRef || parsed.data.ippJobId || "").trim();

    const finalize = await confirmPrintItemDispatch({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_IPP,
      payloadType: PrintPayloadType.PDF,
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: deviceJobRef || null,
      dispatchMetadata: {
        deliveryMode: "SITE_GATEWAY",
        ippJobId: parsed.data.ippJobId || null,
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
      confirmationMode: resolvePrinterConfirmationMode(printer),
      confirmationEvidence: {
        deliveryMode: "SITE_GATEWAY",
        ippJobId: parsed.data.ippJobId || null,
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
    });

    await markGatewaySeen(printer.id);

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
    const parsed = gatewayFailureSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway failure payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_IPP);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const { job, result } = await failGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
      printMode: PrintDispatchMode.NETWORK_IPP,
      reason: parsed.data.reason,
      gatewayMetadata: parsed.data.gatewayMetadata,
    });

    await markGatewaySeen(printer.id, "ERROR", parsed.data.reason);

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        incidentId: result.incident.id,
        frozenCount: result.frozenCount,
      },
    });
  } catch (error: any) {
    console.error("failGatewayIppJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const ackGatewayDirectJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway ack payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_DIRECT);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }
    if (resolvePrinterConfirmationMode(printer) !== "ZEBRA_ODOMETER") {
      return res.status(409).json({ success: false, error: "This gateway-backed raw printer is not certified for strict direct confirmation." });
    }

    const job = await loadGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printMode: PrintDispatchMode.NETWORK_DIRECT,
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const item = await loadGatewayItem(job.printSession.id, parsed.data.printItemId);
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const deviceJobRef = String(parsed.data.deviceJobRef || "").trim();

    await acknowledgePrintItemDispatch({
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
      payloadType: toPayloadType(parsed.data.payloadType, job.payloadType),
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: deviceJobRef || null,
      dispatchMetadata: {
        deliveryMode: "SITE_GATEWAY",
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
      confirmationMode: resolvePrinterConfirmationMode(printer),
    });

    await markGatewaySeen(printer.id);

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printItemId: item.id,
        acknowledged: true,
      },
    });
  } catch (error: any) {
    console.error("ackGatewayDirectJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const confirmGatewayDirectJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayConfirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway confirm payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_DIRECT);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }
    if (resolvePrinterConfirmationMode(printer) !== "ZEBRA_ODOMETER") {
      return res.status(409).json({ success: false, error: "This gateway-backed raw printer is not certified for strict direct confirmation." });
    }

    const job = await loadGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printMode: PrintDispatchMode.NETWORK_DIRECT,
    });
    if (!job || !job.printSession) {
      return res.status(404).json({ success: false, error: "Print job not found for this gateway." });
    }

    const item = await loadGatewayItem(job.printSession.id, parsed.data.printItemId);
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const deviceJobRef = String(parsed.data.deviceJobRef || "").trim();

    const finalize = await confirmPrintItemDispatch({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.NETWORK_DIRECT,
      payloadType: toPayloadType(parsed.data.payloadType, job.payloadType),
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: deviceJobRef || null,
      dispatchMetadata: {
        deliveryMode: "SITE_GATEWAY",
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
      confirmationMode: resolvePrinterConfirmationMode(printer),
      confirmationEvidence: {
        deliveryMode: "SITE_GATEWAY",
        gatewayMetadata: parsed.data.gatewayMetadata || null,
      },
    });

    await markGatewaySeen(printer.id);

    return res.json({
      success: true,
      data: {
        remainingToPrint: finalize.remainingToPrint,
        jobConfirmed: finalize.jobConfirmed,
        confirmedAt: finalize.confirmedAt,
      },
    });
  } catch (error: any) {
    console.error("confirmGatewayDirectJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const failGatewayDirectJob = async (req: Request, res: Response) => {
  try {
    const parsed = gatewayFailureSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid gateway failure payload" });
    }

    const printer = await authenticateGatewayPrinter(req, PrinterConnectionType.NETWORK_DIRECT);
    if (!printer) {
      return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
    }

    const { job, result } = await failGatewayJob({
      printerId: printer.id,
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
      printMode: PrintDispatchMode.NETWORK_DIRECT,
      reason: parsed.data.reason,
      gatewayMetadata: parsed.data.gatewayMetadata,
    });

    await markGatewaySeen(printer.id, "ERROR", parsed.data.reason);

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        incidentId: result.incident.id,
        frozenCount: result.frozenCount,
      },
    });
  } catch (error: any) {
    console.error("failGatewayDirectJob error:", error);
    return res.status(500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

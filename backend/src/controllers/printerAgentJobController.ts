import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrinterTrustStatus,
  QRStatus,
} from "@prisma/client";
import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import { buildApprovedPrintPayload } from "../services/printPayloadService";
import { createAuditLog } from "../services/auditService";
import { failStopPrintSession } from "../services/printLifecycleService";
import {
  acknowledgePrintItemDispatch,
  confirmPrintItemDispatch,
  resolvePrinterConfirmationMode,
} from "../services/printConfirmationService";
import {
  buildPrinterAgentActionPayload,
  isPrinterAgentIssuedAtFresh,
  verifyPrinterAgentPayloadSignature,
} from "../services/printerAgentSigningService";
import { ensurePrinterProfileForPrinter, resolvePrinterPreflight } from "../printing/registry/printerProfileService";

const agentAuthSchema = z
  .object({
    agentId: z.string().trim().min(3).max(180),
    deviceFingerprint: z.string().trim().min(8).max(256),
    printerId: z.string().trim().min(1).max(180),
    issuedAt: z.string().trim().min(10).max(80),
    nonce: z.string().trim().min(8).max(180),
    signature: z.string().trim().min(16).max(4096),
  })
  .strict();

const claimSchema = agentAuthSchema
  .extend({
    selectedPrinterId: z.string().trim().max(180).optional(),
    selectedPrinterName: z.string().trim().max(180).optional(),
    deviceName: z.string().trim().max(180).optional(),
    agentVersion: z.string().trim().max(80).optional(),
  })
  .strict();

const confirmSchema = agentAuthSchema
  .extend({
    printJobId: z.string().trim().uuid(),
    printItemId: z.string().trim().uuid(),
    payloadHash: z.string().trim().max(256).optional().or(z.literal("")),
    bytesWritten: z.coerce.number().int().min(1).max(50_000_000).optional(),
    deviceJobRef: z.string().trim().max(240).optional().or(z.literal("")),
    agentMetadata: z.any().optional(),
  })
  .strict();

const ackSchema = confirmSchema;

const failSchema = agentAuthSchema
  .extend({
    printJobId: z.string().trim().uuid(),
    printItemId: z.string().trim().uuid(),
    reason: z.string().trim().min(2).max(1000),
    agentMetadata: z.any().optional(),
  })
  .strict();

const verifyLocalAgentRequest = async (
  parsed:
    | z.infer<typeof agentAuthSchema>
    | z.infer<typeof claimSchema>
    | z.infer<typeof ackSchema>
    | z.infer<typeof confirmSchema>
    | z.infer<typeof failSchema>,
  action: "claim" | "ack" | "confirm" | "fail",
  identifiers?: { printJobId?: string | null; printItemId?: string | null }
) => {
  if (!isPrinterAgentIssuedAtFresh(parsed.issuedAt)) {
    throw Object.assign(new Error("Agent request timestamp expired."), { statusCode: 401 });
  }

  const registration = await prisma.printerRegistration.findFirst({
    where: {
      agentId: parsed.agentId,
      deviceFingerprint: parsed.deviceFingerprint,
      revokedAt: null,
    },
    orderBy: [{ lastSeenAt: "desc" }, { updatedAt: "desc" }],
  });

  if (!registration || registration.trustStatus === PrinterTrustStatus.REVOKED) {
    throw Object.assign(new Error("Printer registration not trusted."), { statusCode: 401 });
  }

  if (!String(registration.publicKeyPem || "").includes("BEGIN")) {
    throw Object.assign(new Error("Printer registration public key is not enrolled."), { statusCode: 401 });
  }

  const payload = buildPrinterAgentActionPayload({
    action,
    agentId: parsed.agentId,
    deviceFingerprint: parsed.deviceFingerprint,
    printerId: parsed.printerId,
    printJobId: identifiers?.printJobId || null,
    printItemId: identifiers?.printItemId || null,
    nonce: parsed.nonce,
    issuedAt: parsed.issuedAt,
  });

  const signatureValid = verifyPrinterAgentPayloadSignature({
    publicKeyPem: registration.publicKeyPem,
    payload,
    signature: parsed.signature,
  });

  if (!signatureValid) {
    throw Object.assign(new Error("Printer agent signature verification failed."), { statusCode: 401 });
  }

  return registration;
};

const reserveLocalAgentItem = async (params: { printSessionId: string; actorUserId: string }) => {
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
          dispatchMode: PrintDispatchMode.LOCAL_AGENT,
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

export const claimLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = claimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent claim payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "claim");

    const selectedPrinterId = String(parsed.data.selectedPrinterId || parsed.data.printerId || "").trim();
    const candidatePrinters = await prisma.printer.findMany({
      where: {
        connectionType: "LOCAL_AGENT",
        isActive: true,
        printerRegistrationId: registration.id,
        ...(selectedPrinterId ? { nativePrinterId: selectedPrinterId } : {}),
      },
      orderBy: [{ isDefault: "desc" }, { updatedAt: "desc" }],
    });

    const printerIds = candidatePrinters.map((printer) => printer.id);
    if (printerIds.length === 0) {
      return res.json({ success: true, data: null });
    }

    const job = await prisma.printJob.findFirst({
      where: {
        manufacturerId: registration.userId,
        printerId: { in: printerIds },
        printMode: PrintDispatchMode.LOCAL_AGENT,
        status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
        printSession: {
          is: { status: "ACTIVE" },
        },
      },
      include: {
        batch: { select: { id: true, name: true, licenseeId: true } },
        printer: true,
        printSession: true,
      },
      orderBy: [{ createdAt: "asc" }],
    });

    if (!job || !job.printSession || !job.printer) {
      return res.json({ success: true, data: null });
    }

    await ensurePrinterProfileForPrinter(job.printer);
    const preflight = await resolvePrinterPreflight(job.printer, {
      quantity: 1,
      labelWidthMm:
        typeof (job.printer.calibrationProfile as Record<string, unknown> | null)?.labelWidthMm === "number"
          ? Number((job.printer.calibrationProfile as Record<string, unknown>).labelWidthMm)
          : 50,
      labelHeightMm:
        typeof (job.printer.calibrationProfile as Record<string, unknown> | null)?.labelHeightMm === "number"
          ? Number((job.printer.calibrationProfile as Record<string, unknown>).labelHeightMm)
          : 50,
    });

    if (!preflight.ok) {
      await prisma.printJob.update({
        where: { id: job.id },
        data: {
          status: PrintJobStatus.FAILED,
          pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION,
          failureReason: preflight.issues.join(" "),
        },
      });

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

    const item = await reserveLocalAgentItem({
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
        reason: `QR ${item.code} is not in ACTIVATED state for local direct printing.`,
        printItemId: item.id,
        metadata: {
          dispatchMode: PrintDispatchMode.LOCAL_AGENT,
        },
      });
      await prisma.printJob.update({
        where: { id: job.id },
        data: {
          status: PrintJobStatus.FAILED,
          pipelineState: PrintPipelineState.FAILED,
          failureReason: `QR ${item.code} is not in ACTIVATED state for local direct printing.`,
        },
      });
      return res.status(409).json({ success: false, error: "Reserved QR code is not printable anymore." });
    }

    const approvedPayload = buildApprovedPrintPayload({
      printer: {
        id: job.printer.id,
        name: job.printer.name,
        connectionType: job.printer.connectionType,
        commandLanguage: job.printer.commandLanguage,
        nativePrinterId: job.printer.nativePrinterId,
        ipAddress: job.printer.ipAddress,
        port: job.printer.port,
        calibrationProfile: (job.printer.calibrationProfile as Record<string, unknown> | null) || null,
        capabilitySummary: (job.printer.capabilitySummary as Record<string, unknown> | null) || null,
        metadata: (job.printer.metadata as Record<string, unknown> | null) || null,
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
          id: job.printer.id,
          name: job.printer.name,
          nativePrinterId: job.printer.nativePrinterId,
          selectedPrinterId,
          languages:
            Array.isArray((job.printer.capabilitySummary as Record<string, unknown> | null)?.languages)
              ? (((job.printer.capabilitySummary as Record<string, unknown>).languages as unknown[]) || []).map((value) =>
                  String(value || "").trim()
                )
              : [],
        },
        calibrationProfile: (job.printer.calibrationProfile as Record<string, unknown> | null) || null,
        jobNumber: job.jobNumber,
      },
    });
  } catch (error: any) {
    console.error("claimLocalAgentPrintJob error:", error);
    return res.status(error?.statusCode || 500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const ackLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = ackSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent ack payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "ack", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });

    const job = await prisma.printJob.findFirst({
      where: {
        id: parsed.data.printJobId,
        manufacturerId: registration.userId,
        printMode: PrintDispatchMode.LOCAL_AGENT,
      },
      include: {
        batch: { select: { id: true, licenseeId: true } },
        printSession: true,
        printer: true,
      },
    });
    if (!job || !job.printSession || !job.printer || job.printer.printerRegistrationId !== registration.id) {
      return res.status(404).json({ success: false, error: "Print job not found for this printer agent." });
    }

    const item = await prisma.printItem.findFirst({
      where: {
        id: parsed.data.printItemId,
        printSessionId: job.printSession.id,
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
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const confirmationMode = resolvePrinterConfirmationMode(job.printer);
    if (confirmationMode !== "LOCAL_QUEUE") {
      return res.status(409).json({ success: false, error: "This local printer is not configured for queue-backed confirmation." });
    }

    await acknowledgePrintItemDispatch({
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: job.payloadType || null,
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
      dispatchMetadata: {
        printerRegistrationId: registration.id,
        agentMetadata: parsed.data.agentMetadata || null,
      },
      confirmationMode,
    });

    await createAuditLog({
      userId: job.manufacturerId,
      licenseeId: job.batch.licenseeId || undefined,
      action: "LOCAL_AGENT_PRINT_ITEM_ACKED",
      entityType: "PrintItem",
      entityId: item.id,
      details: {
        printJobId: job.id,
        printSessionId: job.printSession?.id || null,
        code: item.code,
        payloadHash,
        deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
        agentMetadata: parsed.data.agentMetadata || null,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: job.printSession?.id || null,
        printItemId: item.id,
        qrId: item.qrCode.id,
        code: item.code,
        acknowledged: true,
        deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
      },
    });
  } catch (error: any) {
    console.error("ackLocalAgentPrintJob error:", error);
    return res.status(error?.statusCode || 500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const confirmLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = confirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent confirm payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "confirm", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });

    const job = await prisma.printJob.findFirst({
      where: {
        id: parsed.data.printJobId,
        manufacturerId: registration.userId,
        printMode: PrintDispatchMode.LOCAL_AGENT,
      },
      include: {
        batch: { select: { id: true, licenseeId: true } },
        printSession: true,
        printer: true,
      },
    });
    if (!job || !job.printSession || !job.printer || job.printer.printerRegistrationId !== registration.id) {
      return res.status(404).json({ success: false, error: "Print job not found for this printer agent." });
    }

    const item = await prisma.printItem.findFirst({
      where: {
        id: parsed.data.printItemId,
        printSessionId: job.printSession.id,
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
    if (!item) {
      return res.status(404).json({ success: false, error: "Print item not found." });
    }

    const payloadHash = String(parsed.data.payloadHash || "").trim();
    const deviceJobRef = String(parsed.data.deviceJobRef || "").trim();
    const confirmationMode = resolvePrinterConfirmationMode(job.printer);
    if (confirmationMode !== "LOCAL_QUEUE") {
      return res.status(409).json({ success: false, error: "This local printer is not configured for queue-backed confirmation." });
    }

    const finalize = await confirmPrintItemDispatch({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      printItemId: item.id,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: job.payloadType || null,
      payloadHash: payloadHash || null,
      bytesWritten: parsed.data.bytesWritten || null,
      deviceJobRef: deviceJobRef || null,
      dispatchMetadata: {
        printerRegistrationId: registration.id,
        agentMetadata: parsed.data.agentMetadata || null,
      },
      confirmationMode,
      confirmationEvidence: {
        printerRegistrationId: registration.id,
        agentMetadata: parsed.data.agentMetadata || null,
        queueConfirmed: true,
      },
    });

    await createAuditLog({
      userId: job.manufacturerId,
      licenseeId: job.batch.licenseeId || undefined,
      action: "LOCAL_AGENT_PRINT_ITEM_CONFIRMED",
      entityType: "PrintItem",
      entityId: item.id,
      details: {
        printJobId: job.id,
        printSessionId: job.printSession?.id || null,
        code: item.code,
        payloadHash,
        remainingToPrint: finalize.remainingToPrint,
        deviceJobRef: deviceJobRef || null,
        agentMetadata: parsed.data.agentMetadata || null,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: job.printSession?.id || null,
        printItemId: item.id,
        qrId: item.qrCode.id,
        code: item.code,
        remainingToPrint: finalize.remainingToPrint,
        jobConfirmed: finalize.jobConfirmed,
        confirmedAt: finalize.confirmedAt?.toISOString() || null,
      },
    });
  } catch (error: any) {
    console.error("confirmLocalAgentPrintJob error:", error);
    return res.status(error?.statusCode || 500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

export const failLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = failSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent failure payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "fail", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });

    const job = await prisma.printJob.findFirst({
      where: {
        id: parsed.data.printJobId,
        manufacturerId: registration.userId,
        printMode: PrintDispatchMode.LOCAL_AGENT,
      },
      include: {
        batch: { select: { id: true, licenseeId: true } },
        printSession: true,
        printer: true,
      },
    });
    if (!job || !job.printSession || !job.printer || job.printer.printerRegistrationId !== registration.id) {
      return res.status(404).json({ success: false, error: "Print job not found for this printer agent." });
    }

    const result = await failStopPrintSession({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      licenseeId: job.batch.licenseeId || null,
      actorUserId: job.manufacturerId,
      reason: parsed.data.reason,
      printItemId: parsed.data.printItemId,
      metadata: parsed.data.agentMetadata || null,
    });

    await prisma.printJob.update({
      where: { id: job.id },
      data: {
        status: PrintJobStatus.FAILED,
        pipelineState: PrintPipelineState.FAILED,
        failureReason: parsed.data.reason,
      },
    });

    return res.json({
      success: true,
      data: {
        printJobId: job.id,
        printSessionId: job.printSession.id,
        reason: parsed.data.reason,
        incidentId: result.incident.id,
        frozenCount: result.frozenCount,
      },
    });
  } catch (error: any) {
    console.error("failLocalAgentPrintJob error:", error);
    return res.status(error?.statusCode || 500).json({ success: false, error: error?.message || "Internal server error" });
  }
};

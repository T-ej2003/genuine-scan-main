import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
} from "@prisma/client";
import { Request, Response } from "express";

import prisma from "../config/database";
import { createAuditLog } from "../services/auditService";
import { markBatchPrintAcknowledged } from "../services/batchStateMachineService";
import { failStopPrintSession } from "../services/printLifecycleService";
import { acknowledgePrintItemDispatch, confirmPrintItemDispatch, resolvePrinterConfirmationMode } from "../services/printConfirmationService";
import {
  buildClaimApprovedPayloadOrFail,
  countLocalAgentClaimItems,
  LOCAL_AGENT_BUSY_RETRY_MS,
  LOCAL_AGENT_NO_WORK_RETRY_MS,
  reserveLocalAgentItem,
} from "../services/localAgentClaimService";
import { CONNECTOR_UPDATE_REQUIRED_CODE, CONNECTOR_UPDATE_REQUIRED_MESSAGE, isLocalAgentProtocolCompatible, LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";
import { ensurePrinterProfileForPrinter, resolvePrinterPreflight } from "../printing/registry/printerProfileService";
import {
  buildLocalAgentValidationErrorPayload,
  claimSchema,
  confirmSchema,
  failSchema,
  getLocalAgentRequestId,
  localAgentAckSchema,
  validateLocalAgentAckDispatchPhase,
} from "../services/localAgentAckProtocolService";
import { buildPrintPayloadDiagnostics } from "../services/printPayloadService";
import { claimLocalAgentPrinterTestJob } from "../services/printerTestLabelService";
import { verifyLocalAgentRequest } from "../services/localAgentRequestAuthService";

const noClaimWork = (res: Response, retryAfterMs = LOCAL_AGENT_NO_WORK_RETRY_MS) => res.json({ success: true, data: null, retryAfterMs });

export const localAgentErrorResponse = (res: Response, error: any) =>
  res.status(error?.statusCode || 500).json({
    success: false, error: error?.message || "Internal server error",
    ...(error?.errorCode ? { code: error.errorCode, errorCode: error.errorCode } : {}),
    ...(error?.serverTime ? { serverTime: error.serverTime } : {}),
    ...(error?.timestampSkewSeconds != null ? { timestampSkewSeconds: error.timestampSkewSeconds } : {}),
  });

const toRecord = (value: unknown) => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
};

const hasQueueConfirmationUnavailable = (value: unknown) => {
  const root = toRecord(value);
  const dispatchMetadata = toRecord(root.dispatchMetadata);
  const agentMetadata = toRecord(root.agentMetadata);
  return Boolean(
    root.queueConfirmationUnavailable ||
      dispatchMetadata.queueConfirmationUnavailable ||
      agentMetadata.queueConfirmationUnavailable
  );
};

export const claimLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = claimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent claim payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "claim");
    if (!isLocalAgentProtocolCompatible(parsed.data.protocolVersion || null)) {
      console.info("local_agent_claim", {
        event: "connector_update_required", registrationId: registration.id, agentId: registration.agentId,
        agentVersion: parsed.data.agentVersion || null, protocolVersion: parsed.data.protocolVersion || null,
        expectedProtocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION, retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
      return res.status(426).json({ success: false, error: CONNECTOR_UPDATE_REQUIRED_MESSAGE, code: CONNECTOR_UPDATE_REQUIRED_CODE,
        errorCode: CONNECTOR_UPDATE_REQUIRED_CODE, retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS,
        expectedProtocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION });
    }

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
      console.info("local_agent_claim", {
        event: "no_registered_printer_match",
        registrationId: registration.id,
        agentId: registration.agentId,
        selectedPrinterId,
        candidatePrinterCount: candidatePrinters.length,
        retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
      return noClaimWork(res);
    }

    const { availableItemCount, inFlightItemCount } = await countLocalAgentClaimItems({
      printerIds,
      manufacturerId: registration.userId,
    });

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
        batch: {
          select: {
            id: true,
            name: true,
            licenseeId: true,
            metadata: true,
            licensee: { select: { id: true, name: true, prefix: true, location: true, metadata: true } },
          },
        },
        manufacturer: { select: { id: true, name: true, location: true, metadata: true } },
        printer: true,
        printSession: true,
      },
      orderBy: [{ createdAt: "asc" }],
    });

    if (!job || !job.printSession || !job.printer) {
      const testClaim = claimLocalAgentPrinterTestJob({ printerIds });
      if (testClaim) {
        console.info("local_agent_claim", {
          event: "test_work_returned",
          registrationId: registration.id,
          agentId: registration.agentId,
          selectedPrinterId,
          printerIds,
          testJobId: testClaim.testJobId,
          payloadDiagnostics: buildPrintPayloadDiagnostics({
            payloadType: testClaim.payloadType,
            labelLanguage: testClaim.commandLanguage,
            payloadContent: testClaim.payloadContent,
          }),
        });
        return res.json({
          success: true,
          retryAfterMs: LOCAL_AGENT_BUSY_RETRY_MS,
          protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
          data: {
            ...testClaim,
            protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
          },
        });
      }
      console.info("local_agent_claim", {
        event: "no_active_job",
        registrationId: registration.id,
        agentId: registration.agentId,
        selectedPrinterId,
        printerIds,
        availableItemCount,
        inFlightItemCount,
        retryAfterMs: inFlightItemCount > 0 ? LOCAL_AGENT_BUSY_RETRY_MS : LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
      return noClaimWork(res, inFlightItemCount > 0 ? LOCAL_AGENT_BUSY_RETRY_MS : LOCAL_AGENT_NO_WORK_RETRY_MS);
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

      console.info("local_agent_claim", {
        event: "preflight_failed",
        registrationId: registration.id,
        agentId: registration.agentId,
        printJobId: job.id,
        printSessionId: job.printSession.id,
        retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
      return noClaimWork(res);
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
      await markBatchPrintAcknowledged({
        batchId: job.batchId,
        printJobId: job.id,
        actorUserId: job.manufacturerId,
      });
    }

    const item = await reserveLocalAgentItem({
      printSessionId: job.printSession.id,
      actorUserId: job.manufacturerId,
    });

    if (!item) {
      console.info("local_agent_claim", {
        event: "no_reserved_item",
        registrationId: registration.id,
        agentId: registration.agentId,
        printJobId: job.id,
        printSessionId: job.printSession.id,
        availableItemCount,
        inFlightItemCount,
        retryAfterMs: inFlightItemCount > 0 ? LOCAL_AGENT_BUSY_RETRY_MS : LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
      return noClaimWork(res, inFlightItemCount > 0 ? LOCAL_AGENT_BUSY_RETRY_MS : LOCAL_AGENT_NO_WORK_RETRY_MS);
    }

    const approved = await buildClaimApprovedPayloadOrFail({ job, item, registration });
    if (!approved.ok) {
      return res.status(approved.status).json({
        success: false,
        error: approved.error,
        code: approved.code,
        errorCode: approved.code,
        retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS,
      });
    }
    const approvedPayload = approved.payload;

    console.info("local_agent_claim", {
      event: "work_returned",
      registrationId: registration.id,
      agentId: registration.agentId,
      printJobId: job.id,
      printSessionId: job.printSession.id,
      printItemId: item.id,
      selectedPrinterId,
      returnedItemCount: 1,
      availableItemCount,
      inFlightItemCount,
      retryAfterMs: LOCAL_AGENT_BUSY_RETRY_MS,
      payloadDiagnostics: buildPrintPayloadDiagnostics({ payloadType: approvedPayload.payloadType, labelLanguage: approvedPayload.commandLanguage, payloadContent: approvedPayload.payloadContent }),
    });

    return res.json({
      success: true,
      retryAfterMs: LOCAL_AGENT_BUSY_RETRY_MS,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      data: {
        protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
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
    return localAgentErrorResponse(res, error);
  }
};

export const ackLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = localAgentAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      const payload = buildLocalAgentValidationErrorPayload({
        req,
        body: req.body || {},
        errorCode: "invalid_local_agent_ack_payload",
        message: "Invalid local agent ACK payload.",
        issues: parsed.error.issues,
      });
      console.info("local_agent_ack", {
        event: "validation_failed",
        requestId: getLocalAgentRequestId(req),
        validationIssuePaths: payload.details.validationIssuePaths,
        missingFields: payload.details.missingFields,
        protocolVersion: payload.details.protocolVersion,
        buildVersion: payload.details.buildVersion,
      });
      return res.status(400).json(payload);
    }

    const dispatchPhase = validateLocalAgentAckDispatchPhase(parsed.data);
    if (!dispatchPhase.ok) {
      const payload = buildLocalAgentValidationErrorPayload({
        req,
        body: req.body || {},
        errorCode: "invalid_local_agent_ack_payload",
        message: "Invalid local agent ACK payload.",
        issues: dispatchPhase.issues,
      });
      console.info("local_agent_ack", {
        event: "dispatch_validation_failed",
        requestId: getLocalAgentRequestId(req),
        printItemId: parsed.data.printItemId,
        markDispatched: parsed.data.markDispatched !== false,
        validationIssuePaths: payload.details.validationIssuePaths,
        missingFields: payload.details.missingFields,
        protocolVersion: payload.details.protocolVersion,
        buildVersion: payload.details.buildVersion,
      });
      return res.status(400).json(payload);
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
        dispatchMetadata: parsed.data.dispatchMetadata || null,
      },
      confirmationMode,
      markDispatched: parsed.data.markDispatched !== false,
    });

    if (hasQueueConfirmationUnavailable(parsed.data)) {
      const message =
        "Sent to printer queue, but local queue confirmation is unavailable. Operator confirmation is required before labels are treated as printed.";
      await prisma.printJob.update({
        where: { id: job.id },
        data: {
          pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION,
          failureReason: message,
        },
      });
      await prisma.printItemEvent.create({
        data: {
          printItemId: item.id,
          eventType: PrintItemEventType.AGENT_ACKED,
          previousState: PrintItemState.AGENT_ACKED,
          nextState: PrintItemState.AGENT_ACKED,
          actorUserId: job.manufacturerId,
          details: {
            dispatchMode: PrintDispatchMode.LOCAL_AGENT,
            queueConfirmationUnavailable: true,
            deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
            message,
          },
        },
      });
    }

    console.info("local_agent_ack", {
      registrationId: registration.id,
      agentId: registration.agentId,
      printJobId: job.id,
      printSessionId: job.printSession?.id || null,
      printItemId: item.id,
      deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
      markDispatched: parsed.data.markDispatched !== false,
      payloadHashPresent: Boolean(payloadHash),
      protocolVersion: parsed.data.protocolVersion || parsed.data.agentMetadata?.protocolVersion || null,
      buildVersion: parsed.data.buildVersion || parsed.data.agentMetadata?.buildVersion || null,
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
    return localAgentErrorResponse(res, error);
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

    console.info("local_agent_confirm", {
      registrationId: registration.id,
      agentId: registration.agentId,
      printJobId: job.id,
      printSessionId: job.printSession?.id || null,
      printItemId: item.id,
      deviceJobRef: deviceJobRef || null,
      remainingToPrint: finalize.remainingToPrint,
      jobConfirmed: finalize.jobConfirmed,
      payloadHashPresent: Boolean(payloadHash),
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
    return localAgentErrorResponse(res, error);
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

    console.info("local_agent_fail", {
      registrationId: registration.id,
      agentId: registration.agentId,
      printJobId: job.id,
      printSessionId: job.printSession.id,
      printItemId: parsed.data.printItemId,
      reasonLength: parsed.data.reason.length,
      frozenCount: result.frozenCount,
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
    return localAgentErrorResponse(res, error);
  }
};

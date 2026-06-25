import { randomBytes } from "crypto";
import { PrintDispatchMode, PrintJobStatus, PrintPipelineState } from "@prisma/client";

import prisma from "../../config/database";
import { AuthRequest } from "../../middleware/auth";
import { createAuditLog } from "../../services/auditService";
import { createUserNotification } from "../../services/notificationService";
import { supportsNetworkDirectPayloadType } from "../../services/printPayloadService";
import { startNetworkDirectDispatch } from "../../services/networkDirectPrintService";
import { startNetworkIppDispatch } from "../../services/networkIppPrintService";
import { completeIdempotentAction } from "../../services/idempotencyService";
import { createPrintJobRecords } from "../../services/printJobCreationTransactionService";
import { publishPrintJobViewEvent } from "../../services/printJobRealtimeService";
import {
  buildAndLogPrintJobCreateFailure,
  getPrintJobCreateRequestId,
  getPrintJobCreateRequestShape,
  logPrintJobCreateEvent,
} from "./createPrintJobObservability";
import { buildPrintJobErrorPayload, describePrintJobCreateFailure } from "./errorResponses";
import {
  beginPrintActionIdempotency, createPrintJobSchema, describePrintDispatchMode, ensureManufacturerUser,
  ensureSelectedPrinterReady, getLockExpiresAt, handleIdempotencyError, hashLockToken, notifySystemPrintEvent,
  replayIdempotentResponseIfAny,
} from "./shared";
import { countReservableQrCodesForPrint } from "../../services/printReservationService";
import { PRINT_JOB_MAX_RUN_LABELS, validatePrintJobRunQuantity } from "../../services/printJobRunLimitService";
import { rejectPrintJobRunQuantity } from "./runLimitResponse";

const getRequestId = getPrintJobCreateRequestId;
const getRequestShape = getPrintJobCreateRequestShape;

export const createPrintJob = async (req: AuthRequest, res: any) => {
  let failureStage = "request_received";
  let transactionStage: string | null = null;
  try {
    logPrintJobCreateEvent(req, "request_received", {
      bodyFields: {
        batchIdPresent: typeof req.body?.batchId === "string" && req.body.batchId.length > 0,
        printerIdPresent: typeof req.body?.printerId === "string" && req.body.printerId.length > 0,
        quantityPresent: req.body?.quantity !== undefined,
      },
    });
    const user = ensureManufacturerUser(req, res);
    if (!user) return;

    const parsed = createPrintJobSchema.safeParse(req.body);
    if (!parsed.success) {
      const missingFields = parsed.error.errors
        .map((issue) => String(issue.path[0] || "").trim())
        .filter(Boolean);
      const validationIssuePaths = parsed.error.errors.map((issue) => issue.path.join(".") || "<root>");
      const requestShape = getRequestShape(req);
      const diagnostics = await buildAndLogPrintJobCreateFailure(req, {
        status: 400,
        errorCode: "invalid_payload",
        reason: "invalid_payload",
        failureStage: "payload_validation",
        missingFields,
        validationIssuePaths,
        batchId: requestShape.batchId,
        printerId: requestShape.printerId,
        quantity: requestShape.quantity,
        parsedQuantity: null,
      });
      return res.status(400).json(
        buildPrintJobErrorPayload({
          code: "invalid_payload",
          message: "The print job request is missing required information.",
          requestId: getRequestId(req),
          failureStage: "payload_validation",
          details: {
            ...(missingFields.length > 0 ? { missingFields } : {}),
            validationIssuePaths,
          },
          data: diagnostics ? { diagnostics } : undefined,
        })
      );
    }

    failureStage = "payload_validated";
    logPrintJobCreateEvent(req, "payload_validated", {
      batchId: parsed.data.batchId,
      printerId: parsed.data.printerId,
      quantity: parsed.data.quantity,
    });

    let idempotency;
    try {
      failureStage = "idempotency_started";
      idempotency = await beginPrintActionIdempotency({
        req,
        action: "print_job_create",
        scope: `user:${user.userId}:batch:${parsed.data.batchId}`,
        payload: parsed.data,
      });
    } catch (error) {
      if (handleIdempotencyError(error, res)) return;
      throw error;
    }

    if (replayIdempotentResponseIfAny(idempotency, res)) return;

    const { batchId, printerId, quantity, rangeStart, rangeEnd } = parsed.data;
    failureStage = "batch_load";
    const batch = await prisma.batch.findFirst({
      where: { id: batchId, manufacturerId: user.userId },
      select: { id: true, name: true, licenseeId: true, manufacturerId: true },
    });
    if (!batch) {
      logPrintJobCreateEvent(req, "request_failed", {
        status: 404,
        errorCode: "batch_not_found",
        failureStage,
        batchId,
      });
      return res.status(404).json(
        buildPrintJobErrorPayload({
          code: "batch_not_found",
          message: "Batch not found or not assigned to you.",
          requestId: getRequestId(req),
          failureStage,
        })
      );
    }
    failureStage = "batch_loaded";
    logPrintJobCreateEvent(req, "batch_loaded", {
      batchId: batch.id,
      licenseeId: batch.licenseeId,
      manufacturerId: batch.manufacturerId,
    });

    failureStage = "quantity_limit";
    const remainingPrintableCount = await countReservableQrCodesForPrint(prisma as any, {
      batchId: batch.id,
      rangeStart,
      rangeEnd,
    });
    const quantityLimit = validatePrintJobRunQuantity({
      quantity,
      remainingPrintableCount,
      maxConfiguredRunLabels: PRINT_JOB_MAX_RUN_LABELS,
    });
    if (!quantityLimit.ok) {
      return rejectPrintJobRunQuantity({ req, res, batchId: batch.id, quantity, failureStage, quantityLimit });
    }

    failureStage = "active_job_check";
    const activeJob = await prisma.printJob.findFirst({
      where: {
        batchId: batch.id,
        manufacturerId: user.userId,
        status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
        printSession: {
          is: {
            status: "ACTIVE",
          },
        },
      },
      orderBy: [{ createdAt: "desc" }],
      select: {
        id: true,
        status: true,
        pipelineState: true,
        printMode: true,
        quantity: true,
        itemCount: true,
        printer: {
          select: {
            id: true,
            name: true,
            connectionType: true,
            commandLanguage: true,
            deliveryMode: true,
          },
        },
        printSession: {
          select: {
            id: true,
            status: true,
            totalItems: true,
            confirmedItems: true,
            frozenItems: true,
          },
        },
      },
    });
    if (activeJob) {
      const activeTotalItems = Number(activeJob.printSession?.totalItems || activeJob.itemCount || activeJob.quantity || 0);
      const activeConfirmedItems = Number(activeJob.printSession?.confirmedItems || 0);
      const activeRemainingItems = Math.max(0, activeTotalItems - activeConfirmedItems);
      logPrintJobCreateEvent(req, "request_failed", {
        status: 409,
        errorCode: "active_print_job_exists",
        failureStage,
        batchId: batch.id,
        activePrintJobId: activeJob.id,
        activePrintSessionId: activeJob.printSession?.id || null,
      });
      const responsePayload = {
        ...buildPrintJobErrorPayload({
          code: "active_print_job_exists",
          message: "An active print run already exists for this batch. Resume the current job instead of starting a duplicate run.",
          requestId: getRequestId(req),
          failureStage,
        }),
        activePrintJobId: activeJob.id,
        activePrintSessionId: activeJob.printSession?.id || null,
        confirmedItems: activeConfirmedItems,
        remainingItems: activeRemainingItems,
        recoveryAction: "resume_active_print_job",
        data: {
          activePrintJobId: activeJob.id,
          activePrintSessionId: activeJob.printSession?.id || null,
          confirmedItems: activeConfirmedItems,
          remainingItems: activeRemainingItems,
          recoveryAction: "resume_active_print_job",
          job: {
            id: activeJob.id,
            status: activeJob.status,
            pipelineState: activeJob.pipelineState,
            printMode: activeJob.printMode,
            quantity: activeJob.quantity,
            itemCount: activeJob.itemCount,
            printer: activeJob.printer,
            session: activeJob.printSession
              ? {
                  ...activeJob.printSession,
                  remainingToPrint: activeRemainingItems,
                }
              : null,
          },
        },
      };
      await completeIdempotentAction({
        keyHash: idempotency.keyHash,
        statusCode: 409,
        responsePayload,
      });
      return res.status(409).json(responsePayload);
    }

    failureStage = "printer_readiness";
    const printerSelection = await ensureSelectedPrinterReady({
      printerId,
      userId: user.userId,
      orgId: user.orgId || null,
      licenseeId: batch.licenseeId || null,
    });
    logPrintJobCreateEvent(req, "printer_loaded", {
      printerId: printerSelection.printer.id,
      printerName: printerSelection.printer.name,
      nativePrinterId: printerSelection.printer.nativePrinterId,
      connectionType: printerSelection.printer.connectionType,
      deliveryMode: (printerSelection.printer as any).deliveryMode || null,
    });
    logPrintJobCreateEvent(req, "heartbeat_loaded", {
      connected: printerSelection.printerStatus?.connected ?? null,
      eligibleForPrinting: printerSelection.printerStatus?.eligibleForPrinting ?? null,
      trusted: printerSelection.printerStatus?.trusted ?? null,
      compatibilityMode: printerSelection.printerStatus?.compatibilityMode ?? null,
      stale: printerSelection.printerStatus?.stale ?? null,
      selectedPrinterId: printerSelection.printerStatus?.selectedPrinterId || null,
      selectedPrinterName: printerSelection.printerStatus?.selectedPrinterName || null,
      printerId: printerSelection.printerStatus?.printerId || null,
      printerName: printerSelection.printerStatus?.printerName || null,
    });
    failureStage = "printer_mapping_resolved";
    logPrintJobCreateEvent(req, "printer_mapping_resolved", {
      requestedPrinterId: printerId,
      resolvedPrinterId: printerSelection.printer.id,
      resolvedNativePrinterId: printerSelection.printer.nativePrinterId || null,
      printMode: printerSelection.printMode,
    });
    if (
      printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT &&
      !supportsNetworkDirectPayloadType(printerSelection.payloadType)
    ) {
      logPrintJobCreateEvent(req, "request_failed", {
        status: 409,
        errorCode: "unsupported_printer_route",
        failureStage: "printer_payload_support",
        printerId,
      });
      return res.status(409).json(
        buildPrintJobErrorPayload({
          code: "unsupported_printer_route",
          message: "This printer profile needs a compatible setup before it can be used.",
          requestId: getRequestId(req),
          failureStage: "printer_payload_support",
        })
      );
    }

    const printLockToken =
      printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT ? randomBytes(24).toString("base64url") : null;
    const printLockTokenHash = printLockToken ? hashLockToken(printLockToken) : null;

    failureStage = "transaction_started";
    logPrintJobCreateEvent(req, "transaction_started", {
      batchId: batch.id,
      printerId: printerSelection.printer.id,
      quantity,
    });
    const created = await createPrintJobRecords({
      batch,
      userId: user.userId,
      printerSelection,
      quantity,
      rangeStart,
      rangeEnd,
      printLockTokenHash,
      onEvent: (event, data) => logPrintJobCreateEvent(req, event, data),
      onStage: (stage, event, data = {}) => {
        transactionStage = stage;
        logPrintJobCreateEvent(req, event, data);
      },
    });
    failureStage = "transaction_completed";

    failureStage = "audit_log";
    await createAuditLog({
      userId: user.userId,
      licenseeId: batch.licenseeId,
      action: "CREATED",
      entityType: "PrintJob",
      entityId: created.job.id,
      details: {
        batchId: batch.id,
        quantity,
        rangeStart: rangeStart || null,
        rangeEnd: rangeEnd || null,
        mode: printerSelection.printMode,
        printerId: printerSelection.printer.id,
        printerName: printerSelection.printer.name,
        printSessionId: created.session.id,
      },
      ipAddress: req.ip,
      userAgent: req.get("user-agent") || undefined,
    });

    const responsePayload = {
      success: true,
      data: {
        printJobId: created.job.id,
        printSessionId: created.session.id,
        printLockToken: null,
        quantity,
        tokenCount: created.preparedCount,
        mode: printerSelection.printMode,
        pipelineState:
          printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
            ? PrintPipelineState.QUEUED
            : PrintPipelineState.PREFLIGHT_OK,
        lockExpiresAt: getLockExpiresAt(created.job.createdAt).toISOString(),
        printer: {
          id: printerSelection.printer.id,
          name: printerSelection.printer.name,
          connectionType: printerSelection.printer.connectionType,
          commandLanguage: printerSelection.printer.commandLanguage,
          ipAddress: printerSelection.printer.ipAddress,
          host: (printerSelection.printer as any).host || null,
          port: printerSelection.printer.port,
          resourcePath: (printerSelection.printer as any).resourcePath || null,
          tlsEnabled: (printerSelection.printer as any).tlsEnabled ?? null,
          printerUri: (printerSelection.printer as any).printerUri || null,
          deliveryMode: (printerSelection.printer as any).deliveryMode || null,
          gatewayId: (printerSelection.printer as any).gatewayId || null,
          nativePrinterId: printerSelection.printer.nativePrinterId,
        },
        printerStatus: printerSelection.printerStatus,
      },
    };

    failureStage = "idempotency_complete";
    await completeIdempotentAction({
      keyHash: idempotency.keyHash,
      statusCode: 201,
      responsePayload,
    });

    void publishPrintJobViewEvent({
      printJobId: created.job.id,
      manufacturerId: user.userId,
      licenseeId: batch.licenseeId || null,
      batchId: batch.id,
      type: "print_job.created",
      reason: "print_job_created",
    });

    try {
      failureStage = "notification_dispatch";
      await createUserNotification({
        userId: user.userId,
        licenseeId: batch.licenseeId,
        type: "manufacturer_print_job_created",
        title:
          printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT
            ? "Network-direct job prepared"
            : printerSelection.printMode === PrintDispatchMode.NETWORK_IPP
              ? "Network IPP job prepared"
              : "Direct-print job prepared",
        body: `${describePrintDispatchMode(printerSelection.printMode)} session ready for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
      await notifySystemPrintEvent({
        licenseeId: batch.licenseeId,
        orgId: user.orgId || null,
        type: "system_print_job_created",
        title: "System print job created",
        body: `${describePrintDispatchMode(printerSelection.printMode)} print job created for ${batch.name} (${quantity} codes).`,
        data: {
          printJobId: created.job.id,
          printSessionId: created.session.id,
          batchId: batch.id,
          batchName: batch.name,
          quantity,
          mode: printerSelection.printMode,
          printerId: printerSelection.printer.id,
          printerName: printerSelection.printer.name,
          targetRoute: "/batches",
        },
      });
    } catch (notifyError) {
      console.error("createPrintJob notification error:", notifyError);
    }

    failureStage = "job_dispatched_queued";
    if (printerSelection.printMode === PrintDispatchMode.NETWORK_DIRECT) {
      void startNetworkDirectDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      }).catch((error) => {
        console.error("startNetworkDirectDispatch error:", error);
      });
    } else if (printerSelection.printMode === PrintDispatchMode.NETWORK_IPP) {
      void startNetworkIppDispatch({
        jobId: created.job.id,
        actorUserId: user.userId,
      }).catch((error) => {
        console.error("startNetworkIppDispatch error:", error);
      });
    }
    logPrintJobCreateEvent(req, "job_dispatched/queued", {
      printJobId: created.job.id,
      printSessionId: created.session.id,
      printMode: printerSelection.printMode,
      pipelineState:
        printerSelection.printMode === PrintDispatchMode.LOCAL_AGENT
          ? PrintPipelineState.QUEUED
          : PrintPipelineState.PREFLIGHT_OK,
    });

    return res.status(201).json(responsePayload);
  } catch (e: any) {
    console.error("createPrintJob error:", e);
    const initialFailure = describePrintJobCreateFailure(e, {
      requestId: getRequestId(req),
      failureStage,
    });
    const requestShape = getRequestShape(req);
    const diagnostics = await buildAndLogPrintJobCreateFailure(req, {
      status: initialFailure.status,
      errorCode: initialFailure.payload.errorCode,
      reason: initialFailure.logReason,
      failureStage,
      transactionStage,
      exceptionName: e?.name || null,
      exceptionCode: e?.code || null,
      cryptoMetadata: e?.safeCryptoMetadata || null,
      missingFields: initialFailure.payload.details?.missingFields,
      batchId: requestShape.batchId,
      printerId: requestShape.printerId,
      quantity: requestShape.quantity,
      parsedQuantity: requestShape.quantity,
    });
    const failure = describePrintJobCreateFailure(e, {
      requestId: getRequestId(req),
      failureStage,
      diagnostics: diagnostics || undefined,
    });
    return res.status(failure.status).json(failure.payload);
  }
};

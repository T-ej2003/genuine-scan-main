import { PrintDispatchMode, PrintPipelineState } from "@prisma/client";

import { AuthRequest } from "../../middleware/auth";
import { createUserNotification } from "../../services/notificationService";
import { startNetworkDirectDispatch } from "../../services/networkDirectPrintService";
import { startNetworkIppDispatch } from "../../services/networkIppPrintService";
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
  abortPrintActionIdempotency, beginPrintActionIdempotency, completePrintActionIdempotency, createPrintJobSchema, describePrintDispatchMode, ensureManufacturerUser,
  getLockExpiresAt, handleIdempotencyError, notifySystemPrintEvent, replayIdempotentResponseIfAny,
} from "./shared";
import { PRINT_JOB_MAX_RUN_LABELS, validatePrintJobRunQuantity } from "../../services/printJobRunLimitService";
import { rejectPrintJobRunQuantity } from "./runLimitResponse";

const getRequestId = getPrintJobCreateRequestId;
const getRequestShape = getPrintJobCreateRequestShape;

export const createPrintJob = async (req: AuthRequest, res: any) => {
  let failureStage = "request_received";
  let transactionStage: string | null = null;
  let idempotency: Awaited<ReturnType<typeof beginPrintActionIdempotency>> | null = null;
  let printJobCommitted = false;
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

    const { batchId, printerId, quantity, rangeStart, rangeEnd } = parsed.data;
    failureStage = "quantity_limit";
    const quantityLimit = validatePrintJobRunQuantity({
      quantity,
      remainingPrintableCount: quantity,
      maxConfiguredRunLabels: PRINT_JOB_MAX_RUN_LABELS,
    });
    if (!quantityLimit.ok) {
      return rejectPrintJobRunQuantity({ req, res, batchId, quantity, failureStage, quantityLimit });
    }

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

    failureStage = "transaction_started";
    logPrintJobCreateEvent(req, "transaction_started", {
      batchId,
      printerId,
      quantity,
    });
    const created = await createPrintJobRecords({
      capability: String(req.databaseSessionCapability || ""),
      requestId: String(getRequestId(req) || ""),
      batchId,
      printerId,
      quantity,
      rangeStart,
      rangeEnd,
      printLockTokenHash: null,
      onEvent: (event, data) => logPrintJobCreateEvent(req, event, data),
      onStage: (stage, event, data = {}) => {
        transactionStage = stage;
        logPrintJobCreateEvent(req, event, data);
      },
    });
    printJobCommitted = true;
    const batch = created.batch;
    const printerSelection = created.printerSelection;
    failureStage = "transaction_completed";

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
    await completePrintActionIdempotency(idempotency, 201, responsePayload);

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
    if (idempotency && !printJobCommitted) {
      await abortPrintActionIdempotency(idempotency).catch((error) => {
        console.error("createPrintJob idempotency abort error:", error);
      });
    }
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

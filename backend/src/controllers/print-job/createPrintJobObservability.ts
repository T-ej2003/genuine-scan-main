import { AuthRequest } from "../../middleware/auth";
import { buildPrintJobCreateDiagnostics } from "../../services/printJobCreateDiagnosticsService";

export type PrintJobCreateFailureLogParams = {
  status: number;
  errorCode: string;
  reason: string;
  failureStage?: string | null;
  transactionStage?: string | null;
  exceptionName?: string | null;
  exceptionCode?: string | null;
  cryptoMetadata?: Record<string, unknown> | null;
  missingFields?: string[];
  validationIssuePaths?: string[];
  batchId?: string | null;
  printerId?: string | null;
  quantity?: number | null;
  parsedQuantity?: number | null;
};

export const getPrintJobCreateRequestId = (req: AuthRequest) =>
  String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || "").trim() || null;

export const getPrintJobCreateRequestShape = (req: AuthRequest) => ({
  batchId: typeof req.body?.batchId === "string" ? req.body.batchId : null,
  printerId: typeof req.body?.printerId === "string" ? req.body.printerId : null,
  quantity: Number.isFinite(Number(req.body?.quantity)) ? Number(req.body.quantity) : null,
});

export const logPrintJobCreateEvent = (
  req: AuthRequest,
  event: string,
  data: Record<string, unknown> = {}
) => {
  console.info("createPrintJob", {
    event,
    requestId: getPrintJobCreateRequestId(req),
    userId: req.user?.userId || null,
    role: req.user?.role || null,
    ...data,
  });
};

export const buildAndLogPrintJobCreateFailure = async (
  req: AuthRequest,
  params: PrintJobCreateFailureLogParams
) => {
  try {
    const diagnostics = await buildPrintJobCreateDiagnostics(req, getPrintJobCreateRequestId(req), params);
    console.warn("createPrintJob", {
      event: "request_failed",
      requestId: getPrintJobCreateRequestId(req),
      userId: req.user?.userId || null,
      role: req.user?.role || null,
      status: params.status,
      errorCode: params.errorCode,
      reason: params.reason,
      failureStage: params.failureStage || null,
      transactionStage: params.transactionStage || null,
      cryptoMetadata: params.cryptoMetadata || null,
      missingFields: params.missingFields || [],
      validationIssuePaths: params.validationIssuePaths || [],
      batchId: params.batchId || null,
      printerId: params.printerId || null,
      quantity: params.quantity ?? null,
      parsedQuantity: params.parsedQuantity ?? params.quantity ?? null,
      diagnostics,
    });
    return diagnostics;
  } catch (diagnosticError) {
    console.warn("createPrintJob", {
      event: "request_failed",
      requestId: getPrintJobCreateRequestId(req),
      userId: req.user?.userId || null,
      role: req.user?.role || null,
      status: params.status,
      errorCode: params.errorCode,
      reason: params.reason,
      failureStage: params.failureStage || null,
      transactionStage: params.transactionStage || null,
      cryptoMetadata: params.cryptoMetadata || null,
      missingFields: params.missingFields || [],
      validationIssuePaths: params.validationIssuePaths || [],
      batchId: params.batchId || null,
      printerId: params.printerId || null,
      quantity: params.quantity ?? null,
      parsedQuantity: params.parsedQuantity ?? params.quantity ?? null,
      diagnosticError: String((diagnosticError as any)?.message || diagnosticError || "diagnostics_unavailable"),
    });
    return null;
  }
};

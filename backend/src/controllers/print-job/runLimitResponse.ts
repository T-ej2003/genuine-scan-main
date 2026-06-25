import { Response } from "express";

import { AuthRequest } from "../../middleware/auth";
import { buildPrintJobErrorPayload } from "./errorResponses";
import { getPrintJobCreateRequestId, logPrintJobCreateEvent } from "./createPrintJobObservability";

type QuantityLimitResult = {
  remainingPrintableCount: number;
  maxRunQuantity: number;
  maxConfiguredRunLabels: number;
};

export const rejectPrintJobRunQuantity = (params: {
  req: AuthRequest;
  res: Response;
  batchId: string;
  quantity: number;
  failureStage: string;
  quantityLimit: QuantityLimitResult;
}) => {
  const { req, res, batchId, quantity, failureStage, quantityLimit } = params;
  logPrintJobCreateEvent(req, "request_failed", {
    status: 400,
    errorCode: "PRINT_QUANTITY_EXCEEDS_RUN_LIMIT",
    failureStage,
    batchId,
    requestedQuantity: quantity,
    remainingPrintableCount: quantityLimit.remainingPrintableCount,
    maxRunQuantity: quantityLimit.maxRunQuantity,
    maxConfiguredRunLabels: quantityLimit.maxConfiguredRunLabels,
  });
  return res.status(400).json(
    buildPrintJobErrorPayload({
      code: "PRINT_QUANTITY_EXCEEDS_RUN_LIMIT",
      message: `Maximum per run: ${quantityLimit.maxRunQuantity.toLocaleString()} labels.`,
      requestId: getPrintJobCreateRequestId(req),
      failureStage,
      data: quantityLimit,
    })
  );
};

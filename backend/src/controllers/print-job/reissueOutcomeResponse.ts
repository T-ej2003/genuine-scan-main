import { Response } from "express";
import { describeMissingPrinterReadinessFields } from "./errorResponses";
import { handleUserSafeError } from "./shared";

export function sendPrintReissueExecutionError(res: Response, error: any) {
  const message = String(error?.message || "");
  const sqlCode = error?.code === "P2010" && error?.meta?.code === "P0001"
    ? /^ERROR:\s+([A-Z_]+)(?:\r?\n|$)/.exec(String(error.meta.message || ""))?.[1] : null;
  if (sqlCode === "PHYSICAL_OUTCOME_UNCONFIRMED" || sqlCode === "INVALID_STATE_TRANSITION") {
    const code = sqlCode;
    return res.status(409).json({
      success: false,
      error: "This run can no longer be safely reissued. Refresh its status before trying again.",
      code, errorCode: code,
    });
  }
  if (sqlCode === "PRINTER_ATTESTATION_STALE" || message.includes("PRINTER_NOT_TRUSTED")) {
    const printerStatus = error?.printerStatus || null;
    return res.status(409).json({
      success: false,
      error: "Printer verification expired. Refresh printer helper before printing.",
      message: "Printer verification expired. Refresh printer helper before printing.",
      code: "PRINTER_ATTESTATION_STALE",
      errorCode: "PRINTER_ATTESTATION_STALE",
      recoveryAction: "refresh_printer_status",
      canRetry: true,
      details: { missingFields: describeMissingPrinterReadinessFields(printerStatus) },
      data: { printerStatus },
    });
  }
  if (sqlCode === "NOT_ENOUGH_CODES" || message.startsWith("NOT_ENOUGH_CODES")) {
    const code = "NOT_ENOUGH_CODES";
    return res.status(409).json({
      success: false,
      error: "The run has too few independently eligible original labels for this reissue.",
      code, errorCode: code,
    });
  }
  if (message === "BATCH_BUSY") {
    return res.status(409).json({
      success: false,
      error: "This source batch is busy. Refresh the workspace and try the reissue again.",
    });
  }
  if (typeof error?.statusCode === "number") {
    const safeMessage = message || "Replacement labels could not be printed.";
    return res.status(error.statusCode).json({
      success: false,
      error: safeMessage,
      message: safeMessage,
      ...(typeof error?.code === "string" ? { code: error.code, errorCode: error.code } : {}),
      ...(error?.details ? { details: error.details } : {}),
    });
  }
  return handleUserSafeError(res, error, "Replacement labels could not be printed.");
}

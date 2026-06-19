import { sanitizePrinterActionError } from "../../utils/printerUserFacingErrors";

type PrintJobErrorCode =
  | "QR_CODES_REQUIRED"
  | "PRINT_ACK_REQUIRED"
  | "PHYSICAL_CONFIRMATION_REQUIRED"
  | "SAMPLE_SCAN_REQUIRED"
  | "APPROVAL_REQUIRED"
  | "CHECKER_REQUIRED"
  | "MAKER_CANNOT_APPROVE"
  | "BATCH_ALREADY_RELEASED"
  | "QR_NOT_IN_PRINT_JOB"
  | "INVALID_STATE_TRANSITION"
  | "active_print_job_exists"
  | "batch_not_found"
  | "batch_not_printable"
  | "internal_print_job_create_failed"
  | "invalid_payload"
  | "invalid_printer"
  | "missing_printer_session"
  | "printer_mapping_missing"
  | "printer_not_found"
  | "printer_not_verified"
  | "printer_selection_mismatch"
  | "printer_status_unavailable"
  | "PRINTER_TEST_LABEL_REQUIRED"
  | "RECOVERY_REQUIRED_BEFORE_NEW_PRINT"
  | "print_job_conflict"
  | "print_job_transaction_failed"
  | "print_item_reservation_failed"
  | "print_signing_configuration_invalid"
  | "print_service_unavailable"
  | "session_expired"
  | "unsupported_printer_route";

type PrinterStatusLike = {
  registrationId?: string | null;
  connected?: boolean | null;
  eligibleForPrinting?: boolean | null;
  stale?: boolean | null;
  trusted?: boolean | null;
  compatibilityMode?: boolean | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  printerName?: string | null;
  selectedPrinterName?: string | null;
};

export type PrintJobErrorPayload = {
  success: false;
  error: string;
  message: string;
  code: PrintJobErrorCode;
  errorCode: PrintJobErrorCode;
  batchId?: string;
  currentLifecycleState?: string;
  requiredPreviousStep?: string | null;
  userMessage?: string;
  recoveryAction?: string;
  canRetry?: boolean;
  canRepairAutomatically?: boolean;
  requestId?: string | null;
  failureStage?: string | null;
  details?: {
    missingFields?: string[];
    validationIssuePaths?: string[];
  };
  data?: Record<string, unknown>;
};

export const buildPrintJobErrorPayload = (params: {
  code: PrintJobErrorCode;
  message: string;
  requestId?: string | null;
  failureStage?: string | null;
  details?: PrintJobErrorPayload["details"];
  data?: Record<string, unknown>;
}): PrintJobErrorPayload => ({
  success: false,
  error: params.message,
  message: params.message,
  code: params.code,
  errorCode: params.code,
  ...(params.requestId ? { requestId: params.requestId } : {}),
  ...(params.failureStage ? { failureStage: params.failureStage } : {}),
  ...(params.details ? { details: params.details } : {}),
  ...(params.data ? { data: params.data } : {}),
});

export const describeMissingPrinterReadinessFields = (printerStatus: PrinterStatusLike | null | undefined): string[] => {
  if (Array.isArray((printerStatus as any)?.missingFields)) {
    return Array.from(new Set((printerStatus as any).missingFields.map((field: unknown) => String(field || "").trim()).filter(Boolean)));
  }
  const missing = new Set<string>();
  if (!printerStatus?.registrationId) missing.add("printerRegistration");
  if (!(printerStatus as any)?.freshHelperHeartbeat && (!printerStatus || printerStatus.stale)) missing.add("freshHelperHeartbeat");
  if (!(printerStatus as any)?.helperConnection && !printerStatus?.connected) missing.add("helperConnection");
  if (!(printerStatus as any)?.eligiblePrinter && !printerStatus?.eligibleForPrinting) missing.add("eligiblePrinter");
  if ((printerStatus as any)?.securePrinterSession === false || !printerStatus?.trusted || printerStatus?.compatibilityMode) {
    missing.add("securePrinterSession");
  }
  if (!printerStatus?.selectedPrinterId && !printerStatus?.printerId) missing.add("selectedPrinter");
  return Array.from(missing);
};

const hasAny = (value: string, fragments: string[]) => fragments.some((fragment) => value.includes(fragment));
const VIRTUAL_PRINTER_TERMS = ["fax", "microsoft print to pdf", "print to pdf", "pdf", "onenote", "xps", "document writer"];

const hasVirtualSelectedPrinter = (printerStatus: PrinterStatusLike | null | undefined) =>
  hasAny(
    [
      printerStatus?.selectedPrinterId,
      printerStatus?.selectedPrinterName,
      printerStatus?.printerId,
      printerStatus?.printerName,
    ]
      .join(" ")
      .toLowerCase(),
    VIRTUAL_PRINTER_TERMS
  );

const batchStateErrorCodes = new Set<PrintJobErrorCode>([
  "QR_CODES_REQUIRED",
  "PRINT_ACK_REQUIRED",
  "PHYSICAL_CONFIRMATION_REQUIRED",
  "SAMPLE_SCAN_REQUIRED",
  "APPROVAL_REQUIRED",
  "CHECKER_REQUIRED",
  "MAKER_CANNOT_APPROVE",
  "BATCH_ALREADY_RELEASED",
  "QR_NOT_IN_PRINT_JOB",
  "INVALID_STATE_TRANSITION",
  "RECOVERY_REQUIRED_BEFORE_NEW_PRINT",
]);

const classifyPrinterReadinessError = (printerStatus: PrinterStatusLike | null | undefined): PrintJobErrorCode => {
  const missing = describeMissingPrinterReadinessFields(printerStatus);
  if (
    missing.includes("printerRegistration") ||
    missing.includes("freshHelperHeartbeat") ||
    missing.includes("helperConnection") ||
    missing.includes("selectedPrinter")
  ) {
    return "missing_printer_session";
  }
  return "printer_not_verified";
};

type PrintJobFailureContext = {
  requestId?: string | null;
  failureStage?: string | null;
  diagnostics?: Record<string, unknown> | null;
};

const withFailureContext = (
  params: {
    code: PrintJobErrorCode;
    message: string;
    details?: PrintJobErrorPayload["details"];
    data?: Record<string, unknown>;
  },
  context?: PrintJobFailureContext
) => {
  const data = {
    ...(params.data || {}),
    ...(context?.diagnostics ? { diagnostics: context.diagnostics } : {}),
  };
  return buildPrintJobErrorPayload({
    ...params,
    requestId: context?.requestId || undefined,
    failureStage: context?.failureStage || undefined,
    data: Object.keys(data).length > 0 ? data : undefined,
  });
};

export const describePrintJobCreateFailure = (error: any, context?: PrintJobFailureContext): {
  status: number;
  payload: PrintJobErrorPayload;
  logReason: string;
} => {
  const msg = String(error?.message || "");
  if (typeof error?.code === "string" && batchStateErrorCodes.has(error.code as PrintJobErrorCode)) {
    const code = error.code as PrintJobErrorCode;
    const stateDetails =
      error.details && typeof error.details === "object" && !Array.isArray(error.details)
        ? (error.details as Record<string, unknown>)
        : {};
    const userSafeMessage = String(stateDetails.userMessage || msg || "Complete the previous batch step first.");
    return {
      status: Number(error?.statusCode || 409),
      logReason: String(code).toLowerCase(),
      payload: {
        ...withFailureContext(
        {
          code,
          message: userSafeMessage,
          data: error.details ? { details: error.details } : undefined,
        },
        context
        ),
        ...(stateDetails.batchId ? { batchId: String(stateDetails.batchId) } : {}),
        ...(stateDetails.currentLifecycleState
          ? { currentLifecycleState: String(stateDetails.currentLifecycleState) }
          : {}),
        ...(stateDetails.requiredPreviousStep !== undefined
          ? { requiredPreviousStep: stateDetails.requiredPreviousStep ? String(stateDetails.requiredPreviousStep) : null }
          : {}),
        ...(stateDetails.userMessage ? { userMessage: String(stateDetails.userMessage) } : {}),
        ...(stateDetails.recoveryAction ? { recoveryAction: String(stateDetails.recoveryAction) } : {}),
        ...(typeof stateDetails.canRetry === "boolean" ? { canRetry: stateDetails.canRetry } : {}),
        ...(typeof stateDetails.canRepairAutomatically === "boolean"
          ? { canRepairAutomatically: stateDetails.canRepairAutomatically }
          : {}),
      },
    };
  }
  if (msg.includes("BATCH_BUSY")) {
    return {
      status: 409,
      logReason: "batch_busy",
      payload: withFailureContext({
        code: "print_job_conflict",
        message: "Another printing action is already using this batch. Please wait a moment and try again.",
      }, context),
    };
  }
  if (msg.startsWith("NOT_ENOUGH_CODES:")) {
    const available = Number(msg.split(":")[1] || "0");
    return {
      status: 400,
      logReason: "not_enough_codes",
      payload: withFailureContext({
        code: "batch_not_printable",
        message: available > 0 ? `Only ${available} label${available === 1 ? "" : "s"} are ready to print.` : "There are no labels ready to print in this batch.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_NOT_TRUSTED")) {
    const printerStatus = error?.printerStatus || null;
    const code = classifyPrinterReadinessError(printerStatus);
    return {
      status: 409,
      logReason: code,
      payload: withFailureContext({
        code,
        message:
          code === "missing_printer_session"
            ? "Refresh the printer connection, then start the print run again."
            : "Finish printer verification or choose a verified printer before starting this print run.",
        details: { missingFields: describeMissingPrinterReadinessFields(printerStatus) },
        data: { printerStatus },
      }, context),
    };
  }
  if (msg.includes("PRINTER_NOT_FOUND")) {
    return {
      status: 404,
      logReason: "printer_not_found",
      payload: withFailureContext({
        code: "printer_not_found",
        message: "Registered printer not found for this manufacturer scope.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_MAPPING_MISSING")) {
    const printerStatus = error?.printerStatus || null;
    return {
      status: 409,
      logReason: "printer_mapping_missing",
      payload: withFailureContext({
        code: "printer_mapping_missing",
        message:
          "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup.",
        details: { missingFields: ["localPrinterMapping"] },
        data: { printerStatus },
      }, context),
    };
  }
  if (msg.includes("PRINTER_INACTIVE")) {
    return {
      status: 409,
      logReason: "printer_inactive",
      payload: withFailureContext({
        code: "invalid_printer",
        message: "Choose the ZDesigner printer again, then start the print run.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_SELECTION_MISMATCH")) {
    const printerStatus = error?.printerStatus || null;
    const message = hasVirtualSelectedPrinter(printerStatus)
      ? "Fax/PDF printers cannot be used for MSCQR labels. Choose the ZDesigner label printer."
      : "Choose the ZDesigner printer under Printer on this computer, then refresh printer setup.";
    return {
      status: 409,
      logReason: "printer_selection_mismatch",
      payload: withFailureContext({
        code: "printer_selection_mismatch",
        message,
        data: { printerStatus },
      }, context),
    };
  }
  if (msg.includes("PRINTER_MODE_UNSUPPORTED")) {
    return {
      status: 400,
      logReason: "printer_mode_unsupported",
      payload: withFailureContext({
        code: "unsupported_printer_route",
        message: "Choose the ZDesigner printer again, then start the print run.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_NETWORK_CONFIG_INVALID")) {
    return {
      status: 409,
      logReason: "printer_network_config_invalid",
      payload: withFailureContext({
        code: "invalid_printer",
        message: "Selected network printer is missing IP address or TCP port.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_NETWORK_LANGUAGE_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_network_language_unsupported",
      payload: withFailureContext({
        code: "unsupported_printer_route",
        message: "This printer profile needs a compatible setup before it can be used.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_NETWORK_UNREACHABLE")) {
    return {
      status: 409,
      logReason: "printer_network_unreachable",
      payload: withFailureContext({
        code: "invalid_printer",
        message: sanitizePrinterActionError(error?.reason, "The saved factory printer could not be reached."),
      }, context),
    };
  }
  if (msg.includes("PRINTER_GATEWAY_CONFIG_INVALID")) {
    return {
      status: 409,
      logReason: "printer_gateway_config_invalid",
      payload: withFailureContext({
        code: "invalid_printer",
        message:
          "Selected gateway-backed IPP printer is missing gateway credentials. Re-save the printer profile and provision the site gateway.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_GATEWAY_OFFLINE")) {
    return {
      status: 409,
      logReason: "printer_gateway_offline",
      payload: withFailureContext({
        code: "missing_printer_session",
        message: sanitizePrinterActionError(
          error?.reason,
          "The site print connector needs attention before this printer can be used."
        ),
      }, context),
    };
  }
  if (msg.includes("PRINTER_TEST_LABEL_REQUIRED")) {
    return {
      status: 428,
      logReason: "printer_test_label_required",
      payload: withFailureContext({
        code: "PRINTER_TEST_LABEL_REQUIRED",
        message: sanitizePrinterActionError(
          error?.reason,
          "Send and confirm a live printer setup test label before starting production printing."
        ),
        data: { recoveryAction: "print_setup_test_label" },
      }, context),
    };
  }
  if (msg.includes("PRINTER_NETWORK_CONFIRMATION_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_network_confirmation_unsupported",
      payload: withFailureContext({
        code: "unsupported_printer_route",
        message:
          "This saved raw printer route cannot prove terminal label completion safely yet. Use the MSCQR connector or switch to a certified Zebra direct profile.",
      }, context),
    };
  }
  if (msg.includes("PRINTER_IPP_FORMAT_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_ipp_format_unsupported",
      payload: withFailureContext({
        code: "unsupported_printer_route",
        message: sanitizePrinterActionError(error?.reason, "This office printer does not support the required MSCQR print format."),
      }, context),
    };
  }
  if (msg.includes("PRINTER_IPP_UNREACHABLE")) {
    return {
      status: 409,
      logReason: "printer_ipp_unreachable",
      payload: withFailureContext({
        code: "invalid_printer",
        message: sanitizePrinterActionError(error?.reason, "The saved office printer could not be reached."),
      }, context),
    };
  }
  const prismaCode = String(error?.code || "").trim();
  const prismaTarget = Array.isArray(error?.meta?.target) ? error.meta.target.join(",") : String(error?.meta?.target || "");
  if (["QR_SIGNING_CONFIGURATION_INVALID", "QR_SIGNING_KEY_TYPE_UNSUPPORTED"].includes(prismaCode)) {
    return {
      status: 500,
      logReason: "print_signing_configuration_invalid",
      payload: withFailureContext({
        code: "print_signing_configuration_invalid",
        message: "Print token signing is not configured correctly. Contact support with the request ID.",
        data: error?.safeCryptoMetadata ? { cryptoMetadata: error.safeCryptoMetadata } : undefined,
      }, context),
    };
  }
  if (prismaCode === "P2002" && hasAny(prismaTarget.toLowerCase(), ["qrcodeid", "printitem"])) {
    return {
      status: 400,
      logReason: "print_item_already_reserved",
      payload: withFailureContext({
        code: "print_item_reservation_failed",
        message:
          "Some labels are still locked by a failed print run. Close and release the failed run, then start printing again.",
      }, context),
    };
  }
  if (["P2003", "P2025"].includes(prismaCode)) {
    return {
      status: 409,
      logReason: prismaCode === "P2003" ? "print_foreign_key_missing" : "print_record_missing",
      payload: withFailureContext({
        code: "print_job_transaction_failed",
        message: "Print job could not be saved. Refresh and try again.",
      }, context),
    };
  }
  if (prismaCode === "P2024") {
    return {
      status: 503,
      logReason: "print_database_timeout",
      payload: withFailureContext({
        code: "print_job_transaction_failed",
        message: "Print job could not be saved. Refresh and try again.",
      }, context),
    };
  }
  if (["P2021", "P2022"].includes(prismaCode)) {
    return {
      status: 503,
      logReason: "print_database_schema_unavailable",
      payload: withFailureContext({
        code: "print_service_unavailable",
        message: "Printing is temporarily unavailable. Please try again.",
      }, context),
    };
  }

  return {
    status: 500,
    logReason: "unclassified_print_job_create_failure",
    payload: withFailureContext({
      code: "internal_print_job_create_failed",
      message: "Print job could not be started.",
    }, context),
  };
};

export const sendPrintJobCreateErrorResponse = (error: any, res: any, context?: PrintJobFailureContext) => {
  const failure = describePrintJobCreateFailure(error, context);
  return res.status(failure.status).json(failure.payload);
};

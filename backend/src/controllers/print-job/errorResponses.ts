import { sanitizePrinterActionError } from "../../utils/printerUserFacingErrors";

type PrintJobErrorCode =
  | "active_print_job_exists"
  | "batch_not_found"
  | "batch_not_printable"
  | "invalid_payload"
  | "invalid_printer"
  | "missing_printer_session"
  | "printer_mapping_missing"
  | "printer_not_verified"
  | "print_job_conflict"
  | "print_service_unavailable"
  | "session_expired";

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
  details?: {
    missingFields?: string[];
  };
  data?: Record<string, unknown>;
};

export const buildPrintJobErrorPayload = (params: {
  code: PrintJobErrorCode;
  message: string;
  details?: PrintJobErrorPayload["details"];
  data?: Record<string, unknown>;
}): PrintJobErrorPayload => ({
  success: false,
  error: params.message,
  message: params.message,
  code: params.code,
  errorCode: params.code,
  ...(params.details ? { details: params.details } : {}),
  ...(params.data ? { data: params.data } : {}),
});

export const describeMissingPrinterReadinessFields = (printerStatus: PrinterStatusLike | null | undefined): string[] => {
  const missing = new Set<string>();
  if (!printerStatus?.registrationId) missing.add("printerRegistration");
  if (!printerStatus || printerStatus.stale) missing.add("freshHelperHeartbeat");
  if (!printerStatus?.connected) missing.add("helperConnection");
  if (!printerStatus?.eligibleForPrinting) missing.add("eligiblePrinter");
  if (!printerStatus?.trusted && !printerStatus?.compatibilityMode) missing.add("securePrinterSession");
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

export const describePrintJobCreateFailure = (error: any): {
  status: number;
  payload: PrintJobErrorPayload;
  logReason: string;
} => {
  const msg = String(error?.message || "");
  if (msg.includes("BATCH_BUSY")) {
    return {
      status: 409,
      logReason: "batch_busy",
      payload: buildPrintJobErrorPayload({
        code: "print_job_conflict",
        message: "Another printing action is already using this batch. Please wait a moment and try again.",
      }),
    };
  }
  if (msg.startsWith("NOT_ENOUGH_CODES:")) {
    const available = Number(msg.split(":")[1] || "0");
    return {
      status: 400,
      logReason: "not_enough_codes",
      payload: buildPrintJobErrorPayload({
        code: "batch_not_printable",
        message: available > 0 ? `Only ${available} label${available === 1 ? "" : "s"} are ready to print.` : "There are no labels ready to print in this batch.",
      }),
    };
  }
  if (msg.includes("PRINTER_NOT_TRUSTED")) {
    const printerStatus = error?.printerStatus || null;
    const code = classifyPrinterReadinessError(printerStatus);
    return {
      status: 409,
      logReason: code,
      payload: buildPrintJobErrorPayload({
        code,
        message:
          code === "missing_printer_session"
            ? "Refresh the printer connection, then start the print run again."
            : "Finish printer verification or choose a verified printer before starting this print run.",
        details: { missingFields: describeMissingPrinterReadinessFields(printerStatus) },
        data: { printerStatus },
      }),
    };
  }
  if (msg.includes("PRINTER_NOT_FOUND")) {
    return {
      status: 404,
      logReason: "printer_not_found",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: "Registered printer not found for this manufacturer scope.",
      }),
    };
  }
  if (msg.includes("PRINTER_MAPPING_MISSING")) {
    const printerStatus = error?.printerStatus || null;
    return {
      status: 409,
      logReason: "printer_mapping_missing",
      payload: buildPrintJobErrorPayload({
        code: "printer_mapping_missing",
        message:
          "The saved printer is not linked to this computer's Zebra printer. Choose the ZDesigner printer again or refresh printer setup.",
        details: { missingFields: ["localPrinterMapping"] },
        data: { printerStatus },
      }),
    };
  }
  if (msg.includes("PRINTER_INACTIVE")) {
    return {
      status: 409,
      logReason: "printer_inactive",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: "Choose the ZDesigner printer again, then start the print run.",
      }),
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
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message,
        data: { printerStatus },
      }),
    };
  }
  if (msg.includes("PRINTER_MODE_UNSUPPORTED")) {
    return {
      status: 400,
      logReason: "printer_mode_unsupported",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: "Choose the ZDesigner printer again, then start the print run.",
      }),
    };
  }
  if (msg.includes("PRINTER_NETWORK_CONFIG_INVALID")) {
    return {
      status: 409,
      logReason: "printer_network_config_invalid",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: "Selected network printer is missing IP address or TCP port.",
      }),
    };
  }
  if (msg.includes("PRINTER_NETWORK_LANGUAGE_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_network_language_unsupported",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: "This printer profile needs a compatible setup before it can be used.",
      }),
    };
  }
  if (msg.includes("PRINTER_NETWORK_UNREACHABLE")) {
    return {
      status: 409,
      logReason: "printer_network_unreachable",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: sanitizePrinterActionError(error?.reason, "The saved factory printer could not be reached."),
      }),
    };
  }
  if (msg.includes("PRINTER_GATEWAY_CONFIG_INVALID")) {
    return {
      status: 409,
      logReason: "printer_gateway_config_invalid",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message:
          "Selected gateway-backed IPP printer is missing gateway credentials. Re-save the printer profile and provision the site gateway.",
      }),
    };
  }
  if (msg.includes("PRINTER_GATEWAY_OFFLINE")) {
    return {
      status: 409,
      logReason: "printer_gateway_offline",
      payload: buildPrintJobErrorPayload({
        code: "missing_printer_session",
        message: sanitizePrinterActionError(
          error?.reason,
          "The site print connector needs attention before this printer can be used."
        ),
      }),
    };
  }
  if (msg.includes("PRINTER_NETWORK_CONFIRMATION_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_network_confirmation_unsupported",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message:
          "This saved raw printer route cannot prove terminal label completion safely yet. Use the MSCQR connector or switch to a certified Zebra direct profile.",
      }),
    };
  }
  if (msg.includes("PRINTER_IPP_FORMAT_UNSUPPORTED")) {
    return {
      status: 409,
      logReason: "printer_ipp_format_unsupported",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: sanitizePrinterActionError(error?.reason, "This office printer does not support the required MSCQR print format."),
      }),
    };
  }
  if (msg.includes("PRINTER_IPP_UNREACHABLE")) {
    return {
      status: 409,
      logReason: "printer_ipp_unreachable",
      payload: buildPrintJobErrorPayload({
        code: "invalid_printer",
        message: sanitizePrinterActionError(error?.reason, "The saved office printer could not be reached."),
      }),
    };
  }
  const prismaCode = String(error?.code || "").trim();
  const prismaTarget = Array.isArray(error?.meta?.target) ? error.meta.target.join(",") : String(error?.meta?.target || "");
  if (prismaCode === "P2002" && hasAny(prismaTarget.toLowerCase(), ["qrcodeid", "printitem"])) {
    return {
      status: 400,
      logReason: "print_item_already_reserved",
      payload: buildPrintJobErrorPayload({
        code: "batch_not_printable",
        message: "There are no labels ready to print in this batch.",
      }),
    };
  }
  if (["P2003", "P2025"].includes(prismaCode)) {
    return {
      status: 400,
      logReason: prismaCode === "P2003" ? "print_foreign_key_missing" : "print_record_missing",
      payload: buildPrintJobErrorPayload({
        code: "invalid_payload",
        message: "The print job request is missing required information.",
      }),
    };
  }
  if (["P2021", "P2022", "P2024"].includes(prismaCode)) {
    return {
      status: 503,
      logReason: prismaCode === "P2024" ? "print_database_timeout" : "print_database_schema_unavailable",
      payload: buildPrintJobErrorPayload({
        code: "print_service_unavailable",
        message: "Printing is temporarily unavailable. Please try again.",
      }),
    };
  }

  return {
    status: 400,
    logReason: "unclassified_print_job_create_failure",
    payload: buildPrintJobErrorPayload({
      code: "invalid_payload",
      message: sanitizePrinterActionError(error?.message, "This print job could not be created."),
    }),
  };
};

export const sendPrintJobCreateErrorResponse = (error: any, res: any) => {
  const failure = describePrintJobCreateFailure(error);
  return res.status(failure.status).json(failure.payload);
};

import { sanitizePrinterActionError } from "../../utils/printerUserFacingErrors";

type PrinterStatusLike = {
  registrationId?: string | null;
  connected?: boolean | null;
  eligibleForPrinting?: boolean | null;
  stale?: boolean | null;
  trusted?: boolean | null;
  compatibilityMode?: boolean | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
};

export type PrintJobErrorPayload = {
  success: false;
  error: string;
  message: string;
  code: string;
  errorCode: string;
  details?: {
    missingFields?: string[];
  };
  data?: Record<string, unknown>;
};

export const buildPrintJobErrorPayload = (params: {
  code: string;
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

export const sendPrintJobCreateErrorResponse = (error: any, res: any) => {
  const msg = String(error?.message || "");
  if (msg.includes("BATCH_BUSY")) {
    return res.status(409).json(buildPrintJobErrorPayload({ code: "BATCH_BUSY", message: "Please retry. Batch busy." }));
  }
  if (msg.startsWith("NOT_ENOUGH_CODES:")) {
    const available = Number(msg.split(":")[1] || "0");
    return res.status(400).json(
      buildPrintJobErrorPayload({
        code: "NOT_ENOUGH_CODES",
        message: `Not enough unprinted codes. Available: ${available}`,
      })
    );
  }
  if (msg.includes("PRINTER_NOT_TRUSTED")) {
    const printerStatus = error?.printerStatus || null;
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NOT_READY",
        message: "Printer needs attention. Check the printer connection or choose another printer.",
        details: { missingFields: describeMissingPrinterReadinessFields(printerStatus) },
        data: { printerStatus },
      })
    );
  }
  if (msg.includes("PRINTER_NOT_FOUND")) {
    return res.status(404).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NOT_FOUND",
        message: "Registered printer not found for this manufacturer scope.",
      })
    );
  }
  if (msg.includes("PRINTER_INACTIVE")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_INACTIVE",
        message: "Selected printer profile is inactive.",
      })
    );
  }
  if (msg.includes("PRINTER_SELECTION_MISMATCH")) {
    const printerStatus = error?.printerStatus || null;
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_SELECTION_MISMATCH",
        message: "Selected local printer does not match the active workstation printer. Switch printer selection and retry.",
        data: { printerStatus },
      })
    );
  }
  if (msg.includes("PRINTER_NETWORK_CONFIG_INVALID")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NETWORK_CONFIG_INVALID",
        message: "Selected network printer is missing IP address or TCP port.",
      })
    );
  }
  if (msg.includes("PRINTER_NETWORK_LANGUAGE_UNSUPPORTED")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NETWORK_LANGUAGE_UNSUPPORTED",
        message:
          "Selected network printer uses a language that is not certified for secure raw-TCP dispatch. Update the printer profile or switch to the MSCQR connector path.",
      })
    );
  }
  if (msg.includes("PRINTER_NETWORK_UNREACHABLE")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NETWORK_UNREACHABLE",
        message: sanitizePrinterActionError(error?.reason, "The saved factory printer could not be reached."),
      })
    );
  }
  if (msg.includes("PRINTER_GATEWAY_CONFIG_INVALID")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_GATEWAY_CONFIG_INVALID",
        message:
          "Selected gateway-backed IPP printer is missing gateway credentials. Re-save the printer profile and provision the site gateway.",
      })
    );
  }
  if (msg.includes("PRINTER_GATEWAY_OFFLINE")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_GATEWAY_OFFLINE",
        message: sanitizePrinterActionError(
          error?.reason,
          "The site print connector needs attention before this printer can be used."
        ),
      })
    );
  }
  if (msg.includes("PRINTER_NETWORK_CONFIRMATION_UNSUPPORTED")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_NETWORK_CONFIRMATION_UNSUPPORTED",
        message:
          "This saved raw printer route cannot prove terminal label completion safely yet. Use the MSCQR connector or switch to a certified Zebra direct profile.",
      })
    );
  }
  if (msg.includes("PRINTER_IPP_FORMAT_UNSUPPORTED")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_IPP_FORMAT_UNSUPPORTED",
        message: sanitizePrinterActionError(error?.reason, "This office printer does not support the required MSCQR print format."),
      })
    );
  }
  if (msg.includes("PRINTER_IPP_UNREACHABLE")) {
    return res.status(409).json(
      buildPrintJobErrorPayload({
        code: "PRINTER_IPP_UNREACHABLE",
        message: sanitizePrinterActionError(error?.reason, "The saved office printer could not be reached."),
      })
    );
  }
  return res.status(400).json(
    buildPrintJobErrorPayload({
      code: "PRINT_JOB_CREATE_FAILED",
      message: sanitizePrinterActionError(error?.message, "This print job could not be created."),
    })
  );
};

const { sanitizePrinterActionError } = require("../dist/utils/printerUserFacingErrors");
const {
  buildPrintJobErrorPayload,
  describePrintJobCreateFailure,
  describeMissingPrinterReadinessFields,
} = require("../dist/controllers/print-job/errorResponses");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const duplicateError =
    "Invalid `prisma.printer.create()` invocation: Unique constraint failed on the fields: (`licenseeId`, `ipAddress`, `port`)";

  assert(
    sanitizePrinterActionError(duplicateError) ===
      "A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.",
    "Duplicate printer endpoint errors should be redacted into a business-safe message"
  );

  assert(
    sanitizePrinterActionError("The browser could not reach localhost:17866") ===
      "The workstation connector is not available on this device right now.",
    "Localhost errors should be redacted"
  );

  const missingFields = describeMissingPrinterReadinessFields({
    connected: false,
    eligibleForPrinting: false,
    stale: true,
  });
  assert(missingFields.includes("printerRegistration"), "Missing registration should be reported as a safe field");
  assert(missingFields.includes("freshHelperHeartbeat"), "Stale helper heartbeat should be reported as a safe field");
  assert(missingFields.includes("helperConnection"), "Missing helper connection should be reported as a safe field");
  assert(missingFields.includes("eligiblePrinter"), "Missing eligible printer should be reported as a safe field");

  const payload = buildPrintJobErrorPayload({
    code: "missing_printer_session",
    message: "Refresh the printer connection, then start the print run again.",
    details: { missingFields },
  });
  assert(payload.success === false, "Print-job error payload should be an explicit failure");
  assert(payload.code === "missing_printer_session", "Print-job error payload should expose a stable code");
  assert(payload.errorCode === "missing_printer_session", "Print-job error payload should expose a stable errorCode");
  assert(payload.message === payload.error, "Print-job error payload should preserve API-client compatibility");
  assert(!JSON.stringify(payload).includes("localhost"), "Print-job error payload should not leak local internals");

  const missingSessionFailure = describePrintJobCreateFailure(
    Object.assign(new Error("PRINTER_NOT_TRUSTED"), {
      printerStatus: {
        connected: false,
        eligibleForPrinting: false,
        stale: true,
      },
    })
  );
  assert(missingSessionFailure.status === 409, "Missing printer sessions should be a conflict");
  assert(
    missingSessionFailure.payload.errorCode === "missing_printer_session",
    "Missing printer sessions should use a structured error code"
  );

  const batchFailure = describePrintJobCreateFailure(new Error("NOT_ENOUGH_CODES:0"));
  assert(batchFailure.status === 400, "Empty batches should be rejected as a bad print request");
  assert(batchFailure.payload.errorCode === "batch_not_printable", "Empty batches should have a printable-state code");

  const unsupportedPrinterFailure = describePrintJobCreateFailure(new Error("PRINTER_MODE_UNSUPPORTED"));
  assert(unsupportedPrinterFailure.status === 400, "Unsupported printer modes should be rejected safely");
  assert(unsupportedPrinterFailure.payload.errorCode === "invalid_printer", "Unsupported printer modes should use invalid_printer");

  console.log("printer user-facing error tests passed");
};

run();

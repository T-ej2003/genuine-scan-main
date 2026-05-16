const { sanitizePrinterActionError } = require("../dist/utils/printerUserFacingErrors");
const {
  buildPrintJobErrorPayload,
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
    code: "PRINTER_NOT_READY",
    message: "Printer needs attention. Check the printer connection or choose another printer.",
    details: { missingFields },
  });
  assert(payload.success === false, "Print-job error payload should be an explicit failure");
  assert(payload.code === "PRINTER_NOT_READY", "Print-job error payload should expose a stable code");
  assert(payload.errorCode === "PRINTER_NOT_READY", "Print-job error payload should expose a stable errorCode");
  assert(payload.message === payload.error, "Print-job error payload should preserve API-client compatibility");
  assert(!JSON.stringify(payload).includes("localhost"), "Print-job error payload should not leak local internals");

  console.log("printer user-facing error tests passed");
};

run();

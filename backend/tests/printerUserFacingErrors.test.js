const { sanitizePrinterActionError } = require("../dist/utils/printerUserFacingErrors");

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

  console.log("printer user-facing error tests passed");
};

run();

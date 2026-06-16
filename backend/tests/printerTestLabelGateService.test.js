const assert = require("node:assert");
const {
  assertPrinterTestLabelConfirmed,
  buildPrinterTestLabelFingerprint,
} = require("../dist/services/printerTestLabelGateService");

const basePrinter = {
  id: "printer-test",
  connectionType: "LOCAL_AGENT",
  deliveryMode: "DIRECT",
  nativePrinterId: "e2e-local-printer",
  ipAddress: null,
  host: null,
  port: null,
  printerUri: null,
  commandLanguage: "AUTO",
};

const run = () => {
  assert.throws(
    () => assertPrinterTestLabelConfirmed({ ...basePrinter, metadata: null }),
    /PRINTER_TEST_LABEL_REQUIRED/,
    "Production printing must require a confirmed setup-test label"
  );

  const metadata = {
    lastTestLabelConfirmedAt: "2026-06-11T00:00:00.000Z",
    lastTestLabelConnectionType: "LOCAL_AGENT",
    lastTestLabelDeviceJobRef: "test-job",
    lastTestLabelFingerprint: buildPrinterTestLabelFingerprint(basePrinter),
  };
  assert.doesNotThrow(
    () => assertPrinterTestLabelConfirmed({ ...basePrinter, metadata }),
    "Matching setup-test proof should allow production readiness"
  );

  assert.throws(
    () => assertPrinterTestLabelConfirmed({ ...basePrinter, nativePrinterId: "different-printer", metadata }),
    /PRINTER_TEST_LABEL_REQUIRED/,
    "Changing the printer route after setup-test proof must require a new test label"
  );

  console.log("printer test label gate service tests passed");
};

run();

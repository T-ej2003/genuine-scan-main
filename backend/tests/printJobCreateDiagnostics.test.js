const assert = require("node:assert/strict");
const repository = require("../dist/rls-waves/session-c/c02/printingLifecycleRepository");
const { buildPrintJobCreateDiagnostics } = require("../dist/services/printJobCreateDiagnosticsService");

const original = repository.readPrintingProjection;
repository.readPrintingProjection = async ({ operation, options }) => {
  if (operation === "PRINTABLE_ITEMS") {
    assert.equal(options.limit, 1);
    return {
      batch: {
        id: "batch-1", manufacturerId: "maker-1", licenseeId: "tenant-1",
        totalCodes: 20, printedAt: "2026-11-18T20:09:30.390Z", suspendedAt: null,
      },
      printableItems: [{ id: "qr-2" }],
    };
  }
  return null;
};

buildPrintJobCreateDiagnostics(
  { user: { userId: "maker-1" }, databaseSessionCapability: "test-capability" },
  "request-1", { batchId: "batch-1", quantity: 1 }
).then(({ batch }) => {
  assert.equal(batch.printedAt, "2026-11-18T20:09:30.390Z");
  assert.equal(batch.printableCount, 1);
  assert.equal(batch.printableCountLimit, 1);
  assert.equal(batch.remainingCodes, null, "a limited selection is not the total remaining inventory");
  assert.equal(batch.blockedByPrintItemEvidenceCount, null, "unmeasured evidence must stay unknown");
  console.log("print-job creation diagnostics tests passed");
}).catch((error) => {
  console.error(error);
  process.exitCode = 1;
}).finally(() => { repository.readPrintingProjection = original; });

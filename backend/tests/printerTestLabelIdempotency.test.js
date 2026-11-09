const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

let statusMode = "denied";
let aborts = 0;
let completions = 0;
let dispatches = 0;
const printer = {
  id: "50000000-0000-4000-8000-000000000001",
  connectionType: "LOCAL_AGENT",
  deliveryMode: "DIRECT",
};

mockModule("rls-waves/session-c/c02/printingLifecycleRepository.js", {
  beginPrintingIdempotency: async () => ({ replayed: false }),
  abortPrintingIdempotency: async () => { aborts += 1; },
  completePrintingIdempotency: async () => { completions += 1; },
  readPrintingProjection: async ({ operation }) => {
    if (operation === "PRINTER" && statusMode === "missing") return null;
    if (operation === "PRINTER") return printer;
    if (operation === "PRINTER_STATUS" && statusMode === "denied") throw new Error("PRINTING_BOUNDARY_DENIED");
    return { trusted: true, connected: true, eligibleForPrinting: true };
  },
  administerPrintingPrinter: async ({ operation }) => {
    if (operation === "AUDIT_TEST_LABEL_ATTENTION" && statusMode === "dispatch-failed") {
      throw new Error("Audit unavailable after dispatch");
    }
    return printer;
  },
});
mockModule("services/printerTestLabelService.js", {
  printTestLabelForRegisteredPrinter: async () => {
    dispatches += 1;
    if (statusMode === "queued") return { outcome: "queued", connectionType: "LOCAL_AGENT" };
    throw new Error("Dispatch outcome unknown");
  },
});

const { testPrinterLabel } = require("../dist/controllers/printerController");
const request = {
  params: { id: printer.id },
  headers: { "x-idempotency-key": "test-label-key" },
  body: {},
  query: {},
  user: {
    userId: "50000000-0000-4000-8000-000000000002",
    role: "MANUFACTURER_ADMIN",
    licenseeId: "50000000-0000-4000-8000-000000000003",
  },
  databaseSessionCapability: "test-capability",
  requestId: "50000000-0000-4000-8000-000000000004",
};
const response = () => ({
  statusCode: 200,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

(async () => {
  const originalConsoleError = console.error;
  console.error = () => undefined;
  try {
    const denied = response();
    await testPrinterLabel(request, denied);
    assert.equal(denied.statusCode, 400);
    assert.equal(dispatches, 0, "authorization failure must not dispatch a label");
    assert.equal(aborts, 1, "a pre-dispatch denial must release its pending idempotency key");

    statusMode = "dispatch-failed";
    const uncertain = response();
    await testPrinterLabel(request, uncertain);
    assert.equal(dispatches, 1);
    assert.equal(aborts, 1, "unknown post-dispatch outcome must keep the key fenced");

    statusMode = "missing";
    const missing = response();
    await testPrinterLabel(request, missing);
    assert.equal(missing.statusCode, 404);
    assert.equal(aborts, 2, "missing printer must not leave a pending key");
    assert.equal(dispatches, 1);

    statusMode = "queued";
    const queued = response();
    await testPrinterLabel(request, queued);
    assert.equal(queued.statusCode, 200);
    assert.equal(queued.body.data.outcome, "queued");
    assert.equal(completions, 1, "accepted work must be recorded as complete");
    assert.equal(aborts, 2, "accepted work must never release its idempotency key");
  } finally {
    console.error = originalConsoleError;
  }
  console.log("printer test-label idempotency boundary tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

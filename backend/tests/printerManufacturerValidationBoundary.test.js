const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

let updates = 0;
let dispatches = 0;
let denyStatus = false;
const printer = {
  id: "50000000-0000-4000-8000-000000000001",
  connectionType: "LOCAL_AGENT",
  deliveryMode: "DIRECT",
};

mockModule("rls-waves/session-c/c02/printingLifecycleRepository.js", {
  beginPrintingIdempotency: async () => ({ replayed: false }),
  completePrintingIdempotency: async () => ({}),
  readPrintingProjection: async ({ operation }) => {
    if (operation === "PRINTER") return printer;
    if (denyStatus) throw new Error("PRINTING_BOUNDARY_DENIED");
    return { trusted: true, connected: true, eligibleForPrinting: true };
  },
  administerPrintingPrinter: async ({ operation }) => {
    if (operation === "UPDATE") {
      updates += 1;
      if (activeRole === "MANUFACTURER_ADMIN") throw new Error("PRINTING_BOUNDARY_DENIED");
    }
    return printer;
  },
});
mockModule("services/printerTestLabelService.js", {
  printTestLabelForRegisteredPrinter: async () => {
    dispatches += 1;
    return { outcome: "queued", connectionType: "LOCAL_AGENT" };
  },
});

const { testPrinterLabel } = require("../dist/controllers/printerController");
let activeRole = "MANUFACTURER_ADMIN";
const request = {
  params: { id: printer.id },
  headers: { "x-idempotency-key": "validation-test-key" },
  body: {},
  query: {},
  user: {
    userId: "50000000-0000-4000-8000-000000000002",
    role: activeRole,
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
    const manufacturer = response();
    await testPrinterLabel(request, manufacturer);
    assert.equal(manufacturer.statusCode, 200, "manufacturer validation must not require printer UPDATE authority");
    assert.equal(manufacturer.body.data.outcome, "queued");
    assert.equal(updates, 0);
    assert.equal(dispatches, 1);

    activeRole = "LICENSEE_ADMIN";
    request.user.role = activeRole;
    const licensee = response();
    await testPrinterLabel(request, licensee);
    assert.equal(licensee.statusCode, 200);
    assert.equal(updates, 1, "licensee validation retains the existing registry update");

    activeRole = "MANUFACTURER_ADMIN";
    request.user.role = activeRole;
    denyStatus = true;
    const denied = response();
    await testPrinterLabel(request, denied);
    assert.equal(denied.statusCode, 400);
    assert.equal(dispatches, 2, "a rejected readiness read must not dispatch");
  } finally {
    console.error = originalConsoleError;
  }
  console.log("manufacturer printer validation boundary tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

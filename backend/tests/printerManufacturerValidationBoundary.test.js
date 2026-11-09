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
let outcome = "queued";
let failConfirmedAudit = false;
const audits = [];
const printer = {
  id: "50000000-0000-4000-8000-000000000001",
  connectionType: "LOCAL_AGENT",
  deliveryMode: "DIRECT",
};

mockModule("services/networkPrinterSocketService.js", {
  testNetworkPrinterConnectivity: async () => ({ latencyMs: 3 }),
});
mockModule("printing/ippClient.js", {
  inspectIppPrinter: async () => ({ pdfSupported: true, printerUri: "ipp://isolated.invalid/ipp/print" }),
});
mockModule("services/printPayloadService.js", {
  supportsNetworkDirectPayload: () => true,
});

mockModule("rls-waves/session-c/c02/printingLifecycleRepository.js", {
  beginPrintingIdempotency: async () => ({ replayed: false }),
  abortPrintingIdempotency: async () => ({}),
  completePrintingIdempotency: async () => ({}),
  readPrintingProjection: async ({ operation }) => {
    if (operation === "PRINTER") return printer;
    if (denyStatus) throw new Error("PRINTING_BOUNDARY_DENIED");
    return { trusted: true, connected: true, eligibleForPrinting: true };
  },
  administerPrintingPrinter: async ({ operation }) => {
    if (operation.startsWith("AUDIT_")) {
      audits.push(operation);
      if (operation === "AUDIT_TEST_LABEL_CONFIRMED" && failConfirmedAudit) {
        throw new Error("Mandatory audit unavailable");
      }
    }
    if (operation === "UPDATE") {
      updates += 1;
      if (activeRole === "MANUFACTURER_ADMIN") throw new Error("PRINTING_BOUNDARY_DENIED");
    }
    return printer;
  },
});
mockModule("services/printerTestLabelService.js", {
  printTestLabelForRegisteredPrinter: async ({ onDispatchStateChange }) => {
    dispatches += 1;
    onDispatchStateChange?.("dispatch_started");
    if (outcome === "throw") throw new Error("Transport outcome unknown");
    if (outcome === "confirmed") onDispatchStateChange?.("confirmed");
    return { outcome, connectionType: printer.connectionType, confirmedAt: outcome === "confirmed" ? new Date().toISOString() : null };
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

    for (const route of [
      { connectionType: "NETWORK_DIRECT", deliveryMode: "DIRECT" },
      { connectionType: "NETWORK_IPP", deliveryMode: "DIRECT" },
      { connectionType: "NETWORK_DIRECT", deliveryMode: "SITE_GATEWAY" },
    ]) {
      Object.assign(printer, route, { gatewayStatus: "ONLINE", gatewayLastSeenAt: new Date().toISOString() });
      outcome = "confirmed";
      const confirmed = response();
      await testPrinterLabel(request, confirmed);
      assert.equal(confirmed.statusCode, 200, `${route.connectionType}/${route.deliveryMode} must remain confirmed`);
      assert.equal(confirmed.body.data.outcome, "confirmed");
      assert.equal(updates, 0, "manufacturer confirmation cannot require registry UPDATE");
      assert.equal(audits.at(-1), "AUDIT_TEST_LABEL_CONFIRMED", "confirmed print requires audit");
    }

    outcome = "throw";
    const uncertain = response();
    await testPrinterLabel(request, uncertain);
    assert.equal(uncertain.body.data.outcome, "needs_attention");
    assert.equal(audits.at(-1), "AUDIT_TEST_LABEL_ATTENTION");

    outcome = "confirmed";
    failConfirmedAudit = true;
    const missingAudit = response();
    await testPrinterLabel(request, missingAudit);
    assert.equal(missingAudit.body.data.outcome, "needs_attention", "mandatory audit failure must remain visible");
    failConfirmedAudit = false;

    activeRole = "LICENSEE_ADMIN";
    request.user.role = activeRole;
    printer.connectionType = "LOCAL_AGENT";
    printer.deliveryMode = "DIRECT";
    outcome = "queued";
    const licensee = response();
    await testPrinterLabel(request, licensee);
    assert.equal(licensee.statusCode, 200);
    assert.equal(updates, 1, "licensee validation retains the existing registry update");

    activeRole = "MANUFACTURER_ADMIN";
    request.user.role = activeRole;
    denyStatus = true;
    const dispatchesBeforeDenial = dispatches;
    const denied = response();
    await testPrinterLabel(request, denied);
    assert.equal(denied.statusCode, 400);
    assert.equal(dispatches, dispatchesBeforeDenial, "a rejected readiness read must not dispatch");
  } finally {
    console.error = originalConsoleError;
  }
  console.log("manufacturer printer validation boundary tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

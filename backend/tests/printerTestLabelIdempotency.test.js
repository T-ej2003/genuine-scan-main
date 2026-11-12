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
const reservations = new Map();
let dispatchStarted;
let releaseDispatch;
const printer = {
  id: "50000000-0000-4000-8000-000000000001",
  connectionType: "LOCAL_AGENT",
  deliveryMode: "DIRECT",
};

mockModule("rls-waves/session-c/c02/printingLifecycleRepository.js", {
  beginPrintingIdempotency: async ({ key }) => {
    const prior = reservations.get(key);
    if (prior?.statusCode) return { replayed: true, statusCode: prior.statusCode,
      responsePayload: prior.responsePayload };
    if (prior) throw new Error("IDEMPOTENCY_KEY_IN_PROGRESS");
    reservations.set(key, {});
    return { replayed: false };
  },
  abortPrintingIdempotency: async ({ key }) => { reservations.delete(key); aborts += 1; },
  completePrintingIdempotency: async ({ key, statusCode, responsePayload }) => {
    reservations.set(key, { statusCode, responsePayload });
    completions += 1;
  },
  readPrintingProjection: async ({ operation }) => {
    if (operation === "PRINTER" && statusMode === "missing") return null;
    if (operation === "PRINTER") return printer;
    if (operation === "PRINTER_STATUS" && statusMode === "denied") throw new Error("PRINTING_BOUNDARY_DENIED");
    return { trusted: true, connected: true, eligibleForPrinting: true, printerId: printer.id };
  },
  administerPrintingPrinter: async ({ operation }) => {
    if (operation === "AUDIT_TEST_LABEL_ATTENTION" && statusMode === "dispatch-failed") {
      throw new Error("Audit unavailable after dispatch");
    }
    return printer;
  },
});
mockModule("services/printerTestLabelService.js", {
  printTestLabelForRegisteredPrinter: async ({ onDispatchStateChange }) => {
    dispatches += 1;
    if (["lease-failed", "render-failed", "baseline-failed"].includes(statusMode)) {
      throw new Error(`${statusMode} before dispatch`);
    }
    if (statusMode === "queue-rejected") {
      onDispatchStateChange("queue_uncertain");
      onDispatchStateChange("not_dispatched");
      throw new Error("SQL rejected queue before commit");
    }
    if (statusMode === "queue-response-lost") {
      onDispatchStateChange("queue_uncertain");
      throw new Error("Durable queue response lost");
    }
    onDispatchStateChange("dispatch_started");
    if (statusMode === "concurrent") {
      dispatchStarted();
      await new Promise((resolve) => { releaseDispatch = resolve; });
      return { outcome: "queued", connectionType: "LOCAL_AGENT" };
    }
    if (statusMode === "queued") return { outcome: "queued", connectionType: "LOCAL_AGENT" };
    if (statusMode === "confirmed" || statusMode === "reconcile-failed") {
      onDispatchStateChange("confirmed");
      if (statusMode === "reconcile-failed") throw new Error("Mandatory reconciliation unavailable");
      return { outcome: "confirmed", connectionType: "NETWORK_DIRECT", confirmedAt: new Date().toISOString() };
    }
    if (statusMode === "ack-lost") throw new Error("Connector acknowledgement lost");
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

    statusMode = "queued";
    const retried = response();
    await testPrinterLabel(request, retried);
    assert.equal(retried.body.data.outcome, "queued", "the same key may retry after proven non-dispatch");
    assert.equal(dispatches, 1);
    const completedReplay = response();
    await testPrinterLabel(request, completedReplay);
    assert.equal(completedReplay.body.data.outcome, "queued");
    assert.equal(dispatches, 1, "completed work must never dispatch twice");

    for (const mode of ["lease-failed", "render-failed", "baseline-failed"]) {
      statusMode = mode;
      request.headers["x-idempotency-key"] = mode;
      const before = aborts;
      const failed = response();
      await testPrinterLabel(request, failed);
      assert.equal(failed.body.data.outcome, "needs_attention");
      assert.equal(aborts, before + 1, `${mode} must release the reservation`);
      statusMode = "queued";
      const retriedAfterFailure = response();
      await testPrinterLabel(request, retriedAfterFailure);
      assert.equal(retriedAfterFailure.body.data.outcome, "queued", `${mode} must permit safe retry`);
    }

    statusMode = "dispatch-failed";
    request.headers["x-idempotency-key"] = "ambiguous-key";
    const uncertain = response();
    await testPrinterLabel(request, uncertain);
    assert.equal(aborts, 4, "unknown post-dispatch outcome must keep the key fenced");
    const pendingReplay = response();
    await testPrinterLabel(request, pendingReplay);
    assert.equal(pendingReplay.statusCode, 202);
    assert.equal(pendingReplay.statusCode, 202, "ambiguous work must not dispatch twice");

    for (const mode of ["queue-response-lost", "ack-lost", "reconcile-failed"]) {
      statusMode = mode;
      request.headers["x-idempotency-key"] = mode;
      const before = aborts;
      const uncertainResult = response();
      await testPrinterLabel(request, uncertainResult);
      assert.equal(uncertainResult.body.data.outcome, "needs_attention");
      if (mode === "reconcile-failed") {
        assert.match(uncertainResult.body.data.message, /printer confirmed.*recording the result needs attention/i);
      }
      assert.equal(aborts, before, `${mode} must keep the reservation fenced`);
      const replay = response();
      await testPrinterLabel(request, replay);
      assert.equal(replay.body.data.outcome, "needs_attention");
    }

    statusMode = "missing";
    request.headers["x-idempotency-key"] = "missing-key";
    const missing = response();
    await testPrinterLabel(request, missing);
    assert.equal(missing.statusCode, 404);
    assert.equal(aborts, 5, "missing printer must not leave a pending key");

    statusMode = "queued";
    request.headers["x-idempotency-key"] = "queued-key";
    const queued = response();
    await testPrinterLabel(request, queued);
    assert.equal(queued.statusCode, 200);
    assert.equal(queued.body.data.outcome, "queued");
    assert.equal(aborts, 5, "accepted work must never release its idempotency key");

    statusMode = "concurrent";
    request.headers["x-idempotency-key"] = "concurrent-key";
    const started = new Promise((resolve) => { dispatchStarted = resolve; });
    const first = response();
    const firstCall = testPrinterLabel(request, first);
    await started;
    const second = response();
    await testPrinterLabel(request, second);
    assert.equal(second.statusCode, 202);
    assert.equal(second.statusCode, 202, "concurrent duplicate submission must not dispatch again");
    releaseDispatch();
    await firstCall;
    assert.equal(first.body.data.outcome, "queued");
    statusMode = "confirmed";
    request.headers["x-idempotency-key"] = "http-failed-after-confirmation";
    const httpFailed = response();
    const originalJson = httpFailed.json;
    let firstWrite = true;
    httpFailed.json = function (body) {
      if (firstWrite) { firstWrite = false; throw new Error("HTTP response unavailable"); }
      return originalJson.call(this, body);
    };
    await testPrinterLabel(request, httpFailed);
    assert.equal(aborts, 5, "physical confirmation and response failure must keep the key fenced");
    const confirmedReplay = response();
    await testPrinterLabel(request, confirmedReplay);
    assert.equal(confirmedReplay.body.data.outcome, "confirmed", "replay retains the recorded physical outcome");

    statusMode = "queue-rejected";
    request.headers["x-idempotency-key"] = "queue-rejected-key";
    const beforeRejectedQueue = aborts;
    await testPrinterLabel(request, response());
    assert.equal(aborts, beforeRejectedQueue + 1, "a confirmed SQL rejection must release the reservation");
    statusMode = "queued";
    const retriedRejectedQueue = response();
    await testPrinterLabel(request, retriedRejectedQueue);
    assert.equal(retriedRejectedQueue.body.data.outcome, "queued");
  } finally {
    console.error = originalConsoleError;
  }
  console.log("printer test-label idempotency boundary tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

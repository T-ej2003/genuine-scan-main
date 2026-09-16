const assert = require("node:assert/strict");
const { test } = require("node:test");
const path = require("node:path");
const { generateKeyPairSync } = require("node:crypto");
const dist = path.resolve(__dirname, "../dist");
const mock = (name, exports) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};
const pair = generateKeyPairSync("ed25519");
const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" }).toString().trim();
const privateKeyPem = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const order = [];
const status = { connected: false, trusted: true, eligibleForPrinting: false };
let storageFails = false;
mock("services/manufacturerScopeService", {});
mock("services/printerConnectionService", { emitConnectionEvent: (event) => { order.push("event"); assert.equal(event.userId, "maker-fixture"); assert.deepEqual(event.status, status); } });
mock("services/printerRegistryService", {});
mock("services/auditService", {});
mock("services/notificationService", {});
mock("services/versionedCacheService", { bumpCacheNamespaceVersion: async () => { order.push("invalidate"); } });
mock("utils/secretConfig", { getPrinterSseSignSecret: () => "unused-test-only" });
mock("rls-waves/session-c/c02/printingLifecycleRepository", {
  registerPrintingConnector: async ({ operation, payload }) => {
    if (operation === "LOOKUP") return { publicKeyPem };
    assert.equal(payload.signatureValid, true);
    if (storageFails) throw new Error("fixture commit rejected");
    order.push("commit");
    return {};
  },
  readPrintingProjection: async ({ operation, subjectId }) => {
    assert.equal(operation, "PRINTER_STATUS");
    assert.equal(subjectId, "maker-fixture");
    order.push("readback"); return status;
  },
});
const signing = require(path.join(dist, "services/printerAgentSigningService"));
const { reportPrinterHeartbeat } = require(path.join(dist, "controllers/printerAgentController"));
test("heartbeat publishes only committed canonical status, never supplied connectivity", async () => {
  const body = { connected: true, agentId: "agent-fixture", deviceFingerprint: "device-fixture",
    printerId: "printer-fixture", heartbeatNonce: "nonce-fixture", heartbeatIssuedAt: new Date().toISOString() };
  body.heartbeatSignature = signing.signPrinterAgentPayload(privateKeyPem, signing.buildPrinterAgentHeartbeatPayload({ ...body, userId: "maker-fixture" }));
  const req = { user: { userId: "maker-fixture", role: "MANUFACTURER_ADMIN" }, body,
    databaseSessionCapability: "fixture-capability", requestId: "fixture-request", get: () => "" };
  const response = () => ({ statusCode: 200, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } });
  const res = response();
  await reportPrinterHeartbeat(req, res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(order, ["commit", "readback", "event", "invalidate"]);
  assert.deepEqual(res.body.data, status);
  order.length = 0; storageFails = true;
  const failed = response();
  await reportPrinterHeartbeat(req, failed);
  assert.equal(failed.statusCode, 500);
  assert.deepEqual(order, []);
});

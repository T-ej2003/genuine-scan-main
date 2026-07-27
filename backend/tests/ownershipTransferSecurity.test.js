const assert = require("assert");
const path = require("path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

const calls = [];
mockModule("rls-waves/session-b/b01/runtimeClients.js", { getB01PreAuthPrisma: () => ({}) });
mockModule("rls-waves/session-b/b02/publicBoundaryRepository.js", {
  acceptCustomerOwnershipTransfer: async (_db, input) => {
    calls.push(input);
    throw new Error("PUBLIC_VERIFICATION_CUSTOMER_DENIED");
  },
});
mockModule("services/auth/authEmailService.js", { sendAuthEmail: async () => null });

const { acceptOwnershipTransfer } = require("../dist/controllers/verify/acceptOwnershipTransferHandler");

const response = () => ({
  statusCode: 200,
  body: null,
  status(code) { this.statusCode = code; return this; },
  json(payload) { this.body = payload; return this; },
});

(async () => {
  const req = {
    body: { token: "transfer-token-1" },
    ip: "203.0.113.15",
    requestId: "request-1",
    customerDatabaseCapability: "customer-capability",
    get: () => "ownership-transfer-security-test-agent",
  };
  const res = response();

  await acceptOwnershipTransfer(req, res);

  assert.equal(res.statusCode, 403);
  assert.match(String(res.body?.error || ""), /invalid, expired, or bound to another customer/i);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].customerCapability, "customer-capability");
  assert.equal(calls[0].requestId, "request-1");
  assert.ok(!("databaseBoundary" in calls[0]), "retired generic boundary must not return");

  console.log("ownership transfer capability-denial test passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

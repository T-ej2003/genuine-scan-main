const assert = require("node:assert/strict");
const path = require("node:path");
const { test } = require("node:test");

const dist = path.resolve(__dirname, "../dist");
const database = require.resolve(path.join(dist, "config/database"));
let projection;
let committed = false;
const client = { $queryRaw: async () => [{ result: structuredClone(projection) }] };
require.cache[database] = { id: database, filename: database, loaded: true, exports: {
  __esModule: true,
  default: { $transaction: async (callback) => {
    committed = false;
    const result = await callback(client);
    committed = true;
    return result;
  } },
} };
const { recordConnectorEvent } = require(path.join(dist, "rls-waves/session-c/c02/printingLifecycleRepository"));
const input = {
  registrationId: "registration", agentId: "agent", deviceFingerprint: "device",
  nonce: "nonce", issuedAt: new Date(), requestId: "request", operation: "CLAIM",
  jobId: "job", printerId: "printer",
};

test("claim timestamp projection is hydrated as UTC before commit", async () => {
  projection = { available: true, qrCode: {
    tokenIssuedAt: "2026-06-01T10:00:00.999", tokenExpiresAt: "2026-06-02T10:00:00.999",
  } };
  const result = await recordConnectorEvent(input);
  assert.equal(result.qrCode.tokenIssuedAt.toISOString(), "2026-06-01T10:00:00.999Z");
  assert.equal(result.qrCode.tokenExpiresAt.toISOString(), "2026-06-02T10:00:00.999Z");
  assert.equal(committed, true);
});

test("invalid token dates fail within the claim transaction", async () => {
  for (const value of [null, 0, "not-a-date", "2026-02-31T10:00:00", "2026-06-03T10:00:00Z"]) {
    projection = { available: true, qrCode: {
      tokenIssuedAt: value, tokenExpiresAt: "2026-06-02T10:00:00Z",
    } };
    await assert.rejects(recordConnectorEvent(input), /PRINTING_BOUNDARY_INVALID_TOKEN_TIMESTAMP/);
    assert.equal(committed, false);
  }
});

test("empty claims do not invent token metadata", async () => {
  projection = { available: false };
  assert.deepEqual(await recordConnectorEvent(input), projection);
});

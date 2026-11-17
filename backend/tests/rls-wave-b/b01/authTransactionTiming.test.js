const assert = require("node:assert/strict");
const path = require("node:path");

delete process.env.LOG_FORMAT;
delete process.env.LOG_JSON;
const distRoot = path.resolve(__dirname, "../../../dist");
const runtimePath = require.resolve(path.join(distRoot, "rls-waves/session-b/b01/runtimeClients.js"));
require.cache[runtimePath] = {
  id: runtimePath, filename: runtimePath, loaded: true,
  exports: { getB01AuthenticatedPrisma: () => ({ $transaction: () => assert.fail("unexpected default runner") }) },
};
const { withDatabaseAuthenticatedSession } = require("../../../dist/rls-waves/session-b/b01/canonicalAuthContext");

const claims = { userId: "synthetic-user", sessionId: "synthetic-session" };
const requestId = "5fc5219a-78e6-4710-8e65-87b9ea816d77";
const capability = "A".repeat(43);
const p2028 = () => Object.assign(new Error("Synthetic Prisma transaction failure"), { code: "P2028" });

const run = async () => {
  const logged = [];
  const originalInfo = console.info;
  console.info = (message) => logged.push(JSON.parse(message));
  try {
    const input = { capability, requestId, purpose: "auth-session-hydration" };
    const callback = async () => assert.fail("protected callback must not run");
    const acquisitionFailure = p2028();
    await assert.rejects(
      withDatabaseAuthenticatedSession(claims, input, callback, {
        $transaction: async () => { throw acquisitionFailure; },
      }),
      (error) => error === acquisitionFailure
    );
    const executionFailure = p2028();
    await assert.rejects(
      withDatabaseAuthenticatedSession(claims, input, callback, {
        $transaction: async (transaction) => transaction({ $queryRaw: async () => { throw executionFailure; } }),
      }),
      (error) => error === executionFailure
    );
  } finally {
    console.info = originalInfo;
  }

  assert.equal(logged.length, 2);
  assert.deepEqual(logged.map((entry) => entry.p2028Phase), ["acquisition", "execution"]);
  for (const entry of logged) {
    assert.equal(entry.event, "auth_transaction_timing");
    assert.equal(entry.requestId, requestId);
    assert.equal(entry.errorCode, "P2028");
    assert.equal(entry.outcome, "error");
    assert.equal(typeof entry.acquisitionMs, "number");
    assert(!JSON.stringify(entry).includes(capability), "capability must not be logged");
    assert(!JSON.stringify(entry).includes("synthetic-user"), "actor identity must not be logged");
  }
  assert.equal(logged[0].transactionExecutionMs, null);
  assert.equal(typeof logged[1].transactionExecutionMs, "number");
  assert.equal(typeof logged[1].capabilityMs, "number");
  console.log("auth transaction timing diagnostics tests passed");
};

run().catch((error) => { console.error(error); process.exitCode = 1; });

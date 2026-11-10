const assert = require("node:assert/strict");

const { timeReliabilityStage } = require("../dist/observability/reliabilityStageTiming");

const requestId = "11111111-1111-4111-8111-111111111111";
const messages = [];
const originalInfo = console.info;
console.info = (message) => messages.push(message);

(async () => {
  assert.equal(await timeReliabilityStage(requestId, "GET /api/qr/batches", "scope", async () => {
    await new Promise((resolve) => setTimeout(resolve, 260));
    return 7;
  }), 7);
  assert.equal(messages.length, 1);
  const first = JSON.parse(messages[0]);
  assert.ok(first.durationMs >= 0);
  delete first.durationMs;
  assert.deepEqual(first, {
    event: "production_reliability_stage",
    requestId,
    route: "GET /api/qr/batches",
    stage: "scope",
    outcome: "ok",
  });

  await assert.rejects(
    timeReliabilityStage(requestId, "GET /api/dashboard/stats", "scope", async () => {
      throw new Error("AUTH_SESSION_CAPABILITY_DENIED secret-value");
    }),
    /AUTH_SESSION_CAPABILITY_DENIED secret-value/
  );
  assert.equal(JSON.parse(messages[1]).outcome, "error");
  assert.doesNotMatch(messages[1], /secret-value|AUTH_SESSION_CAPABILITY_DENIED/);

  await assert.rejects(
    timeReliabilityStage("invalid\nrequest", "GET /api/qr/batches", "scope", async () => { throw new Error("denied"); }),
    /denied/
  );
  assert.equal(messages.length, 2, "unvalidated request IDs must not enter logs");

  console.info = () => { throw new Error("logging failed"); };
  assert.equal(await timeReliabilityStage(requestId, "GET /api/qr/batches", "scope", async () => {
    await new Promise((resolve) => setTimeout(resolve, 260));
    return 9;
  }), 9);
  await assert.rejects(
    timeReliabilityStage(requestId, "GET /api/qr/batches", "scope", async () => { throw new Error("database failure"); }),
    /database failure/
  );
})().finally(() => { console.info = originalInfo; }).catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

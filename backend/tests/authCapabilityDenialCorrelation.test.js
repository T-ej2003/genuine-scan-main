const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { requireAuthenticatedSessionCapability } = require("../dist/services/auth/authenticatedSessionCapabilityService");
const { logger } = require("../dist/utils/logger");

const requestId = "aaaa5fab-7f42-474f-8014-e735a1fa8803";
const capability = "A".repeat(43);
const input = { capability, purpose: "auth-session-hydration", requestId };
const originalError = logger.error;
const events = [];
logger.error = (message) => events.push(message);

const checkEvent = (index, expectedRequestId = requestId) => {
  const event = JSON.parse(events[index]);
  assert.deepEqual(Object.keys(event), ["event", "timestamp", "requestId"]);
  assert.equal(event.event, "auth_session_capability_denied");
  assert.match(event.timestamp, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(event.requestId, expectedRequestId);
};

(async () => {
  try {
    const sensitive = "secret-password bearer-token user-id tenant-id";
    const denial = new Error(`Raw query failed: AUTH_SESSION_CAPABILITY_DENIED ${sensitive}`);
    await assert.rejects(
      requireAuthenticatedSessionCapability({ $queryRaw: async () => { throw denial; } }, input),
      (error) => error === denial,
    );
    assert.equal(events.length, 1);
    checkEvent(0);
    assert.doesNotMatch(events[0], /A{43}|secret-password|bearer-token|user-id|tenant-id|Raw query failed|auth-session-hydration/);

    for (const rows of [[], [{}], [{ sessionId: "", userId: "someone" }]]) {
      const count = events.length;
      await assert.rejects(
        requireAuthenticatedSessionCapability({ $queryRaw: async () => rows }, input),
        (error) => error.message === "AUTH_SESSION_CAPABILITY_DENIED",
      );
      assert.equal(events.length, count + 1, "one event for each invalid result");
      checkEvent(count);
    }

    const injected = `${requestId}\n{"token":"secret-password"}`;
    const count = events.length;
    await assert.rejects(
      requireAuthenticatedSessionCapability({ $queryRaw: async () => [] }, { ...input, requestId: injected }),
      /AUTH_SESSION_CAPABILITY_DENIED/,
    );
    assert.equal(events.length, count + 1);
    checkEvent(count, null);
    assert.doesNotMatch(events[count], /secret-password|token|\\n/);

    const unrelated = new Error(`connection unavailable ${sensitive}`);
    await assert.rejects(
      requireAuthenticatedSessionCapability({ $queryRaw: async () => { throw unrelated; } }, input),
      (error) => error === unrelated,
    );
    assert.equal(events.length, count + 1, "unrelated failures emit nothing");

    const validRow = { sessionId: "session", userId: "user", role: "MANUFACTURER" };
    assert.equal(await requireAuthenticatedSessionCapability({ $queryRaw: async () => [validRow] }, input), validRow);
    assert.equal(events.length, count + 1, "success emits nothing");

    logger.error = () => { throw new Error("logging unavailable"); };
    await assert.rejects(
      requireAuthenticatedSessionCapability({ $queryRaw: async () => { throw denial; } }, input),
      (error) => error === denial,
    );
    await assert.rejects(
      requireAuthenticatedSessionCapability({ $queryRaw: async () => [] }, input),
      /AUTH_SESSION_CAPABILITY_DENIED/,
    );
  } finally {
    logger.error = originalError;
  }

  const script = `
    const service = require("./dist/services/auth/authenticatedSessionCapabilityService");
    service.requireAuthenticatedSessionCapability(
      { $queryRaw: async () => { throw new Error("AUTH_SESSION_CAPABILITY_DENIED"); } },
      { capability: "${capability}", purpose: "auth-session-hydration", requestId: "${requestId}" }
    ).catch(() => {});
  `;
  for (const format of ["plain", "json"]) {
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: process.cwd(),
      env: { ...process.env, LOG_FORMAT: format, LOG_JSON: "false", LOG_LEVEL: "error" },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr);
    const lines = result.stderr.trim().split("\n");
    assert.equal(lines.length, 1, `${format} logger must emit one CloudWatch line`);
    const payload = JSON.parse(lines[0]);
    const event = format === "json" ? JSON.parse(payload.message) : payload;
    assert.equal(event.event, "auth_session_capability_denied");
    assert.equal(event.requestId, requestId);
  }
  console.log("auth capability denial correlation tests passed");
})().catch((error) => { console.error(error); process.exit(1); });

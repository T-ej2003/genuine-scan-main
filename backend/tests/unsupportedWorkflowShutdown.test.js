const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

process.env.NODE_ENV = "test";
process.env.IP_HASH_SALT_CURRENT ||= "unsupported-workflow-shutdown-test-ip-hash-salt";
delete process.env.REDIS_URL;
delete process.env.REDIS_HOST;
delete process.env.MSCQR_TEST_ALLOW_UNSUPPORTED_WORKFLOWS;

const { logger } = require("../dist/utils/logger");
const {
  __resetUnsupportedWorkflowDenialCountersForTests,
  buildUnsupportedWorkflowDenialBucket,
  compileEnabledRoutes,
  createUnsupportedWorkflowShutdown,
  getUnsupportedWorkflowDenialCounters,
  reducedSurfaceDedicatedBoundaryPrefixes,
  reducedSurfaceDedicatedBoundaryRoutes,
  reducedSurfaceEnabledRoutes,
} = require("../dist/middleware/unsupportedWorkflowShutdown");

const invoke = (middleware, request = {}) =>
  new Promise((resolve, reject) => {
    const headers = {};
    const result = { next: false, status: null, body: null, headers, request: null };
    const requestHeaders = Object.fromEntries(
      Object.entries(request.headers || {}).map(([name, value]) => [String(name).toLowerCase(), String(value)])
    );
    const req = {
      method: "GET",
      path: "/qr/batches",
      originalUrl: "/qr/batches",
      baseUrl: "",
      requestId: "req-shutdown-test",
      ip: "203.0.113.10",
      socket: { remoteAddress: "203.0.113.10" },
      body: {},
      query: {},
      get(name) { return requestHeaders[String(name).toLowerCase()] || ""; },
      ...request,
    };
    delete req.headers;
    result.request = req;

    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const res = {
      headersSent: false,
      writableEnded: false,
      setHeader(name, value) { headers[String(name).toLowerCase()] = String(value); return this; },
      status(value) { result.status = value; return this; },
      json(value) { result.body = value; this.writableEnded = true; finish(); return this; },
    };

    try {
      Promise.resolve(middleware(req, res, (error) => {
        if (error) return reject(error);
        result.next = true;
        finish();
      })).catch(reject);
    } catch (error) {
      reject(error);
    }
  });

const failingStore = {
  init() {},
  async increment() { throw new Error("shared backend unavailable"); },
  async decrement() { throw new Error("shared backend unavailable"); },
  async resetKey() { throw new Error("shared backend unavailable"); },
};

const createSharedStore = () => {
  const hits = new Map();
  return {
    init() {},
    async increment(key) {
      const totalHits = (hits.get(key) || 0) + 1;
      hits.set(key, totalHits);
      return { totalHits, resetTime: new Date(Date.now() + 60_000) };
    },
    async decrement(key) { hits.set(key, Math.max(0, (hits.get(key) || 0) - 1)); },
    async resetKey(key) { hits.delete(key); },
  };
};

(async () => {
  assert.deepEqual(reducedSurfaceEnabledRoutes, []);
  const contract = JSON.parse(
    fs.readFileSync(path.join(__dirname, "../../documents/security/rls-program/unsupported-workflow-shutdown.json"), "utf8")
  );
  assert.deepEqual(contract.dedicatedBoundaryPrefixes, reducedSurfaceDedicatedBoundaryPrefixes);
  assert.deepEqual(contract.dedicatedBoundaryRoutes, reducedSurfaceDedicatedBoundaryRoutes);
  assert.equal(contract.denialControl.limitDefault, 60);
  assert.equal(contract.denialControl.logThresholdDefault, 5);

  const inactive = await invoke(createUnsupportedWorkflowShutdown({ environment: "production", sharedStore: null }));
  assert.equal(inactive.next, true, "the pre-RLS application preserves registered workflow behavior while shutdown is inactive");
  assert.throws(
    () => createUnsupportedWorkflowShutdown({ environment: "production", active: true, sharedStore: null }),
    /requires at least one reviewed protected route/,
    "an active empty allowlist must fail startup instead of blanket-disabling the application"
  );

  const activeOptions = { active: true, enabledRoutes: ["GET /account/profile"] };

  const firstBucket = buildUnsupportedWorkflowDenialBucket({ ip: "198.51.100.20", socket: {} });
  const mappedBucket = buildUnsupportedWorkflowDenialBucket({ ip: "::ffff:198.51.100.20", socket: {} });
  const secondBucket = buildUnsupportedWorkflowDenialBucket({ ip: "198.51.100.21", socket: {} });
  assert.equal(firstBucket, mappedBucket, "canonical forms of one address must share a bucket");
  assert.notEqual(firstBucket, secondBucket, "different networks must have distinct buckets");
  assert.doesNotMatch(firstBucket, /198\.51\.100\.20/, "the bucket must not expose the address");
  assert.match(firstBucket, /:ip:[^:]+:[a-f0-9]{64}:resource:global$/, "the address bucket must use the versioned application HMAC");

  const logs = [];
  const originalWarn = logger.warn;
  logger.warn = (...args) => logs.push(args);
  try {
    __resetUnsupportedWorkflowDenialCountersForTests();
    const middleware = createUnsupportedWorkflowShutdown({
      ...activeOptions,
      environment: "test",
      denialWindowMs: 60_000,
      denialMax: 3,
      denialLogMax: 1,
      sharedStore: null,
    });
    const sensitiveRequest = {
      path: "/incidents/secret-incident-id",
      originalUrl: "/incidents/secret-incident-id?email=secret@example.test&token=secret-token",
      requestId: "secret-request-token",
      body: { password: "secret-password" },
      query: { email: "secret@example.test", token: "secret-token" },
      headers: { authorization: "Bearer secret-bearer-token" },
    };

    const normal = await invoke(middleware, sensitiveRequest);
    assert.equal(normal.status, 503, "normal denial remains the existing generic 503");
    assert.deepEqual(normal.body, {
      error: "This operation is temporarily unavailable",
      code: "WORKFLOW_DISABLED",
      requestId: "secret-request-token",
    });
    assert.equal(normal.request.unsupportedWorkflowDenial, true, "request telemetry must be marked for redaction");
    assert.equal(logs.length, 1);
    assert.equal(logs[0][1].route, "UNRESOLVED_PROTECTED_ROUTE");
    assert.equal(logs[0][1].event, "UNSUPPORTED_WORKFLOW_DISABLED");
    assert.match(logs[0][1].networkBucket, /^[a-f0-9]{16}$/);
    assert.notEqual(logs[0][1].requestRef, sensitiveRequest.requestId);

    const threshold = await invoke(middleware, sensitiveRequest);
    const suppressed = await invoke(middleware, sensitiveRequest);
    const limited = await invoke(middleware, sensitiveRequest);
    const limitedAgain = await invoke(middleware, sensitiveRequest);
    assert.equal(threshold.status, 503);
    assert.equal(suppressed.status, 503);
    assert.equal(limited.status, 429, "the first over-limit denial must remain fail closed");
    assert.equal(limitedAgain.status, 429, "burst denials must stay bounded and fail closed");
    assert.equal(limited.body.code, "RATE_LIMITED");
    assert(Number(limited.headers["retry-after"]) > 0);
    assert.equal(logs.length, 2, "only one denial and one suppression summary may be logged");
    assert.equal(logs[1][1].event, "UNSUPPORTED_WORKFLOW_DENIAL_LOGS_SUPPRESSED");
    assert.equal(logs[1][1].logThreshold, 1);

    const serializedLogs = JSON.stringify(logs);
    assert.doesNotMatch(
      serializedLogs,
      /secret-incident-id|secret@example|secret-token|secret-password|secret-bearer-token|\/incidents\//,
      "shutdown logs must exclude paths, identifiers, bodies, queries, and tokens"
    );
    assert.deepEqual(getUnsupportedWorkflowDenialCounters(), {
      denied: 5,
      rateLimited: 2,
      logsEmitted: 2,
      logsSuppressed: 4,
      sharedStoreFallbacks: 0,
    });

    logs.length = 0;
    __resetUnsupportedWorkflowDenialCountersForTests();
    const separateBuckets = createUnsupportedWorkflowShutdown({
      ...activeOptions,
      environment: "test",
      denialMax: 1,
      denialLogMax: 1,
      sharedStore: null,
    });
    assert.equal((await invoke(separateBuckets, { ip: "198.51.100.30", socket: { remoteAddress: "198.51.100.30" } })).status, 503);
    assert.equal((await invoke(separateBuckets, { ip: "198.51.100.31", socket: { remoteAddress: "198.51.100.31" } })).status, 503);
    assert.equal((await invoke(separateBuckets, { ip: "198.51.100.30", socket: { remoteAddress: "198.51.100.30" } })).status, 429);
    assert.equal(logs.filter((entry) => entry[1].event === "UNSUPPORTED_WORKFLOW_DISABLED").length, 2);

    logs.length = 0;
    __resetUnsupportedWorkflowDenialCountersForTests();
    const backendFailure = createUnsupportedWorkflowShutdown({
      ...activeOptions,
      environment: "test",
      denialMax: 2,
      denialLogMax: 1,
      sharedStore: failingStore,
    });
    assert.equal((await invoke(backendFailure)).status, 503);
    assert.equal((await invoke(backendFailure)).status, 503);
    assert.equal((await invoke(backendFailure)).status, 429, "shared-store failure must fall back to local denial limiting");
    assert.equal(getUnsupportedWorkflowDenialCounters().sharedStoreFallbacks, 3);

    logs.length = 0;
    __resetUnsupportedWorkflowDenialCountersForTests();
    const sharedStore = createSharedStore();
    const firstInstance = createUnsupportedWorkflowShutdown({
      ...activeOptions,
      environment: "test",
      denialMax: 1,
      denialLogMax: 1,
      sharedStore,
    });
    const secondInstance = createUnsupportedWorkflowShutdown({
      ...activeOptions,
      environment: "test",
      denialMax: 1,
      denialLogMax: 1,
      sharedStore,
    });
    assert.equal((await invoke(firstInstance)).status, 503);
    assert.equal((await invoke(secondInstance)).status, 429, "the shared backend must bound one bucket across instances");

    __resetUnsupportedWorkflowDenialCountersForTests();
    const publicUnknown = await invoke(
      createUnsupportedWorkflowShutdown({ environment: "test", sharedStore: null }),
      { path: "/public/does-not-exist", originalUrl: "/public/does-not-exist" }
    );
    assert.equal(publicUnknown.next, true, "unknown public paths must reach the final 404 handler");
    assert.equal(getUnsupportedWorkflowDenialCounters().denied, 0, "dedicated public paths are not denial buckets");
  } finally {
    logger.warn = originalWarn;
  }

  const enabledMiddleware = createUnsupportedWorkflowShutdown({
    active: true,
    environment: "test",
    sharedStore: null,
    enabledRoutes: ["GET /internal/release", "GET /qr/batches/:id", "GET /orgs/:orgId/batches/:batchId", "GET /api/audit/:id"],
  });
  assert.equal((await invoke(enabledMiddleware, { path: "/internal/release" })).next, true, "static route");
  assert.equal((await invoke(enabledMiddleware, { path: "/qr/batches/123" })).next, true, "one parameter");
  assert.equal((await invoke(enabledMiddleware, { path: "/orgs/o-1/batches/b-1" })).next, true, "multiple parameters");
  assert.equal((await invoke(enabledMiddleware, { baseUrl: "/api", path: "/audit/a-1" })).next, true, "nested router mount");
  assert.equal((await invoke(enabledMiddleware, { path: "/qr/batches/%31%32%33" })).next, true, "safe encoded segment");
  assert.equal((await invoke(enabledMiddleware, { method: "POST", path: "/qr/batches/123" })).status, 503, "wrong method");
  assert.equal((await invoke(enabledMiddleware, { path: "/qr/batches/123/extra" })).status, 503, "near match");
  assert.equal((await invoke(enabledMiddleware, { path: "/qr/batches/a%2Fb" })).status, 503, "encoded slash");
  assert.equal(
    (await invoke(enabledMiddleware, { method: "POST", path: "/telemetry/route-transition" })).next,
    true,
    "the exact public telemetry ingestion route retains its dedicated boundary"
  );
  assert.equal(
    (await invoke(enabledMiddleware, { path: "/telemetry/route-transition/summary" })).status,
    503,
    "the protected telemetry summary cannot inherit a public-prefix exemption"
  );
  assert.equal(
    (await invoke(enabledMiddleware, { path: "/telemetry/unknown" })).status,
    503,
    "unknown telemetry descendants fail closed"
  );

  assert.throws(() => compileEnabledRoutes(["GET /qr/*"]), /Unsupported/);
  assert.throws(() => compileEnabledRoutes(["GET /qr/:id", "GET /qr/:name"]), /ambiguous/);
  assert.throws(() => compileEnabledRoutes(["GET /health", "GET /health"]), /Duplicate/);
  assert.throws(() => createUnsupportedWorkflowShutdown({ environment: "production", testOverride: true }), /prohibited in production/);
  assert.equal((await invoke(createUnsupportedWorkflowShutdown({ ...activeOptions, environment: "test", testOverride: true, sharedStore: null }))).next, true);

  const originalLogger = { ...logger };
  const appLogs = [];
  for (const level of ["debug", "info", "warn", "error"]) logger[level] = (message, meta) => appLogs.push({ level, message, meta });
  try {
    const { request, withServer } = require("./helpers/p1TestApp");
    await withServer(async (baseUrl) => {
      const denied = await request(
        baseUrl,
        "GET",
        "/api/incidents/00000000-0000-4000-8000-000000000000",
        null,
        undefined
      );
      assert.equal(denied.status, 401, "a supported protected route must reach its normal authentication boundary before RLS activation");
      const unknownPublic = await request(baseUrl, "GET", "/api/public/does-not-exist");
      assert.equal(unknownPublic.status, 404, "unknown public route contract remains 404");
    });
  } finally {
    Object.assign(logger, originalLogger);
  }

  assert.equal(
    appLogs.filter((entry) => entry.meta?.path === "/api/UNRESOLVED_PROTECTED_ROUTE").length,
    0,
    "inactive shutdown must not manufacture an unresolved-route log label"
  );
  assert.equal(
    appLogs.filter((entry) => entry.meta?.event === "UNSUPPORTED_WORKFLOW_DISABLED").length,
    0,
    "an inactive shutdown emits no temporary-disable warnings for supported routes"
  );

  console.log("Unsupported workflow shutdown tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

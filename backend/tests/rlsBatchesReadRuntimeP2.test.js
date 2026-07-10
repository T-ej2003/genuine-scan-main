const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const { PrismaClient, UserRole } = require("@prisma/client");

const {
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
  withP2TestApp,
} = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");
const {
  applyCandidateRls,
  buildRoleUrl,
  createRestrictedRlsReadRole,
  dropRestrictedRlsReadRole,
  rollbackCandidateRls,
} = require("./helpers/rlsReadRuntimeRole");

const command = "MSCQR_STAGING_RLS_BATCHES_READ_TEST=true npm --prefix backend run test:rls:batches-read-runtime";
const flagName = "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_STAGING_RLS_BATCHES_READ_TEST)) {
  console.log(`RLS batches read runtime P2 test skipped. Run with: ${command}`);
  process.exit(0);
}

const authHeader = (token) => ({ authorization: `Bearer ${token}` });
const backendRoot = path.resolve(__dirname, "..");
const distRoot = path.join(backendRoot, "dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const clearDistRequireCache = () => {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(distRoot)) delete require.cache[key];
  }
};

const request = async (baseUrl, method, route, body, options = {}) => {
  const headers = { ...(options.headers || {}) };
  const hasBody = body !== undefined && body !== null;
  if (hasBody && !headers["content-type"] && !headers["Content-Type"]) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: hasBody ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  return { status: response.status, headers: response.headers, text, payload };
};

const listen = async (app) => {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return {
    server,
    baseUrl: `http://127.0.0.1:${address.port}`,
  };
};

const readContext = async (client) => {
  const rows = await client.$queryRaw`
    SELECT
      current_setting('app.user_id', true) AS user_id,
      current_setting('app.role', true) AS role,
      current_setting('app.licensee_id', true) AS licensee_id,
      current_setting('app.manufacturer_id', true) AS manufacturer_id,
      current_setting('app.organization_id', true) AS organization_id,
      current_setting('app.is_platform_admin', true) AS is_platform_admin
  `;
  return rows[0] || {};
};

const readContextFromRunner = (runner) => runner.$transaction((tx) => readContext(tx));

const assertBatchMarkers = (response, expectedMarker, forbiddenMarker, label) => {
  assert.equal(response.status, 200, `${label}: ${response.text}`);
  assert.match(response.text, new RegExp(expectedMarker, "i"), `${label}: expected ${expectedMarker}`);
  assert.doesNotMatch(response.text, new RegExp(forbiddenMarker, "i"), `${label}: leaked ${forbiddenMarker}`);
};

const withConsoleCapture = async (callback) => {
  const logs = [];
  const originalInfo = console.info;
  const originalWarn = console.warn;
  console.info = (...args) => logs.push({ level: "info", args });
  console.warn = (...args) => logs.push({ level: "warn", args });
  try {
    await callback(logs);
  } finally {
    console.info = originalInfo;
    console.warn = originalWarn;
  }
  return logs;
};

const getProofLogs = (logs) =>
  logs
    .filter((entry) => entry.args[0] === "staging_rls_batches_read_proof")
    .map((entry) => ({ level: entry.level, event: entry.args[1] }));

const safeProofEventKeys = [
  "contextClass",
  "durationMs",
  "failureCategory",
  "flagEnabled",
  "metric",
  "route",
  "rowCount",
  "success",
];

const assertSafeProofEvent = (event) => {
  assert.deepEqual(Object.keys(event).sort(), safeProofEventKeys, "proof event must contain only safe telemetry fields");
  assert.strictEqual(event.metric, "staging_rls_batches_read");
  assert.strictEqual(event.route, "GET /api/qr/batches");
  assert.strictEqual(event.flagEnabled, true);
  assert(["platform_admin", "manufacturer", "tenant_user"].includes(event.contextClass), "safe context class expected");
  assert.strictEqual(typeof event.durationMs, "number");
  assert(event.durationMs >= 0, "duration must be non-negative");
  assert.strictEqual(typeof event.rowCount, "number");
  assert(event.rowCount >= 0, "row count must be non-negative");

  const serialized = JSON.stringify(event);
  for (const forbidden of [
    ids.licenseeAdminA,
    ids.manufacturerA,
    ids.superAdmin,
    ids.licenseeA,
    ids.orgA,
    "licensee-admin-a@mscqr.test",
    "manufacturer-a@mscqr.test",
  ]) {
    assert(!serialized.includes(forbidden), `proof event leaked raw identifier: ${forbidden}`);
  }

  for (const forbiddenKey of [
    "userId",
    "actorUserId",
    "licenseeId",
    "manufacturerId",
    "organizationId",
    "orgId",
    "qrCode",
    "token",
    "secret",
    "email",
  ]) {
    assert(!Object.prototype.hasOwnProperty.call(event, forbiddenKey), `proof event includes ${forbiddenKey}`);
  }
};

const runFlagOffRouteAssertions = async () => {
  process.env[flagName] = "false";
  delete process.env.RLS_READ_DATABASE_URL;
  const logs = await withConsoleCapture(async () => {
    await withP2TestApp(async ({ request, prisma }) => {
      await seedP2Fixtures(prisma);
      const tokens = await issueBearerTokens();

      const licensee = await request("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminA) });
      assertBatchMarkers(licensee, "P2 Batch A", "P2 Batch B", "flag off licensee batch list");

      const manufacturer = await request("GET", "/api/qr/batches", null, { headers: authHeader(tokens.manufacturerA) });
      assertBatchMarkers(manufacturer, "P2 Batch A", "P2 Batch B", "flag off manufacturer batch list");
    });
  });
  assert.deepEqual(getProofLogs(logs), [], "flag-off cached path must not emit RLS proof events");
};

const runFlagOnRouteAssertions = async () => {
  process.env[flagName] = "true";
  let databaseInfo = null;
  let adminPrisma = null;
  let appPrisma = null;
  let server = null;
  let appRoleName = null;

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);

    adminPrisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });
    await seedP2Fixtures(adminPrisma);

    appRoleName = createRestrictedRlsReadRole(databaseInfo.databaseUrl, "mscqr_batches_rls_read");
    applyCandidateRls(databaseInfo.databaseUrl, appRoleName);

    process.env.RLS_READ_DATABASE_URL = buildRoleUrl(databaseInfo.databaseUrl, appRoleName);
    clearDistRequireCache();

    const proofLogs = [];
    const requestLogs = [];
    const captureLogger = (level, message, meta) => {
      if (message === "staging_rls_batches_read_proof") proofLogs.push({ level, event: meta });
      if (message === "HTTP request completed") {
        requestLogs.push({ level, event: meta });
      }
    };
    mockModule("utils/logger.js", {
      logger: {
        info: (message, meta) => captureLogger("info", message, meta),
        warn: (message, meta) => captureLogger("warn", message, meta),
        error: (message, meta) => captureLogger("error", message, meta),
        debug: (message, meta) => captureLogger("debug", message, meta),
      },
    });

    appPrisma = require("../dist/config/database").default;
    const { createBackendApp } = require("../dist/app");
    const app = createBackendApp();
    const listener = await listen(app);
    server = listener.server;
    const routeRequest = (method, route, body, options) => request(listener.baseUrl, method, route, body, options);
    const tokens = await issueBearerTokens();

    try {
      const { getRlsReadPrisma } = require("../dist/config/rlsReadDatabase");
      const rlsReadPrisma = getRlsReadPrisma();
      const plainRows = await rlsReadPrisma.$transaction((tx) => tx.batch.findMany({ orderBy: [{ id: "asc" }] }));
      assert.deepEqual(plainRows, [], "Batch RLS must fail closed without transaction-local app context");
      const runtimeWriteProbe = new PrismaClient({
        datasources: { db: { url: process.env.RLS_READ_DATABASE_URL } },
      });
      try {
        await assert.rejects(
          () => runtimeWriteProbe.$executeRawUnsafe('UPDATE "Batch" SET "name" = "name" WHERE false'),
          /permission denied/i,
          "restricted RLS read credential must be denied writes by PostgreSQL"
        );
      } finally {
        await runtimeWriteProbe.$disconnect();
      }

      const licensee = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminA) });
      assertBatchMarkers(licensee, "P2 Batch A", "P2 Batch B", "flag on licensee batch list");

      const licenseeTrailingSlash = await routeRequest("GET", "/api/qr/batches/", null, {
        headers: authHeader(tokens.licenseeAdminA),
      });
      assertBatchMarkers(licenseeTrailingSlash, "P2 Batch A", "P2 Batch B", "flag on licensee trailing-slash batch list");

      const manufacturer = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.manufacturerA) });
      assertBatchMarkers(manufacturer, "P2 Batch A", "P2 Batch B", "flag on manufacturer batch list");

      const platform = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.superAdmin) });
      assert.equal(platform.status, 200, platform.text);
      assert.match(platform.text, /P2 Batch A/i, "platform admin should see tenant A batch");
      assert.match(platform.text, /P2 Batch B/i, "platform admin should see tenant B batch through explicit platform context");

      const { listScopedBatchReadPayload } = require("../dist/services/stagingRlsBatchReadService");
      await assert.rejects(
        () => listScopedBatchReadPayload({
          user: {
            userId: ids.licenseeAdminA,
            email: "org-admin-a@mscqr.test",
            role: UserRole.ORG_ADMIN,
            licenseeId: ids.licenseeA,
            orgId: ids.orgA,
            sessionStage: "ACTIVE",
            authAssurance: "ADMIN_MFA",
          },
          requestedLicenseeId: null,
          scopeKey: "org-admin-rls-proof",
          limit: 10,
          offset: 0,
        }),
        /phase-one access is not enabled/,
        "dormant organization admin must not gain phase-one RLS access"
      );

      const [concurrentTenantA, concurrentTenantB] = await Promise.all([
        routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminA) }),
        routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminB) }),
      ]);
      assertBatchMarkers(concurrentTenantA, "P2 Batch A", "P2 Batch B", "concurrent tenant A batch list");
      assertBatchMarkers(concurrentTenantB, "P2 Batch B", "P2 Batch A", "concurrent tenant B batch list");

      const childRoutePath = `/api/qr/batches/${ids.batchA}/validation-evidence`;
      const childRoute = await routeRequest("GET", childRoutePath, null, { headers: authHeader(tokens.licenseeAdminA) });
      assert.notEqual(childRoute.status, 401, `child route should pass auth before telemetry assertion: ${childRoute.text}`);

      const successProofs = proofLogs.filter((entry) => entry.event.success);
      assert.equal(successProofs.length, 6, "only active phase-one roles may emit successful RLS proof events");
      assert.deepEqual(
        successProofs.map((entry) => entry.event.contextClass).sort(),
        ["manufacturer", "platform_admin", "tenant_user", "tenant_user", "tenant_user", "tenant_user"],
        "proof events must expose context class only"
      );
      for (const entry of successProofs) {
        assert.strictEqual(entry.level, "info");
        assertSafeProofEvent(entry.event);
        assert.strictEqual(entry.event.failureCategory, null);
      }
      const batchRequestLogs = requestLogs.filter((entry) =>
        ["/api/qr/batches", "/api/qr/batches/"].includes(entry.event.path)
      );
      assert.equal(batchRequestLogs.length, 6, "flag-on batch request telemetry should be emitted for each route call");
      assert.deepEqual(
        batchRequestLogs.map((entry) => entry.event.actorContextClass).sort(),
        ["manufacturer", "platform_admin", "tenant_user", "tenant_user", "tenant_user", "tenant_user"],
        "request telemetry must expose context class only under the staging RLS flag"
      );
      const exactPathLog = batchRequestLogs.find((entry) => entry.event.path === "/api/qr/batches");
      const trailingSlashLog = batchRequestLogs.find((entry) => entry.event.path === "/api/qr/batches/");
      assert(exactPathLog, "exact batch-list path should emit request telemetry");
      assert(trailingSlashLog, "trailing-slash batch-list path should emit request telemetry");
      for (const entry of batchRequestLogs) {
        assert.strictEqual(entry.event.actorUserId, null, "flag-on request telemetry must redact actor user id");
        assert.strictEqual(entry.event.actorRole, null, "flag-on request telemetry must redact actor role");
        assert.strictEqual(entry.event.actorLicenseeId, null, "flag-on request telemetry must redact licensee id");
        assert.strictEqual(entry.event.actorOrgId, null, "flag-on request telemetry must redact organization id");
        const serialized = JSON.stringify(entry.event);
        assert(!serialized.includes(ids.licenseeAdminA), "request telemetry leaked licensee admin id");
        assert(!serialized.includes(ids.manufacturerA), "request telemetry leaked manufacturer id");
        assert(!serialized.includes(ids.licenseeA), "request telemetry leaked licensee id");
        assert(!serialized.includes(ids.orgA), "request telemetry leaked organization id");
      }
      const childRouteLog = requestLogs.find((entry) => entry.event.path === childRoutePath);
      assert(childRouteLog, "child batch route should emit request telemetry");
      assert.strictEqual(childRouteLog.event.actorContextClass, null, "child batch route must not be classified as RLS proof telemetry");
      assert.strictEqual(childRouteLog.event.actorUserId, ids.licenseeAdminA, "child batch route must not redact actor user id");
      assert.strictEqual(childRouteLog.event.actorRole, UserRole.LICENSEE_ADMIN, "child batch route must not redact actor role");
      assert.strictEqual(childRouteLog.event.actorLicenseeId, ids.licenseeA, "child batch route must not redact licensee id");
      assert.strictEqual(childRouteLog.event.actorOrgId, ids.orgA, "child batch route must not redact organization id");

      const context = await readContextFromRunner(rlsReadPrisma);
      assert.equal(context.user_id || "", "", "app.user_id leaked after route transaction");
      assert.equal(context.role || "", "", "app.role leaked after route transaction");
      assert.equal(context.licensee_id || "", "", "app.licensee_id leaked after route transaction");
      assert.equal(context.manufacturer_id || "", "", "app.manufacturer_id leaked after route transaction");
      assert.equal(context.organization_id || "", "", "app.organization_id leaked after route transaction");
      assert.equal(context.is_platform_admin || "", "", "app.is_platform_admin leaked after route transaction");

      const {
        buildStagingRlsBatchReadContext,
        withStagingRlsBatchReadTransaction,
      } = require("../dist/lib/stagingRlsBatchReadContext");
      await assert.rejects(
        () =>
          withStagingRlsBatchReadTransaction(
            {
              userId: ids.licenseeAdminA,
              email: "licensee-admin-a@mscqr.test",
              role: UserRole.LICENSEE_ADMIN,
              licenseeId: ids.licenseeA,
              orgId: ids.orgA,
              sessionStage: "ACTIVE",
              authAssurance: "ADMIN_MFA",
            },
            async (tx) => {
              const rollbackContext = await readContext(tx);
              assert.equal(rollbackContext.user_id, ids.licenseeAdminA);
              throw new Error("intentional transaction rollback proof");
            }
          ),
        /intentional transaction rollback proof/
      );
      const contextAfterRollback = await readContextFromRunner(rlsReadPrisma);
      assert.equal(contextAfterRollback.user_id || "", "", "app.user_id leaked after rollback");
      assert.equal(contextAfterRollback.licensee_id || "", "", "app.licensee_id leaked after rollback");

      assert.throws(
        () =>
          buildStagingRlsBatchReadContext({
            userId: ids.licenseeAdminA,
            email: "missing-tenant@mscqr.test",
            role: UserRole.LICENSEE_ADMIN,
            licenseeId: null,
            orgId: ids.orgA,
            sessionStage: "ACTIVE",
            authAssurance: "ADMIN_MFA",
          }),
        /requires app\.licensee_id/,
        "tenant user missing licensee context must fail closed"
      );

      await assert.rejects(
        () =>
          listScopedBatchReadPayload({
            user: {
              userId: ids.licenseeAdminA,
              email: "missing-tenant@mscqr.test",
              role: UserRole.LICENSEE_ADMIN,
              licenseeId: null,
              orgId: ids.orgA,
              sessionStage: "ACTIVE",
              authAssurance: "ADMIN_MFA",
            },
            requestedLicenseeId: null,
            scopeKey: "rls-proof-failure-test",
            limit: 1,
            offset: 0,
          }),
        /requires app\.licensee_id/,
        "staging RLS service must fail closed when tenant context is missing"
      );

      const failureProof = proofLogs.find((entry) => !entry.event.success && entry.event.failureCategory === "rls_context_missing");
      assert(failureProof, "flag-on failures must emit a categorized proof event");
      assert.strictEqual(failureProof.level, "warn");
      assertSafeProofEvent(failureProof.event);
      assert.strictEqual(failureProof.event.failureCategory, "rls_context_missing");
      assert(!JSON.stringify(failureProof.event).includes("requires app.licensee_id"), "failure proof must not log error text");
    } finally {
      rollbackCandidateRls(databaseInfo.databaseUrl, appRoleName);
    }
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    const rlsReadModule = require.cache[require.resolve("../dist/config/rlsReadDatabase")]
      ? require("../dist/config/rlsReadDatabase")
      : null;
    if (rlsReadModule) await rlsReadModule.disconnectRlsReadPrisma().catch(() => {});
    if (appPrisma?.$disconnect) await appPrisma.$disconnect().catch(() => {});
    if (adminPrisma?.$disconnect) await adminPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.databaseUrl && appRoleName) dropRestrictedRlsReadRole(databaseInfo.databaseUrl, appRoleName);
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
    delete process.env.RLS_READ_DATABASE_URL;
  }
};

(async () => {
  await runFlagOffRouteAssertions();
  await runFlagOnRouteAssertions();
  console.log("RLS batches read runtime P2 tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

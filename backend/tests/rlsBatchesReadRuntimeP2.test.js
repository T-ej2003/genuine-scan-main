const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
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
const repoRoot = path.resolve(__dirname, "../..");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i, "Unsafe PostgreSQL identifier");
  return `"${value.replace(/"/g, '""')}"`;
};

const parseDatabaseName = (databaseUrl) => {
  const parsed = new URL(databaseUrl);
  return decodeURIComponent(parsed.pathname.replace(/^\//, ""));
};

const buildRoleUrl = (databaseUrl, roleName) => {
  const parsed = new URL(databaseUrl);
  parsed.username = roleName;
  parsed.password = "";
  return parsed.toString();
};

const applySql = (databaseUrl, sql) => {
  execFileSync("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c", sql], {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: "inherit",
  });
};

const createAppRole = (databaseUrl) => {
  const roleName = `mscqr_batches_rls_app_${process.pid}_${Date.now()}`.toLowerCase();
  const databaseName = parseDatabaseName(databaseUrl);
  const role = quoteIdent(roleName);
  applySql(
    databaseUrl,
    `
      DROP ROLE IF EXISTS ${role};
      CREATE ROLE ${role} LOGIN;
      GRANT CONNECT ON DATABASE ${quoteIdent(databaseName)} TO ${role};
      GRANT USAGE ON SCHEMA public TO ${role};
      GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role};
      GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO ${role};
    `
  );
  return roleName;
};

const dropAppRole = (databaseUrl, roleName) => {
  if (!roleName) return;
  const role = quoteIdent(roleName);
  applySql(databaseUrl, `DROP OWNED BY ${role}; DROP ROLE IF EXISTS ${role};`);
};

const clearDistRequireCache = () => {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(distRoot)) delete require.cache[key];
  }
};

const applyBatchRouteRls = (databaseUrl) => {
  applySql(databaseUrl, `
    DROP POLICY IF EXISTS test_rls_batches_read_batch_select ON "Batch";
    DROP POLICY IF EXISTS test_rls_batches_read_qrcode_select ON "QRCode";

    ALTER TABLE "Batch" ENABLE ROW LEVEL SECURITY;
    ALTER TABLE "Batch" FORCE ROW LEVEL SECURITY;
    ALTER TABLE "QRCode" ENABLE ROW LEVEL SECURITY;
    ALTER TABLE "QRCode" FORCE ROW LEVEL SECURITY;

    CREATE POLICY test_rls_batches_read_batch_select ON "Batch"
      FOR SELECT
      USING (
        lower(COALESCE(current_setting('app.is_platform_admin', true), 'false')) = 'true'
        OR "licenseeId" = NULLIF(current_setting('app.licensee_id', true), '')
        OR "manufacturerId" = NULLIF(current_setting('app.manufacturer_id', true), '')
      );

    CREATE POLICY test_rls_batches_read_qrcode_select ON "QRCode"
      FOR SELECT
      USING (
        lower(COALESCE(current_setting('app.is_platform_admin', true), 'false')) = 'true'
        OR "licenseeId" = NULLIF(current_setting('app.licensee_id', true), '')
        OR EXISTS (
          SELECT 1
          FROM "Batch" b
          WHERE b."id" = "QRCode"."batchId"
            AND (
              b."licenseeId" = NULLIF(current_setting('app.licensee_id', true), '')
              OR b."manufacturerId" = NULLIF(current_setting('app.manufacturer_id', true), '')
            )
        )
      );
  `);
};

const rollbackBatchRouteRls = (databaseUrl) => {
  applySql(databaseUrl, `
    DROP POLICY IF EXISTS test_rls_batches_read_qrcode_select ON "QRCode";
    DROP POLICY IF EXISTS test_rls_batches_read_batch_select ON "Batch";
    ALTER TABLE "QRCode" NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE "QRCode" DISABLE ROW LEVEL SECURITY;
    ALTER TABLE "Batch" NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE "Batch" DISABLE ROW LEVEL SECURITY;
  `);
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

const assertSafeProofEvent = (event) => {
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

    appRoleName = createAppRole(databaseInfo.databaseUrl);
    applyBatchRouteRls(databaseInfo.databaseUrl);

    process.env.DATABASE_URL = buildRoleUrl(databaseInfo.databaseUrl, appRoleName);
    clearDistRequireCache();

    const proofLogs = [];
    const batchRequestLogs = [];
    const captureLogger = (level, message, meta) => {
      if (message === "staging_rls_batches_read_proof") proofLogs.push({ level, event: meta });
      if (message === "HTTP request completed" && meta?.path === "/api/qr/batches") {
        batchRequestLogs.push({ level, event: meta });
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
      const plainRows = await appPrisma.$transaction((tx) => tx.batch.findMany({ orderBy: [{ id: "asc" }] }));
      assert.deepEqual(plainRows, [], "Batch RLS must fail closed without transaction-local app context");

      const licensee = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.licenseeAdminA) });
      assertBatchMarkers(licensee, "P2 Batch A", "P2 Batch B", "flag on licensee batch list");

      const manufacturer = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.manufacturerA) });
      assertBatchMarkers(manufacturer, "P2 Batch A", "P2 Batch B", "flag on manufacturer batch list");

      const platform = await routeRequest("GET", "/api/qr/batches", null, { headers: authHeader(tokens.superAdmin) });
      assert.equal(platform.status, 200, platform.text);
      assert.match(platform.text, /P2 Batch A/i, "platform admin should see tenant A batch");
      assert.match(platform.text, /P2 Batch B/i, "platform admin should see tenant B batch through explicit platform context");

      const successProofs = proofLogs.filter((entry) => entry.event.success);
      assert.equal(successProofs.length, 3, "flag-on route requests must emit success proof events");
      assert.deepEqual(
        successProofs.map((entry) => entry.event.contextClass).sort(),
        ["manufacturer", "platform_admin", "tenant_user"],
        "proof events must expose context class only"
      );
      for (const entry of successProofs) {
        assert.strictEqual(entry.level, "info");
        assertSafeProofEvent(entry.event);
        assert.strictEqual(entry.event.failureCategory, null);
      }
      assert.equal(batchRequestLogs.length, 3, "flag-on batch request telemetry should be emitted for each route call");
      assert.deepEqual(
        batchRequestLogs.map((entry) => entry.event.actorContextClass).sort(),
        ["manufacturer", "platform_admin", "tenant_user"],
        "request telemetry must expose context class only under the staging RLS flag"
      );
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

      const context = await readContext(appPrisma);
      assert.notEqual(context.user_id, ids.licenseeAdminA, "app.user_id leaked after route transaction");
      assert.notEqual(context.role, UserRole.LICENSEE_ADMIN, "app.role leaked after route transaction");
      assert.notEqual(context.licensee_id, ids.licenseeA, "app.licensee_id leaked after route transaction");
      assert.notEqual(context.manufacturer_id, ids.manufacturerA, "app.manufacturer_id leaked after route transaction");
      assert.notEqual(context.organization_id, ids.orgA, "app.organization_id leaked after route transaction");
      assert.notEqual(context.is_platform_admin, "true", "app.is_platform_admin leaked after route transaction");

      const { buildStagingRlsBatchReadContext } = require("../dist/lib/stagingRlsBatchReadContext");
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

      const { listScopedBatchReadPayload } = require("../dist/services/stagingRlsBatchReadService");
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

      const failureProof = proofLogs.find((entry) => !entry.event.success);
      assert(failureProof, "flag-on failures must emit a categorized proof event");
      assert.strictEqual(failureProof.level, "warn");
      assertSafeProofEvent(failureProof.event);
      assert.strictEqual(failureProof.event.failureCategory, "rls_context_missing");
      assert(!JSON.stringify(failureProof.event).includes("requires app.licensee_id"), "failure proof must not log error text");
    } finally {
      rollbackBatchRouteRls(databaseInfo.databaseUrl);
    }
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (appPrisma?.$disconnect) await appPrisma.$disconnect().catch(() => {});
    if (adminPrisma?.$disconnect) await adminPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.databaseUrl && appRoleName) dropAppRole(databaseInfo.databaseUrl, appRoleName);
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
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

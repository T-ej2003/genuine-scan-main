const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const http = require("node:http");
const path = require("node:path");
const {
  PrismaClient,
  PrinterCommandLanguage,
  PrinterConnectionType,
  PrinterDeliveryMode,
  UserRole,
} = require("@prisma/client");

const {
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
  withP2TestApp,
} = require("./helpers/p2TestDb");
const { ids, issueBearerTokens, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const command =
  "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_TEST=true npm --prefix backend run test:rls:manufacturer-printers-read-runtime";
const flagName = "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_TEST)) {
  console.log(`RLS manufacturer printer read runtime P2 test skipped. Run with: ${command}`);
  process.exit(0);
}

const printerIds = {
  printerA: "00000000-0000-4202-9400-000000000001",
  printerB: "00000000-0000-4202-9400-000000000002",
};

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
  const roleName = `mscqr_printer_read_rls_app_${process.pid}_${Date.now()}`.toLowerCase();
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

const applyManufacturerPrintersRouteRls = (databaseUrl) => {
  applySql(databaseUrl, `
    DROP POLICY IF EXISTS test_rls_manufacturer_printer_select ON "Printer";

    ALTER TABLE "Printer" ENABLE ROW LEVEL SECURITY;
    ALTER TABLE "Printer" FORCE ROW LEVEL SECURITY;

    CREATE POLICY test_rls_manufacturer_printer_select ON "Printer"
      FOR SELECT
      USING (
        lower(COALESCE(current_setting('app.is_platform_admin', true), 'false')) = 'true'
        OR "licenseeId" = NULLIF(current_setting('app.licensee_id', true), '')
        OR "orgId" = NULLIF(current_setting('app.organization_id', true), '')
        OR "assignedUserId" = NULLIF(current_setting('app.user_id', true), '')
        OR "createdByUserId" = NULLIF(current_setting('app.user_id', true), '')
        OR EXISTS (
          SELECT 1
          FROM "PrinterRegistration" pr
          WHERE pr."id" = "Printer"."printerRegistrationId"
            AND pr."userId" = NULLIF(current_setting('app.user_id', true), '')
        )
      );
  `);
};

const rollbackManufacturerPrintersRouteRls = (databaseUrl) => {
  applySql(databaseUrl, `
    DROP POLICY IF EXISTS test_rls_manufacturer_printer_select ON "Printer";
    ALTER TABLE "Printer" NO FORCE ROW LEVEL SECURITY;
    ALTER TABLE "Printer" DISABLE ROW LEVEL SECURITY;
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

const createPrinterFixtures = async (prisma) => {
  await prisma.printer.deleteMany({ where: { id: { in: Object.values(printerIds) } } });
  await prisma.printer.createMany({
    data: [
      {
        id: printerIds.printerA,
        name: "P2 Printer A",
        vendor: "Zebra",
        model: "ZT410",
        connectionType: PrinterConnectionType.NETWORK_DIRECT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        ipAddress: "10.10.10.10",
        port: 9100,
        deliveryMode: PrinterDeliveryMode.DIRECT,
        orgId: ids.orgA,
        licenseeId: ids.licenseeA,
        createdByUserId: ids.licenseeAdminA,
        isActive: true,
        isDefault: true,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 printer A ready",
      },
      {
        id: printerIds.printerB,
        name: "P2 Printer B",
        vendor: "Zebra",
        model: "ZT410",
        connectionType: PrinterConnectionType.NETWORK_DIRECT,
        commandLanguage: PrinterCommandLanguage.ZPL,
        ipAddress: "10.20.20.20",
        port: 9100,
        deliveryMode: PrinterDeliveryMode.DIRECT,
        orgId: ids.orgB,
        licenseeId: ids.licenseeB,
        createdByUserId: ids.licenseeAdminB,
        isActive: true,
        isDefault: true,
        lastValidationStatus: "READY",
        lastValidationMessage: "P2 printer B ready",
      },
    ],
  });
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
    .filter((entry) => entry.args[0] === "staging_rls_manufacturer_printers_read_proof")
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

const assertPrinterList = (response, expectedName, forbiddenName, label) => {
  assert.equal(response.status, 200, `${label}: ${response.text}`);
  assert.equal(response.payload?.success, true, `${label}: expected success payload`);
  assert(Array.isArray(response.payload?.data), `${label}: expected data array`);
  assert.match(response.text, new RegExp(expectedName, "i"), `${label}: expected ${expectedName}`);
  assert.doesNotMatch(response.text, new RegExp(forbiddenName, "i"), `${label}: leaked ${forbiddenName}`);
};

const assertSafeProofEvent = (event) => {
  assert.deepEqual(Object.keys(event).sort(), safeProofEventKeys, "proof event must contain only safe telemetry fields");
  assert.strictEqual(event.metric, "staging_rls_manufacturer_printers_read");
  assert.strictEqual(event.route, "GET /api/manufacturer/printers");
  assert.strictEqual(event.flagEnabled, true);
  assert(["platform_admin", "manufacturer", "tenant_user"].includes(event.contextClass), "safe context class expected");
  assert.strictEqual(typeof event.durationMs, "number");
  assert(event.durationMs >= 0, "duration must be non-negative");
  assert(Number.isInteger(event.rowCount), "row count must be an integer");
  assert(event.rowCount >= 0, "row count must be non-negative");

  const serialized = JSON.stringify(event);
  for (const forbidden of [
    ids.licenseeAdminA,
    ids.licenseeAdminB,
    ids.manufacturerA,
    ids.manufacturerB,
    ids.superAdmin,
    ids.licenseeA,
    ids.licenseeB,
    ids.orgA,
    ids.orgB,
    printerIds.printerA,
    printerIds.printerB,
    "P2 Printer A",
    "P2 Printer B",
    "10.10.10.10",
    "10.20.20.20",
    "p2-licensee-a@mscqr.test",
    "p2-manufacturer-a@mscqr.test",
  ]) {
    assert(!serialized.includes(forbidden), `proof event leaked raw identifier: ${forbidden}`);
  }

  for (const forbiddenKey of [
    "printerId",
    "printerName",
    "deviceName",
    "userId",
    "actorUserId",
    "licenseeId",
    "manufacturerId",
    "organizationId",
    "orgId",
    "ipAddress",
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
      await createPrinterFixtures(prisma);
      const tokens = await issueBearerTokens();

      const manufacturer = await request("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(manufacturer, "P2 Printer A", "P2 Printer B", "flag off manufacturer printer list");

      const wrongManufacturer = await request("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerB),
      });
      assertPrinterList(wrongManufacturer, "P2 Printer B", "P2 Printer A", "flag off wrong manufacturer filtered list");
    });
  });
  assert.deepEqual(getProofLogs(logs), [], "flag-off path must not emit manufacturer printer RLS proof events");
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
    await createPrinterFixtures(adminPrisma);

    appRoleName = createAppRole(databaseInfo.databaseUrl);
    applyManufacturerPrintersRouteRls(databaseInfo.databaseUrl);

    process.env.DATABASE_URL = buildRoleUrl(databaseInfo.databaseUrl, appRoleName);
    clearDistRequireCache();

    const proofLogs = [];
    const requestLogs = [];
    const captureLogger = (level, message, meta) => {
      if (message === "staging_rls_manufacturer_printers_read_proof") proofLogs.push({ level, event: meta });
      if (message === "HTTP request completed") requestLogs.push({ level, event: meta });
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
      const plainRows = await appPrisma.$transaction((tx) =>
        tx.printer.findMany({ where: { id: { in: Object.values(printerIds) } }, orderBy: [{ id: "asc" }] })
      );
      assert.deepEqual(plainRows, [], "Printer RLS must fail closed without transaction-local app context");

      const manufacturer = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(manufacturer, "P2 Printer A", "P2 Printer B", "flag on manufacturer printer list");

      const manufacturerTrailingSlash = await routeRequest("GET", "/api/manufacturer/printers/", null, {
        headers: authHeader(tokens.manufacturerA),
      });
      assertPrinterList(
        manufacturerTrailingSlash,
        "P2 Printer A",
        "P2 Printer B",
        "flag on trailing-slash manufacturer printer list"
      );

      const wrongManufacturer = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.manufacturerB),
      });
      assertPrinterList(wrongManufacturer, "P2 Printer B", "P2 Printer A", "flag on wrong manufacturer filtered list");

      const platformAdmin = await routeRequest("GET", "/api/manufacturer/printers", null, {
        headers: authHeader(tokens.superAdmin),
      });
      assert.equal(platformAdmin.status, 200, `platform admin printer list: ${platformAdmin.text}`);
      assert.match(platformAdmin.text, /P2 Printer A/i, "platform admin should explicitly retain printer A visibility");
      assert.match(platformAdmin.text, /P2 Printer B/i, "platform admin should explicitly retain printer B visibility");

      const siblingRoutePath = `/api/manufacturer/printers/${printerIds.printerA}/test`;
      const siblingRoute = await routeRequest("POST", siblingRoutePath, {}, {
        headers: authHeader(tokens.licenseeAdminA),
      });
      assert.notEqual(siblingRoute.status, 401, `sibling printer test route should pass auth before telemetry assertion: ${siblingRoute.text}`);

      const successProofs = proofLogs.filter((entry) => entry.event.success);
      assert.equal(successProofs.length, 4, "flag-on manufacturer printer reads must emit proof events");
      assert.deepEqual(
        successProofs.map((entry) => entry.event.contextClass).sort(),
        ["manufacturer", "manufacturer", "manufacturer", "platform_admin"],
        "proof events must expose context class only"
      );
      assert.deepEqual(
        successProofs.map((entry) => entry.event.rowCount).sort((a, b) => a - b),
        [1, 1, 1, 2],
        "proof row counts should be coarse and scoped"
      );
      for (const entry of successProofs) {
        assert.strictEqual(entry.level, "info");
        assertSafeProofEvent(entry.event);
        assert.strictEqual(entry.event.failureCategory, null);
      }

      const printerRequestLogs = requestLogs.filter((entry) =>
        entry.event.path === "/api/manufacturer/printers"
      );
      assert.equal(printerRequestLogs.length, 4, "flag-on printer request telemetry should be emitted");
      assert.deepEqual(
        printerRequestLogs.map((entry) => entry.event.actorContextClass).sort(),
        ["manufacturer", "manufacturer", "manufacturer", "platform_admin"],
        "request telemetry must expose context class only under the printer-read flag"
      );
      for (const entry of printerRequestLogs) {
        assert.strictEqual(entry.event.actorUserId, null, "flag-on request telemetry must redact actor user id");
        assert.strictEqual(entry.event.actorRole, null, "flag-on request telemetry must redact actor role");
        assert.strictEqual(entry.event.actorLicenseeId, null, "flag-on request telemetry must redact licensee id");
        assert.strictEqual(entry.event.actorOrgId, null, "flag-on request telemetry must redact organization id");
        const serialized = JSON.stringify(entry.event);
        assert(!serialized.includes(ids.manufacturerA), "request telemetry leaked manufacturer id");
        assert(!serialized.includes(ids.licenseeA), "request telemetry leaked licensee id");
        assert(!serialized.includes(ids.orgA), "request telemetry leaked organization id");
        assert(!serialized.includes(printerIds.printerA), "request telemetry leaked printer id");
        assert(!serialized.includes("P2 Printer A"), "request telemetry leaked printer name");
      }

      const siblingRouteLog = requestLogs.find((entry) => entry.event.path === siblingRoutePath);
      assert(siblingRouteLog, "sibling printer route should emit request telemetry");
      assert.strictEqual(siblingRouteLog.event.actorContextClass, null, "sibling printer route must not be classified as printer-read RLS telemetry");
      assert.strictEqual(siblingRouteLog.event.actorUserId, ids.licenseeAdminA, "sibling route must not redact actor user id");
      assert.strictEqual(siblingRouteLog.event.actorRole, UserRole.LICENSEE_ADMIN, "sibling route must not redact actor role");
      assert.strictEqual(siblingRouteLog.event.actorLicenseeId, ids.licenseeA, "sibling route must not redact licensee id");
      assert.strictEqual(siblingRouteLog.event.actorOrgId, ids.orgA, "sibling route must not redact organization id");

      const context = await readContext(appPrisma);
      assert.notEqual(context.user_id, ids.manufacturerA, "app.user_id leaked after route transaction");
      assert.notEqual(context.role, UserRole.MANUFACTURER, "app.role leaked after route transaction");
      assert.notEqual(context.licensee_id, ids.licenseeA, "app.licensee_id leaked after route transaction");
      assert.notEqual(context.manufacturer_id, ids.manufacturerA, "app.manufacturer_id leaked after route transaction");
      assert.notEqual(context.organization_id, ids.orgA, "app.organization_id leaked after route transaction");
      assert.notEqual(context.is_platform_admin, "true", "app.is_platform_admin leaked after route transaction");

      const { listScopedManufacturerPrintersReadPayload } = require("../dist/services/stagingRlsManufacturerPrintersReadService");
      await assert.rejects(
        () =>
          listScopedManufacturerPrintersReadPayload({
            user: {
              userId: ids.licenseeAdminA,
              email: "missing-tenant@mscqr.test",
              role: UserRole.LICENSEE_ADMIN,
              licenseeId: null,
              orgId: ids.orgA,
              sessionStage: "ACTIVE",
              authAssurance: "ADMIN_MFA",
            },
            userId: ids.licenseeAdminA,
            orgId: ids.orgA,
            licenseeId: null,
            licenseeIds: null,
            includeInactive: false,
          }),
        /requires app\.licensee_id/,
        "staging RLS printer service must fail closed when tenant context is missing"
      );

      const failureProof = proofLogs.find((entry) => !entry.event.success);
      assert(failureProof, "flag-on printer read failures must emit a categorized proof event");
      assert.strictEqual(failureProof.level, "warn");
      assertSafeProofEvent(failureProof.event);
      assert.strictEqual(failureProof.event.failureCategory, "rls_context_missing");
      assert(!JSON.stringify(failureProof.event).includes("requires app.licensee_id"), "failure proof must not log error text");
    } finally {
      rollbackManufacturerPrintersRouteRls(databaseInfo.databaseUrl);
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
  console.log("RLS manufacturer printer read runtime P2 tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

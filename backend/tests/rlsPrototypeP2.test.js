const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { PrismaClient } = require("@prisma/client");

const {
  P2TestDbSkip,
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
} = require("./helpers/p2TestDb");
const { ids, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const command = "MSCQR_RLS_PROTOTYPE_TEST=true npm --prefix backend run test:rls:prototype";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_RLS_PROTOTYPE_TEST)) {
  console.log(`RLS prototype P2 test skipped. Run with: ${command}`);
  process.exit(0);
}

const backendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(backendRoot, "..");
const prototypeSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_prototype.sql");
const rollbackSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_rollback.sql");

const rlsTargetTables = [
  "Organization",
  "Licensee",
  "User",
  "Batch",
  "QRCode",
  "PrintJob",
  "PrintItem",
  "QrScanLog",
  "Incident",
  "AuditLog",
  "Printer",
  "TenantFeatureFlag",
  "VerificationDecision",
  "PrintReissueRequest",
  "BatchPrintPackToken",
  "CustomerVerificationSession",
  "SupportTicket",
];

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i, "Unsafe PostgreSQL identifier");
  return `"${value.replace(/"/g, '""')}"`;
};

const sqlLiteral = (value) => `'${String(value).replace(/'/g, "''")}'`;

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

const applySqlFile = (databaseUrl, filePath) => {
  execFileSync("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-f", filePath], {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: "inherit",
  });
};

const applyAdminSql = (databaseUrl, sql) => {
  execFileSync("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-c", sql], {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: "inherit",
  });
};

const createAppRole = (databaseUrl) => {
  const roleName = `mscqr_rls_app_${process.pid}_${Date.now()}`.toLowerCase();
  const databaseName = parseDatabaseName(databaseUrl);
  const role = quoteIdent(roleName);
  applyAdminSql(
    databaseUrl,
    [
      `DROP ROLE IF EXISTS ${role};`,
      `CREATE ROLE ${role} LOGIN;`,
      `GRANT CONNECT ON DATABASE ${quoteIdent(databaseName)} TO ${role};`,
      `GRANT USAGE ON SCHEMA public TO ${role};`,
      `GRANT USAGE ON SCHEMA app_rls TO ${role};`,
      `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${role};`,
      `GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls TO ${role};`,
    ].join("\n")
  );
  return roleName;
};

const dropAppRole = (databaseUrl, roleName) => {
  if (!roleName) return;
  const role = quoteIdent(roleName);
  applyAdminSql(databaseUrl, `DROP OWNED BY ${role}; DROP ROLE IF EXISTS ${role};`);
};

const loadRlsFlags = (client) => {
  const tableList = rlsTargetTables.map(sqlLiteral).join(", ");
  return client.$queryRawUnsafe(`
    SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind = 'r'
      AND c.relname IN (${tableList})
    ORDER BY c.relname;
  `);
};

const assertRlsFlags = async (client, expectedEnabled, expectedForced) => {
  const rows = await loadRlsFlags(client);
  assert.equal(rows.length, rlsTargetTables.length, "All prototype RLS target tables must be present");
  for (const row of rows) {
    assert.equal(row.relrowsecurity, expectedEnabled, `${row.relname} relrowsecurity`);
    assert.equal(row.relforcerowsecurity, expectedForced, `${row.relname} relforcerowsecurity`);
  }
};

const withRlsContext = (client, context, callback) =>
  client.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT set_config('app.user_id', ${context.userId || ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.role', ${context.role || ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.licensee_id', ${context.licenseeId || ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.manufacturer_id', ${context.manufacturerId || ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.organization_id', ${context.organizationId || ""}, true)`;
    await tx.$executeRaw`SELECT set_config('app.is_platform_admin', ${context.isPlatformAdmin ? "true" : "false"}, true)`;
    return callback(tx);
  });

const idsFromRows = (rows) => rows.map((row) => row.id).sort();

const runBehaviorAssertions = async (appPrisma) => {
  await withRlsContext(
    appPrisma,
    {
      userId: ids.licenseeAdminA,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeA,
      organizationId: ids.orgA,
    },
    async (tx) => {
      const own = await tx.$queryRaw`SELECT "id" FROM "Batch" WHERE "id" = ${ids.batchA}`;
      const foreign = await tx.$queryRaw`SELECT "id" FROM "Batch" WHERE "id" = ${ids.batchB}`;
      const visible = await tx.$queryRaw`SELECT "id" FROM "Batch" ORDER BY "id"`;
      assert.equal(own.length, 1, "licensee A should read its own batch");
      assert.equal(foreign.length, 0, "licensee A must not read licensee B batch");
      assert.deepEqual(idsFromRows(visible), [ids.batchA], "licensee A batch list must be tenant-scoped");
    }
  );

  await withRlsContext(
    appPrisma,
    {
      userId: ids.manufacturerA,
      role: "MANUFACTURER",
      manufacturerId: ids.manufacturerA,
      organizationId: ids.orgA,
    },
    async (tx) => {
      const batches = await tx.$queryRaw`SELECT "id" FROM "Batch" ORDER BY "id"`;
      const qrCodes = await tx.$queryRaw`SELECT "id" FROM "QRCode" ORDER BY "id"`;
      assert.deepEqual(idsFromRows(batches), [ids.batchA], "manufacturer should read only linked/assigned licensee batches");
      assert.deepEqual(idsFromRows(qrCodes), [ids.qrA], "manufacturer should read only linked/assigned licensee QR data");
    }
  );

  await withRlsContext(
    appPrisma,
    {
      userId: ids.superAdmin,
      role: "SUPER_ADMIN",
      isPlatformAdmin: true,
    },
    async (tx) => {
      const batchRows = await tx.$queryRaw`SELECT "id" FROM "Batch" ORDER BY "id"`;
      const qrRows = await tx.$queryRaw`SELECT "id" FROM "QRCode" ORDER BY "id"`;
      const userRows = await tx.$queryRaw`SELECT "id" FROM "User" WHERE "id" IN (${ids.superAdmin}, ${ids.licenseeAdminA}, ${ids.licenseeAdminB}, ${ids.manufacturerA}, ${ids.manufacturerB}) ORDER BY "id"`;
      assert.deepEqual(idsFromRows(batchRows), [ids.batchA, ids.batchB], "platform admin context should read global batches");
      assert.deepEqual(idsFromRows(qrRows), [ids.qrA, ids.qrB], "platform admin context should read global QR rows");
      assert.equal(userRows.length, 5, "platform admin context should read global protected user rows");
    }
  );

  await withRlsContext(
    appPrisma,
    {
      role: "public_verification",
    },
    async (tx) => {
      const rawBatches = await tx.$queryRaw`SELECT "id" FROM "Batch"`;
      const rawUsers = await tx.$queryRaw`SELECT "id" FROM "User"`;
      const rawQrCodes = await tx.$queryRaw`SELECT "id", "code" FROM "QRCode" WHERE "code" = ${"P2A000001"}`;
      const rawDecisions = await tx.$queryRaw`SELECT "id" FROM "VerificationDecision"`;
      assert.equal(rawBatches.length, 0, "public verification must not raw SELECT Batch");
      assert.equal(rawUsers.length, 0, "public verification must not raw SELECT User");
      assert.equal(rawQrCodes.length, 0, "public verification must not raw SELECT QRCode");
      assert.equal(rawDecisions.length, 0, "public verification must not raw SELECT VerificationDecision");

      const safeRows = await tx.$queryRaw`SELECT * FROM app_rls.public_verify_qr_safe(${"P2A000001"})`;
      assert.equal(safeRows.length, 1, "public verification safe function should return the requested QR-safe row");
      assert.equal(safeRows[0].code, "P2A000001");
      assert.ok(Object.prototype.hasOwnProperty.call(safeRows[0], "status"), "safe function should expose status");
      assert.ok(!Object.prototype.hasOwnProperty.call(safeRows[0], "licenseeId"), "safe function must not expose licenseeId");
      assert.ok(!Object.prototype.hasOwnProperty.call(safeRows[0], "batchId"), "safe function must not expose batchId");
      assert.ok(!Object.prototype.hasOwnProperty.call(safeRows[0], "tokenHash"), "safe function must not expose tokenHash");
    }
  );
};

const main = async () => {
  let databaseInfo = null;
  let adminPrisma = null;
  let appPrisma = null;
  let appRole = null;

  process.env.NODE_ENV = "test";

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);

    adminPrisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });
    await seedP2Fixtures(adminPrisma);

    applySqlFile(databaseInfo.databaseUrl, prototypeSqlPath);
    await assertRlsFlags(adminPrisma, true, true);

    appRole = createAppRole(databaseInfo.databaseUrl);
    appPrisma = new PrismaClient({ datasources: { db: { url: buildRoleUrl(databaseInfo.databaseUrl, appRole) } } });
    await runBehaviorAssertions(appPrisma);
    await appPrisma.$disconnect();
    appPrisma = null;

    applySqlFile(databaseInfo.databaseUrl, rollbackSqlPath);
    await assertRlsFlags(adminPrisma, false, false);

    console.log("RLS prototype P2 behavioral tests passed");
  } catch (error) {
    if (error instanceof P2TestDbSkip && !isTruthy(process.env.P2_TEST_DATABASE_REQUIRED)) {
      console.log(`RLS prototype P2 test skipped: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    if (appPrisma?.$disconnect) await appPrisma.$disconnect().catch(() => {});
    if (adminPrisma?.$disconnect) await adminPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.databaseUrl && appRole) {
      try {
        dropAppRole(databaseInfo.databaseUrl, appRole);
      } catch (error) {
        console.warn(`RLS prototype P2 test role cleanup warning: ${error?.message || error}`);
      }
    }
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

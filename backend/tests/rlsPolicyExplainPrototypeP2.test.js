const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { PrismaClient } = require("@prisma/client");
const { withRlsPrototypeTransaction } = require("../dist/lib/rlsTransactionContextPrototype");

const {
  P2TestDbSkip,
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
} = require("./helpers/p2TestDb");
const { ids, seedP2Fixtures } = require("./helpers/p2SeedFactories");

const command = "MSCQR_RLS_EXPLAIN_PROTOTYPE_TEST=true npm --prefix backend run test:rls:explain-prototype";
const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

if (!isTruthy(process.env.MSCQR_RLS_EXPLAIN_PROTOTYPE_TEST)) {
  console.log(`RLS policy EXPLAIN prototype test skipped. Run with: ${command}`);
  process.exit(0);
}

const backendRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(backendRoot, "..");
const prototypeSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_prototype.sql");
const rollbackSqlPath = path.join(repoRoot, "documents/security/mscqr_staging_rls_rollback.sql");

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
  const roleName = `mscqr_rls_explain_${process.pid}_${Date.now()}`.toLowerCase();
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
      `GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${role};`,
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

const explain = async (tx, name, sql) => {
  const rows = await tx.$queryRawUnsafe(`EXPLAIN ${sql}`);
  assert.ok(Array.isArray(rows), `${name} should return EXPLAIN rows`);
  assert.ok(rows.length > 0, `${name} should produce at least one plan row`);
  return rows;
};

const runExplainAssertions = async (appPrisma) => {
  await withRlsPrototypeTransaction(
    appPrisma,
    {
      userId: ids.licenseeAdminA,
      role: "LICENSEE_ADMIN",
      licenseeId: ids.licenseeA,
      organizationId: ids.orgA,
    },
    async (tx) => {
      await explain(
        tx,
        "licensee batch list",
        'SELECT "id", "licenseeId", "manufacturerId", "updatedAt", "createdAt" FROM "Batch" ORDER BY "updatedAt" DESC, "createdAt" DESC LIMIT 20'
      );
      await explain(
        tx,
        "batch allocation-map read",
        `SELECT "id", "licenseeId", "manufacturerId", "parentBatchId", "rootBatchId", "createdAt" FROM "Batch" WHERE "licenseeId" = '${ids.licenseeA}' AND ("id" = '${ids.batchA}' OR "parentBatchId" = '${ids.batchA}' OR "rootBatchId" = '${ids.batchA}') ORDER BY "createdAt" ASC, "id" ASC LIMIT 100`
      );
      await explain(
        tx,
        "incident list",
        'SELECT "id", "licenseeId", "qrCodeId", "status", "createdAt" FROM "Incident" ORDER BY "createdAt" DESC LIMIT 20'
      );
      await explain(
        tx,
        "incident metadata read",
        `SELECT "id", "licenseeId", "qrCodeId", "status", "createdAt" FROM "Incident" WHERE "id" = '${ids.incidentA}' LIMIT 1`
      );
      await explain(
        tx,
        "QRCode lookup by code",
        "SELECT \"id\", \"code\", \"licenseeId\", \"batchId\" FROM \"QRCode\" WHERE \"code\" = 'P2A000001' LIMIT 1"
      );
      await explain(
        tx,
        "latest VerificationDecision by QR/code",
        `SELECT "id", "qrCodeId", "code", "createdAt" FROM "VerificationDecision" WHERE "qrCodeId" = '${ids.qrA}' OR "code" = 'P2A000001' ORDER BY "createdAt" DESC LIMIT 1`
      );
    }
  );

  await withRlsPrototypeTransaction(
    appPrisma,
    {
      userId: ids.manufacturerA,
      role: "MANUFACTURER",
      manufacturerId: ids.manufacturerA,
      organizationId: ids.orgA,
    },
    async (tx) => {
      await explain(
        tx,
        "manufacturer printer list/status read",
        'SELECT "id", "licenseeId", "orgId", "assignedUserId", "createdByUserId", "connectionType", "isActive", "createdAt" FROM "Printer" ORDER BY "connectionType" ASC, "isDefault" DESC, "name" ASC LIMIT 50'
      );
      await explain(
        tx,
        "manufacturer linked-licensee access",
        "SELECT b.\"id\", b.\"licenseeId\", b.\"manufacturerId\", b.\"createdAt\" FROM \"Batch\" b WHERE EXISTS (SELECT 1 FROM \"ManufacturerLicenseeLink\" mll WHERE mll.\"manufacturerId\" = current_setting('app.manufacturer_id', true) AND mll.\"licenseeId\" = b.\"licenseeId\") ORDER BY b.\"createdAt\" DESC LIMIT 20"
      );
    }
  );
};

const main = async () => {
  let databaseInfo = null;
  let adminPrisma = null;
  let appPrisma = null;
  let appRole = null;
  let prototypeApplied = false;
  let primaryError = null;
  let rollbackError = null;

  process.env.NODE_ENV = "test";

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);

    adminPrisma = new PrismaClient({ datasources: { db: { url: databaseInfo.databaseUrl } } });
    await seedP2Fixtures(adminPrisma);

    applySqlFile(databaseInfo.databaseUrl, prototypeSqlPath);
    prototypeApplied = true;

    appRole = createAppRole(databaseInfo.databaseUrl);
    appPrisma = new PrismaClient({ datasources: { db: { url: buildRoleUrl(databaseInfo.databaseUrl, appRole) } } });
    await runExplainAssertions(appPrisma);
  } catch (error) {
    if (error instanceof P2TestDbSkip && !isTruthy(process.env.P2_TEST_DATABASE_REQUIRED)) {
      console.log(`RLS policy EXPLAIN prototype test skipped: ${error.message}`);
      return;
    }
    primaryError = error;
  } finally {
    if (prototypeApplied && databaseInfo?.databaseUrl) {
      try {
        console.log("RLS policy EXPLAIN cleanup: applying rollback SQL");
        applySqlFile(databaseInfo.databaseUrl, rollbackSqlPath);
        prototypeApplied = false;
      } catch (error) {
        rollbackError = error;
      }
    }
    if (appPrisma?.$disconnect) await appPrisma.$disconnect().catch(() => {});
    if (adminPrisma?.$disconnect) await adminPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.databaseUrl && appRole) {
      try {
        dropAppRole(databaseInfo.databaseUrl, appRole);
      } catch (error) {
        console.warn(`RLS policy EXPLAIN app role cleanup warning: ${error?.message || error}`);
      }
    }
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }

  if (primaryError && rollbackError) {
    console.error("RLS policy EXPLAIN rollback failed after the original test failure:");
    console.error(rollbackError);
    primaryError.rollbackError = rollbackError;
    throw primaryError;
  }
  if (primaryError) throw primaryError;
  if (rollbackError) throw rollbackError;
  console.log("RLS policy EXPLAIN prototype test passed");
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { gunzipSync } = require("node:zlib");
const { canonicalJson, collectAppOnlyDatabaseCatalogueRows, hashProductionRlsCatalogue } = require("./production-printing-routine-delta-executor.cjs");
const historical = require("./production-seven-routine-scope.json");
const reviewed = require("./production-printing-restoration-scope.json");
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const database = "mscqr_production_rls_green_phase2";
const administrator = "mscqr_prod_admin";
const authOwner = "mscqr_prd_rls_phase2_auth_owner";
const schemaOwner = "mscqr_prd_rls_phase2_owner";
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const digest = value => sha256(canonicalJson(value));
const catalogueDigest = catalogue => {
  const rows = hashProductionRlsCatalogue(catalogue);
  return Object.fromEntries(collections.map(name => [name, digest(rows[name])]));
};

function decodeProductionPrintingRestorationPackage(encoded, expectedSha256) {
  assert.match(encoded ?? "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 32768);
  assert.match(expectedSha256 ?? "", /^[a-f0-9]{64}$/);
  const bytes = gunzipSync(Buffer.from(encoded, "base64"), { maxOutputLength: 256 * 1024 });
  assert.equal(sha256(bytes), expectedSha256);
  const pkg = JSON.parse(bytes.toString("utf8"));
  assert.equal(canonicalJson(pkg) + "\n", bytes.toString("utf8"));
  const { packageSha256, ...body } = pkg;
  assert.equal(packageSha256, digest(body));
  assert.equal(pkg.schemaVersion, 1);
  assert.equal(pkg.kind, "PRODUCTION_PRINTING_RESTORATION_DELTA");
  assert.equal(pkg.database, database);
  assert.equal(pkg.databaseInstance, historical.databaseInstance);
  assert.equal(pkg.databaseResourceId, historical.databaseResourceId);
  assert.match(pkg.databaseHostname ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);
  assert.match(pkg.sourceSha ?? "", /^[a-f0-9]{40}$/);
  assert.match(pkg.requirementsSha256 ?? "", /^[a-f0-9]{64}$/);
  assert.match(pkg.securityInventorySha256 ?? "", /^[a-f0-9]{64}$/);
  assert.deepEqual(pkg.predecessorCatalogue, historical.successorCatalogue);
  assert.equal(reviewed.kind, "PRODUCTION_PRINTING_RESTORATION_SCOPE");
  assert.deepEqual(pkg.successorCatalogue, reviewed.successorCatalogue);
  assert.equal(pkg.mutations?.length, 12);
  const names = ["printing_readiness", "printing_reissue_request", "printing_worker_reconcile"];
  for (const [index, row] of pkg.mutations.entries()) {
    assert.ok(typeof row.sql === "string" && Buffer.byteLength(row.sql) > 0 && Buffer.byteLength(row.sql) < 48 * 1024);
    if (index < 3) {
      assert.equal(row.owner, "auth");
      assert.ok(row.sql.startsWith(`CREATE OR REPLACE FUNCTION app_rls.${names[index]}(`));
    } else {
      assert.equal(row.owner, "schema");
      assert.match(row.sql, index < 5 ? /^GRANT SELECT \(/ : /^(?:DROP POLICY|CREATE POLICY|COMMENT ON POLICY) /);
    }
  }
  assert.deepEqual(pkg.mutations.slice(3, 5).map(row => row.sql), [
    'GRANT SELECT ("printItemId") ON TABLE public."PrintItemEvent" TO "mscqr_prd_rls_phase2_auth_owner";',
    'GRANT SELECT ("printJobId", "printSessionId") ON TABLE public."PrintJobChunk" TO "mscqr_prd_rls_phase2_auth_owner";',
  ]);
  const sql = pkg.mutations.map(row => row.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n";
  assert.equal(pkg.sqlSha256, sha256(sql));
  assert.equal(pkg.sqlSha256, reviewed.sqlSha256, "Only reviewed printing-restoration SQL may run");
  return pkg;
}

async function executeProductionPrintingRestorationTransaction({ tx, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows,
  checkpoint = async () => {} }) {
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '2s'");
  await tx.$executeRawUnsafe("SET LOCAL statement_timeout = '120s'");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-printing-restoration',0))");
  const validateIdentity = value => {
    assert.equal(value.role, administrator); assert.equal(value.session_role, administrator);
    assert.equal(value.database, database); assert.equal(value.read_only, "off");
    assert.equal(value.rolsuper, false); assert.equal(value.rolbypassrls, false);
    assert.equal(value.rolcreaterole, true); assert.equal(value.rolcreatedb, true);
  };
  const [version] = await tx.$queryRawUnsafe("SELECT current_setting('server_version_num') AS value");
  assert.equal(version.value, "180004");
  const before = catalogueDigest(await collect(tx, validateIdentity));
  if (canonicalJson(before) === canonicalJson(pkg.successorCatalogue)) return { status: "ALREADY_CONVERGED", writeCount: 0 };
  assert.deepEqual(before, pkg.predecessorCatalogue, "Production predecessor catalogue differs");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${schemaOwner}`);
  await tx.$executeRawUnsafe(`GRANT CREATE ON SCHEMA app_rls TO ${authOwner}`);
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("after-temporary-grant");
  let writeCount = 0;
  for (const owner of ["auth", "schema"]) {
    await tx.$executeRawUnsafe(`SET LOCAL ROLE ${owner === "auth" ? authOwner : schemaOwner}`);
    if (owner === "schema") await tx.$executeRawUnsafe(`REVOKE CREATE ON SCHEMA app_rls FROM ${authOwner}`);
    for (const mutation of pkg.mutations.filter(row => row.owner === owner)) {
      await tx.$executeRawUnsafe(mutation.sql);
      await checkpoint(`after-${++writeCount}`);
    }
    await tx.$executeRawUnsafe("RESET ROLE");
  }
  assert.equal(writeCount, 12);
  assert.deepEqual(catalogueDigest(await collect(tx, validateIdentity)), pkg.successorCatalogue,
    "Production successor catalogue differs");
  return { status: "APPLIED", writeCount };
}

async function main() {
  let client;
  try {
    assert.equal(process.argv.length, 5);
    const [encoded, payloadHash, hostname] = process.argv.slice(2);
    const pkg = decodeProductionPrintingRestorationPackage(encoded, payloadHash);
    assert.equal(hostname, pkg.databaseHostname);
    assert.deepEqual(JSON.parse(fs.readFileSync("/app/image-source.json", "utf8")), { gitSha: pkg.sourceSha });
    assert.equal(process.env.RELEASE_GIT_SHA, pkg.sourceSha);
    const password = process.env.MSCQR_RLS_SEVEN_ADMIN_PASSWORD;
    assert.ok(password);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = administrator; url.password = password; url.hostname = hostname; url.port = "5432";
    url.searchParams.set("sslmode", "require");
    url.searchParams.set("application_name", "mscqr-production-printing-restoration");
    const { PrismaClient } = require("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    const result = await client.$transaction(tx => executeProductionPrintingRestorationTransaction({ tx, package: pkg }),
      { maxWait: 10000, timeout: 180000 });
    const successor = await client.$transaction(async tx => {
      await tx.$executeRawUnsafe("SET TRANSACTION READ ONLY");
      return catalogueDigest(await collectAppOnlyDatabaseCatalogueRows(tx, identity => {
        assert.equal(identity.role, administrator); assert.equal(identity.session_role, administrator);
        assert.equal(identity.database, database); assert.equal(identity.read_only, "on");
        assert.equal(identity.rolsuper, false); assert.equal(identity.rolbypassrls, false);
      }));
    }, { maxWait: 10000, timeout: 60000 });
    assert.deepEqual(successor, pkg.successorCatalogue);
    const body = { schemaVersion: 1, kind: "PRODUCTION_PRINTING_RESTORATION_RESULT", sourceSha: pkg.sourceSha,
      packageSha256: pkg.packageSha256, sqlSha256: pkg.sqlSha256, database, databaseRole: administrator,
      successorCatalogue: successor, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: digest(body) })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"printing-restoration-failed-closed"}\n');
    process.exitCode = 1;
  } finally { if (client) await client.$disconnect(); }
}

module.exports = { decodeProductionPrintingRestorationPackage, executeProductionPrintingRestorationTransaction, catalogueDigest };
if (require.main === module) main();

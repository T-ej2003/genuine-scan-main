"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { gunzipSync } = require("node:zlib");
const { canonicalJson, collectAppOnlyDatabaseCatalogueRows, hashProductionRlsCatalogue } = require("./production-printing-routine-delta-executor.cjs");
const scopeBytes = fs.readFileSync(require.resolve("./production-seven-routine-scope.json"));
const scope = JSON.parse(scopeBytes);
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

function decodeProductionSevenRoutinePackage(encoded, expectedSha256) {
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
  assert.equal(pkg.kind, "PRODUCTION_RLS_SEVEN_ROUTINE_PACKAGE");
  assert.equal(pkg.database, database);
  assert.equal(pkg.databaseInstance, scope.databaseInstance);
  assert.equal(pkg.databaseResourceId, scope.databaseResourceId);
  assert.match(pkg.databaseHostname ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);
  assert.match(pkg.sourceSha ?? "", /^[a-f0-9]{40}$/);
  assert.match(pkg.requirementsSha256 ?? "", /^[a-f0-9]{64}$/);
  assert.match(pkg.securityInventorySha256 ?? "", /^[a-f0-9]{64}$/);
  assert.equal(pkg.scopeSha256, sha256(scopeBytes));
  assert.deepEqual(pkg.predecessorCatalogue, scope.predecessorCatalogue);
  assert.deepEqual(pkg.successorCatalogue, scope.successorCatalogue);
  assert.equal(pkg.mutations?.length, 7);
  for (const [index, item] of pkg.mutations.entries()) {
    const reviewed = scope.objects[index];
    assert.equal(item.identity, reviewed.identity);
    assert.equal(item.owner, index < 5 ? "auth" : "schema");
    assert.ok(typeof item.sql === "string" && item.sql.length > 0 && item.sql.length < 30000);
    assert.ok(item.sql.startsWith(`CREATE OR REPLACE FUNCTION ${item.identity.slice(0, item.identity.indexOf("("))}(`));
  }
  const sql = pkg.mutations.map(item => item.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n";
  assert.equal(pkg.sqlSha256, sha256(sql));
  assert.equal(pkg.sqlSha256, scope.sqlSha256, "Only reviewed seven-routine SQL may run");
  return pkg;
}

async function executeProductionSevenRoutineTransaction({ tx, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows,
  checkpoint = async () => {} }) {
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '2s'");
  await tx.$executeRawUnsafe("SET LOCAL statement_timeout = '120s'");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-rls-seven-routine',0))");
  const validateIdentity = value => {
    assert.equal(value.role, administrator); assert.equal(value.session_role, administrator);
    assert.equal(value.database, database); assert.equal(value.read_only, "off");
    assert.equal(value.rolsuper, false); assert.equal(value.rolbypassrls, false);
    assert.equal(value.rolcreaterole, true); assert.equal(value.rolcreatedb, true);
  };
  const [version] = await tx.$queryRawUnsafe("SELECT current_setting('server_version_num') AS value");
  assert.equal(version.value, "180004", "Production migration requires PostgreSQL 18.4");
  const before = catalogueDigest(await collect(tx, validateIdentity));
  if (canonicalJson(before) === canonicalJson(pkg.successorCatalogue)) return { status: "ALREADY_CONVERGED", writeCount: 0 };
  assert.equal(canonicalJson(before), canonicalJson(pkg.predecessorCatalogue), "Production predecessor catalogue differs");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${schemaOwner}`);
  await tx.$executeRawUnsafe(`GRANT CREATE ON SCHEMA app_rls TO ${authOwner}`);
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("after-temporary-grant");
  let writeCount = 0;
  for (const owner of ["auth", "schema"]) {
    await tx.$executeRawUnsafe(`SET LOCAL ROLE ${owner === "auth" ? authOwner : schemaOwner}`);
    if (owner === "schema") await tx.$executeRawUnsafe(`REVOKE CREATE ON SCHEMA app_rls FROM ${authOwner}`);
    for (const mutation of pkg.mutations.filter(item => item.owner === owner)) {
      await tx.$executeRawUnsafe(mutation.sql);
      writeCount++;
      await checkpoint(`after-${writeCount}`);
    }
    await tx.$executeRawUnsafe("RESET ROLE");
  }
  assert.equal(writeCount, 7);
  assert.equal(canonicalJson(catalogueDigest(await collect(tx, validateIdentity))), canonicalJson(pkg.successorCatalogue),
    "Production successor catalogue differs");
  return { status: "APPLIED", writeCount };
}

async function verifyProductionSevenRoutineCommitted({ client, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows }) {
  const verified = await client.$transaction(async tx => {
    await tx.$executeRawUnsafe("SET TRANSACTION READ ONLY");
    return catalogueDigest(await collect(tx, value => {
      assert.equal(value.role, administrator); assert.equal(value.session_role, administrator);
      assert.equal(value.database, database); assert.equal(value.read_only, "on");
      assert.equal(value.rolsuper, false); assert.equal(value.rolbypassrls, false);
    }));
  }, { maxWait: 10000, timeout: 60000 });
  assert.deepEqual(verified, pkg.successorCatalogue);
  return verified;
}

async function main() {
  let client;
  try {
    assert.equal(process.argv.length, 5);
    const [encoded, payloadHash, hostname] = process.argv.slice(2);
    assert.match(hostname ?? "", /^[a-z0-9.-]+$/);
    const pkg = decodeProductionSevenRoutinePackage(encoded, payloadHash);
    assert.equal(hostname, pkg.databaseHostname);
    const imageSource = JSON.parse(fs.readFileSync("/app/image-source.json", "utf8"));
    assert.deepEqual(imageSource, { gitSha: pkg.sourceSha });
    assert.equal(process.env.RELEASE_GIT_SHA, pkg.sourceSha);
    const password = process.env.MSCQR_RLS_SEVEN_ADMIN_PASSWORD;
    assert.ok(password);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = administrator; url.password = password; url.hostname = hostname; url.port = "5432";
    url.searchParams.set("sslmode", "require");
    url.searchParams.set("application_name", "mscqr-production-rls-seven-routine");
    const { PrismaClient } = require("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    const result = await client.$transaction(tx => executeProductionSevenRoutineTransaction({ tx, package: pkg }),
      { maxWait: 10000, timeout: 180000 });
    const successorCatalogue = await verifyProductionSevenRoutineCommitted({ client, package: pkg });
    const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_SEVEN_ROUTINE_RESULT", sourceSha: pkg.sourceSha,
      packageSha256: pkg.packageSha256, sqlSha256: pkg.sqlSha256, database, databaseRole: administrator,
      successorCatalogue, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: digest(body) })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"rls-seven-routine-failed-closed"}\n');
    process.exitCode = 1;
  } finally { if (client) await client.$disconnect(); }
}

module.exports = { decodeProductionSevenRoutinePackage, executeProductionSevenRoutineTransaction,
  verifyProductionSevenRoutineCommitted, catalogueDigest };
if (require.main === module) main();

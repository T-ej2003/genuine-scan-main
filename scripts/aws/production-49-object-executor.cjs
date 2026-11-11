"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const { gunzipSync } = require("node:zlib");
const { canonicalJson, collectAppOnlyDatabaseCatalogueRows, hashProductionRlsCatalogue } = require("./production-printing-routine-delta-executor.cjs");
const scopeBytes = fs.readFileSync(require.resolve("./production-49-object-scope.json"));
const scope = JSON.parse(scopeBytes);
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const database = "mscqr_production_rls_green_phase2";
const administrator = "mscqr_prod_admin";
const schemaOwner = "mscqr_prd_rls_phase2_owner";
const authOwner = "mscqr_prd_rls_phase2_auth_owner";
const sha256 = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const digest = value => sha256(canonicalJson(value));
const catalogueDigest = catalogue => {
  const rows = hashProductionRlsCatalogue(catalogue);
  return Object.fromEntries(collections.map(name => [name, digest(rows[name])]));
};

function decodeProduction49Package(encoded, expectedSha256) {
  assert.match(encoded ?? "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 32768);
  assert.match(expectedSha256 ?? "", /^[a-f0-9]{64}$/);
  const bytes = gunzipSync(Buffer.from(encoded, "base64"), { maxOutputLength: 256 * 1024 });
  assert.equal(sha256(bytes), expectedSha256);
  const value = JSON.parse(bytes.toString("utf8"));
  assert.equal(canonicalJson(value) + "\n", bytes.toString("utf8"));
  const { packageSha256, ...body } = value;
  assert.equal(packageSha256, digest(body));
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.kind, "PRODUCTION_RLS_49_OBJECT_INCREMENTAL_PACKAGE");
  assert.equal(body.database, database);
  assert.equal(body.databaseInstance, scope.databaseInstance);
  assert.equal(body.databaseResourceId, scope.databaseResourceId);
  assert.match(body.databaseHostname ?? "", /^[a-z0-9.-]+\.rds\.amazonaws\.com$/);
  assert.match(body.sourceSha ?? "", /^[a-f0-9]{40}$/);
  assert.match(body.requirementsSha256 ?? "", /^[a-f0-9]{64}$/);
  assert.match(body.securityInventorySha256 ?? "", /^[a-f0-9]{64}$/);
  assert.equal(body.scopeSha256, sha256(scopeBytes));
  for (const catalogue of [body.predecessorCatalogue, body.successorCatalogue]) {
    assert.deepEqual(Object.keys(catalogue ?? {}).sort(), [...collections].sort());
    for (const hash of Object.values(catalogue)) assert.match(hash, /^[a-f0-9]{64}$/);
  }
  assert.deepEqual(body.predecessorCatalogue, scope.predecessorCatalogue);
  assert.deepEqual(body.successorCatalogue, scope.successorCatalogue);
  assert.equal(body.mutations?.length, 50);
  const identities = body.mutations.map(row => row.identity);
  assert.deepEqual([...new Set(identities)].sort(), scope.objects.map(row => row.identity).sort());
  assert.ok(body.mutations.slice(0, 5).every(row => row.owner === "auth"));
  assert.ok(body.mutations.slice(5).every(row => row.owner === "schema"));
  assert.ok(body.mutations.every(row => typeof row.sql === "string" && row.sql.length > 0 && row.sql.length < 30000));
  const sql = body.mutations.map(row => row.sql.trimEnd().replace(/;$/, "")).join(";\n") + ";\n";
  assert.equal(body.sqlSha256, sha256(sql));
  assert.equal(body.sqlSha256, scope.sqlSha256, "Only reviewed SQL may run");
  return value;
}

async function executeProduction49Transaction({ tx, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows,
  checkpoint = async () => {} }) {
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '2s'");
  await tx.$executeRawUnsafe("SET LOCAL statement_timeout = '120s'");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-rls-49-object',0))");
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
      writeCount += 1;
      await checkpoint(`after-${writeCount}`);
    }
    await tx.$executeRawUnsafe("RESET ROLE");
  }
  assert.equal(writeCount, 50);
  assert.equal(canonicalJson(catalogueDigest(await collect(tx, validateIdentity))), canonicalJson(pkg.successorCatalogue),
    "Production successor catalogue differs");
  return { status: "APPLIED", writeCount };
}

async function verifyProduction49Committed({ client, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows }) {
  const verified = await client.$transaction(async tx => {
    await tx.$executeRawUnsafe("SET TRANSACTION READ ONLY");
    return catalogueDigest(await collect(tx, value => {
      assert.equal(value.role, administrator); assert.equal(value.session_role, administrator);
      assert.equal(value.database, database); assert.equal(value.read_only, "on");
      assert.equal(value.rolsuper, false); assert.equal(value.rolbypassrls, false);
    }));
  }, { maxWait: 10000, timeout: 60000 });
  assert.equal(canonicalJson(verified), canonicalJson(pkg.successorCatalogue));
  return verified;
}

async function main() {
  let client;
  try {
    assert.equal(process.argv.length, 5);
    const [encoded, payloadHash, hostname] = process.argv.slice(2);
    assert.match(hostname ?? "", /^[a-z0-9.-]+$/);
    const pkg = decodeProduction49Package(encoded, payloadHash);
    assert.equal(hostname, pkg.databaseHostname);
    const imageSource = JSON.parse(fs.readFileSync("/app/image-source.json", "utf8"));
    assert.deepEqual(imageSource, { gitSha: pkg.sourceSha });
    assert.equal(process.env.RELEASE_GIT_SHA, pkg.sourceSha);
    const password = process.env.MSCQR_RLS_49_ADMIN_PASSWORD;
    assert.ok(password);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = administrator; url.password = password; url.hostname = hostname; url.port = "5432";
    url.searchParams.set("sslmode", "require");
    url.searchParams.set("application_name", "mscqr-production-rls-49-object");
    const { PrismaClient } = require("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    const result = await client.$transaction(tx => executeProduction49Transaction({ tx, package: pkg }),
      { maxWait: 10000, timeout: 180000 });
    const successorCatalogue = await verifyProduction49Committed({ client, package: pkg });
    const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_49_OBJECT_RESULT", sourceSha: pkg.sourceSha,
      packageSha256: pkg.packageSha256, sqlSha256: pkg.sqlSha256, database, databaseRole: administrator,
      successorCatalogue, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: digest(body) })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"rls-49-object-failed-closed"}\n');
    process.exitCode = 1;
  } finally { if (client) await client.$disconnect(); }
}

module.exports = { decodeProduction49Package, executeProduction49Transaction, verifyProduction49Committed, catalogueDigest };
if (require.main === module) main();

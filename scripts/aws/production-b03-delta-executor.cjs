"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { gunzipSync } = require("node:zlib");
const { canonicalJson, collectAppOnlyDatabaseCatalogueRows, hashProductionRlsCatalogue } = require("./production-printing-routine-delta-executor.cjs");

const database = "mscqr_production_rls_green_phase2";
const administrator = "mscqr_prod_admin";
const schemaOwner = "mscqr_prd_rls_phase2_owner";
const authOwner = "mscqr_prd_rls_phase2_auth_owner";
const collections = ["routines", "tables", "policies", "schemas", "roles"];
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const digest = (value) => sha256(canonicalJson(value));

function decodePackage(encoded, expectedSha256) {
  assert.match(encoded || "", /^[A-Za-z0-9+/]+={0,2}$/);
  assert.ok(encoded.length <= 32768);
  assert.match(expectedSha256 || "", /^[a-f0-9]{64}$/);
  const bytes = gunzipSync(Buffer.from(encoded, "base64"), { maxOutputLength: 96 * 1024 });
  assert.equal(sha256(bytes), expectedSha256);
  const value = JSON.parse(bytes.toString("utf8"));
  assert.equal(canonicalJson(value), bytes.toString("utf8"));
  const { packageSha256, ...body } = value;
  assert.equal(packageSha256, digest(body));
  assert.equal(body.schemaVersion, 1);
  assert.equal(body.kind, "PRODUCTION_B03_INCREMENTAL_PACKAGE");
  assert.equal(body.predecessorSourceSha, "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec");
  assert.match(body.sourceSha || "", /^[a-f0-9]{40}$/);
  assert.match(body.predecessorRequirementsSha256 || "", /^[a-f0-9]{64}$/);
  assert.match(body.successorRequirementsSha256 || "", /^[a-f0-9]{64}$/);
  for (const value of [body.predecessorCatalogue, body.successorCatalogue]) {
    assert.deepEqual(Object.keys(value || {}).sort(), [...collections].sort());
    for (const hash of Object.values(value)) assert.match(hash, /^[a-f0-9]{64}$/);
  }
  assert.equal(body.mutations?.length, 44);
  assert.ok(body.mutations.every(({ owner, sql }) => ["auth", "schema"].includes(owner) && typeof sql === "string" && sql.length < 10000));
  return value;
}

function catalogueDigest(catalogue) {
  const rows = hashProductionRlsCatalogue(catalogue);
  return Object.fromEntries(collections.map((name) => [name, digest(rows[name])]));
}

async function executeB03DeltaTransaction({ tx, package: pkg,
  collect = collectAppOnlyDatabaseCatalogueRows, checkpoint = async () => {} }) {
  const predecessor = pkg.predecessorCatalogue, successor = pkg.successorCatalogue;
  assert.deepEqual(Object.keys(predecessor).sort(), [...collections].sort());
  assert.deepEqual(Object.keys(successor).sort(), [...collections].sort());
  for (const value of [...Object.values(predecessor), ...Object.values(successor)]) assert.match(value, /^[a-f0-9]{64}$/);
  await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE");
  await tx.$executeRawUnsafe("SET LOCAL lock_timeout = '15s'");
  await tx.$executeRawUnsafe("SET LOCAL statement_timeout = '60s'");
  await tx.$executeRawUnsafe("SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('mscqr-production-b03-incremental',0))");
  const validateIdentity = (identity) => {
    assert.equal(identity.role, administrator); assert.equal(identity.session_role, administrator);
    assert.equal(identity.database, database); assert.equal(identity.read_only, "off");
    assert.equal(identity.rolsuper, false); assert.equal(identity.rolbypassrls, false);
    assert.equal(identity.rolcreaterole, true); assert.equal(identity.rolcreatedb, true);
  };
  const before = catalogueDigest(await collect(tx, validateIdentity));
  if (canonicalJson(before) === canonicalJson(successor)) return { status: "ALREADY_CONVERGED", writeCount: 0 };
  assert.equal(canonicalJson(before), canonicalJson(predecessor), "B03 predecessor catalogue is not exact");
  await tx.$executeRawUnsafe(`SET LOCAL ROLE ${schemaOwner}`);
  await tx.$executeRawUnsafe(`GRANT CREATE ON SCHEMA app_rls TO ${authOwner}`);
  await tx.$executeRawUnsafe("RESET ROLE");
  await checkpoint("after-temporary-grant");
  let writeCount = 0;
  for (const owner of ["auth", "schema"]) {
    await tx.$executeRawUnsafe(`SET LOCAL ROLE ${owner === "auth" ? authOwner : schemaOwner}`);
    if (owner === "schema") await tx.$executeRawUnsafe(`REVOKE CREATE ON SCHEMA app_rls FROM ${authOwner}`);
    for (const mutation of pkg.mutations.filter((item) => item.owner === owner)) {
      await tx.$executeRawUnsafe(mutation.sql);
      writeCount += 1;
      await checkpoint(`after-${writeCount}`);
    }
    await tx.$executeRawUnsafe("RESET ROLE");
  }
  assert.equal(writeCount, 44);
  assert.equal(canonicalJson(catalogueDigest(await collect(tx, validateIdentity))), canonicalJson(successor), "B03 successor catalogue verification failed");
  return { status: "APPLIED", writeCount };
}

async function verifyCommittedB03Catalogue({ client, package: pkg, collect = collectAppOnlyDatabaseCatalogueRows }) {
  const verified = await client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET TRANSACTION READ ONLY");
    const identity = (value) => {
      assert.equal(value.role, administrator); assert.equal(value.session_role, administrator);
      assert.equal(value.database, database); assert.equal(value.read_only, "on");
      assert.equal(value.rolsuper, false); assert.equal(value.rolbypassrls, false);
    };
    return catalogueDigest(await collect(tx, identity));
  }, { maxWait: 10000, timeout: 60000 });
  assert.equal(canonicalJson(verified), canonicalJson(pkg.successorCatalogue), "Committed B03 catalogue differs from successor");
  return verified;
}

async function main() {
  let client;
  try {
    assert.equal(process.argv.length, 5, "B03 executor arguments are immutable");
    const [encoded, payloadHash, hostname] = process.argv.slice(2);
    assert.match(hostname || "", /^[a-z0-9.-]+$/);
    const pkg = decodePackage(encoded, payloadHash);
    assert.equal(pkg.sourceSha, process.env.RELEASE_GIT_SHA);
    const password = process.env.MSCQR_B03_DELTA_ADMIN_PASSWORD;
    assert.ok(password);
    const url = new URL(`postgresql://unused/${database}`);
    url.username = administrator; url.password = password; url.hostname = hostname; url.port = "5432";
    url.searchParams.set("sslmode", "require"); url.searchParams.set("application_name", "mscqr-production-b03-incremental");
    const { PrismaClient } = require("@prisma/client");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    const result = await client.$transaction((tx) => executeB03DeltaTransaction({ tx, package: pkg }),
      { maxWait: 10000, timeout: 180000 });
    const verified = await verifyCommittedB03Catalogue({ client, package: pkg });
    const body = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_RESULT", sourceSha: pkg.sourceSha,
      packageSha256: pkg.packageSha256, database, databaseRole: administrator, successorCatalogue: verified, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: digest(body) })}\n`);
  } catch {
    process.stderr.write('{"status":"blocked","reason":"b03-incremental-failed-closed"}\n');
    process.exitCode = 1;
  } finally { if (client) await client.$disconnect(); }
}

module.exports = { catalogueDigest, decodePackage, executeB03DeltaTransaction, verifyCommittedB03Catalogue };
if (require.main === module) main();

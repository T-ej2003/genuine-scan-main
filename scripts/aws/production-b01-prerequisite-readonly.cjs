"use strict";

async function executeB01ReadOnlyTransaction({ client, input, collect, inspect, lockSql, stage = () => {}, lockTimeoutMs = 10000 }) {
  if (!Number.isInteger(lockTimeoutMs) || lockTimeoutMs <= 0 || lockTimeoutMs > 10000) throw new TypeError("B01 synchronization timeout is invalid.");
  if (typeof lockSql !== "string" || !lockSql.startsWith("SELECT pg_catalog.pg_advisory_xact_lock(")) throw new TypeError("B01 synchronization lock is invalid.");
  return client.$transaction(async (tx) => {
    await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY");
    await tx.$executeRawUnsafe(`SET LOCAL statement_timeout = '${lockTimeoutMs}ms'`);
    stage("DATABASE_SYNCHRONIZATION");
    await tx.$executeRawUnsafe(lockSql);
    await tx.$executeRawUnsafe("SET LOCAL statement_timeout = '0'");
    stage("PREDECESSOR_COLLECTION");
    const state = await collect(tx);
    stage("PREDECESSOR_CLASSIFICATION");
    const result = inspect(state, input.contract, "on");
    return {
      classification: result.classification,
      liveRlsIdentity: result.identity,
      livePredecessorMatch: result.classification === "PREDECESSOR",
      liveSuccessorMatch: result.classification === "SUCCESSOR",
      unauthorizedCatalogueDelta: result.classification === "PARTIAL",
      temporaryPrivilegeResidue: result.classification === "PARTIAL" ? null : false,
      mismatchIdentifiers: result.classification === "PARTIAL" ? ["CATALOGUE_IDENTITY"] : [],
      transactionReadOnly: state.identity.read_only === "on",
    };
  }, { maxWait: 5000, timeout: 30000 });
}

async function readOnlyMain(argv = process.argv.slice(2)) {
  let client, stage = "BOOTSTRAP";
  try {
    const { gunzipSync } = require("node:zlib");
    stage = "INPUT_AUTHENTICATION";
    assert.equal(argv.length, 2);
    const bytes = gunzipSync(Buffer.from(argv[0], "base64"), { maxOutputLength: 128 * 1024 });
    assert.equal(hash(bytes), argv[1]);
    const input = JSON.parse(bytes); assert.equal(canonicalJson(input), bytes.toString("utf8"));
    assert.equal(hash(input.contract), input.contractSha256);
    assert.equal(input.contract.rlsDeltaOriginSha, ORIGIN);
    assert.match(input.contract.deploymentSourceSha || "", /^[a-f0-9]{40}$/);
    assert.match(input.contract.ambiguousMutationTaskEvidenceSha256 || "", /^[a-f0-9]{64}$/);
    assert.equal(input.contract.migrationSetDigest, "6642442a81cd98c7a132d241fa98e50ae231510896c9da67ab70d86b050d02db");
    assert.equal(input.contract.sourceContractSha256, "099399a7d3f4b2392acdba6c54bf1ac6a919ff60691e69d31023d32161d99e71");
    stage = "SECRET_ACCESS";
    assert.ok(typeof process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD === "string" && process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD.length > 0);
    const { PrismaClient } = require("@prisma/client");
    const url = new URL(`postgresql://${ADMIN}:${encodeURIComponent(process.env.MSCQR_B01_PREREQUISITE_ADMIN_PASSWORD)}@${input.databaseHostname}:5432/${DATABASE}`);
    url.searchParams.set("sslmode", "require"); url.searchParams.set("application_name", "mscqr-production-b01-prerequisite-readonly");
    client = new PrismaClient({ datasources: { db: { url: url.toString() } } });
    stage = "DATABASE_CONNECTIVITY"; await client.$connect();
    stage = "DATABASE_SYNCHRONIZATION";
    const result = await executeB01ReadOnlyTransaction({ client, input, collect: collectB01State, inspect: inspectB01State,
      lockSql: B01_MUTATION_ADVISORY_LOCK_SQL, stage: (value) => { stage = value; } });
    stage = "RECEIPT_PRECONDITION";
    const body = { schemaVersion: 1, kind: "PRODUCTION_B01_READONLY_RESULT", mode: "READ_ONLY", rlsDeltaOriginSha: ORIGIN,
      contractSha256: input.contractSha256, ...result };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: hash(body) })}\n`);
  } catch (error) {
    const body = { schemaVersion: 1, kind: "PRODUCTION_B01_READONLY_RESULT", mode: "READ_ONLY", classification: "UNKNOWN",
      stage, code: error?.name === "AssertionError" ? "CONTRACT_REJECTED" : "UNEXPECTED_FAILURE" };
    process.stdout.write(`${JSON.stringify({ ...body, evidenceSha256: hash(body) })}\n`); process.exitCode = 2;
  } finally { if (client) try { await client.$disconnect(); } catch {} }
}

module.exports = { executeB01ReadOnlyTransaction };
if (module.id === "[eval]") readOnlyMain(process.argv.slice(1));

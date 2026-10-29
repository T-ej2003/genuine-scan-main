import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import { canonicalJson, canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const runtime = createRequire(import.meta.url)("../aws/production-b03-delta-executor.cjs");
const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const empty = () => ({ routines: [], tables: [], policies: [], schemas: [], roles: [] });
const successor = () => ({ ...empty(), routines: [{ schema: "app_rls", name: "synthetic", arguments: "", body: "new" }] });
const pkg = (before, after) => {
  const catalogue = (value) => runtime.catalogueDigest(value);
  const body = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_PACKAGE", predecessorSourceSha: "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec",
    sourceSha: "4".repeat(40), predecessorRequirementsSha256: "1".repeat(64), successorRequirementsSha256: "2".repeat(64),
    predecessorCatalogue: catalogue(before), successorCatalogue: catalogue(after),
    mutations: Array.from({ length: 44 }, (_, index) => ({ owner: index < 22 ? "auth" : "schema", sql: `SELECT ${index}` })) };
  return { ...body, packageSha256: canonicalSha256(body) };
};

test("B03 package transport is bounded and detects altered bytes", () => {
  const value = pkg(empty(), successor());
  const bytes = Buffer.from(canonicalJson(value));
  const encoded = gzipSync(bytes, { level: 9, mtime: 0 }).toString("base64");
  assert.deepEqual(runtime.decodePackage(encoded, hash(bytes)), value);
  assert.throws(() => runtime.decodePackage(encoded, "0".repeat(64)));
  assert.throws(() => runtime.decodePackage(encoded, hash(bytes).slice(1)));
});

test("B03 transaction accepts only exact predecessor and verifies successor", async () => {
  const before = empty(), after = successor(), value = pkg(before, after);
  let writes = 0, collected = 0;
  const tx = { $executeRawUnsafe: async (sql) => { if (sql.startsWith("SELECT ") && /^SELECT \d+$/.test(sql)) writes += 1; } };
  const collect = async (_tx, validateIdentity) => {
    validateIdentity({ role: "mscqr_prod_admin", session_role: "mscqr_prod_admin", database: "mscqr_production_rls_green_phase2",
      read_only: "off", rolsuper: false, rolbypassrls: false, rolcreaterole: true, rolcreatedb: true });
    return ++collected === 1 ? before : after;
  };
  assert.deepEqual(await runtime.executeB03DeltaTransaction({ tx, package: value, collect }), { status: "APPLIED", writeCount: 44 });
  assert.equal(writes, 44);
  await assert.rejects(runtime.executeB03DeltaTransaction({ tx, package: value, collect: async () => ({ ...before, routines: [{ schema: "app_rls", name: "unknown", arguments: "", body: "drift" }] }) }), /predecessor catalogue is not exact/);
  assert.deepEqual(await runtime.executeB03DeltaTransaction({ tx, package: value, collect: async () => after }), { status: "ALREADY_CONVERGED", writeCount: 0 });
});

test("interrupted B03 execution cannot claim completion", async () => {
  const before = empty(), after = successor(), value = pkg(before, after);
  const tx = { $executeRawUnsafe: async () => {} };
  for (const stage of ["after-temporary-grant", "after-1", "after-22", "after-44"]) {
    await assert.rejects(runtime.executeB03DeltaTransaction({ tx, package: value, collect: async () => before,
      checkpoint: async (point) => { if (point === stage) throw new Error(stage); } }), new RegExp(stage));
  }
});

test("B03 completion requires a fresh read-only committed successor", async () => {
  const value = pkg(empty(), successor());
  const statements = [];
  const client = { $transaction: async (run) => run({ $executeRawUnsafe: async (sql) => { statements.push(sql); } }) };
  const collect = async (_tx, identity) => {
    identity({ role: "mscqr_prod_admin", session_role: "mscqr_prod_admin", database: "mscqr_production_rls_green_phase2",
      read_only: "on", rolsuper: false, rolbypassrls: false });
    return successor();
  };
  assert.deepEqual(await runtime.verifyCommittedB03Catalogue({ client, package: value, collect }), value.successorCatalogue);
  assert.deepEqual(statements, ["SET TRANSACTION READ ONLY"]);
  await assert.rejects(runtime.verifyCommittedB03Catalogue({ client, package: value, collect: async () => empty() }), /Committed B03 catalogue differs/);
});

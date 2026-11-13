import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { authenticateProductionSevenRoutineResult, buildProductionSevenRoutineTaskDefinition } from "../aws/production-seven-routine-package.mjs";

const require = createRequire(import.meta.url);
const { catalogueDigest, decodeProductionSevenRoutinePackage, executeProductionSevenRoutineTransaction } = require("../aws/production-seven-routine-executor.cjs");
const { canonicalJson } = require("../aws/production-printing-routine-delta-executor.cjs");
const scopeBytes = fs.readFileSync(new URL("../aws/production-seven-routine-scope.json", import.meta.url));
const scope = JSON.parse(scopeBytes);
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const empty = () => ({ routines: [], tables: [], policies: [], schemas: [], roles: [] });
const predecessor = empty();
const successor = { ...empty(), schemas: [{ name: "app_rls" }] };
const mutations = scope.objects.map((row, index) => ({ identity: row.identity, owner: index < 5 ? "auth" : "schema", sql: `SELECT ${index + 1}` }));
const pkg = { predecessorCatalogue: catalogueDigest(predecessor), successorCatalogue: catalogueDigest(successor), mutations };
const identity = { role: "mscqr_prod_admin", session_role: "mscqr_prod_admin", database: "mscqr_production_rls_green_phase2",
  read_only: "off", rolsuper: false, rolbypassrls: false, rolcreaterole: true, rolcreatedb: true };

function harness({ before = predecessor, after = successor, failAt = "" } = {}) {
  const commands = [];
  let reads = 0;
  const tx = { async $executeRawUnsafe(sql) { commands.push(sql); },
    async $queryRawUnsafe(sql) { commands.push(sql); return [{ value: "180004" }]; } };
  const collect = async (_tx, validateIdentity) => { validateIdentity(identity); return reads++ === 0 ? before : after; };
  const checkpoint = async stage => { if (stage === failAt) throw new Error("injected failure"); };
  return { commands, run: () => executeProductionSevenRoutineTransaction({ tx, package: pkg, collect, checkpoint }) };
}

test("scope is exactly seven existing routines with unchanged owner and grant contracts", () => {
  assert.equal(scope.objects.length, 7);
  assert.equal(new Set(scope.objects.map(row => row.identity)).size, 7);
  assert.deepEqual(scope.objects.map(row => row.owner), [
    ...Array(5).fill("mscqr_prd_rls_phase2_auth_owner"), ...Array(2).fill("mscqr_prd_rls_phase2_owner")]);
  for (const row of scope.objects) {
    assert.match(row.predecessorHash, /^[a-f0-9]{64}$/);
    assert.match(row.targetHash, /^[a-f0-9]{64}$/);
    assert.ok(row.grants.length > 0 && !row.grants.includes("PUBLIC"));
  }
});

test("task definition carries a digest-pinned image and bounded migration payload", () => {
  const image = `${APP_ONLY.backendRepository}@sha256:${"a".repeat(64)}`;
  const built = buildProductionSevenRoutineTaskDefinition({ package: {
    ...pkg, kind: "PRODUCTION_RLS_SEVEN_ROUTINE_PACKAGE", scopeSha256: hash(scopeBytes),
    sqlSha256: scope.sqlSha256, sourceSha: "a".repeat(40), databaseHostname: "test.rds.amazonaws.com",
  }, backendImage: image });
  const container = built.definition.containerDefinitions[0];
  assert.equal(container.image, image);
  assert.equal(container.command[0], "/app/scripts/aws/production-seven-routine-executor.cjs");
  assert.equal(container.secrets.length, 1);
  assert.equal(container.environment.find(item => item.name === "RELEASE_GIT_SHA").value, "a".repeat(40));
  assert.throws(() => buildProductionSevenRoutineTaskDefinition({ package: pkg, backendImage: `${APP_ONLY.backendRepository}:latest` }));
});

test("decoder refuses tampered SQL even when package checksums are self-consistent", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_SEVEN_ROUTINE_PACKAGE", sourceSha: "a".repeat(40),
    requirementsSha256: "b".repeat(64), securityInventorySha256: "c".repeat(64), scopeSha256: hash(scopeBytes),
    database: identity.database, databaseInstance: scope.databaseInstance, databaseResourceId: scope.databaseResourceId,
    databaseHostname: "test.rds.amazonaws.com", predecessorCatalogue: scope.predecessorCatalogue,
    successorCatalogue: scope.successorCatalogue, sqlSha256: hash(mutations.map(row => row.sql + ";").join("\n") + "\n"), mutations };
  const bytes = Buffer.from(canonicalJson({ ...body, packageSha256: hash(canonicalJson(body)) }) + "\n");
  assert.throws(() => decodeProductionSevenRoutinePackage(gzipSync(bytes).toString("base64"), hash(bytes)));
  assert.throws(() => decodeProductionSevenRoutinePackage(gzipSync(bytes).toString("base64"), "0".repeat(64)));
});

test("predecessor drift stops before DDL; converged state is idempotent", async () => {
  assert.deepEqual(await harness({ before: successor }).run(), { status: "ALREADY_CONVERGED", writeCount: 0 });
  const drift = harness({ before: { ...empty(), tables: [{ name: "unexpected" }] } });
  await assert.rejects(drift.run(), /predecessor catalogue differs/);
  assert.equal(drift.commands.some(sql => sql.startsWith("GRANT CREATE") || sql.startsWith("CREATE OR REPLACE")), false);
});

test("executor bounds locks, serializes owner changes, and verifies the successor", async () => {
  const fixture = harness();
  assert.deepEqual(await fixture.run(), { status: "APPLIED", writeCount: 7 });
  assert.ok(fixture.commands.includes("SET LOCAL lock_timeout = '2s'"));
  assert.ok(fixture.commands.indexOf("GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner")
    < fixture.commands.indexOf("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner"));
  assert.ok(fixture.commands.indexOf("REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner")
    < fixture.commands.indexOf("SELECT 6"));
  await assert.rejects(harness({ after: predecessor }).run(), /successor catalogue differs/);
  const failed = harness({ failAt: "after-3" });
  await assert.rejects(failed.run(), /injected failure/);
  assert.equal(failed.commands.includes("SELECT 4"), false);
});

test("receipt rejects a different package or write count", () => {
  const approved = { sourceSha: "a".repeat(40), packageSha256: "b".repeat(64),
    sqlSha256: scope.sqlSha256, database: identity.database };
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_SEVEN_ROUTINE_RESULT", sourceSha: approved.sourceSha,
    packageSha256: approved.packageSha256, sqlSha256: approved.sqlSha256, database: approved.database,
    databaseRole: identity.role, successorCatalogue: scope.successorCatalogue, status: "APPLIED", writeCount: 7 };
  const message = JSON.stringify({ ...body, evidenceSha256: hash(canonicalJson(body)) });
  assert.deepEqual(authenticateProductionSevenRoutineResult(message, approved), JSON.parse(message));
  assert.throws(() => authenticateProductionSevenRoutineResult(message, { ...approved, packageSha256: "c".repeat(64) }));
  assert.throws(() => authenticateProductionSevenRoutineResult(JSON.stringify({ ...body, writeCount: 6,
    evidenceSha256: hash(canonicalJson({ ...body, writeCount: 6 })) }), approved));
});

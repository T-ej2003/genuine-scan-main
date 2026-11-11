import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import { APP_ONLY } from "../aws/production-app-only-contract.mjs";
import { authenticateProduction49Result, buildProduction49TaskDefinition } from "../aws/production-49-object-package.mjs";

const require = createRequire(import.meta.url);
const { catalogueDigest, decodeProduction49Package, executeProduction49Transaction } = require("../aws/production-49-object-executor.cjs");
const { canonicalJson } = require("../aws/production-printing-routine-delta-executor.cjs");
const scope = JSON.parse(fs.readFileSync(new URL("../aws/production-49-object-scope.json", import.meta.url)));
const hash = bytes => crypto.createHash("sha256").update(bytes).digest("hex");
const empty = () => ({ routines: [], tables: [], policies: [], schemas: [], roles: [] });
const identity = { role: "mscqr_prod_admin", session_role: "mscqr_prod_admin", database: "mscqr_production_rls_green_phase2",
  read_only: "off", rolsuper: false, rolbypassrls: false, rolcreaterole: true, rolcreatedb: true };
const predecessor = empty();
const successor = { ...empty(), schemas: [{ name: "app_rls" }] };
const mutations = Array.from({ length: 50 }, (_, index) => ({ identity: scope.objects[Math.min(index, 48)].identity,
  owner: index < 5 ? "auth" : "schema", sql: `SELECT ${index + 1}` }));
const pkg = { predecessorCatalogue: catalogueDigest(predecessor), successorCatalogue: catalogueDigest(successor), mutations };

function harness({ before = predecessor, after = successor, failAt = "" } = {}) {
  const commands = [];
  let reads = 0;
  const tx = {
    async $executeRawUnsafe(sql) { commands.push(sql); },
    async $queryRawUnsafe(sql) { commands.push(sql); return [{ value: "180004" }]; },
  };
  const collect = async (_tx, validateIdentity) => { validateIdentity(identity); return reads++ === 0 ? before : after; };
  const checkpoint = async stage => { if (stage === failAt) throw new Error("injected failure"); };
  return { commands, run: () => executeProduction49Transaction({ tx, package: pkg, collect, checkpoint }) };
}

test("the production scope contains only seven routines and 42 policies with a fixed SQL digest", () => {
  assert.equal(scope.objects.length, 49);
  assert.equal(scope.objects.filter(row => row.kind === "routines").length, 7);
  assert.equal(scope.objects.filter(row => row.kind === "policies").length, 42);
  assert.match(scope.sqlSha256, /^[a-f0-9]{64}$/);
  assert.equal(new Set(scope.objects.map(row => `${row.kind}:${row.identity}`)).size, 49);
});

test("task definition carries only the immutable backend image and bounded migration payload", () => {
  const image = `${APP_ONLY.backendRepository}@sha256:${"a".repeat(64)}`;
  const built = buildProduction49TaskDefinition({ package: { ...pkg,
    kind: "PRODUCTION_RLS_49_OBJECT_INCREMENTAL_PACKAGE", scopeSha256: hash(fs.readFileSync(new URL("../aws/production-49-object-scope.json", import.meta.url))),
    sqlSha256: scope.sqlSha256, databaseHostname: "test.rds.amazonaws.com" }, backendImage: image });
  const container = built.definition.containerDefinitions[0];
  assert.equal(container.image, image);
  assert.deepEqual(container.entryPoint, ["node"]);
  assert.equal(container.command[0], "/app/scripts/aws/production-49-object-executor.cjs");
  assert.equal(container.command[3], "test.rds.amazonaws.com");
  assert.equal(container.secrets.length, 1);
  assert.equal(container.environment.length, 1);
  assert.equal(container.readonlyRootFilesystem, true);
  assert.throws(() => buildProduction49TaskDefinition({ package: pkg, backendImage: `${APP_ONLY.backendRepository}:latest` }));
});

test("payload decoding refuses replacement SQL even with a self-consistent package checksum", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_49_OBJECT_INCREMENTAL_PACKAGE", sourceSha: "a".repeat(40),
    requirementsSha256: "b".repeat(64), securityInventorySha256: "c".repeat(64),
    scopeSha256: hash(fs.readFileSync(new URL("../aws/production-49-object-scope.json", import.meta.url))),
    database: identity.database, databaseInstance: scope.databaseInstance, databaseResourceId: scope.databaseResourceId,
    databaseHostname: "test.rds.amazonaws.com", predecessorCatalogue: scope.predecessorCatalogue,
    successorCatalogue: scope.successorCatalogue,
    sqlSha256: hash(mutations.map(row => row.sql + ";").join("\n") + "\n"), mutations };
  const bytes = Buffer.from(canonicalJson({ ...body, packageSha256: hash(canonicalJson(body)) }) + "\n");
  assert.throws(() => decodeProduction49Package(gzipSync(bytes).toString("base64"), hash(bytes)), /Only reviewed SQL may run/);
  assert.throws(() => decodeProduction49Package(gzipSync(bytes).toString("base64"), "0".repeat(64)));
});

test("predecessor drift is rejected before temporary grants or DDL", async () => {
  const fixture = harness({ before: successor });
  const result = await fixture.run();
  assert.equal(result.status, "ALREADY_CONVERGED");
  assert.equal(result.writeCount, 0);
  const drift = harness({ before: { ...empty(), tables: [{ name: "unexpected" }] } });
  await assert.rejects(drift.run(), /predecessor catalogue differs/);
  assert.equal(drift.commands.some(sql => sql.startsWith("GRANT CREATE") || sql.startsWith("ALTER POLICY")), false);
});

test("the executor bounds locks, orders owners, and verifies the successor", async () => {
  const fixture = harness();
  assert.deepEqual(await fixture.run(), { status: "APPLIED", writeCount: 50 });
  const commands = fixture.commands;
  assert.ok(commands.includes("SET LOCAL lock_timeout = '2s'"));
  assert.ok(commands.includes("SET LOCAL statement_timeout = '120s'"));
  assert.ok(commands.indexOf("GRANT CREATE ON SCHEMA app_rls TO mscqr_prd_rls_phase2_auth_owner") < commands.indexOf("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner"));
  assert.ok(commands.indexOf("REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner") < commands.indexOf("SELECT 6"));
  const tampered = harness({ after: predecessor });
  await assert.rejects(tampered.run(), /successor catalogue differs/);
});

test("an injected DDL failure stops before remaining statements", async () => {
  const fixture = harness({ failAt: "after-10" });
  await assert.rejects(fixture.run(), /injected failure/);
  assert.equal(fixture.commands.includes("SELECT 11"), false);
});

test("the execution receipt is bound to the exact package and successor catalogue", () => {
  const approved = { ...pkg, sourceSha: "a".repeat(40), packageSha256: "b".repeat(64),
    sqlSha256: scope.sqlSha256, database: identity.database };
  const body = { schemaVersion: 1, kind: "PRODUCTION_RLS_49_OBJECT_RESULT", sourceSha: approved.sourceSha,
    packageSha256: approved.packageSha256, sqlSha256: approved.sqlSha256, database: approved.database,
    databaseRole: identity.role, successorCatalogue: scope.successorCatalogue, status: "APPLIED", writeCount: 50 };
  const message = JSON.stringify({ ...body, evidenceSha256: hash(canonicalJson(body)) });
  assert.deepEqual(authenticateProduction49Result(message, approved), JSON.parse(message));
  assert.throws(() => authenticateProduction49Result(message, { ...approved, packageSha256: "c".repeat(64) }));
  assert.throws(() => authenticateProduction49Result(JSON.stringify({ ...body, status: "APPLIED", writeCount: 49,
    evidenceSha256: hash(canonicalJson({ ...body, writeCount: 49 })) }), approved));
});

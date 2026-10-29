import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { buildC02SessionPrerequisitePackage } from "../aws/production-c02-session-package.mjs";
import { authenticateC02SessionResult, buildC02SessionTask } from "../aws/apply-production-c02-session-prerequisite.mjs";
import { canonicalJson, canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const runtime = createRequire(import.meta.url)("../aws/production-c02-session-executor.cjs");
const sourceSha = "a".repeat(40);
const pkg = buildC02SessionPrerequisitePackage({ sourceSha });
const initial = { role: "mscqr_prod_admin", session_role: "mscqr_prod_admin",
  database: "mscqr_production_rls_green_phase2", read_only: "off", superuser: false, bypass_rls: false,
  force_rls: true, migration_ready: true,
  function_body_sha256: null, function_owner: null, security_definer: null, policy_count: 0,
  named_policy_count: 0, app_execute: null, no_public_execute: null,
  no_broad_select: true, no_broad_insert: true, no_broad_update: true, no_app_grants: true,
  grants: [], policies: [] };
const successor = { ...initial, function_body_sha256: pkg.functionBodySha256,
  function_owner: "mscqr_prd_rls_phase2_auth_owner", security_definer: true,
  policy_count: 3, named_policy_count: 3, app_execute: true, no_public_execute: true,
  grants: runtime.expectedColumnGrants(pkg), policies: Object.entries(pkg.policyDigests).sort(([a], [b]) => a.localeCompare(b))
    .map(([name, digest]) => ({ name, command: name.endsWith("_select") ? "r" : name.endsWith("_insert") ? "a" : "w",
      permissive: true, role: "mscqr_prd_rls_phase2_auth_owner", digest })) };

const harness = (before = initial, { failAt } = {}) => {
  const commands = []; let applied = before === successor;
  return { commands, tx: {
    async $executeRawUnsafe(sql) {
      commands.push(sql);
      if (sql.includes(failAt || "\0")) throw new Error("injected installation failure");
      if (sql.startsWith("CREATE OR REPLACE FUNCTION")) applied = true;
    },
    async $queryRawUnsafe(sql) {
      commands.push(sql);
      const state = applied ? successor : before;
      if (sql.includes("SELECT current_user AS role")) return [state];
      if (sql.includes("acl.privilege_type||':'||a.attname")) return state.grants.map((entry) => ({ entry }));
      if (sql.includes("p.polname AS name")) return state.policies;
      throw new Error("unexpected catalogue query");
    },
  } };
};

test("C02 source package contains only the exact session function, policies and column grants", () => {
  assert.equal(pkg.tableGrants.length, 3);
  assert.equal(pkg.policySql.length, 6);
  assert.ok(pkg.definition.endsWith("$fn$;"));
  assert.doesNotMatch(pkg.tableGrants.join("\n"), /GRANT (?:INSERT|UPDATE) ON TABLE/);
  assert.doesNotMatch(pkg.definition, /\{\{[A-Z_]+\}\}/);
  const task = buildC02SessionTask({ sourceSha, hostname: "test.invalid" });
  assert.ok(task.serialized.length < 60 * 1024);
  const encoded = gzipSync(Buffer.from(canonicalJson(pkg)), { level: 9, mtime: 0 }).toString("base64");
  assert.deepEqual(runtime.decodePackage(encoded, createRequire(import.meta.url)("node:crypto").createHash("sha256")
    .update(Buffer.from(canonicalJson(pkg))).digest("hex")), pkg);
  assert.equal(task.definition.containerDefinitions[0].secrets.length, 1);
});

test("C02 installation requires migration and FORCE RLS, and refuses partial predecessors", async () => {
  for (const missing of ["migration_ready", "force_rls"]) {
    const h = harness({ ...initial, [missing]: false });
    await assert.rejects(runtime.executeC02SessionInstallTransaction({ tx: h.tx, pkg }));
    assert.equal(h.commands.some((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")), false);
  }
  for (const partial of [{ policy_count: 1 }, { grants: ["UPDATE:lastMessageSeq"] },
    { function_body_sha256: "b".repeat(64) }, { no_broad_update: false }]) {
    const h = harness({ ...initial, ...partial });
    await assert.rejects(runtime.executeC02SessionInstallTransaction({ tx: h.tx, pkg }));
    assert.equal(h.commands.some((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")), false);
  }
});

test("C02 installer uses the established owner split, verifies successor, and is idempotent", async () => {
  const h = harness();
  assert.deepEqual(await runtime.executeC02SessionInstallTransaction({ tx: h.tx, pkg }),
    { status: "APPLIED", writeCount: 15 });
  assert.ok(h.commands.indexOf("SET LOCAL ROLE mscqr_prd_rls_phase2_auth_owner") <
    h.commands.findIndex((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")));
  assert.ok(h.commands.indexOf("REVOKE CREATE ON SCHEMA app_rls FROM mscqr_prd_rls_phase2_auth_owner") >
    h.commands.findIndex((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")));
  const repeated = harness(successor);
  assert.deepEqual(await runtime.executeC02SessionInstallTransaction({ tx: repeated.tx, pkg }),
    { status: "ALREADY_CONVERGED", writeCount: 0 });
  assert.equal(repeated.commands.some((sql) => sql.startsWith("CREATE OR REPLACE FUNCTION")), false);
});

test("C02 installation result must bind exact source and package evidence", () => {
  const body = { schemaVersion: 1, kind: "PRODUCTION_C02_SESSION_INSTALL_RESULT", sourceSha,
    packageSha256: pkg.packageSha256, database: "mscqr_production_rls_green_phase2",
    databaseRole: "mscqr_prod_admin", status: "APPLIED", writeCount: 15 };
  const message = JSON.stringify({ ...body, evidenceSha256: canonicalSha256(body) });
  assert.equal(authenticateC02SessionResult(message, { sourceSha, packageSha256: pkg.packageSha256 }).status, "APPLIED");
  assert.throws(() => authenticateC02SessionResult(message, { sourceSha: "b".repeat(40), packageSha256: pkg.packageSha256 }));
  assert.throws(() => authenticateC02SessionResult(message, { sourceSha, packageSha256: "0".repeat(64) }));
});

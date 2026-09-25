import test from "node:test";
import assert from "node:assert/strict";
import { collectAppOnlyDatabaseCatalogue, evaluateAppOnlyDatabaseCatalogue } from "../aws/production-app-only-database-verifier.mjs";

function fixture() {
  const observed = {
    routines: [{ schema: "app_auth", name: "example", arguments: "value text", result: "boolean", owner: "owner", security_definer: true,
      volatility: "s", parallel: "u", leakproof: false, strict: false, config: ["search_path=pg_catalog, public"], body: "SELECT true", language: "sql",
      definition: "CREATE FUNCTION app_auth.example(value text) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
      grants: [{ role: "app", privilege: "EXECUTE", grantable: false }] }],
    schemas: [{ name: "app_auth", owner: "owner", grants: [] }, { name: "public", owner: "owner", grants: [] }],
    roles: [{ name: "mscqr_prd_rls_phase2_app", superuser: false, inherit: false, memberships: [], members: [] }],
    tables: [{ name: "Example", owner: "owner", kind: "r", rls: true, forced: true, columns: [{ name: "id", type: "text", notNull: true }], constraints: [], grants: [], column_grants: [] }],
    policies: [{ table: "Example", name: "tenant_read", command: "r", permissive: true, roles: ["app"], using: "id = current_user", check: null }],
  };
  return { observed, required: { ...structuredClone(observed), contractSha256: "a".repeat(64) } };
}
test("positive proof is required for each database/RLS domain", () => {
  const { observed, required } = fixture();
  assert.ok(Object.values(evaluateAppOnlyDatabaseCatalogue(observed, required)).every((r) => r === "COMPATIBLE"));
  assert.ok(Object.values(evaluateAppOnlyDatabaseCatalogue(observed, {})).every((r) => r === "UNPROVEN"));
  for (const collection of ["routines", "tables", "policies", "schemas", "roles"]) {
    const changed = structuredClone(observed); changed[collection] = [];
    assert.ok(Object.values(evaluateAppOnlyDatabaseCatalogue(changed, required)).some((r) => r !== "COMPATIBLE"));
    changed[collection] = [...observed[collection], ...observed[collection]];
    assert.ok(Object.values(evaluateAppOnlyDatabaseCatalogue(changed, required)).every((r) => r === "UNPROVEN"));
  }
});
for (const [collection, fields] of Object.entries({ routines: ["arguments", "result", "owner", "security_definer", "volatility", "parallel", "leakproof", "strict", "config", "body", "language", "definition", "grants"], tables: ["owner", "columns", "constraints", "grants", "column_grants", "rls", "forced", "kind"], policies: ["roles", "command", "using", "check", "permissive"], schemas: ["owner", "grants"], roles: ["superuser", "inherit", "memberships", "members"] })) {
  for (const field of fields) test(`rejects incompatible ${collection}.${field}`, () => {
    const { observed, required } = fixture(); observed[collection][0][field] = "changed";
    assert.notEqual(evaluateAppOnlyDatabaseCatalogue(observed, required).GENERATED_RLS_CONTRACT, "COMPATIBLE");
  });
}
test("additional permissive policy on a required table cannot pass", () => {
  const { observed, required } = fixture();
  observed.policies.push({ ...observed.policies[0], name: "public_bypass", using: "true" });
  assert.equal(evaluateAppOnlyDatabaseCatalogue(observed, required).RLS_POLICIES, "INCOMPATIBLE");
});
const identity = () => ({ role: "mscqr_prod_rls_canary_read", session_role: "mscqr_prod_rls_canary_read", database: "mscqr_production_rls_green_phase2",
  server_version_num: 180004, read_only: "on", default_read_only: "on", ...Object.fromEntries(["rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls", "memberships", "write_privileges", "schema_write", "database_write"].map((key) => [key, false])) });
test("all fixed catalogue statements use one read-only repeatable-read transaction", async () => {
  const calls = [];
  const { observed } = fixture(); let read = 0;
  const tx = { $executeRawUnsafe: async (sql) => calls.push(sql), $queryRawUnsafe: async (sql) => { calls.push(sql); return [[identity()], [{ rows: observed.routines }], [{ rows: observed.tables }], [{ rows: observed.tables.map((row) => ({ schema: "public", ...row })) }], [{ rows: observed.policies }], [{ rows: observed.policies.map((row) => ({ schema: "public", ...row })) }], [{ rows: observed.schemas }], [{ rows: observed.schemas }], [{ rows: observed.roles }], ...Array.from({ length: 6 }, () => [{ rows: [] }])][read++]; } };
  const client = { $transaction: async (fn, options) => { assert.equal(options.timeout, 30000); return fn(tx); } };
  const result = await collectAppOnlyDatabaseCatalogue(client);
  assert.deepEqual(result.routines, observed.routines);
  assert.equal(calls[0], "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  assert.equal(calls[1], "SET LOCAL search_path = pg_catalog");
  assert.equal(read, 15);
  // Inspection check, not the security boundary: callers cannot supply SQL;
  // database privileges, fixed code and read-only transaction enforce the limit.
  assert.ok(calls.slice(2).every((sql) => sql.startsWith("SELECT ")));
});
for (const field of Object.keys(identity())) test(`database identity boundary rejects ${field} substitution`, async () => {
  const bad = { ...identity(), [field]: typeof identity()[field] === "boolean" ? true : "wrong" };
  let reads = 0;
  const client = { $transaction: async (fn) => fn({ $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => { reads++; return [bad]; } }) };
  await assert.rejects(collectAppOnlyDatabaseCatalogue(client));
  assert.equal(reads, 1);
});

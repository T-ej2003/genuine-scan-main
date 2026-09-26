import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { collectAppOnlyDatabaseCatalogue, evaluateAppOnlyDatabaseCatalogue, SUBSCRIPTION_PROJECTION_BODY_SHA256, SUBSCRIPTION_PROJECTION_STATUS_CONTRACT } from "../aws/production-app-only-database-verifier.mjs";

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
test("missing subscription projection is an explicit fail-closed provisioning prerequisite", async () => {
  const calls = [];
  const missingProjection = { ...structuredClone(SUBSCRIPTION_PROJECTION_STATUS_CONTRACT),
    role_exists: false, function_exists: false, readable_columns: [] };
  const responses = [[identity()], [{ rows: [] }], [{ rows: [] }], [missingProjection]];
  let read = 0;
  const client = { $transaction: async (fn) => fn({
    $executeRawUnsafe: async (sql) => calls.push(sql),
    $queryRawUnsafe: async (sql) => { calls.push(sql); return responses[read++] ?? []; },
  }) };
  await assert.rejects(collectAppOnlyDatabaseCatalogue(client), /Subscription security inventory capability is unavailable/);
  assert.equal(calls.includes("SELECT * FROM app_rls.production_security_subscription_inventory() ORDER BY subscription_name"), false);
  const runbook = fs.readFileSync("documents/security/rls-program/production-security-rebaseline-inventory.md", "utf8");
  assert.match(runbook, /Required database prerequisite[\s\S]*?production-green-phase-4-read-only-canary-provision\.sql/);
  assert.match(runbook, /distinct, explicitly authorized provisioning change/);
});
const identity = () => ({ role: "mscqr_prod_rls_canary_read", session_role: "mscqr_prod_rls_canary_read", database: "mscqr_production_rls_green_phase2",
  server_version_num: 180004, read_only: "on", default_read_only: "on", ...Object.fromEntries(["rolsuper", "rolinherit", "rolcreaterole", "rolcreatedb", "rolreplication", "rolbypassrls", "memberships", "write_privileges", "schema_write", "database_write"].map((key) => [key, false])) });
test("all fixed catalogue statements use one read-only repeatable-read transaction", async () => {
  const calls = [];
  const { observed } = fixture(); let read = 0;
  const responses = [[identity()], ...Array.from({ length: 2 }, () => [{ rows: [] }]),
    [structuredClone(SUBSCRIPTION_PROJECTION_STATUS_CONTRACT)],
    [], [{ rows: observed.routines }], [{ rows: observed.routines }], [{ rows: observed.tables }],
    [{ rows: observed.tables.map((row) => ({ schema: "public", ...row })) }],
    ...Array.from({ length: 4 }, () => [{ rows: [] }]), [{ rows: observed.policies }],
    [{ rows: observed.policies.map((row) => ({ schema: "public", ...row })) }], [{ rows: observed.schemas }],
    [{ rows: observed.schemas }], [{ rows: observed.roles }], [{ rows: observed.roles }],
    ...Array.from({ length: 7 }, () => [{ rows: [] }])];
  const tx = { $executeRawUnsafe: async (sql) => calls.push(sql), $queryRawUnsafe: async (sql) => { calls.push(sql); return responses[read++]; } };
  const client = { $transaction: async (fn, options) => { assert.equal(options.timeout, 30000); return fn(tx); } };
  const result = await collectAppOnlyDatabaseCatalogue(client);
  assert.deepEqual(result.routines, observed.routines);
  assert.equal(calls[0], "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
  assert.equal(calls[1], "SET LOCAL search_path = pg_catalog");
  assert.equal(read, 26);
  // Inspection check, not the security boundary: callers cannot supply SQL;
  // database privileges, fixed code and read-only transaction enforce the limit.
  assert.ok(calls.slice(2).every((sql) => /^\s*(?:SELECT\b|WITH RECURSIVE\b)/.test(sql)), JSON.stringify(calls.slice(2).filter((sql) => !/^\s*(?:SELECT\b|WITH RECURSIVE\b)/.test(sql))));
  assert.ok(calls.some((sql) => sql.includes("c.relkind IN ('r','p','v','m','f')")), "security collector covers relation kinds with ACLs");
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_get_viewdef(c.oid,false)")), "view definitions are collected canonically");
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_trigger") && sql.includes("NOT t.tgisinternal") && sql.includes("pg_get_triggerdef")), "user triggers are collected separately");
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_trigger") && sql.includes("t.tgisinternal") && sql.includes("t.tgconstraint<>0") && sql.includes("t.tgenabled")), "stable internal constraint-trigger enforcement is collected");
  assert.ok(calls.some((sql) => sql.includes("FROM pg_catalog.pg_extension")), "installed extensions are inventoried before extension-owned members are excluded");
  const bindingsSql=calls.find((sql) => sql.includes("FROM pg_catalog.pg_publication") && sql.includes("pg_catalog.pg_user_mappings"));
  assert.ok(bindingsSql?.includes("pg_catalog.pg_publication_rel") && bindingsSql.includes("pg_get_expr(pr.prqual") && bindingsSql.includes("value_sha256") && bindingsSql.includes("mscqr-security-option-v1"), "publication membership and hashed foreign bindings are collected without raw option values");
  assert.ok(bindingsSql?.includes("pg_catalog.pg_publication_rel") && !bindingsSql.includes("pg_catalog.pg_subscription"),
    "restricted collector does not read the protected subscription catalog directly");
  assert.ok(calls.some((sql) => sql.includes("p.proname='production_security_subscription_inventory'")
    && sql.includes("has_column_privilege") && sql.includes("pg_catalog.pg_attribute") && sql.includes("projection.prosrc")
    && sql.includes("pg_catalog.aclexplode") && sql.includes("rolcanlogin")), "subscription projection body, ACL, role and exact column privileges are authenticated");
  assert.ok(calls.includes("SELECT * FROM app_rls.production_security_subscription_inventory() ORDER BY subscription_name"),
    "the restricted collector invokes only the fixed safe subscription projection");
  const provisioning = fs.readFileSync("documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql", "utf8");
  const projectionBody = provisioning.match(/AS \$subscription_inventory\$(.*?)\$subscription_inventory\$;/s)?.[1];
  assert.ok(projectionBody, "the source-owned fixed projection definition is present");
  assert.equal(crypto.createHash("sha256").update(projectionBody, "utf8").digest("hex"), SUBSCRIPTION_PROJECTION_BODY_SHA256,
    "the runtime authenticates exactly the reviewed projection body before calling SECURITY DEFINER");
  assert.ok(calls.some((sql) => sql.includes("FROM pg_catalog.pg_parameter_acl") && sql.includes("a.grantor") && sql.includes("a.is_grantable")), "parameter ACL grants are collected with grantor identity");
  for (const source of ["pg_proc p", "pg_class c", "pg_namespace n", "pg_database d", "pg_default_acl d", "pg_type t"]) {
    const sql = calls.find((query) => query.includes(`FROM pg_catalog.${source}`) && query.includes("aclexplode") && query.includes("grantor.rolname"));
    assert.ok(sql?.includes("grantor.rolname") && sql.includes("a.grantor") || sql?.includes("grantor.rolname") && sql.includes("acl.grantor"), `${source} security ACL collector preserves grantor`);
  }
  assert.ok(calls.some((sql) => sql.includes("c.relkind='S'") && sql.includes("grantor.rolname") && sql.includes("a.grantor")), "sequence ACL collector preserves grantor");
  assert.ok(calls.some((sql) => sql.includes("d.classid='pg_catalog.pg_proc'") && sql.includes("d.deptype='e'")), "user-schema routines exclude extension-owned system objects only");
  const securityRolesSql = calls.find((sql) => sql.includes("FROM pg_catalog.pg_roles r WHERE r.rolname !~"));
  assert.ok(securityRolesSql?.includes("pg_catalog.pg_auth_members") && securityRolesSql.includes("m.admin_option")
    && securityRolesSql.includes("m.inherit_option") && securityRolesSql.includes("m.set_option") && securityRolesSql.includes("m.grantor")
    && securityRolesSql.includes("grantor.rolname"), "security inventory observes membership grantors and all PostgreSQL 18 options");
  assert.ok(calls.some((sql) => sql.includes("WITH RECURSIVE membership_closure") && sql.includes("m.inherit_option") && sql.includes("intermediate.rolinherit")),
    "operator capability collection evaluates recursively inherited roles");
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_type") && sql.includes("t.typcategory<>'A'")),
    "generated array types are excluded because PostgreSQL does not allow independent ACLs on them; element-type ACLs are collected");
  const defaultAclSql = calls.find((sql) => sql.includes("FROM pg_catalog.pg_default_acl d"));
  assert.ok(defaultAclSql && !/\bWHERE\b/.test(defaultAclSql), "security inventory observes global and schema-specific default ACLs for every owner");
  const routinesSql = calls.find((sql) => sql.includes("p.prokind::text AS kind"));
  assert.ok(routinesSql?.includes("pg_catalog.pg_aggregate") && routinesSql.includes("aggregate_state_sha256")
    && routinesSql.includes("CASE WHEN p.prokind='a'"), "functions, procedures, windows, and aggregates have stable distinct security identities");
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_rewrite") && sql.includes("r.rulename<>'_RETURN'") && sql.includes("pg_get_ruledef")));
  assert.ok(calls.some((sql) => sql.includes("pg_catalog.pg_event_trigger") && sql.includes("e.evtfoid") && sql.includes("evttags")));
  assert.ok(calls.some((sql) => sql.includes("pg_get_constraintdef") && sql.includes("parent_identity") && sql.includes("pno.nspname")));
  assert.ok(calls.some((sql) => sql.includes("r.rolvaliduntil::text AS valid_until")), "role credential expiry is included without exposing verifier/password fields");
  responses[3] = [{ ...structuredClone(SUBSCRIPTION_PROJECTION_STATUS_CONTRACT), function_body_sha256: "0".repeat(64) }];
  read = 0;
  const hostileCalls = [];
  const hostileClient = { $transaction: async (fn) => fn({
    $executeRawUnsafe: async (sql) => hostileCalls.push(sql),
    $queryRawUnsafe: async (sql) => { hostileCalls.push(sql); return responses[read++]; },
  }) };
  await assert.rejects(collectAppOnlyDatabaseCatalogue(hostileClient), /Subscription security inventory capability is unavailable: function_body_sha256/);
  assert.equal(hostileCalls.includes("SELECT * FROM app_rls.production_security_subscription_inventory() ORDER BY subscription_name"), false,
    "a replaced SECURITY DEFINER projection is never invoked");
});
for (const field of Object.keys(identity())) test(`database identity boundary rejects ${field} substitution`, async () => {
  const bad = { ...identity(), [field]: typeof identity()[field] === "boolean" ? true : "wrong" };
  let reads = 0;
  const client = { $transaction: async (fn) => fn({ $executeRawUnsafe: async () => {}, $queryRawUnsafe: async () => { reads++; return [bad]; } }) };
  await assert.rejects(collectAppOnlyDatabaseCatalogue(client));
  assert.equal(reads, 1);
});

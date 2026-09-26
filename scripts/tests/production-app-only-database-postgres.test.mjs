import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { collectAppOnlyDatabaseCatalogue, evaluateAppOnlyDatabaseCatalogue } from "../aws/production-app-only-database-verifier.mjs";

// Deliberately requires the repository's local tmpfs PostgreSQL harness. No
// DATABASE_URL override, production connection, mock fallback or silent skip.
const container = "mscqr-p2-auth-security-postgres";
const database = "mscqr_production_rls_green_phase2";
const role = "mscqr_prod_rls_canary_read";
const appRole = "mscqr_prd_rls_phase2_app";
const subscriptionObserver = "mscqr_prod_subscription_observer";
const requireBackend = createRequire(new URL("../../backend/package.json", import.meta.url));
const { PrismaClient } = requireBackend("@prisma/client");
function sql(statement, db = database) {
  return execFileSync("docker", ["exec", "-i", container, "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U", "mscqr_p2_test", "-d", db], {
    input: statement, encoding: "utf8", timeout: 15000, stdio: ["pipe", "pipe", "pipe"],
  }).trim();
}
function client() {
  return new PrismaClient({ datasources: { db: { url: `postgresql://${role}@127.0.0.1:55432/${database}?connection_limit=1` } } });
}
async function collect() {
  const db = client();
  try { return await collectAppOnlyDatabaseCatalogue(db); } finally { await db.$disconnect(); }
}

test("real PostgreSQL catalogue and hostile read-only verifier regressions", { timeout: 120000 }, async (t) => {
  const [instance] = JSON.parse(execFileSync("docker", ["inspect", container], { encoding: "utf8", timeout: 10000 }));
  assert.equal(instance.Config.Labels["com.docker.compose.project"], "mscqr-p2-auth-security");
  assert.equal(instance.Config.Labels["com.docker.compose.service"], "p2-postgres");
  assert.equal(instance.Config.Image, "postgres:18.4");
  assert.ok(Object.hasOwn(instance.HostConfig.Tmpfs, "/var/lib/postgresql"));
  assert.deepEqual(instance.HostConfig.PortBindings["5432/tcp"], [{ HostIp: "127.0.0.1", HostPort: "55432" }]);
  assert.equal(sql("SELECT current_database()", "mscqr_p2_admin_test"), "mscqr_p2_admin_test");
  assert.equal(sql(`SELECT count(*) FROM pg_database WHERE datname='${database}'`, "mscqr_p2_admin_test"), "0", "never overwrite an existing test database");
  assert.equal(sql(`SELECT count(*) FROM pg_roles WHERE rolname IN ('${role}','${appRole}','${subscriptionObserver}','app_only_fixture_member','app_only_unexpected_subscription_reader','app_only_unexpected_subscription_member','app_only_subscription_provisioner','app_only_temporary_subscription_observer')`, "mscqr_p2_admin_test"), "0", "never replace existing roles");
  let createdDb = false, createdRole = false, createdAppRole = false, createdSubscriptionObserver = false;
  try {
    sql(`CREATE DATABASE ${database}`, "mscqr_p2_admin_test"); createdDb = true;
    sql(`CREATE ROLE ${role} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); createdRole = true;
    sql(`CREATE ROLE ${appRole} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); createdAppRole = true;
    sql(`CREATE ROLE ${subscriptionObserver} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`); createdSubscriptionObserver = true;
    sql(`ALTER ROLE ${role} SET default_transaction_read_only=on;
      REVOKE ALL ON DATABASE ${database} FROM PUBLIC;
      GRANT CONNECT ON DATABASE ${database} TO ${role};
      REVOKE CREATE ON SCHEMA public FROM PUBLIC;
      GRANT USAGE ON SCHEMA public TO ${role};
      CREATE SCHEMA app_auth;
      CREATE FUNCTION app_auth.fixture(value integer) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path=pg_catalog,public AS 'SELECT value > 0';
      REVOKE ALL ON FUNCTION app_auth.fixture(integer) FROM PUBLIC;
      GRANT USAGE ON SCHEMA app_auth TO ${role};
      GRANT EXECUTE ON FUNCTION app_auth.fixture(integer) TO ${role};
      CREATE TYPE public.app_only_status AS ENUM ('pending','ready');
      CREATE TABLE public.app_only_fixture (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        tenant text NOT NULL DEFAULT 'fixture',
        status public.app_only_status,
        status_history public.app_only_status[],
        amount integer NOT NULL DEFAULT 1 CHECK (amount > 0),
        doubled integer GENERATED ALWAYS AS (amount * 2) STORED);
      ALTER TABLE public.app_only_fixture ENABLE ROW LEVEL SECURITY;
      ALTER TABLE public.app_only_fixture FORCE ROW LEVEL SECURITY;
      GRANT SELECT(tenant) ON public.app_only_fixture TO ${role};
      CREATE POLICY fixture_policy ON public.app_only_fixture FOR ALL TO ${role}
        USING (tenant = current_user) WITH CHECK (amount > 0);`);
    const provisioning = fs.readFileSync(path.join(process.cwd(), "documents/ops/iam/production-green-phase-4-read-only-canary-provision.sql"), "utf8");
    const projection = provisioning.match(/CREATE OR REPLACE FUNCTION app_rls\.production_security_subscription_inventory\([\s\S]*?\$subscription_inventory\$;/)?.[0];
    assert.ok(projection, "the test installs the exact source-owned restricted subscription projection");
    sql(`CREATE SCHEMA app_rls AUTHORIZATION mscqr_p2_test;
      GRANT SELECT (subconninfo) ON pg_catalog.pg_subscription TO ${subscriptionObserver};
      GRANT USAGE, CREATE ON SCHEMA app_rls TO ${subscriptionObserver};
      GRANT USAGE ON SCHEMA app_rls TO ${role};
      SET ROLE ${subscriptionObserver};
      ${projection}
      RESET ROLE;
      REVOKE USAGE, CREATE ON SCHEMA app_rls FROM ${subscriptionObserver};
      REVOKE ALL ON FUNCTION app_rls.production_security_subscription_inventory() FROM PUBLIC;
      GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO ${role};`);
    const baseline = await collect();
    const required = { ...structuredClone(baseline), contractSha256: "a".repeat(64) };
    await t.test("real pg_subscription column ACL rejects an extra secret-capable grantee", async () => {
      sql("CREATE ROLE app_only_unexpected_subscription_reader NOLOGIN");
      try {
        sql("GRANT SELECT (subconninfo) ON pg_catalog.pg_subscription TO app_only_unexpected_subscription_reader");
        await assert.rejects(collect(), /subscription_conninfo_acl/);
      } finally {
        sql("REVOKE SELECT (subconninfo) ON pg_catalog.pg_subscription FROM app_only_unexpected_subscription_reader; DROP ROLE app_only_unexpected_subscription_reader");
      }
    });
    await t.test("real observer membership graph rejects a role that can SET ROLE to the secret reader", async () => {
      sql("CREATE ROLE app_only_unexpected_subscription_member NOLOGIN");
      try {
        sql("GRANT mscqr_prod_subscription_observer TO app_only_unexpected_subscription_member WITH ADMIN FALSE, INHERIT FALSE, SET TRUE");
        await assert.rejects(collect(), /observer_memberships/);
      } finally {
        sql("REVOKE mscqr_prod_subscription_observer FROM app_only_unexpected_subscription_member; DROP ROLE app_only_unexpected_subscription_member");
      }
    });
    await t.test("a non-superuser CREATEROLE provisioner can use and then revoke only its temporary SET membership", () => {
      sql(`BEGIN;
        CREATE ROLE app_only_subscription_provisioner CREATEROLE NOLOGIN;
        SET SESSION AUTHORIZATION app_only_subscription_provisioner;
        CREATE ROLE app_only_temporary_subscription_observer NOLOGIN;
        GRANT app_only_temporary_subscription_observer TO app_only_subscription_provisioner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
        SET ROLE app_only_temporary_subscription_observer;
        DO $$ BEGIN IF current_user<>'app_only_temporary_subscription_observer' THEN RAISE EXCEPTION 'SET ROLE did not switch to observer'; END IF; END $$;
        RESET ROLE;
        REVOKE app_only_temporary_subscription_observer FROM app_only_subscription_provisioner;
        RESET SESSION AUTHORIZATION;
        DROP ROLE app_only_temporary_subscription_observer;
        DROP ROLE app_only_subscription_provisioner;
        COMMIT;`);
    });
    await t.test("catalogues expose ACLs, function security, policies, constraints and generated/default/identity columns", () => {
      const fn = baseline.routines.find((r) => r.name === "fixture");
      assert.equal(fn.security_definer, true); assert.equal(fn.body, "SELECT value > 0");
      assert.match(fn.definition, /SECURITY DEFINER/);
      assert.ok(baseline.schemas.some((s) => s.name === "app_auth" && s.owner === "mscqr_p2_test"));
      assert.deepEqual(fn.config, ["search_path=pg_catalog, public"]);
      assert.ok(fn.grants.some((g) => g.role === role && g.privilege === "EXECUTE"));
      assert.ok(!fn.grants.some((g) => g.role === "PUBLIC"));
      const table = baseline.tables.find((r) => r.name === "app_only_fixture");
      assert.equal(table.rls, true); assert.equal(table.forced, true);
      assert.equal(table.columns.find((r) => r.name === "id").identity, "a");
      assert.deepEqual(table.columns.find((r) => r.name === "status").enumLabels, ['pending','ready']);
      assert.deepEqual(table.columns.find((r) => r.name === "status_history").enumLabels, ['pending','ready']);
      assert.equal(table.columns.find((r) => r.name === "doubled").generated, "s");
      assert.match(table.columns.find((r) => r.name === "tenant").default, /fixture/);
      // PostgreSQL 18 records the three NOT NULL constraints in pg_constraint,
      // alongside the primary key and CHECK; do not discard them as noise.
      assert.equal(table.constraints.length, 5);
      assert.equal(table.constraints.filter((c) => c.definition.startsWith("NOT NULL")).length, 3);
      assert.ok(table.constraints.some((c) => c.definition === "PRIMARY KEY (id)"));
      assert.ok(table.constraints.some((c) => c.definition === "CHECK ((amount > 0))"));
      assert.ok(table.column_grants.some((g) => g.column === "tenant" && g.role === role && g.privilege === "SELECT"));
      assert.match(baseline.policies[0].using, /tenant.*CURRENT_USER/i);
      assert.match(baseline.policies[0].check, /amount > 0/);
      assert.ok(Object.values(evaluateAppOnlyDatabaseCatalogue(baseline, required)).every((v) => v === "COMPATIBLE"));
    });
    await t.test("real transaction is repeatable-read/read-only and refuses writes", async () => {
      const db = client();
      try {
        await db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
          const [settings] = await tx.$queryRawUnsafe("SELECT current_setting('transaction_isolation') AS isolation, current_setting('transaction_read_only') AS ro");
          assert.deepEqual(settings, { isolation: "repeatable read", ro: "on" });
        });
        await assert.rejects(db.$transaction(async (tx) => {
          await tx.$executeRawUnsafe("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
          await tx.$executeRawUnsafe("INSERT INTO public.app_only_fixture(amount) VALUES (2)");
        }), /read.only|permission denied/i);
      } finally { await db.$disconnect(); }
    });
    for (const [name, change, restore, domain] of [
      ["FORCE RLS", "ALTER TABLE app_only_fixture NO FORCE ROW LEVEL SECURITY", "ALTER TABLE app_only_fixture FORCE ROW LEVEL SECURITY", "RLS_FORCE_STATUS"],
      ["RLS enabled", "ALTER TABLE app_only_fixture DISABLE ROW LEVEL SECURITY", "ALTER TABLE app_only_fixture ENABLE ROW LEVEL SECURITY", "RLS_FORCE_STATUS"],
      ["PUBLIC function grant", "GRANT EXECUTE ON FUNCTION app_auth.fixture(integer) TO PUBLIC", "REVOKE EXECUTE ON FUNCTION app_auth.fixture(integer) FROM PUBLIC", "RLS_GRANTS"],
      ["function security", "ALTER FUNCTION app_auth.fixture(integer) SECURITY INVOKER", "ALTER FUNCTION app_auth.fixture(integer) SECURITY DEFINER", "RLS_FUNCTIONS"],
      ["policy expressions", "ALTER POLICY fixture_policy ON app_only_fixture USING (true) WITH CHECK (true)", "ALTER POLICY fixture_policy ON app_only_fixture USING (tenant = current_user) WITH CHECK (amount > 0)", "RLS_POLICIES"],
      ["column default", "ALTER TABLE app_only_fixture ALTER COLUMN amount SET DEFAULT 2", "ALTER TABLE app_only_fixture ALTER COLUMN amount SET DEFAULT 1", "DATABASE_SCHEMA"],
      ["enum label with unchanged type name", "ALTER TYPE app_only_status RENAME VALUE 'ready' TO 'incompatible'", "ALTER TYPE app_only_status RENAME VALUE 'incompatible' TO 'ready'", "DATABASE_SCHEMA"],
      ["table SELECT grant", `GRANT SELECT ON app_only_fixture TO ${role}`, `REVOKE SELECT ON app_only_fixture FROM ${role}`, "RLS_GRANTS"],
      ["schema PUBLIC grant", "GRANT USAGE ON SCHEMA app_auth TO PUBLIC", "REVOKE USAGE ON SCHEMA app_auth FROM PUBLIC", "RLS_GRANTS"],
      ["function search_path", "ALTER FUNCTION app_auth.fixture(integer) SET search_path=public,pg_catalog", "ALTER FUNCTION app_auth.fixture(integer) SET search_path=pg_catalog,public", "RLS_FUNCTIONS"],
      ["application BYPASSRLS", `ALTER ROLE ${appRole} BYPASSRLS`, `ALTER ROLE ${appRole} NOBYPASSRLS`, "RLS_GRANTS"],
      ["application inherited-role authority", `CREATE ROLE app_only_fixture_member; GRANT app_only_fixture_member TO ${appRole} WITH INHERIT TRUE`, `REVOKE app_only_fixture_member FROM ${appRole}; DROP ROLE app_only_fixture_member`, "RLS_GRANTS"],
    ]) await t.test(`real incompatible ${name} fails closed`, async () => {
      sql(change); try { assert.equal(evaluateAppOnlyDatabaseCatalogue(await collect(), required)[domain], "INCOMPATIBLE"); } finally { sql(restore); }
    });
    for (const [name, change, restore] of [
      ["column write", `GRANT UPDATE(amount) ON app_only_fixture TO ${role}`, `REVOKE UPDATE(amount) ON app_only_fixture FROM ${role}`],
      ["PUBLIC write", "GRANT INSERT ON app_only_fixture TO PUBLIC", "REVOKE INSERT ON app_only_fixture FROM PUBLIC"],
      ["inheritance", `ALTER ROLE ${role} INHERIT`, `ALTER ROLE ${role} NOINHERIT`],
      ["role membership", `CREATE ROLE app_only_fixture_member; GRANT app_only_fixture_member TO ${role}`, `REVOKE app_only_fixture_member FROM ${role}; DROP ROLE app_only_fixture_member`],
      ["writable default", `ALTER ROLE ${role} SET default_transaction_read_only=off`, `ALTER ROLE ${role} SET default_transaction_read_only=on`],
      ["schema ownership", `ALTER SCHEMA app_auth OWNER TO ${role}`, "ALTER SCHEMA app_auth OWNER TO mscqr_p2_test"],
    ]) await t.test(`restricted identity rejects ${name}`, async () => {
      sql(change); try { await assert.rejects(collect(), /restricted read-only contract/); } finally { sql(restore); }
    });
  } finally {
    if (createdDb) sql(`DROP DATABASE ${database}`, "mscqr_p2_admin_test");
    if (createdRole) sql(`DROP ROLE ${role}`, "mscqr_p2_admin_test");
    if (createdAppRole) sql(`DROP ROLE ${appRole}`, "mscqr_p2_admin_test");
    if (createdSubscriptionObserver) sql(`DROP ROLE ${subscriptionObserver}`, "mscqr_p2_admin_test");
  }
});

import { assertDisposablePostgresImage } from "../lib/container-image-identity.mjs";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { CatalogueOperationFailure, collectAppOnlyDatabaseCatalogue, evaluateAppOnlyDatabaseCatalogue, SUBSCRIPTION_PROJECTION_BODY_SHA256 } from "../aws/production-app-only-database-verifier.mjs";

// Deliberately requires the repository's local tmpfs PostgreSQL harness. No
// DATABASE_URL override, production connection, mock fallback or silent skip.
const container = "mscqr-p2-auth-security-postgres";
const database = "mscqr_production_rls_green_phase2";
const role = "mscqr_prod_rls_canary_read";
const appRole = "mscqr_prd_rls_phase2_app";
const subscriptionObserver = "mscqr_prod_subscription_observer";
const requireBackend = createRequire(new URL("../../backend/package.json", import.meta.url));
const { PrismaClient } = requireBackend("@prisma/client");
const printing = createRequire(import.meta.url)("../aws/production-printing-routine-delta-executor.cjs");
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
  assertDisposablePostgresImage(instance);
  assert.ok(Object.hasOwn(instance.HostConfig.Tmpfs, "/var/lib/postgresql"));
  assert.deepEqual(instance.HostConfig.PortBindings["5432/tcp"], [{ HostIp: "127.0.0.1", HostPort: "55432" }]);
  assert.equal(sql("SELECT current_database()", "mscqr_p2_admin_test"), "mscqr_p2_admin_test");
  assert.equal(sql(`SELECT count(*) FROM pg_database WHERE datname='${database}'`, "mscqr_p2_admin_test"), "0", "never overwrite an existing test database");
  assert.equal(sql(`SELECT count(*) FROM pg_roles WHERE rolname IN ('${role}','${appRole}','${subscriptionObserver}','app_only_fixture_member','app_only_unexpected_subscription_reader','app_only_unexpected_subscription_member','app_only_subscription_provisioner','app_only_temporary_subscription_observer','app_only_projection_acl_grantor')`, "mscqr_p2_admin_test"), "0", "never replace existing roles");
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
    const projection = provisioning.match(/CREATE(?: OR REPLACE)? FUNCTION app_rls\.production_security_subscription_inventory\([\s\S]*?\$subscription_inventory\$;/)?.[0];
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
    const liveProjection = JSON.parse(sql(`SELECT pg_catalog.jsonb_build_object(
      'projection',pg_catalog.jsonb_build_object('arguments',pg_catalog.pg_get_function_identity_arguments(p.oid),
        'result',pg_catalog.pg_get_function_result(p.oid),'owner',o.rolname,'security_definer',p.prosecdef,
        'volatility',p.provolatile::text,'config',p.proconfig,'body',p.prosrc,'language',l.lanname,
        'grants',(SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('role',g.rolname,'privilege',a.privilege_type,'grantable',a.is_grantable)
          ORDER BY g.rolname,a.privilege_type,a.is_grantable) FROM pg_catalog.aclexplode(p.proacl) a
          JOIN pg_catalog.pg_roles g ON g.oid=a.grantee)),
      'properties',pg_catalog.jsonb_build_object('kind',p.prokind::text,'parallel',p.proparallel::text,
        'leakproof',p.proleakproof,'strict',p.proisstrict))
      FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles o ON o.oid=p.proowner
      JOIN pg_catalog.pg_language l ON l.oid=p.prolang
      WHERE p.oid='app_rls.production_security_subscription_inventory()'::pg_catalog.regprocedure`));
    assert.equal(liveProjection.projection.language, "sql");
    assert.doesNotThrow(() => printing.authenticateSubscriptionProjection(liveProjection.projection, liveProjection.properties));
    assert.throws(() => printing.authenticateSubscriptionProjection({ ...liveProjection.projection, language: "plpgsql" }, liveProjection.properties));
    const baseline = await collect();
    const required = { ...structuredClone(baseline), contractSha256: "a".repeat(64) };
    await t.test("missing subscription projection returns a bounded failure and never invokes it", async () => {
      sql(`GRANT USAGE, CREATE ON SCHEMA app_rls TO ${subscriptionObserver};
        SET ROLE ${subscriptionObserver};
        DROP FUNCTION app_rls.production_security_subscription_inventory();
        RESET ROLE;
        REVOKE USAGE, CREATE ON SCHEMA app_rls FROM ${subscriptionObserver};`);
      try {
        await assert.rejects(collect(), (error) => error instanceof CatalogueOperationFailure
          && error.operation === "SUBSCRIPTION_PROJECTION_MISSING");
      } finally {
        sql(`GRANT USAGE, CREATE ON SCHEMA app_rls TO ${subscriptionObserver};
          SET ROLE ${subscriptionObserver};
          ${projection}
          REVOKE ALL ON FUNCTION app_rls.production_security_subscription_inventory() FROM PUBLIC;
          GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO ${role};
          RESET ROLE;
          REVOKE USAGE, CREATE ON SCHEMA app_rls FROM ${subscriptionObserver};`);
      }
      assert.deepEqual(await collect(), baseline);
    });
    await t.test("database settings from an unrelated database do not create false drift", async () => {
      sql("ALTER DATABASE mscqr_p2_admin_test SET row_security=off", "mscqr_p2_admin_test");
      try {
        const catalogue = await collect();
        assert.equal(catalogue.securityBindings.some(({ kind, name }) => kind === "database_setting" && name === "mscqr_p2_admin_test"), false);
      } finally {
        sql("ALTER DATABASE mscqr_p2_admin_test RESET row_security", "mscqr_p2_admin_test");
      }
    });
    await t.test("real large-object ownership and ACL metadata are collected without object IDs or contents", async () => {
      const oid = sql("SELECT lo_create(0)::text");
      try {
        sql(`ALTER LARGE OBJECT ${oid} OWNER TO ${appRole}; GRANT SELECT ON LARGE OBJECT ${oid} TO ${role}`);
        const catalogue = await collect();
        const binding = catalogue.securityBindings.find(({ kind }) => kind === "large_objects");
        assert.ok(binding, "restricted real collector includes large-object access metadata");
        assert.equal(binding.owner, appRole);
        assert.equal(binding.definition.count, 1);
        assert.ok(binding.definition.grants.some(({ role: grantee, privilege }) => grantee === role && privilege === "SELECT"));
        assert.equal(JSON.stringify(binding).includes(oid), false, "database-local OID is not used as inventory identity");
      } finally {
        sql(`SELECT lo_unlink(${oid})`);
      }
    });
    await t.test("real non-system tablespace ownership and ACL metadata are collected", async () => {
      const directory = "/tmp/mscqr-rebaseline-tablespace";
      execFileSync("docker", ["exec", container, "sh", "-c", `install -d -o postgres -g postgres ${directory}`], { timeout: 10000 });
      try {
        sql(`CREATE TABLESPACE rebaseline_tablespace LOCATION '${directory}'; GRANT CREATE ON TABLESPACE rebaseline_tablespace TO ${appRole}`);
        const binding = (await collect()).securityBindings.find(({ kind, name }) => kind === "tablespace" && name === "rebaseline_tablespace");
        assert.equal(binding?.owner, "mscqr_p2_test");
        assert.ok(binding.definition.grants.some(({ role: grantee, privilege }) => grantee === appRole && privilege === "CREATE"));
      } finally {
        sql("DROP TABLESPACE IF EXISTS rebaseline_tablespace");
        execFileSync("docker", ["exec", container, "sh", "-c", `rmdir ${directory}`], { timeout: 10000 });
      }
    });
    await t.test("real subscription projection grant option is rejected before invoking the function", async () => {
      sql(`GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO ${role} WITH GRANT OPTION`);
      try {
        await assert.rejects(collect(), /projection_acl_valid/);
      } finally {
        sql(`REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() FROM ${role}`);
      }
      assert.deepEqual(await collect(), baseline, "removing the grant option restores the authenticated projection contract");
    });
    await t.test("real subscription projection ACL with a different grantor is rejected", async () => {
      const delegate = "app_only_projection_acl_grantor";
      sql(`CREATE ROLE ${delegate} NOLOGIN`);
      try {
        sql(`GRANT USAGE ON SCHEMA app_rls TO ${delegate};
          GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO ${delegate} WITH GRANT OPTION;
          SET ROLE ${delegate};
          GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() TO ${role};
          RESET ROLE`);
        await assert.rejects(collect(), /projection_acl_valid|unexpected_execute_roles/);
      } finally {
        sql(`SET ROLE ${delegate};
          REVOKE EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() FROM ${role};
          RESET ROLE;
          REVOKE EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory() FROM ${delegate};
          REVOKE USAGE ON SCHEMA app_rls FROM ${delegate};
          DROP ROLE ${delegate}`);
      }
      assert.deepEqual(await collect(), baseline, "removing the unexpected grantor ACL restores the reviewed grantor");
    });
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
    await t.test("real PostgreSQL 18 non-superuser projects the exact body without a catalogue grant option", async () => {
      const admin = "mscqr_prod_admin";
      const source = fs.readFileSync(path.join(process.cwd(), "documents/ops/iam/production-rds-subscription-projection-remediation.sql"), "utf8");
      const guard = source.match(/  IF pg_catalog\.to_regprocedure\('app_rls\.production_security_subscription_inventory\(\)'\) IS NOT NULL[\s\S]*?  END IF;/)?.[0];
      assert.ok(guard);
      assert.doesNotThrow(() => sql(`DO $$ BEGIN ${guard.replaceAll("production_security_subscription_inventory()", "production_security_subscription_inventory_missing_test()")} END $$;`),
        "an absent predecessor must not evaluate a throwing regprocedure cast");
      assert.throws(() => sql(`DO $$ BEGIN ${guard} END $$;`), "an existing observer-owned predecessor must fail closed");
      const projection = source.match(/CREATE FUNCTION app_rls\.production_security_subscription_inventory\(\)[\s\S]*?\$subscription_inventory\$;/)?.[0];
      assert.ok(projection);
      const body = projection.match(/AS \$subscription_inventory\$(.*?)\$subscription_inventory\$;/s)?.[1];
      assert.equal(crypto.createHash("sha256").update(body, "utf8").digest("hex"), SUBSCRIPTION_PROJECTION_BODY_SHA256);
      const testProjection = projection.replace("production_security_subscription_inventory()", "production_security_subscription_inventory_rds_test()");
      sql(`CREATE ROLE ${admin} NOLOGIN CREATEROLE;
        GRANT SELECT ON pg_catalog.pg_subscription TO ${admin};
        GRANT USAGE, CREATE ON SCHEMA app_rls TO ${admin}`);
      try {
        assert.equal(sql(`SELECT has_column_privilege('${admin}','pg_catalog.pg_subscription','subconninfo','SELECT')::text,
          has_column_privilege('${admin}','pg_catalog.pg_subscription','subconninfo','SELECT WITH GRANT OPTION')::text`), "true|false");
        const db = client();
        try {
          const state = await printing.readRdsSubscriptionState(db);
          assert.equal(state.observer_absent, false, "printing rejects mixed observer and DBA projection state");
          assert.notEqual(state.catalogue_owner, "rdsadmin", "disposable PostgreSQL does not impersonate RDS catalogue ownership");
        } finally { await db.$disconnect(); }
        sql(`SET ROLE ${admin}; ${testProjection}
          REVOKE ALL ON FUNCTION app_rls.production_security_subscription_inventory_rds_test() FROM PUBLIC;
          GRANT EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory_rds_test() TO ${role}; RESET ROLE`);
        sql("CREATE SUBSCRIPTION rds_projection_disposable CONNECTION 'host=127.0.0.1 dbname=unused password=synthetic_fixture_only' PUBLICATION rds_projection_disposable WITH (connect=false, create_slot=false, enabled=false)");
        try {
          assert.equal(sql(`SET ROLE ${role};
            SELECT subscription_name,connection_info_sha256 ~ '^[a-f0-9]{64}$',
              has_column_privilege(current_user,'pg_catalog.pg_subscription','subconninfo','SELECT')
            FROM app_rls.production_security_subscription_inventory_rds_test()
            WHERE subscription_name='rds_projection_disposable'; RESET ROLE`), "SET\nrds_projection_disposable|t|f\nRESET");
          assert.equal(sql(`SELECT pg_get_function_result('app_rls.production_security_subscription_inventory_rds_test()'::regprocedure)`),
            "TABLE(subscription_name text, subscription_owner text, enabled boolean, \"binary\" boolean, streaming text, two_phase text, disable_on_error boolean, password_required boolean, run_as_owner boolean, failover boolean, slot_name text, synchronous_commit text, publications text[], origin text, skip_lsn text, relations jsonb, connection_info_sha256 text)");
        } finally { sql("ALTER SUBSCRIPTION rds_projection_disposable SET (slot_name = NONE); DROP SUBSCRIPTION rds_projection_disposable"); }
        const rdsRollback = `BEGIN;
          DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
              WHERE p.oid='app_rls.production_security_subscription_inventory_rds_test()'::pg_catalog.regprocedure
                AND owner.rolname='${admin}' AND p.prosecdef AND p.provolatile='s'
                AND p.proconfig=ARRAY['search_path=pg_catalog']::text[]
                AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(p.prosrc,'UTF8')),'hex')='${SUBSCRIPTION_PROJECTION_BODY_SHA256}')
            THEN RAISE EXCEPTION 'RDS rollback predecessor changed'; END IF;
          END $$;
          REVOKE EXECUTE ON FUNCTION app_rls.production_security_subscription_inventory_rds_test() FROM ${role};
          DROP FUNCTION app_rls.production_security_subscription_inventory_rds_test();
          COMMIT;`;
        assert.throws(() => sql(rdsRollback.replace("COMMIT;", "DO $$ BEGIN RAISE EXCEPTION 'intentional rollback proof'; END $$; COMMIT;")));
        assert.equal(sql("SELECT to_regprocedure('app_rls.production_security_subscription_inventory_rds_test()') IS NOT NULL"), "t", "failed RDS rollback preserves the exact projection");
        sql(rdsRollback);
        assert.equal(sql("SELECT to_regprocedure('app_rls.production_security_subscription_inventory_rds_test()') IS NULL"), "t", "RDS rollback drops only the DBA-owned test projection");
        assert.equal(sql(`SELECT to_regrole('${subscriptionObserver}') IS NOT NULL`), "t", "RDS rollback never revokes or drops the separate observer contract");
      } finally {
        sql(`DROP FUNCTION IF EXISTS app_rls.production_security_subscription_inventory_rds_test();
          REVOKE USAGE, CREATE ON SCHEMA app_rls FROM ${admin};
          REVOKE SELECT ON pg_catalog.pg_subscription FROM ${admin}; DROP ROLE ${admin}`);
      }
    });
  } finally {
    if (createdDb) sql(`DROP DATABASE ${database}`, "mscqr_p2_admin_test");
    if (createdRole) sql(`DROP ROLE ${role}`, "mscqr_p2_admin_test");
    if (createdAppRole) sql(`DROP ROLE ${appRole}`, "mscqr_p2_admin_test");
    if (createdSubscriptionObserver) sql(`DROP ROLE ${subscriptionObserver}`, "mscqr_p2_admin_test");
  }
});

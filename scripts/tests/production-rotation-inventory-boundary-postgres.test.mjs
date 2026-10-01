import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";
import { rotationInventoryFunctionSql, rotationInventoryPolicySql, ROTATION_INVENTORY_TABLES } from "../rls/lib/rotation-inventory-contract.mjs";
import { executeProductionRotationInventory } from "../security/production-rotation-state-inventory.mjs";
import { assertBoundedRotationInventory } from "../security/production-runtime-rotation-inventory.mjs";

const adminUrl = process.env.MSCQR_INVENTORY_BOUNDARY_TEST_DATABASE_URL;
const sql = (url, command) => execFileSync("psql", [url, "-XAt", "-v", "ON_ERROR_STOP=1", "-c", command], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
test("PostgreSQL18 fixed aggregate boundary preserves app isolation and forced RLS", { skip: !adminUrl }, () => {
  assert.equal(sql(adminUrl, "SELECT current_setting('server_version_num')::int/10000"), "18");
  assert.equal(sql(adminUrl, "SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'"), "0", "dedicated empty disposable database required");
  const owner = "inventory_fixture_owner", app = "inventory_fixture_app";
  const appUrl = new URL(adminUrl); appUrl.username = app; appUrl.password = "";
  const columns = {
    RefreshToken: '"userId" text,"revokedAt" timestamp,"expiresAt" timestamp',
    User: '"id" text,"status" text,"isActive" boolean,"deletedAt" timestamp,"role" text',
    CustomerAuthSession: '"revokedAt" timestamp,"expiresAt" timestamp',
    CustomerVerificationSession: '"expiresAt" timestamp',
    Invite: '"usedAt" timestamp,"expiresAt" timestamp', PasswordReset: '"usedAt" timestamp,"expiresAt" timestamp', EmailVerificationToken: '"usedAt" timestamp,"expiresAt" timestamp',
    QRCode: '"issuanceMode" text,"tokenExpiresAt" timestamp', CompliancePackJob: '"signatureAlgorithm" text,"finishedAt" timestamp',
  };
  sql(adminUrl, `CREATE ROLE ${owner} NOLOGIN NOINHERIT NOBYPASSRLS; CREATE ROLE ${app} LOGIN NOINHERIT NOBYPASSRLS; CREATE SCHEMA app_rls AUTHORIZATION ${owner}; GRANT USAGE ON SCHEMA public,app_rls TO ${app};`);
  try {
    sql(adminUrl, ROTATION_INVENTORY_TABLES.map((table) => `CREATE TABLE public."${table}" (${columns[table]}); ALTER TABLE public."${table}" OWNER TO ${owner}; ALTER TABLE public."${table}" ENABLE ROW LEVEL SECURITY; ALTER TABLE public."${table}" FORCE ROW LEVEL SECURITY;`).join("\n"));
    sql(adminUrl, `SET ROLE ${owner}; ${rotationInventoryFunctionSql({ owner, app })} ${rotationInventoryPolicySql({ owner, app })} RESET ROLE;`);
    sql(adminUrl, `INSERT INTO public."RefreshToken" VALUES ('secret-user-id',NULL,now()+interval '1 day'); INSERT INTO public."User" VALUES ('secret-user-id','ACTIVE',true,NULL,'ORG_ADMIN');`);
    const inventory = executeProductionRotationInventory({ env: { ...process.env, DATABASE_URL: appUrl.toString(), ROTATION_INVENTORY_APPROVED: "true", ROTATION_INVENTORY_OPERATION: "rotation-inventory-v1" } });
    assertBoundedRotationInventory(inventory);
    assert.equal(inventory.refreshSessions.count, 1); assert.equal(inventory.adminSessions.count, 1);
    assert.doesNotMatch(JSON.stringify(inventory), /secret-user-id/);
    assert.equal(sql(adminUrl, `SELECT has_function_privilege('public','app_rls.production_rotation_inventory()','EXECUTE')`), "f");
    assert.equal(sql(adminUrl, `SELECT pg_has_role('${app}','${owner}','MEMBER')`), "f");
    assert.equal(sql(adminUrl, `SELECT bool_and(relrowsecurity AND relforcerowsecurity) FROM pg_class WHERE relnamespace='public'::regnamespace AND relkind='r'`), "t");
    for (const table of ROTATION_INVENTORY_TABLES) {
      assert.equal(sql(adminUrl, `SELECT has_table_privilege('${app}','public."${table}"','SELECT')`), "f");
      assert.throws(() => sql(appUrl, `BEGIN READ ONLY; SET LOCAL app.rotation_inventory_operation='rotation-inventory-v1'; SELECT * FROM public."${table}"; ROLLBACK;`));
    }
    assert.throws(() => sql(appUrl, "SELECT app_rls.production_rotation_inventory()"));
    assert.throws(() => sql(appUrl, "BEGIN READ ONLY; SELECT app_rls.production_rotation_inventory('User'); ROLLBACK;"));
    assert.throws(() => sql(adminUrl, "BEGIN READ ONLY; SELECT app_rls.production_rotation_inventory(); ROLLBACK;"));
    assert.equal(sql(appUrl, "BEGIN READ ONLY; SET LOCAL app.user_id='must-restore'; SELECT app_rls.production_rotation_inventory() IS NOT NULL; SELECT current_setting('app.user_id'); ROLLBACK;"), "BEGIN\nSET\nt\nmust-restore\nROLLBACK");
  } finally {
    sql(adminUrl, `DROP SCHEMA app_rls CASCADE; ${ROTATION_INVENTORY_TABLES.map((table) => `DROP TABLE public."${table}";`).join(" ")} DROP OWNED BY ${app},${owner}; DROP ROLE ${app},${owner};`);
  }
});

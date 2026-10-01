import assert from "node:assert/strict";
import crypto from "node:crypto";
import { rotationInventoryFunctionSql, rotationInventoryPolicySql, ROTATION_INVENTORY_TABLES } from "../rls/lib/rotation-inventory-contract.mjs";

const owner = "mscqr_prd_rls_phase2_owner", app = "mscqr_prd_rls_phase2_app";
export function canonicalInventoryInstallation() {
  const source = rotationInventoryFunctionSql({ owner, app });
  const end = source.indexOf("$inventory$;", source.indexOf("AS $inventory$")) + "$inventory$;".length;
  assert.ok(end > 0);
  const policies = rotationInventoryPolicySql({ owner, app }).split("\n");
  const statements = [`SET LOCAL ROLE "${owner}"`, source.slice(0, end), `REVOKE ALL ON FUNCTION app_rls.production_rotation_inventory() FROM PUBLIC`, `GRANT EXECUTE ON FUNCTION app_rls.production_rotation_inventory() TO "${app}"`, ...policies.flatMap((line) => line.split("; ").map((sql) => sql.replace(/;$/, ""))), "RESET ROLE"];
  const policyExpression = `((CURRENT_USER = '${owner}'::name) AND (SESSION_USER = '${app}'::name) AND (current_setting('transaction_read_only'::text) = 'on'::text) AND (current_setting('app.rotation_inventory_operation'::text, true) = 'rotation-inventory-v1'::text) AND (COALESCE(current_setting('app.user_id'::text, true), ''::text) = ''::text) AND (COALESCE(current_setting('app.role'::text, true), ''::text) = ''::text) AND (COALESCE(current_setting('app.licensee_id'::text, true), ''::text) = ''::text) AND (COALESCE(current_setting('app.auth_session_id'::text, true), ''::text) = ''::text) AND (COALESCE(current_setting('app.context_installed'::text, true), ''::text) = ''::text))`;
  const functionBody = source.slice(source.indexOf("AS $inventory$") + "AS $inventory$".length, end - "$inventory$;".length);
  return Object.freeze({ owner, app, tables: ROTATION_INVENTORY_TABLES, statements, functionBody, policyExpression, statementsSha256: crypto.createHash("sha256").update(JSON.stringify(statements)).digest("hex") });
}

// Used by the fixed one-shot production executor and the PostgreSQL upgrade test.
// The command builder embeds the canonical contract; no SQL is accepted from CLI.
export async function executeInventoryInstallation(tx, contract) {
  const { owner, app, tables, statements } = contract;
  await tx.$executeRawUnsafe("SET LOCAL search_path=pg_catalog");
  await tx.$executeRawUnsafe("SELECT pg_advisory_xact_lock(hashtextextended('mscqr-production-rotation-inventory-v1',0))");
  const [identity] = await tx.$queryRawUnsafe("SELECT current_user AS role, current_database() AS database, current_setting('server_version_num')::int/10000 AS version");
  assert.equal(identity.role, "mscqr_prod_admin"); assert.equal(identity.database, "mscqr_production_rls_green_phase2"); assert.equal(identity.version, 18);
  const baseline = async () => {
    const tableState = await tx.$queryRawUnsafe(`SELECT c.relname AS name,r.rolname AS owner,c.relrowsecurity AS rls,c.relforcerowsecurity AS forced,c.relacl::text AS acl FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY($1::text[]) ORDER BY c.relname`, tables);
    const columns = await tx.$queryRawUnsafe(`SELECT c.relname AS table,a.attname AS column,a.attacl::text AS acl FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY($1::text[]) AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`, tables);
    const membership = await tx.$queryRawUnsafe("SELECT roleid::text AS role,member::text AS member,grantor::text AS grantor,admin_option,inherit_option,set_option FROM pg_auth_members ORDER BY roleid,member,grantor");
    const policies = await tx.$queryRawUnsafe(`SELECT c.relname AS table,p.polname AS name,p.polroles::text AS roles,p.polcmd::text AS command,p.polqual::text AS predicate,p.polwithcheck::text AS check FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE c.relnamespace='public'::regnamespace AND c.relname=ANY($1::text[]) AND p.polname NOT LIKE 'rotation_inventory_%' ORDER BY c.relname,p.polname`, tables);
    return { tables: tableState, columns, membership, policies };
  };
  const before = await baseline();
  assert.equal(before.tables.length, tables.length);
  for (const table of before.tables) assert.ok(table.owner === owner && table.rls && table.forced, "inventory installation requires the existing exact forced-RLS owner");
  const [roles] = await tx.$queryRawUnsafe(`SELECT (SELECT NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=$1) AS owner_safe, (SELECT NOT rolsuper AND NOT rolbypassrls FROM pg_roles WHERE rolname=$2) AS app_safe, pg_has_role($2,$1,'MEMBER') AS app_owner_member`, owner, app);
  assert.ok(roles.owner_safe && roles.app_safe && !roles.app_owner_member);
  const [present] = await tx.$queryRawUnsafe("SELECT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname='production_rotation_inventory') AS function_present, (SELECT count(*)::int FROM pg_policy WHERE polname LIKE 'rotation_inventory_%') AS policy_count");
  if (present.function_present || present.policy_count) throw new Error("Inventory contract already exists or is partial; authenticate it read-only before retrying.");
  for (const sql of statements) await tx.$executeRawUnsafe(sql);
  assert.deepEqual(await baseline(), before, "inventory installation changed existing grants, memberships, policies or forced RLS");
  const [routine] = await tx.$queryRawUnsafe(`SELECT r.rolname AS owner,p.prosecdef AS definer,p.provolatile::text AS volatility,p.proconfig AS configuration,p.prosrc AS body,has_function_privilege('public',p.oid,'EXECUTE') AS public_execute,has_function_privilege($1,p.oid,'EXECUTE') AS app_execute FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='app_rls' AND p.proname='production_rotation_inventory' AND p.pronargs=0`, app);
  assert.equal(routine.body, contract.functionBody);
  assert.equal(routine.owner, owner); assert.equal(routine.definer, true); assert.equal(routine.volatility, "s"); assert.equal(routine.public_execute, false); assert.equal(routine.app_execute, true); assert.deepEqual(routine.configuration, ["search_path=pg_catalog, public", "row_security=on"]);
  const installed = await tx.$queryRawUnsafe(`SELECT c.relname AS table,p.polname AS name,p.polcmd::text AS command, p.polpermissive AS permissive,pg_get_expr(p.polqual,p.polrelid) AS expression,p.polwithcheck IS NULL AS no_check,p.polroles=ARRAY[(SELECT oid FROM pg_roles WHERE rolname=$1)] AS owner_only FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid WHERE p.polname LIKE 'rotation_inventory_%' ORDER BY c.relname`, owner);
  assert.deepEqual(installed.map((row) => row.table).sort(), [...tables].sort());
  assert.ok(installed.every((row) => row.command === "r" && row.permissive && row.owner_only && row.no_check && row.expression === contract.policyExpression));
  return { status: "APPLIED", statementsSha256: contract.statementsSha256, functionCount: 1, policyCount: tables.length, directTableGrantsAdded: 0 };
}

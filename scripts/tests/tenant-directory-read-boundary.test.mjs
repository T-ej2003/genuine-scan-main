import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { NAMED_SQL_FUNCTION_CONTRACTS, validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const read = (path) => fs.readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const contracts = NAMED_SQL_FUNCTION_CONTRACTS.filter((contract) => contract.id.startsWith("tenant-directory-"));

test("tenant directory has exactly two capability-bearing reviewed contracts", () => {
  validateNamedSqlFunctionContracts();
  assert.deepEqual(contracts.map(({ name, signature }) => [name, signature]), [
    ["read_licensee_directory", "text,text,text,text,boolean"],
    ["read_user_directory", "text,text,text,text,boolean,text,integer,integer"],
  ]);
  for (const contract of contracts) {
    assert.equal(contract.security.mode, "SECURITY DEFINER");
    assert.equal(contract.security.ownerRole, "authOwner");
    assert.deepEqual(contract.security.runtimeExecuteGrantees, ["app"]);
    assert.equal(contract.security.publicExecute, "revoked");
    assert.match(contract.context, /capability/i);
  }
});

test("Release Fix 2 admits only the four approved caller roles", () => {
  const source = read("backend/src/rls-waves/session-a/operationalReadBoundaries.sql").split("-- Release Fix 2:")[1];
  const rbac = read("backend/src/middleware/rbac.ts").match(/export const requireTenantDirectoryReader = requireRole\(([\s\S]*?)\);/)?.[1] || "";
  for (const role of ["SUPER_ADMIN", "PLATFORM_SUPER_ADMIN", "LICENSEE_ADMIN", "MANUFACTURER_ADMIN"]) {
    assert.match(source, new RegExp(`['.]${role}`));
    assert.match(rbac, new RegExp(`UserRole\\.${role}`));
  }
  for (const role of ["ORG_ADMIN", "MANUFACTURER_USER"]) {
    assert.doesNotMatch(source, new RegExp(role));
    assert.doesNotMatch(rbac, new RegExp(role));
  }
  assert.doesNotMatch(source, /'MANUFACTURER'/);
  assert.doesNotMatch(rbac, /UserRole\.MANUFACTURER\b/);
  assert.doesNotMatch(source, /SELECT\s+l\.\*\s+FROM\s+public\."Licensee"/i);
});

test("three routes use exact repository reads without legacy context or direct Prisma", () => {
  const licensee = read("backend/src/controllers/licenseeController.ts");
  const users = read("backend/src/controllers/userController.ts");
  const routes = read("backend/src/routes/index.ts");
  const licenseeReads = licensee.slice(licensee.indexOf("export const getLicensees"), licensee.indexOf("export const updateLicensee"));
  const userRead = users.slice(users.indexOf("export const getUsers"), users.indexOf("export const getManufacturers"));
  assert.match(licenseeReads, /readLicenseeDirectory/);
  assert.doesNotMatch(licenseeReads, /prisma\.licensee|withCanonicalDbContext|install_actor_context/);
  assert.match(userRead, /readUserDirectory/);
  assert.doesNotMatch(userRead, /prisma\.user|buildScopedUserWhere|withCanonicalDbContext|install_actor_context/);
  assert.match(routes, /get\("\/licensees"[\s\S]*?requireTenantDirectoryReader/);
  assert.match(routes, /get\("\/licensees\/:id"[\s\S]*?requireTenantDirectoryReader/);
  assert.match(routes, /get\("\/users"[\s\S]*?requireTenantDirectoryReader/);
});

test("generated package exposes exact functions and QRRange read policy only", () => {
  const helpers = read("scripts/rls/sql/generated/20-context-helpers.sql");
  const grants = read("scripts/rls/sql/generated/21-runtime-grants.sql");
  const executableSql = `${helpers}\n${grants}`;
  const policies = read("scripts/rls/sql/generated/30-policies.sql");
  const rollback = read("backend/src/rls-waves/session-a/operationalReadBoundariesRollback.sql");
  assert.match(helpers, /CREATE OR REPLACE FUNCTION app_rls\.read_licensee_directory/);
  assert.match(helpers, /CREATE OR REPLACE FUNCTION app_rls\.read_user_directory/);
  assert.match(executableSql, /GRANT EXECUTE ON FUNCTION app_rls\.read_licensee_directory\(text,text,text,text,boolean\) TO "mscqr_rls_cert_app"/);
  assert.match(executableSql, /GRANT EXECUTE ON FUNCTION app_rls\.read_user_directory\(text,text,text,text,boolean,text,integer,integer\) TO "mscqr_rls_cert_app"/);
  assert.match(policies, /CREATE POLICY "tenant_directory_qrrange_select"[\s\S]*FOR SELECT/);
  assert.doesNotMatch(policies, /tenant_directory_qrrange_(insert|update|delete)/i);
  assert.match(rollback, /DROP FUNCTION IF EXISTS app_rls\.read_licensee_directory/);
  assert.match(rollback, /DROP FUNCTION IF EXISTS app_rls\.read_user_directory/);
  assert.doesNotMatch(executableSql, /GRANT EXECUTE ON ALL FUNCTIONS|GRANT ALL ON ALL FUNCTIONS/);
});

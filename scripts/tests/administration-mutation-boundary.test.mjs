import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import { NAMED_SQL_FUNCTION_CONTRACTS, validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const read = (path) => fs.readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
const names = ["session_c_create_licensee","session_c_update_licensee","session_c_delete_licensee","session_c_create_user","session_c_update_user","session_c_delete_user","session_c_restore_manufacturer","prepare_invitation"];

test("Release Fix 3 registers only exact administration mutation boundaries", () => {
  validateNamedSqlFunctionContracts();
  const contracts = NAMED_SQL_FUNCTION_CONTRACTS.filter(({ id }) => id.startsWith("c01-administration-"));
  assert.deepEqual(contracts.map(({ name }) => name).sort(), [...names].sort());
  for (const contract of contracts) {
    assert.equal(contract.security.ownerRole, "authOwner");
    assert.equal(contract.security.publicExecute, "revoked");
    assert.deepEqual(contract.security.runtimeExecuteGrantees, ["app"]);
    assert.equal(contract.security.mode, "SECURITY DEFINER");
  }
});

test("administration mutation authority admits no deprecated role family", () => {
  const source = read("backend/src/rls-waves/session-c/c01/administration.sql");
  const rbac = read("backend/src/middleware/rbac.ts").match(/export const requireAdministrationMutator = requireRole\(([\s\S]*?)\);/)?.[1] || "";
  for (const role of ["SUPER_ADMIN","PLATFORM_SUPER_ADMIN","LICENSEE_ADMIN"]) assert.match(source, new RegExp(`'${role}'`));
  assert.match(source, /p_requested_role NOT IN \('SUPER_ADMIN','PLATFORM_SUPER_ADMIN','LICENSEE_ADMIN','MANUFACTURER_ADMIN'\)/);
  for (const role of ["ORG_ADMIN","MANUFACTURER_USER"]) {
    assert.doesNotMatch(source, new RegExp(role));
    assert.doesNotMatch(rbac, new RegExp(`UserRole\\.${role}`));
  }
  assert.doesNotMatch(source, /'MANUFACTURER'/);
  assert.doesNotMatch(rbac, /UserRole\.MANUFACTURER\b/);
});

test("in-scope controllers use exact repository mutations and no canonical context", () => {
  for (const file of ["backend/src/controllers/licenseeController.ts","backend/src/controllers/userController.ts","backend/src/controllers/licenseeInviteController.ts","backend/src/controllers/authController.ts"]) {
    const source = read(file);
    assert.doesNotMatch(source, /withCanonicalDbContext|install_actor_context/);
  }
  const licensee = read("backend/src/controllers/licenseeController.ts");
  const users = read("backend/src/controllers/userController.ts");
  assert.match(licensee, /createLicenseeBoundary|updateLicenseeBoundary|deleteLicenseeBoundary/);
  assert.match(users, /createUserBoundary|updateUserBoundary|deleteUserBoundary|restoreManufacturerBoundary/);
});

test("generated package has exact grants, policies and rollback", () => {
  const helpers = read("scripts/rls/sql/generated/20-context-helpers.sql");
  const grants = read("scripts/rls/sql/generated/21-runtime-grants.sql");
  const executableSql = `${helpers}\n${grants}`;
  const policies = read("scripts/rls/sql/generated/30-policies.sql");
  const rollback = read("backend/src/rls-waves/session-c/c01/administrationRollback.sql");
  for (const name of names) {
    assert.match(helpers, new RegExp(`CREATE OR REPLACE FUNCTION app_rls\\.${name}`));
    assert.match(executableSql, new RegExp(`GRANT EXECUTE ON FUNCTION app_rls\\.${name}\\(`));
    assert.match(rollback, new RegExp(`DROP FUNCTION IF EXISTS app_rls\\.${name}`));
  }
  assert.match(policies, /c01_administration_invite_insert/);
  assert.match(policies, /c01_administration_manufacturerlicenseelink_delete/);
  assert.doesNotMatch(`${helpers}\n${grants}\n${policies}`, /GRANT EXECUTE ON ALL FUNCTIONS|GRANT ALL ON ALL FUNCTIONS|USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|(?:CREATE|ALTER)\s+ROLE[^;]*(?<!NO)BYPASSRLS/i);
});

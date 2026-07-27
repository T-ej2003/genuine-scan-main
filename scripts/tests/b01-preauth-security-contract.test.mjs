import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");
const source = read("backend/src/rls-waves/session-b/b01/b01PreAuthSecurityFunctions.sql");
const rollback = read("backend/src/rls-waves/session-b/b01/b01PreAuthSecurityRollback.sql");
const generated = read("scripts/rls/sql/generated/20-context-helpers.sql");
const runtimeGrants = read("scripts/rls/sql/generated/21-runtime-grants.sql");
const functions = [
  "lookup_password_user",
  "record_password_failure",
  "request_password_reset",
  "consume_password_reset_token",
  "lookup_invitation_token",
  "consume_invitation_token",
  "consume_email_verification_token",
];

test("B01 pre-auth contracts are exact reviewed bearer boundaries", () => {
  const contracts = validateNamedSqlFunctionContracts().filter((contract) =>
    contract.definitionLocation.endsWith("b01PreAuthSecurityFunctions.sql"),
  );
  assert.deepEqual(contracts.map(({ name }) => name).sort(), [...functions].sort());
  for (const contract of contracts) {
    assert.equal(contract.definitionStatus, "production-reviewed");
    assert.equal(contract.security.ownerIdentity, "identity-auth-function-owner");
    assert.equal(contract.security.publicExecute, "revoked");
    assert.deepEqual(contract.security.runtimeExecuteGrantees, ["preauth"]);
    assert.deepEqual(contract.disposableProbes, ["b01-preauth-security-postgres18"]);
    assert(contract.repositoryCallers.length > 0);
    assert(contract.canonicalWorkflowIds.length > 0);
    assert(contract.tableCommands.length > 0);
    assert.match(source, new RegExp(`CREATE OR REPLACE FUNCTION app_auth\\.${contract.name}\\(`));
    assert.match(rollback, new RegExp(`DROP FUNCTION IF EXISTS app_auth\\.${contract.name}\\(`));
  }
});

test("generated package preserves exact grants and excludes unsafe authority", () => {
  for (const name of functions) {
    assert.match(generated, new RegExp(`CREATE OR REPLACE FUNCTION app_auth\\.${name}\\(`));
    assert.match(generated, new RegExp(`GRANT EXECUTE ON FUNCTION app_auth\\.${name}\\(`));
  }
  assert.doesNotMatch(`${generated}\n${runtimeGrants}`, /GRANT EXECUTE ON ALL FUNCTIONS|ALTER DEFAULT PRIVILEGES/i);
  assert.doesNotMatch(`${generated}\n${runtimeGrants}`, /GRANT EXECUTE ON FUNCTION app_auth\.b01_preauth_audit/i);
  assert.doesNotMatch(`${generated}\n${runtimeGrants}`, /GRANT EXECUTE ON FUNCTION app_rls\.install_actor_context/i);
  assert.doesNotMatch(source, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|BYPASSRLS|md5\s*\(|SELECT\s+\*/i);
  assert.doesNotMatch(source, /STABLE\s+PARALLEL\s+SAFE/i, "transaction-local context installers must be volatile and parallel-unsafe");
  assert.match(source, /FOR UPDATE/);
  assert.match(source, /sessionCapabilityRevokedAt/);
  assert.match(source, /AuditLogOutbox/);
});

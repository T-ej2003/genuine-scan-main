import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { namedFunctionContractFor } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const source = fs.readFileSync(path.join(root, "backend/src/rls-waves/session-b/b01/b01AuthenticationClosureFunctions.sql"), "utf8");
const generated = fs.readFileSync(path.join(root, "scripts/rls/sql/generated/20-context-helpers.sql"), "utf8");
const policies = fs.readFileSync(path.join(root, "scripts/rls/sql/generated/30-policies.sql"), "utf8");
const authService = fs.readFileSync(path.join(root, "backend/src/services/auth/authService.ts"), "utf8");

const expected = [
  "create_refresh_token",
  "load_recent_auth_session_risk_inputs",
  "record_auth_session_risk_signal",
  "revalidate_authenticated_actor",
  "load_authenticated_actor",
  "find_refresh_token_by_id",
  "revoke_refresh_token_by_id",
  "require_recent_mfa_session",
];

test("Release Fix 1 registers eight exact reviewed authentication boundaries", () => {
  for (const name of expected) {
    const contract = namedFunctionContractFor(`app_rls.${name}`);
    assert(contract, `${name} contract missing`);
    assert.equal(contract.definitionStatus, "production-reviewed");
    assert.equal(contract.security.ownerRole, "authOwner");
    assert.equal(contract.security.publicExecute, "revoked");
    assert.match(generated, new RegExp(`GRANT EXECUTE ON FUNCTION app_rls\\.${name}\\(`));
  }
  assert.doesNotMatch(generated, /GRANT EXECUTE ON ALL FUNCTIONS/i);
  assert.match(fs.readFileSync(path.join(root, "scripts/rls/sql/generated/21-runtime-grants.sql"), "utf8"), /GRANT USAGE ON SCHEMA app_rls TO "mscqr_rls_cert_preauth"/);
  assert.doesNotMatch(source, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|BYPASSRLS|install_actor_context|md5\(/i);
});

test("login challenge and risk policies are exact and actor-bound", () => {
  assert.match(policies, /b01_auth_closure_authsessionrisksignal_insert/);
  assert.match(policies, /b01_auth_closure_mfaloginchallenge_insert/);
  assert.match(policies, /"userId"=current_setting\('app\.auth_closure_user_id',true\)/);
  assert.doesNotMatch(policies, /ON public\."AuthWebAuthnChallenge"[\s\S]{0,240}b01_auth_closure/);
  assert.match(source, /p_user_id IS DISTINCT FROM current_setting\('app\.b01_preauth_user_id',true\)/);
  assert.match(source, /app_rls\.b01_authenticated_actor/);
  const refreshSelectPolicy = policies.split("\n").find((line) => line.includes('CREATE POLICY "b01_auth_closure_refreshtoken_select"'));
  assert(refreshSelectPolicy, "authentication closure refresh SELECT policy missing");
  assert.doesNotMatch(refreshSelectPolicy, /EXISTS\s*\(SELECT 1 FROM public\."RefreshToken"/i, "RefreshToken policy must not recursively query itself");
});

test("login, logout and auth me no longer install caller-selected canonical context", () => {
  const login = authService.slice(authService.indexOf("export const loginWithPassword"), authService.indexOf("export const refreshSession"));
  const logout = authService.slice(authService.indexOf("export const logoutSession"), authService.indexOf("export const disableUserSessions"));
  assert.doesNotMatch(login, /withCanonicalDbContext|install_actor_context/);
  assert.doesNotMatch(logout, /withCanonicalDbContext|install_actor_context/);
  assert.match(login, /getB01PreAuthPrisma/);
  assert.match(logout, /revokeRefreshTokenById/);
  assert(logout.indexOf("queueAuditLogOutbox") < logout.indexOf("revokeRefreshTokenById"), "logout audit must be queued before capability revocation");
});

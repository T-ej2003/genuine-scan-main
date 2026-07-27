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
const verification = fs.readFileSync(path.join(root, "scripts/rls/sql/generated/40-post-apply-verification.sql"), "utf8");
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
  const adminMfaActor = namedFunctionContractFor("app_rls.b01_admin_mfa_actor");
  assert.equal(adminMfaActor?.internalOnly, true);
  assert.deepEqual(adminMfaActor?.security.runtimeExecuteGrantees, []);
  assert.doesNotMatch(generated, /GRANT EXECUTE ON FUNCTION app_rls\.b01_admin_mfa_actor\(\)/);
  for (const table of ["AdminWebAuthnCredential", "UserMfaFactor", "UserBackupCode"]) {
    assert.match(verification, new RegExp(`'${table}'::text,'mscqr_rls_cert_auth_owner'::text,'mscqr_rls_cert_owner'::text,'DELETE'::text`));
  }
  assert.match(policies, /b01_auth_closure_authsessionrisksignal_insert/);
  assert.match(policies, /b01_auth_closure_mfaloginchallenge_insert/);
  assert.match(policies, /"userId"=current_setting\('app\.auth_closure_user_id',true\)/);
  for (const table of ["mfaloginchallenge", "authmfachallenge"]) {
    const selectPolicy = policies.split("\n").find((line) =>
      line.includes(`CREATE POLICY "b01_auth_closure_${table}_select"`)
    );
    assert(selectPolicy, `${table} SELECT policy missing`);
    assert.match(selectPolicy, /IN \('mfa-challenge-read','mfa-challenge-fail','mfa-challenge-complete'\)/);
  }
  assert.match(policies, /'AUTH_MFA_SUCCESS','AUTH_MFA_LOGIN_COMPLETE'/);
  const webauthnPolicies = policies.split("\n").filter((line) =>
    line.includes('CREATE POLICY "b01_auth_closure_authwebauthnchallenge_')
  );
  assert.deepEqual(
    webauthnPolicies.map((line) => line.match(/CREATE POLICY "([^"]+)"/)?.[1]),
    [
      "b01_auth_closure_authwebauthnchallenge_select",
      "b01_auth_closure_authwebauthnchallenge_insert",
      "b01_auth_closure_authwebauthnchallenge_update",
    ]
  );
  for (const policy of webauthnPolicies) {
    assert.match(policy, /TO "mscqr_rls_cert_auth_owner"/);
    assert.match(policy, /"userId"=current_setting\('app\.auth_closure_user_id',true\)/);
    assert.doesNotMatch(policy, /app\.b01_preauth_user_id|USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)/);
  }
  assert.match(source, /p_user_id IS DISTINCT FROM current_setting\('app\.b01_preauth_user_id',true\)/);
  assert.deepEqual(
    namedFunctionContractFor("app_rls.create_refresh_token")?.security.runtimeExecuteGrantees,
    ["preauth", "app"]
  );
  assert.match(source, /authenticated-session-create/);
  assert.match(source, /app_rls\.b01_authenticated_actor/);
  assert.match(source, /actor\.role<>'MANUFACTURER_ADMIN'[\s\S]*?p_organization_id IS DISTINCT FROM nullif\(current_setting\('app\.organization_id',true\),''\)/);
  assert.match(source, /load_admin_mfa_challenge[\s\S]*?"expiresAt" AT TIME ZONE 'UTC'/);
  assert.match(source, /revoke_all_refresh_tokens[\s\S]*?DECLARE actor record; changed integer;/);
  assert.doesNotMatch(source, /;\s*RETURNING "riskScore","riskLevel",reasons INTO challenge/);
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

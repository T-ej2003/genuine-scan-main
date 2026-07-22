import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { namedFunctionContractFor } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const source = fs.readFileSync(path.join(root, "backend/src/rls-waves/session-b/b01/authenticatedSessionCapabilityFunctions.sql"), "utf8");
const generator = fs.readFileSync(path.join(root, "scripts/rls/generate-clean-room-rls-sql.mjs"), "utf8");
const generatedContext = fs.readFileSync(path.join(root, "scripts/rls/sql/generated/20-context-helpers.sql"), "utf8");

test("authenticated session capability is a database-verified, hash-only boundary", () => {
  const contract = namedFunctionContractFor("app_auth.require_authenticated_session");
  assert(contract);
  assert.equal(contract.security.ownerRole, "authOwner");
  assert.deepEqual(contract.security.runtimeExecuteGrantees, ["app"]);
  assert.deepEqual(contract.tableCommands, [
    ["RefreshToken", "SELECT"], ["RefreshToken", "UPDATE"], ["User", "SELECT"],
  ]);
  assert.match(source, /encode\(sha256\(convert_to\(p_capability,'UTF8'\)\),'hex'\)/);
  assert.match(source, /set_config\('app\.user_id','',true\)/);
  assert.match(source, /p_refresh_token_hash !~ '\^\(\[0-9a-f\]\{12\}:\)\?\[a-f0-9\]\{64\}\$'/);
  assert.match(source, /rt\."tokenHash"=p_refresh_token_hash/);
  assert.match(source, /s\."sessionCapabilityHash"=current_setting\('app\.auth_session_hash',true\)/);
  assert.match(source, /s\."revokedAt" IS NULL/);
  assert.match(source, /REVOKE ALL ON FUNCTION app_auth\.auth_session_prepare/);
  assert.match(source, /CREATE OR REPLACE FUNCTION app_auth\.revoke_authenticated_session_capability/);
  assert.match(source, /CREATE OR REPLACE FUNCTION app_auth\.revoke_all_authenticated_session_capabilities/);
  assert.match(source, /rt\."userId"=actor_row\."userId"/);
  assert.match(source, /SELECT \* INTO actor_row FROM app_auth\.require_authenticated_session/);
  assert.doesNotMatch(source, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|BYPASSRLS|md5\(/i);
});

test("authenticated runtime execution is exact and excludes generic context installation", () => {
  assert.doesNotMatch(generator, /GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls TO/);
  assert.match(generator, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA app_rls FROM \$\{q\(roleNames\.app\)\}/);
  assert.match(generator, /appRuntimeFunctionSignatures/);
  const allowlist = generator.slice(generator.indexOf("const appRuntimeFunctionSignatures"), generator.indexOf("const b01FunctionOwnerGrants"));
  assert.doesNotMatch(allowlist, /install_actor_context/);
  assert.match(generator, /authenticatedSessionAppSignatures/);
  assert.doesNotMatch(generatedContext, /GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app_rls TO/);
  assert.match(generatedContext, /GRANT EXECUTE ON FUNCTION app_auth\.issue_authenticated_session_capability\(text,text,text,text,timestamp without time zone\) TO "mscqr_rls_cert_preauth"/);
  assert.match(generatedContext, /GRANT EXECUTE ON FUNCTION app_auth\.require_authenticated_session\(text,text,text\) TO "mscqr_rls_cert_app"/);
  assert.match(generatedContext, /GRANT EXECUTE ON FUNCTION app_auth\.revoke_authenticated_session_capability\(text,text,text,text\) TO "mscqr_rls_cert_app"/);
  assert.match(generatedContext, /GRANT EXECUTE ON FUNCTION app_auth\.revoke_all_authenticated_session_capabilities\(text,text,text\) TO "mscqr_rls_cert_app"/);
});

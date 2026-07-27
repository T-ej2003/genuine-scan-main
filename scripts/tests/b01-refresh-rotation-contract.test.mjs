import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { NAMED_SQL_FUNCTION_CONTRACTS, validateNamedSqlFunctionContracts } from "../rls/lib/named-sql-function-contracts.mjs";

const root = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
const source = fs.readFileSync(path.join(root, "backend/src/rls-waves/session-b/b01/b01RefreshRotationFunctions.sql"), "utf8");

test("B01 production refresh functions use the reviewed owner-and-bearer FORCE-RLS contract", () => {
  const contracts = validateNamedSqlFunctionContracts().filter((contract) =>
    contract.definitionLocation.endsWith("b01RefreshRotationFunctions.sql")
  );
  assert.equal(contracts.length, 5);
  assert(contracts.every((contract) => contract.security.ownerIdentity === "identity-auth-function-owner"));
  assert(contracts.every((contract) => contract.security.publicExecute === "revoked"));
  assert(contracts.every((contract) => contract.security.runtimeExecuteGrantees.join(",") === "preauth"));
  assert(contracts.every((contract) => contract.canonicalWorkflowIds.includes("workflow-internal-backend-src-services-auth-auth-service-ts-refresh-session")));
  assert.match(source, /SELECT rt\.id,rt\."userId",rt\."orgId",rt\."revokedAt",rt\."replacedByTokenHash",rt\."expiresAt",\s+rt\."authenticatedAt",rt\."mfaVerifiedAt",rt\."rotationRequestId"\s+INTO t FROM public\."RefreshToken" rt WHERE rt\."tokenHash"=ANY\(p_hashes\) FOR UPDATE/);
  assert.match(source, /FROM public\."AdminMfaCredential" amc WHERE amc\."userId"=u\.id/);
  assert.match(source, /FROM public\."AdminWebAuthnCredential" awc WHERE awc\."userId"=u\.id/);
  assert.match(source, /FROM public\."UserMfaFactor" umf WHERE umf\."userId"=u\.id/);
  assert.match(source, /FROM public\."UserBackupCode" ubc WHERE ubc\."userId"=u\.id/);
  assert.doesNotMatch(source, /FROM public\."(?:AdminMfaCredential|AdminWebAuthnCredential|UserMfaFactor|UserBackupCode)" WHERE "userId"=/);
  assert.match(source, /IF u\.role::text IN \('LICENSEE_ADMIN','ORG_ADMIN'\) THEN[\s\S]*selected\.id,selected\."orgId",NULL,selected\.id,selected\.name,selected\.prefix/);
  assert.match(source, /"rotationRequestId"=p_request_id,"rotationClaimedAt"=coalesce/);
  assert.match(source, /"replacedByTokenHash"=p_token_hash,"rotationCompletedAt"=p_rotated_at/);
  assert.match(source, /revoke_refresh_token_scope\([^)]*p_request_id text\)/);
  assert.match(source, /complete_refresh_token_rotation\([^)]*p_request_id text\)/);
  assert.match(source, /t\."rotationRequestId" IS DISTINCT FROM p_request_id OR t\."rotationCompletedAt" IS NOT NULL/);
  assert.match(source, /B01_REFRESH_CLAIM_AMBIGUOUS/);
  assert.match(source, /gen_random_uuid\(\)::text/);
  assert.match(source, /AUTH_REFRESH_REUSE_DETECTED/);
  assert.match(source, /REVOKE ALL ON FUNCTION app_auth\.claim_refresh_token_rotation/);
  assert.doesNotMatch(source, /USING\s*\(\s*true\s*\)|WITH CHECK\s*\(\s*true\s*\)|BYPASSRLS|raw successor|md5\(random/i);
});

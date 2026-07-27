const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../../../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const repository = read("backend/src/rls-waves/session-b/b01/sessionCredentialRepository.ts");
const refresh = read("backend/src/services/auth/refreshTokenService.ts");
const auth = read("backend/src/services/auth/authService.ts");
const sessions = read("backend/src/controllers/authSessionController.ts");
const controller = read("backend/src/controllers/authController.ts");
const admin = read("backend/src/controllers/authAdminSecurityController.ts");
const routes = read("backend/src/routes/modules/authRoutes.ts");
const sessionProjection = read("backend/src/rls-waves/session-b/b01/authenticatedSessionProjection.ts");

for (const functionName of [
  "app_auth.claim_refresh_token_rotation",
  "app_auth.load_refresh_session_state",
  "app_auth.create_refresh_mfa_challenge",
  "app_auth.revoke_refresh_token_scope",
  "app_auth.complete_refresh_token_rotation",
  "app_rls.create_refresh_token",
  "app_rls.find_refresh_token_by_id",
  "app_rls.list_active_refresh_tokens",
  "app_rls.revoke_all_refresh_tokens",
  "app_rls.revoke_refresh_token_by_id",
]) {
  assert.match(repository, new RegExp(functionName.replace(".", "\\.")), `${functionName} must be static`);
}

assert.doesNotMatch(repository, /\$queryRawUnsafe|\bprisma\./);
assert.doesNotMatch(refresh, /\.refreshToken\.|\$queryRawUnsafe|SET\s+(?:LOCAL\s+)?ROLE/i);
assert.equal(
  (refresh.match(/getB01PreAuthPrisma\(\)\.\$transaction/g) || []).length,
  1,
  "rotation owns one pre-authentication transaction"
);
const rotationBody = refresh.slice(refresh.indexOf("return getB01PreAuthPrisma().$transaction"));
assert.match(rotationBody, /\}, \{ timeout: 15_000 \}\);/);
assert.doesNotMatch(rotationBody, /installCanonicalDbContext/);
assert.ok(rotationBody.indexOf("input.decide") < rotationBody.indexOf("completeRefreshTokenRotation"));
assert.match(rotationBody, /tokenHashCandidates: presentedHashCandidates/);
const claimContract = repository.slice(
  repository.indexOf("export type RefreshRotationClaim"),
  repository.indexOf("export type RefreshLinkedLicensee")
);
assert.doesNotMatch(claimContract, /replacedByTokenHash|\["revokedAt"/);
assert.match(repository, /Object\.values\(UserRole\)/);
assert.match(repository, /refreshAssuranceLevels/);
assert.match(repository, /typeof row\.isPrimary !== "boolean"/);
assert.match(repository, /Number\.isSafeInteger\(result\.revokedCount\)/);
assert.match(repository, /"app_auth\.revoke_refresh_token_scope", 1/);
for (const functionName of [
  "load_refresh_session_state",
  "create_refresh_mfa_challenge",
  "revoke_refresh_token_scope",
  "complete_refresh_token_rotation",
]) {
  const sqlCall = repository.indexOf(`SELECT * FROM app_auth.${functionName}`);
  assert.notEqual(sqlCall, -1, `${functionName} must use a static SQL call`);
  const call = repository.slice(
    sqlCall,
    sqlCall + 650
  );
  assert.match(call, /tokenHashes\(input\.tokenHashCandidates\)/, `${functionName} must bind the presented bearer hashes`);
}

assert.doesNotMatch(sessions, /revokeRefreshTokenByRaw|getRefreshTokenFromRequest|\bprisma\./);
assert.match(sessions, /withAdminMfaClaimsTransaction/);
assert.match(sessions, /claims\.sessionId/);
assert.match(controller, /withDatabaseAuthenticatedSession[\s\S]*logoutSession/);
assert.match(controller, /authenticatedSessionProjection/);
assert.match(sessions, /authenticatedSessionProjection/);
assert.match(sessionProjection, /findRefreshTokenById/);
assert.doesNotMatch(sessionProjection, /findRefreshTokenByRaw|\bprisma\.|config\/database/);
assert.match(refresh, /createRefreshTokenRecord\(db,/);
assert.doesNotMatch(admin, /revokeRefreshTokenByRaw/);
assert.match(auth, /loadRefreshSessionState/);
assert.match(auth, /getB01PreAuthPrisma\(\)/);
assert.doesNotMatch(auth, /from "\.\.\/\.\.\/config\/database"/);
assert.doesNotMatch(
  auth.slice(auth.indexOf("export const refreshSession"), auth.indexOf("export const logoutSession")),
  /tx\.(?:user|refreshToken|manufacturerLicenseeLink|adminMfaCredential|userMfaFactor|adminWebAuthnCredential)/
);

const logoutController = controller.slice(controller.indexOf("export const logout"), controller.indexOf("export const forgotPassword"));
assert.ok(logoutController.indexOf("await withCanonicalAuthClaims") < logoutController.indexOf("clearAuthCookies(res)"));
assert.ok(sessions.lastIndexOf("await withAdminMfaClaimsTransaction") < sessions.lastIndexOf("setAuthCookies(res"));

for (const registeredRoot of [
  /router\.post\("\/auth\/refresh"[^\n]+\brefresh\)/,
  /router\.post\("\/auth\/logout"[^\n]+\blogout\)/,
  /router\.get\("\/auth\/sessions"[^\n]+\blistSessions\)/,
  /router\.post\("\/auth\/sessions\/revoke-all"[^\n]+\brevokeAllSessionsController\)/,
  /router\.post\("\/auth\/sessions\/:id\/revoke"[^\n]+\brevokeSessionController\)/,
]) {
  assert.match(routes, registeredRoot, "refresh/session proof requires the registered HTTP root");
}

console.log("B01 refresh/session shared-boundary static tests passed");

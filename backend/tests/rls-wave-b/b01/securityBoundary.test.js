const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "../../../..");
const read = (relative) => fs.readFileSync(path.join(repoRoot, relative), "utf8");

const preAuth = read("backend/src/rls-waves/session-b/b01/preAuthRepository.ts");
const revalidation = read("backend/src/rls-waves/session-b/b01/actorRevalidationRepository.ts");
const canonical = read("backend/src/rls-waves/session-b/b01/canonicalAuthContext.ts");
const runtimeClients = read("backend/src/rls-waves/session-b/b01/runtimeClients.ts");
const account = read("backend/src/controllers/accountController.ts");
const email = read("backend/src/services/auth/emailVerificationService.ts");
const { resolveB01RuntimeDatabaseConfiguration } = require(
  "../../../dist/rls-waves/session-b/b01/runtimeClients"
);

const preAuthFunctions = [
  "app_auth.lookup_password_user",
  "app_auth.record_password_failure",
  "app_auth.request_password_reset",
  "app_auth.consume_password_reset_token",
  "app_auth.consume_email_verification_token",
  "app_auth.lookup_invitation_token",
  "app_auth.consume_invitation_token",
];
for (const functionName of preAuthFunctions) {
  assert.equal(
    (preAuth.match(new RegExp(`FROM ${functionName.replace(".", "\\.")}\\(`, "g")) || []).length,
    1,
    `${functionName} must have one static call site`
  );
}
assert.doesNotMatch(preAuth, /\$queryRawUnsafe|\bprisma\.|\.(user|invite|passwordReset|emailVerificationToken)\./);
assert.match(preAuth, /rows\.length > 1/);
assert.match(preAuth, /inviteId/);
assert.match(preAuth, /getB01PreAuthPrisma\(\)/);

assert.match(runtimeClients, /PREAUTH_DATABASE_URL/);
assert.match(runtimeClients, /AUTHENTICATED_APP_DATABASE_URL/);
assert.match(runtimeClients, /env\.NODE_ENV === "test"/);
assert.match(runtimeClients, /mscqr_\(dev\|staging\|prod\)_/);
assert.match(runtimeClients, /B01_RUNTIME_DATABASE_CREDENTIAL_REUSED/);
assert.match(runtimeClients, /B01_RUNTIME_DATABASE_REUSES_DEFAULT/);

assert.deepEqual(resolveB01RuntimeDatabaseConfiguration({ NODE_ENV: "test" }), {
  preAuthDatabaseUrl: null,
  authenticatedDatabaseUrl: null,
});
const stagingPreAuth = "postgresql://mscqr_staging_preauth@db.internal/mscqr";
const stagingApp = "postgresql://mscqr_staging_app@db.internal/mscqr";
assert.deepEqual(resolveB01RuntimeDatabaseConfiguration({
  NODE_ENV: "production",
  PREAUTH_DATABASE_URL: stagingPreAuth,
  AUTHENTICATED_APP_DATABASE_URL: stagingApp,
  DATABASE_URL: stagingApp,
}), {
  preAuthDatabaseUrl: stagingPreAuth,
  authenticatedDatabaseUrl: stagingApp,
});
assert.throws(
  () => resolveB01RuntimeDatabaseConfiguration({}),
  (error) => error.code === "B01_RUNTIME_DATABASE_URL_MISSING"
);
assert.throws(
  () => resolveB01RuntimeDatabaseConfiguration({ NODE_ENV: "production" }),
  (error) => error.code === "B01_RUNTIME_DATABASE_URL_MISSING"
);
assert.throws(
  () => resolveB01RuntimeDatabaseConfiguration({
    NODE_ENV: "production",
    PREAUTH_DATABASE_URL: stagingPreAuth,
    AUTHENTICATED_APP_DATABASE_URL: "postgresql://mscqr_prod_app@db.internal/mscqr",
  }),
  (error) => error.code === "B01_RUNTIME_DATABASE_ENVIRONMENT_MISMATCH"
);
assert.throws(
  () => resolveB01RuntimeDatabaseConfiguration({
    NODE_ENV: "production",
    PREAUTH_DATABASE_URL: stagingPreAuth,
    AUTHENTICATED_APP_DATABASE_URL: stagingApp,
    DATABASE_URL: stagingPreAuth,
  }),
  (error) => error.code === "B01_RUNTIME_DATABASE_REUSES_DEFAULT"
);

assert.equal(
  (revalidation.match(/FROM app_rls\.revalidate_authenticated_actor\(/g) || []).length,
  1
);
assert.doesNotMatch(revalidation, /\$queryRawUnsafe|\bprisma\./);
assert.match(revalidation, /Object\.values\(UserRole\)/);
assert.match(revalidation, /returned a foreign actor/);
assert.match(revalidation, /returned an unsupported assurance/);
assert.ok(
  canonical.indexOf("await revalidateAuthenticatedActor") < canonical.indexOf("await installCanonicalDbContext"),
  "actor revalidation must precede canonical context installation"
);
assert.match(canonical, /required\(claims\.sessionId/);
assert.match(canonical, /getB01AuthenticatedPrisma\(\)\.\$transaction/);
assert.doesNotMatch(canonical, /claims\.role|authAssurance:\s*claims/);

assert.ok(account.indexOf("requireRecentSensitiveSession") < account.indexOf('authAssurance: "step-up-verified"'));
assert.ok(account.indexOf("proveAuthenticatedPasswordStepUp") < account.lastIndexOf('authAssurance: "step-up-verified"'));
assert.match(account, /emailChangeRequested:/);
assert.doesNotMatch(account, /pendingEmail:\s*pendingEmail/);
assert.doesNotMatch(email, /\bprisma\.|\.user\.|\.emailVerificationToken\./);
assert.ok(
  account.indexOf("await result.emailChange?.deliver()") > account.indexOf("withCanonicalAuthClaims"),
  "verification delivery must start only after the canonical transaction resolves"
);

console.log("B01 security-boundary static tests passed");

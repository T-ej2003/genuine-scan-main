const assert = require("assert");

process.env.JWT_SECRET_CURRENT = "cookie-token-protection-current";
process.env.JWT_SECRET_PREVIOUS = "cookie-token-protection-previous";

const {
  isProtectedCookieToken,
  openCookieToken,
  sealCookieToken,
} = require("../dist/services/auth/cookieTokenProtectionService");

const accessToken = "header.payload.signature";
const sealedAccessToken = sealCookieToken(accessToken, "auth.access");

assert.notStrictEqual(sealedAccessToken, accessToken, "sealed access tokens must not match the raw token");
assert(!sealedAccessToken.includes(accessToken), "sealed access tokens must not embed the raw token");
assert.strictEqual(openCookieToken(sealedAccessToken, "auth.access"), accessToken, "access token should round-trip");
assert.strictEqual(openCookieToken(sealedAccessToken, "auth.refresh"), null, "protected cookies must be purpose-bound");
assert.strictEqual(isProtectedCookieToken(sealedAccessToken), true, "sealed cookies should advertise the protection envelope");

const previousSealedAccessToken = (() => {
  const current = process.env.JWT_SECRET_CURRENT;
  const previous = process.env.JWT_SECRET_PREVIOUS;
  process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_PREVIOUS;
  delete process.env.JWT_SECRET_PREVIOUS;
  const sealed = sealCookieToken(accessToken, "auth.access");
  process.env.JWT_SECRET_CURRENT = current;
  process.env.JWT_SECRET_PREVIOUS = previous;
  return sealed;
})();
assert.strictEqual(openCookieToken(previousSealedAccessToken, "auth.access"), accessToken, "previous cookies should open during overlap");
process.env.JWT_SECRET_PREVIOUS = "different-previous";
assert.strictEqual(openCookieToken(previousSealedAccessToken, "auth.access"), null, "wrong previous cookies must fail closed");
delete process.env.JWT_SECRET_PREVIOUS;
assert.strictEqual(openCookieToken(previousSealedAccessToken, "auth.access"), null, "previous cookies must fail after cleanup");
assert.strictEqual(openCookieToken(sealedAccessToken, "auth.access"), accessToken, "current cookies must remain valid after cleanup");
process.env.JWT_SECRET_PREVIOUS = "cookie-token-protection-previous";

for (const purpose of ["auth.access", "auth.refresh", "auth.database-session", "customer-verify.session"]) {
  const sealed = sealCookieToken(`fixture-${purpose}`, purpose);
  assert.strictEqual(openCookieToken(sealed, purpose), `fixture-${purpose}`, `${purpose} should round-trip`);
  assert.strictEqual(openCookieToken(sealed, purpose === "auth.access" ? "auth.refresh" : "auth.access"), null, `${purpose} must be purpose-bound`);
}

const verifySessionToken = "verify-customer-session-token";
const sealedVerifySessionToken = sealCookieToken(verifySessionToken, "customer-verify.session");
assert.strictEqual(
  openCookieToken(sealedVerifySessionToken, "customer-verify.session"),
  verifySessionToken,
  "customer verify session cookies should round-trip through protection"
);

console.log("cookie token protection tests passed");

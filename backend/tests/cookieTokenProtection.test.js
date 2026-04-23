const assert = require("assert");

process.env.JWT_SECRET = "cookie-token-protection-jwt-secret";

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

const verifySessionToken = "verify-customer-session-token";
const sealedVerifySessionToken = sealCookieToken(verifySessionToken, "customer-verify.session");
assert.strictEqual(
  openCookieToken(sealedVerifySessionToken, "customer-verify.session"),
  verifySessionToken,
  "customer verify session cookies should round-trip through protection"
);

console.log("cookie token protection tests passed");

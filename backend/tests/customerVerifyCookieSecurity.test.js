const assert = require("assert");

process.env.JWT_SECRET = "customer-verify-cookie-security-jwt-secret";
process.env.CUSTOMER_VERIFY_TOKEN_SECRET = "customer-verify-cookie-security-token-secret";
process.env.VERIFY_CUSTOMER_COOKIE_AUTH_ENABLED = "true";

const {
  CUSTOMER_VERIFY_CSRF_COOKIE_NAME,
  CUSTOMER_VERIFY_SESSION_COOKIE_NAME,
  readCustomerVerifyCsrfCookie,
  readCustomerVerifySessionCookie,
  setCustomerVerifySessionCookie,
} = require("../dist/services/customerVerifyCookieService");
const { buildCustomerVerifyAuthResponse } = require("../dist/controllers/verify/customerAuthResponsePolicy");

const cookies = [];
const response = {
  cookie(name, value, options) {
    cookies.push({ name, value, options });
    return this;
  },
};

setCustomerVerifySessionCookie(response, "customer-session-token");

const sessionCookie = cookies.find((entry) => entry.name === CUSTOMER_VERIFY_SESSION_COOKIE_NAME);
const csrfCookie = cookies.find((entry) => entry.name === CUSTOMER_VERIFY_CSRF_COOKIE_NAME);

assert(sessionCookie, "customer verify session cookie should be set");
assert(csrfCookie, "customer verify csrf cookie should be set");
assert.notStrictEqual(sessionCookie.value, "customer-session-token", "session cookies must not store the raw token");
assert(!sessionCookie.value.includes("customer-session-token"), "session cookies must not leak the raw token");
assert.strictEqual(sessionCookie.options.httpOnly, true, "customer session cookie should remain httpOnly");
assert.strictEqual(csrfCookie.options.httpOnly, false, "customer verify csrf cookie must remain readable by the browser");

const request = {
  cookies: {
    [CUSTOMER_VERIFY_SESSION_COOKIE_NAME]: sessionCookie.value,
    [CUSTOMER_VERIFY_CSRF_COOKIE_NAME]: csrfCookie.value,
  },
};

assert.strictEqual(
  readCustomerVerifySessionCookie(request),
  "customer-session-token",
  "customer verify session cookies should be recoverable only through the protection service"
);
assert.strictEqual(readCustomerVerifyCsrfCookie(request), csrfCookie.value, "verify csrf cookie should be readable");

const authResponse = buildCustomerVerifyAuthResponse({
  userId: "cust_1",
  email: "customer@example.com",
  authStrength: "EMAIL_OTP",
  authProvider: "EMAIL_OTP",
});

assert.strictEqual("token" in authResponse, false, "cookie-backed customer verify responses must not expose bearer tokens");
assert.strictEqual(authResponse.auth.cookieBacked, true);
assert.strictEqual(authResponse.auth.authenticated, true);

console.log("customer verify cookie security tests passed");

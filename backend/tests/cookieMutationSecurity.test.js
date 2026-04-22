const assert = require("assert");

const { enforceCookieMutationSecurity } = require("../dist/middleware/cookieMutationSecurity");
const { ACCESS_TOKEN_COOKIE, CSRF_TOKEN_COOKIE } = require("../dist/services/auth/tokenService");
const {
  CUSTOMER_VERIFY_CSRF_COOKIE_NAME,
  CUSTOMER_VERIFY_SESSION_COOKIE_NAME,
} = require("../dist/services/customerVerifyCookieService");

const buildResponse = () => ({
  statusCode: 200,
  body: null,
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(payload) {
    this.body = payload;
    return this;
  },
});

let nextCalled = false;
const runMiddleware = (req) => {
  nextCalled = false;
  const res = buildResponse();
  enforceCookieMutationSecurity(req, res, () => {
    nextCalled = true;
  });
  return { res, nextCalled };
};

{
  const { res } = runMiddleware({
    method: "POST",
    originalUrl: "/api/auth/logout",
    headers: {},
    cookies: { [ACCESS_TOKEN_COOKIE]: "sealed-auth-cookie" },
  });

  assert.strictEqual(res.statusCode, 403, "admin cookie mutations should reject missing CSRF");
  assert.strictEqual(res.body?.error, "CSRF token missing or invalid");
}

{
  const { res, nextCalled: advanced } = runMiddleware({
    method: "POST",
    originalUrl: "/api/auth/logout",
    headers: { "x-csrf-token": "csrf-match" },
    cookies: {
      [ACCESS_TOKEN_COOKIE]: "sealed-auth-cookie",
      [CSRF_TOKEN_COOKIE]: "csrf-match",
    },
  });

  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(advanced, true, "admin cookie mutations should proceed when CSRF matches");
}

{
  const { res } = runMiddleware({
    method: "POST",
    originalUrl: "/api/verify/session/session-1/reveal",
    headers: {},
    cookies: { [CUSTOMER_VERIFY_SESSION_COOKIE_NAME]: "sealed-verify-cookie" },
  });

  assert.strictEqual(res.statusCode, 403, "customer verify cookie mutations should reject missing CSRF");
}

{
  const { res, nextCalled: advanced } = runMiddleware({
    method: "POST",
    originalUrl: "/api/verify/session/session-1/reveal",
    headers: { "x-csrf-token": "verify-csrf-match" },
    cookies: {
      [CUSTOMER_VERIFY_SESSION_COOKIE_NAME]: "sealed-verify-cookie",
      [CUSTOMER_VERIFY_CSRF_COOKIE_NAME]: "verify-csrf-match",
    },
  });

  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(advanced, true, "customer verify cookie mutations should proceed when CSRF matches");
}

console.log("cookie mutation security tests passed");

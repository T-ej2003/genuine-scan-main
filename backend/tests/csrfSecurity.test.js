const assert = require("assert");

const { requireCsrf, requireCustomerVerifyCsrf } = require("../dist/middleware/csrf");
const { CSRF_TOKEN_COOKIE } = require("../dist/services/auth/tokenService");
const { CUSTOMER_VERIFY_CSRF_COOKIE_NAME } = require("../dist/services/customerVerifyCookieService");

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

const runAdminCsrf = (req) => {
  const res = buildResponse();
  let nextCalled = false;
  requireCsrf(req, res, () => {
    nextCalled = true;
  });
  return { res, nextCalled };
};

const runCustomerCsrf = (req) => {
  const res = buildResponse();
  let nextCalled = false;
  requireCustomerVerifyCsrf(req, res, () => {
    nextCalled = true;
  });
  return { res, nextCalled };
};

{
  const { res } = runAdminCsrf({
    method: "POST",
    headers: {},
    cookies: { [CSRF_TOKEN_COOKIE]: "server-token" },
    authMode: "cookie",
  });
  assert.strictEqual(res.statusCode, 403, "cookie-backed admin mutations should reject missing CSRF headers");
}

{
  const { res, nextCalled } = runAdminCsrf({
    method: "POST",
    headers: { "x-csrf-token": "server-token" },
    cookies: { [CSRF_TOKEN_COOKIE]: "server-token" },
    authMode: "cookie",
  });
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(nextCalled, true, "cookie-backed admin mutations should accept matching CSRF");
}

{
  const { res } = runCustomerCsrf({
    method: "POST",
    headers: {},
    cookies: { [CUSTOMER_VERIFY_CSRF_COOKIE_NAME]: "verify-token" },
    customerAuthSource: "cookie",
  });
  assert.strictEqual(res.statusCode, 403, "cookie-backed customer mutations should reject missing CSRF headers");
}

{
  const { res, nextCalled } = runCustomerCsrf({
    method: "POST",
    headers: { "x-csrf-token": "verify-token" },
    cookies: { [CUSTOMER_VERIFY_CSRF_COOKIE_NAME]: "verify-token" },
    customerAuthSource: "cookie",
  });
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(nextCalled, true, "cookie-backed customer mutations should accept matching CSRF");
}

console.log("csrf security tests passed");

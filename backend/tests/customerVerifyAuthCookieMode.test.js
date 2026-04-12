const assert = require("assert");

process.env.JWT_SECRET = "customer-verify-auth-cookie-mode-jwt-secret";
process.env.CUSTOMER_VERIFY_TOKEN_SECRET = "customer-verify-auth-cookie-mode-token-secret";
process.env.VERIFY_CUSTOMER_COOKIE_AUTH_ENABLED = "true";
process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED = "true";

const { deriveCustomerVerifyUserId, issueCustomerVerifyToken } = require("../dist/services/customerVerifyAuthService");
const { optionalCustomerVerifyAuth, requireCustomerVerifyAuth } = require("../dist/middleware/customerVerifyAuth");

const buildReq = (overrides = {}) => ({
  headers: {},
  cookies: {},
  ip: "::ffff:203.0.113.5",
  method: "GET",
  path: "/api/verify/session/session-1",
  originalUrl: "/api/verify/session/session-1",
  get: (name) => {
    const lower = String(name || "").toLowerCase();
    if (lower === "user-agent") return "customer-auth-test-agent";
    return "";
  },
  ...overrides,
});

const buildRes = () => {
  const res = {
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
  };
  return res;
};

const token = issueCustomerVerifyToken({
  userId: deriveCustomerVerifyUserId("cookie-mode@example.com"),
  email: "cookie-mode@example.com"
});

// Cookie token should authenticate first.
{
  const req = buildReq({ cookies: { mscqr_verify_session: token } });
  const res = buildRes();
  optionalCustomerVerifyAuth(req, res, () => {});
  assert(req.customer, "cookie session should authenticate");
  assert.strictEqual(req.customerAuthSource, "cookie");
}

// Bearer compatibility remains available while enabled.
{
  const req = buildReq({
    headers: { authorization: `Bearer ${token}` },
  });
  const res = buildRes();
  optionalCustomerVerifyAuth(req, res, () => {});
  assert(req.customer, "bearer token should still authenticate while compatibility is enabled");
  assert.strictEqual(req.customerAuthSource, "bearer");
}

// Bearer-only auth should fail closed when compatibility is disabled.
{
  process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED = "false";
  const req = buildReq({
    headers: { authorization: `Bearer ${token}` },
  });
  const res = buildRes();
  optionalCustomerVerifyAuth(req, res, () => {});
  assert(!req.customer, "bearer token should be ignored when compatibility is disabled");
}

// Required auth should pass with cookie session even when bearer compatibility is disabled.
{
  process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED = "false";
  const req = buildReq({ cookies: { mscqr_verify_session: token } });
  const res = buildRes();
  let nextCalled = false;
  requireCustomerVerifyAuth(req, res, () => {
    nextCalled = true;
  });
  assert(nextCalled, "cookie session should satisfy required customer auth");
  assert.strictEqual(req.customerAuthSource, "cookie");
}

// Required auth should reject anonymous requests.
{
  process.env.VERIFY_CUSTOMER_BEARER_COMPAT_ENABLED = "true";
  const req = buildReq();
  const res = buildRes();
  requireCustomerVerifyAuth(req, res, () => {});
  assert.strictEqual(res.statusCode, 401, "missing customer auth should return 401");
  assert.strictEqual(res.body?.success, false);
}

console.log("customer verify cookie auth mode tests passed");

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
const {
  DATABASE_SESSION_CAPABILITY_HEADER,
  getDatabaseSessionCapability,
  hydrateTenantIfNeeded,
} = require("../dist/middleware/auth");

const request = ({ cookie = "", header = "" } = {}) => ({
  headers: { cookie },
  get: (name) => name.toLowerCase() === DATABASE_SESSION_CAPABILITY_HEADER ? header : "",
});

const cookieCapability = "cookie-capability";
const bearerCapability = "bearer-capability";
const sealedCookie = sealCookieToken(cookieCapability, "auth.database-session");
const sealedBearer = sealCookieToken(bearerCapability, "auth.database-session");

assert.equal(
  getDatabaseSessionCapability(request({ cookie: `aq_db_session=${encodeURIComponent(sealedCookie)}` }), null),
  cookieCapability,
  "cookie authentication must retain its protected capability transport"
);
assert.equal(
  getDatabaseSessionCapability(request({ header: sealedBearer }), "access-token"),
  bearerCapability,
  "bearer-only authentication must accept the protected capability header"
);
assert.equal(
  getDatabaseSessionCapability(request({ header: "not-a-protected-token" }), "access-token"),
  null,
  "invalid bearer capability transport must fail closed"
);
assert.equal(getDatabaseSessionCapability(request(), "access-token"), null, "missing bearer capability must fail closed");
assert.equal(
  getDatabaseSessionCapability(
    request({ cookie: `aq_db_session=${encodeURIComponent(sealedCookie)}`, header: sealedBearer }),
    "access-token"
  ),
  bearerCapability,
  "the bearer capability header must deterministically take precedence on bearer requests"
);
assert.equal(
  getDatabaseSessionCapability(
    request({ cookie: `aq_db_session=${encodeURIComponent(sealedCookie)}` }),
    "access-token"
  ),
  cookieCapability,
  "existing bearer-plus-cookie clients must retain their cookie capability fallback"
);
assert.equal(
  getDatabaseSessionCapability(
    request({ cookie: `aq_db_session=${encodeURIComponent(sealedCookie)}`, header: sealedBearer }),
    null
  ),
  cookieCapability,
  "cookie requests must ignore bearer-only capability headers"
);
assert.match(
  fs.readFileSync(path.resolve(__dirname, "../src/app.ts"), "utf8"),
  /"X-Database-Session-Capability"/,
  "cross-origin bearer clients must be allowed to send the protected capability header"
);

hydrateTenantIfNeeded({ userId: "user", role: "LICENSEE_ADMIN" }, null)
  .then(() => assert.fail("missing capability must not hydrate an authenticated actor"))
  .catch((error) => assert.match(String(error?.message || error), /AUTH_SESSION_CAPABILITY_DENIED/))
  .then(() => console.log("Bearer database capability transport tests passed"));

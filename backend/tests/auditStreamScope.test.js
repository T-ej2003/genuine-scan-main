const assert = require("node:assert/strict");
const { test } = require("node:test");
let listener = null;
for (const module of ["config/database", "services/manufacturerScopeService", "services/auditCsvExportService", "lib/canonicalDbContext", "services/fraudReportQueryService", "services/auditLogQueryService", "rls-waves/session-c/c02/auditTraceRepository", "rls-waves/session-b/b01/canonicalAuthContext"]) {
  const id = require.resolve(`../dist/${module}`);
  require.cache[id] = { id, filename: id, loaded: true, exports: { resolveAccessibleLicenseeIdsForUser: async () => [] } };
}
const audit = require.resolve("../dist/services/auditService");
require.cache[audit] = { id: audit, filename: audit, loaded: true, exports: { onAuditLog: (callback) => { listener = callback; return () => { listener = null; }; } } };
const { streamLogs } = require("../dist/controllers/auditController");
const A = "11111111-1111-4111-8111-111111111111", B = "22222222-2222-4222-8222-222222222222";

// Keep the real SSE middleware and controller; stub cryptography/DB hydration only.
let actor;
let hydrationDenied = false;
const fixtureToken = "sse-fixture-not-a-credential";
for (const [module, exports] of Object.entries({
  "services/auth/tokenService": {
    ACCESS_TOKEN_COOKIE: "access", AUTHENTICATED_SESSION_CAPABILITY_COOKIE: "capability",
    verifyAccessToken: (token) => {
      if (token === "expired-token") throw Object.assign(new Error("expired fixture token"), { name: "TokenExpiredError" });
      if (token !== fixtureToken) throw new Error("invalid fixture token");
      return actor;
    },
  },
  "services/auth/cookieTokenProtectionService": { openCookieToken: (value) => ["corrupt-cookie", "unavailable-key-cookie"].includes(value) ? null : value },
  "services/manufacturerScopeService": {
    isManufacturerRole: () => false, isPlatformRole: (role) => role === "SUPER_ADMIN",
    isLicenseeAdminRole: (role) => role === "LICENSEE_ADMIN",
  },
  "services/accessControlService": { isDisabledUserRecord: () => false },
  "services/auth/authService": {}, "controllers/authControllerShared": {},
  "rls-waves/session-b/b01/canonicalAuthContext": {
    withDatabaseAuthenticatedSession: async (_payload, _options, callback) => {
      if (hydrationDenied) throw new Error("sensitive database detail");
      return callback({}, { userId: actor.userId, role: actor.role, authAssurance: "mfa-verified" });
    },
  },
  "rls-waves/session-b/b01/authenticatedSecurityRepository": { loadAuthenticatedActor: async () => ({ ...actor, id: actor.userId }) },
})) {
  const id = require.resolve(`../dist/${module}`);
  require.cache[id] = { id, filename: id, loaded: true, exports };
}
const { authenticateSSE } = require("../dist/middleware/auth");

test("dashboard and printer SSE denials identify validation stage without credentials", async () => {
  const requestId = "33333333-3333-4333-8333-333333333333";
  const diagnosticRequestId = "44444444-4444-4444-8444-444444444444";
  const messages = [];
  const originalWarn = console.warn;
  console.warn = (message) => messages.push(message);
  actor = { userId: "actor", role: "SUPER_ADMIN", licenseeId: null, orgId: null };
  try {
    for (const [path, token, deny, expected, source] of [
      ["/events/dashboard", null, false, "missing_token", "none"],
      ["/events/dashboard", "", false, "token_validation_failed", "cookie"],
      ["/events/dashboard", "corrupt-cookie", false, "token_validation_failed", "cookie"],
      ["/events/dashboard", "unavailable-key-cookie", false, "token_validation_failed", "cookie"],
      ["/events/dashboard", "expired-token", false, "token_validation_failed", "cookie"],
      ["/manufacturer/printer-agent/events", fixtureToken, true, "session_validation_failed", "cookie"],
    ]) {
      hydrationDenied = deny;
      const req = { path, requestId, diagnosticRequestId, query: {}, headers: {}, cookies: token === null ? {} : { access: token, capability: "fixture-capability" }, get: () => undefined };
      const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(payload) { this.body = payload; return this; } };
      await authenticateSSE(req, res, () => { throw new Error("denied stream opened"); });
      assert.equal(res.statusCode, 401);
      assert.equal(JSON.parse(messages.at(-1)).reason, expected);
      assert.equal(JSON.parse(messages.at(-1)).credentialSource, source);
    }
    assert.equal(messages.length, 6);
    for (const message of messages) {
      const event = JSON.parse(message);
      assert.equal(event.event, "sse_auth_rejected");
      assert.equal(event.requestId, requestId);
      assert.equal(event.diagnosticRequestId, diagnosticRequestId);
      assert.doesNotMatch(message, /corrupt-cookie|unavailable-key-cookie|expired-token|fixture-capability|sensitive database detail/);
    }

    const req = { path: "/events/dashboard", requestId: "invalid\nrequest", diagnosticRequestId: "invalid\nrequest", query: {}, headers: {}, cookies: {}, get: () => undefined };
    const res = { status: () => res, json: () => res };
    await authenticateSSE(req, res, () => {});
    assert.equal(messages.length, 6, "unvalidated request IDs must not be logged");
  } finally {
    hydrationDenied = false;
    console.warn = originalWarn;
  }
});

test("real SSE authentication policy composes with strict scope and never serializes query tokens", async () => {
  const original = { NODE_ENV: process.env.NODE_ENV, AUTH_SSE_QUERY_TOKEN_ENABLED: process.env.AUTH_SSE_QUERY_TOKEN_ENABLED };
  try {
    for (const [mode, enabled, role, query, expectedStatus, visibleTenant] of [
      ["cookie", false, "SUPER_ADMIN", { licenseeId: A }, 200, A],
      ["header", false, "SUPER_ADMIN", { licenseeId: A }, 200, A],
      ["query", true, "SUPER_ADMIN", { licenseeId: A }, 200, A],
      ["query", false, "SUPER_ADMIN", { licenseeId: A }, 401, null],
      ["query", true, "SUPER_ADMIN", {}, 400, null],
      ["query", true, "SUPER_ADMIN", { licenseeId: "invalid" }, 400, null],
      ["query", true, "SUPER_ADMIN", { licenseeId: A, extra: "unexpected" }, 400, null],
      ["query", true, "LICENSEE_ADMIN", {}, 200, A],
      ["query", true, "LICENSEE_ADMIN", { licenseeId: B }, 200, null],
    ]) {
      process.env.NODE_ENV = "production";
      process.env.AUTH_SSE_QUERY_TOKEN_ENABLED = String(enabled);
      actor = { userId: "actor", role, licenseeId: role === "LICENSEE_ADMIN" ? A : null, orgId: role === "LICENSEE_ADMIN" ? A : null };
      let close, status = 200;
      const sent = [];
      const req = {
        query: { ...query, ...(mode === "query" ? { token: fixtureToken } : {}) },
        headers: mode === "header" ? { authorization: `Bearer ${fixtureToken}` } : {},
        cookies: { capability: "fixture-capability", access: mode === "cookie" ? fixtureToken : "corrupt-cookie" },
        get: () => undefined, on: (_event, fn) => { close = fn; },
      };
      const res = { status: (value) => { status = value; return res; }, json: (value) => { sent.push(JSON.stringify(value)); return res; }, end: () => {}, setHeader: () => {}, flushHeaders: () => {}, write: (value) => sent.push(value) };
      try {
        await authenticateSSE(req, res, () => streamLogs(req, res));
        assert.equal(status, expectedStatus, `${mode}/${enabled}/${role}/${JSON.stringify(query)}`);
        if (status === 200) {
          for (const licenseeId of [A, B]) listener({ licenseeId, action: "LOGIN_SUCCESS" });
          assert.equal(sent.length, visibleTenant ? 1 : 0);
          if (visibleTenant) assert.ok(sent[0].includes(visibleTenant));
        } else assert.equal(listener, null);
        assert.ok(sent.every((value) => !value.includes(fixtureToken)));
      } finally { close?.(); }
    }
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test("actual stream narrows platform scope before serialization and retains tenant restrictions", async () => {
  for (const [role, actorTenant, query, expectedStatus, visibleTenant] of [
    ["SUPER_ADMIN", null, {}, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: "all" }, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: [A, B] }, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: A, token: ["one", "two"] }, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: A }, 200, A],
    ["SUPER_ADMIN", null, { licenseeId: B }, 200, B],
    ["LICENSEE_ADMIN", A, {}, 200, A],
    ["LICENSEE_ADMIN", A, { licenseeId: B }, 200, null],
  ]) {
    let close, status = 200;
    const sent = [];
    const req = { user: { role, userId: "actor", licenseeId: actorTenant }, query, on: (_event, fn) => { close = fn; } };
    const res = { status: (value) => { status = value; return res; }, json: () => res, end: () => {}, setHeader: () => {}, flushHeaders: () => {}, write: (value) => sent.push(value) };
    try {
      await streamLogs(req, res);
      assert.equal(status, expectedStatus);
      if (status === 200) {
        for (const licenseeId of [A, B]) listener({ licenseeId, action: "LOGIN_SUCCESS" });
        assert.equal(sent.length, visibleTenant ? 1 : 0);
        if (visibleTenant) assert.ok(sent[0].includes(visibleTenant));
      } else assert.equal(listener, null);
    } finally { close?.(); }
  }
});

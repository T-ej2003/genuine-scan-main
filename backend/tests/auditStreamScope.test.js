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
const fixtureToken = "sse-fixture-not-a-credential";
for (const [module, exports] of Object.entries({
  "services/auth/tokenService": {
    ACCESS_TOKEN_COOKIE: "access", AUTHENTICATED_SESSION_CAPABILITY_COOKIE: "capability",
    verifyAccessToken: (token) => { assert.equal(token, fixtureToken); return actor; },
  },
  "services/auth/cookieTokenProtectionService": { openCookieToken: (value) => value },
  "services/manufacturerScopeService": {
    isManufacturerRole: () => false, isPlatformRole: (role) => role === "SUPER_ADMIN",
    isLicenseeAdminRole: (role) => role === "LICENSEE_ADMIN",
  },
  "services/accessControlService": { isDisabledUserRecord: () => false },
  "services/auth/authService": {}, "controllers/authControllerShared": {},
  "rls-waves/session-b/b01/canonicalAuthContext": {
    withDatabaseAuthenticatedSession: async (_payload, _options, callback) => callback({}, {
      userId: actor.userId, role: actor.role, authAssurance: "mfa-verified",
    }),
  },
  "rls-waves/session-b/b01/authenticatedSecurityRepository": { loadAuthenticatedActor: async () => ({ ...actor, id: actor.userId }) },
})) {
  const id = require.resolve(`../dist/${module}`);
  require.cache[id] = { id, filename: id, loaded: true, exports };
}
const { authenticateSSE } = require("../dist/middleware/auth");

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
        cookies: { capability: "fixture-capability", ...(mode === "cookie" ? { access: fixtureToken } : {}) },
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

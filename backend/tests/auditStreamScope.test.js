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

test("actual stream narrows platform scope before serialization and retains tenant restrictions", async () => {
  for (const [role, actorTenant, query, expectedStatus, visibleTenant] of [
    ["SUPER_ADMIN", null, {}, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: "all" }, 400, null],
    ["SUPER_ADMIN", null, { licenseeId: [A, B] }, 400, null],
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

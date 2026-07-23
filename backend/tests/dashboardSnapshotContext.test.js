const assert = require("node:assert");
const { UserRole } = require("@prisma/client");

process.env.NODE_ENV = "test";
delete process.env.REDIS_URL;
delete process.env.REDIS_HOST;

const ids = {
  actor: "11111111-1111-4111-8111-111111111111",
  tenant: "22222222-2222-4222-8222-222222222222",
  foreign: "33333333-3333-4333-8333-333333333333",
  organization: "44444444-4444-4444-8444-444444444444",
};
const now = Date.parse("2026-07-21T12:00:00.000Z");

const events = [];
const calls = { contexts: [], scopes: [], data: [], cacheKeys: [], transactionOptions: [] };
let denyScope = false;
let denyCapability = false;
let fingerprint = "a".repeat(32);
let dataRow = {
  total_qr_codes: 10n,
  active_licensees: 1n,
  manufacturers: 2n,
  total_batches: 3n,
  dormant: 1n,
  active: 2n,
  activated: 1n,
  allocated: 1n,
  printed: 2n,
  redeemed: 1n,
  blocked: 1n,
  scanned: 1n,
  rollup_authoritative: true,
};

const tx = {
  $executeRaw: async (strings, ...values) => {
    throw new Error(`legacy context installer called: ${strings.join("?")}:${values.length}`);
  },
  $queryRaw: async (strings, ...values) => {
    assert.equal(values[0], "A".repeat(43), "capability is the first database authority argument");
    const sql = strings.join("?");
    if (/dashboard_snapshot_scope/.test(sql)) {
      events.push("scope");
      calls.scopes.push(values);
      if (denyCapability) throw new Error("AUTH_SESSION_CAPABILITY_DENIED");
      if (denyScope) throw new Error("dashboard access denied");
      return [{ scope_fingerprint: fingerprint }];
    }
    assert.match(sql, /dashboard_snapshot_data/);
    events.push("data");
    calls.data.push(values);
    return [dataRow];
  },
};

const runner = {
  $transaction: async (callback, options) => {
    calls.transactionOptions.push(options);
    events.push("transaction-begin");
    const value = await callback(tx);
    events.push("transaction-end");
    return value;
  },
};

const cache = new Map();
const databasePath = require.resolve("../dist/config/database");
require.cache[databasePath] = {
  id: databasePath,
  filename: databasePath,
  loaded: true,
  exports: { __esModule: true, default: runner },
};
const authServicePath = require.resolve("../dist/services/auth/authService");
require.cache[authServicePath] = {
  id: authServicePath,
  filename: authServicePath,
  loaded: true,
  exports: { getAdminStepUpWindowMinutes: () => 30 },
};
const cachePath = require.resolve("../dist/services/versionedCacheService");
require.cache[cachePath] = {
  id: cachePath,
  filename: cachePath,
  loaded: true,
  exports: {
    getOrComputeVersionedCache: async (_namespace, key, _ttl, compute) => {
      calls.cacheKeys.push(key);
      if (!cache.has(key)) cache.set(key, await compute());
      return cache.get(key);
    },
  },
};

const {
  buildDashboardSnapshotBoundary,
  canDeliverDashboardAuditDelta,
  DashboardSnapshotAccessError,
  getDashboardSnapshot,
} = require("../dist/services/dashboardSnapshotService");
const { getDashboardStats } = require("../dist/controllers/dashboardController");

const actor = (overrides = {}) => ({
  userId: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  authenticatedAt: new Date(now).toISOString(),
  mfaVerifiedAt: null,
  ...overrides,
});
const request = (user = actor(), overrides = {}) => ({
  user,
  query: {},
  originalUrl: "/api/dashboard/stats",
  requestId: "dashboard-request-1",
  databaseSessionCapability: "A".repeat(43),
  ...overrides,
});
const denied = (req) => assert.throws(
  () => buildDashboardSnapshotBoundary(req, now),
  (error) => error instanceof DashboardSnapshotAccessError
);

(async () => {
  const tenantBoundary = buildDashboardSnapshotBoundary(request(), now);
  assert.deepStrictEqual(tenantBoundary.context, {
    userId: ids.actor,
    role: UserRole.LICENSEE_ADMIN,
    organizationId: ids.organization,
    licenseeId: ids.tenant,
    manufacturerId: null,
    authAssurance: "password-verified",
    requestId: "dashboard-request-1",
    purpose: "dashboard-snapshot-read",
  });

  const manufacturerBoundary = buildDashboardSnapshotBoundary(request(actor({
    role: UserRole.MANUFACTURER,
    licenseeId: ids.tenant,
    orgId: ids.organization,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date(now - 60_000).toISOString(),
  })), now);
  assert.strictEqual(manufacturerBoundary.context.licenseeId, null, "unselected manufacturer keeps its full linked set");
  assert.strictEqual(manufacturerBoundary.context.organizationId, null);
  assert.strictEqual(manufacturerBoundary.context.manufacturerId, ids.actor);

  const platformBoundary = buildDashboardSnapshotBoundary(request(actor({
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date(now - 60_000).toISOString(),
  }), { query: { licenseeId: ids.tenant } }), now);
  assert.strictEqual(platformBoundary.context.licenseeId, ids.tenant);
  assert.strictEqual(platformBoundary.context.authAssurance, "mfa-verified");

  denied(request(actor(), { query: { licenseeId: ids.foreign } }));
  denied(request(actor(), { query: { licenseeId: [ids.tenant] } }));
  denied(request(actor(), { requestId: "" }));
  denied(request(actor(), { originalUrl: "/api/analytics/risk-scores" }));
  denied(request(actor({ sessionStage: "MFA_BOOTSTRAP" })));
  denied(request(actor({ role: UserRole.MANUFACTURER, authAssurance: "PASSWORD", mfaVerifiedAt: null })));
  denied(request(actor({
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "PASSWORD",
  })));
  denied(request(actor({
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date(now - 31 * 60_000).toISOString(),
  })));

  const first = await getDashboardSnapshot(request());
  const second = await getDashboardSnapshot(request(undefined, { requestId: "dashboard-request-2" }));
  assert.deepStrictEqual(second, first);
  assert.deepStrictEqual(first, {
    totalQRCodes: 10,
    activeLicensees: 1,
    manufacturers: 2,
    totalBatches: 3,
    qr: {
      total: 10,
      byStatus: { DORMANT: 1, ACTIVE: 2, ACTIVATED: 1, ALLOCATED: 1, PRINTED: 2, REDEEMED: 1, BLOCKED: 1, SCANNED: 1 },
      dormant: 3,
      allocated: 2,
      printed: 2,
      redeemed: 2,
      blocked: 1,
    },
  });
  assert.strictEqual(calls.contexts.length, 0, "caller-selected canonical context is never installed");
  assert.strictEqual(calls.scopes.length, 2, "cache hits still revalidate database scope");
  assert.strictEqual(calls.data.length, 1, "unchanged approved scope reuses the existing 20-second cache");
  assert(calls.transactionOptions.every((options) => options.isolationLevel === "RepeatableRead"));
  assert(calls.cacheKeys.every((key) => /^[0-9a-f]{64}$/.test(key)));
  assert(calls.cacheKeys.every((key) => !key.includes(ids.actor) && !key.includes(ids.tenant)));
  assert.strictEqual(calls.scopes[0][5], "GET /api/dashboard/stats");
  assert.strictEqual(calls.data[0][6], "a".repeat(32));
  assert.deepStrictEqual(events.slice(0, 4), ["transaction-begin", "scope", "data", "transaction-end"]);

  const dataCallsBeforeDelta = calls.data.length;
  assert.strictEqual(await canDeliverDashboardAuditDelta(request(undefined, { requestId: "dashboard-delta-1" }), ids.tenant), true);
  assert.strictEqual(await canDeliverDashboardAuditDelta(request(undefined, { requestId: "dashboard-delta-2" }), ids.foreign), false);
  assert.strictEqual(calls.data.length, dataCallsBeforeDelta, "SSE delta authorization does not reload aggregate data");

  const platformRequest = request(actor({
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date().toISOString(),
  }), { requestId: "dashboard-delta-platform" });
  assert.strictEqual(await canDeliverDashboardAuditDelta(platformRequest, null), true, "global platform SSE preserves null-scope events");

  denyScope = true;
  await assert.rejects(getDashboardSnapshot(request(undefined, { requestId: "dashboard-request-3" })), DashboardSnapshotAccessError);
  assert.strictEqual(calls.data.length, 1, "revoked scope cannot consume a cached snapshot");
  denyScope = false;

  denyCapability = true;
  const response = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  await getDashboardStats(request(undefined, { requestId: "dashboard-request-capability-denied" }), response);
  assert.deepStrictEqual([response.statusCode, response.body], [404, { success: false, error: "Dashboard not found" }]);
  denyCapability = false;

  fingerprint = "b".repeat(32);
  dataRow = {
    ...dataRow,
    total_qr_codes: 2n,
    dormant: 0n,
    active: 2n,
    activated: 0n,
    allocated: 0n,
    printed: 0n,
    redeemed: 0n,
    blocked: 0n,
    scanned: 0n,
    rollup_authoritative: false,
  };
  const fallback = await getDashboardSnapshot(request(undefined, { requestId: "dashboard-request-fallback" }));
  assert.deepStrictEqual(fallback.qr.byStatus, { ACTIVE: 2 }, "raw QR fallback preserves the sparse groupBy response shape");

  fingerprint = "c".repeat(32);
  dataRow = { ...dataRow, total_qr_codes: BigInt(Number.MAX_SAFE_INTEGER) + 1n };
  await assert.rejects(
    getDashboardSnapshot(request(undefined, { requestId: "dashboard-request-4" })),
    /invalid QR code count/
  );

  console.log("dashboard snapshot canonical-context tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

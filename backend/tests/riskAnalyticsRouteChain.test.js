const assert = require("node:assert/strict");
const path = require("node:path");
const { UserRole, UserStatus } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};
const ids = {
  actor: "44444444-4444-4444-8444-444444444444",
  tenant: "11111111-1111-4111-8111-111111111111",
  organization: "33333333-3333-4333-8333-333333333333",
  foreign: "22222222-2222-4222-8222-222222222222",
};
const basePayload = (overrides = {}) => ({
  userId: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  linkedLicenseeIds: [],
  sessionStage: "ACTIVE",
  authAssurance: "PASSWORD",
  authenticatedAt: new Date().toISOString(),
  mfaVerifiedAt: null,
  sessionId: "session-a",
  ...overrides,
});
const baseDatabaseUser = (overrides = {}) => ({
  id: ids.actor,
  email: "admin@example.test",
  role: UserRole.LICENSEE_ADMIN,
  licenseeId: ids.tenant,
  orgId: ids.organization,
  isActive: true,
  status: UserStatus.ACTIVE,
  deletedAt: null,
  disabledAt: null,
  ...overrides,
});
const manufacturerLink = (licenseeId = ids.tenant, orgId = ids.organization) => ({
  licenseeId,
  isPrimary: true,
  createdAt: new Date("2026-01-01T00:00:00.000Z"),
  updatedAt: new Date("2026-01-02T00:00:00.000Z"),
  licensee: {
    id: licenseeId,
    name: "Linked tenant",
    prefix: "LINKED",
    brandName: null,
    orgId,
  },
});
const response = () => ({
  statusCode: 200,
  body: null,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

let payload = basePayload();
let databaseUser = baseDatabaseUser();
let databaseLinks = [];
let transactionCount = 0;
const events = [];
const authTx = {
  $executeRaw: async (strings) => {
    events.push(/INSERT INTO public\."AuditLog"/.test(strings.join("?"))
      ? "audit"
      : transactionCount === 1 ? "actor-self-context" : "risk-context");
    return 1;
  },
  $queryRaw: async () => { events.push("policy"); return []; },
  user: { findUnique: async () => { events.push("actor-self-user"); return databaseUser; } },
  manufacturerLicenseeLink: { findMany: async () => { events.push("actor-membership"); return databaseLinks; } },
  licensee: {
    findUnique: async () => {
      events.push("licensee");
      return { id: ids.tenant, orgId: ids.organization, isActive: true, suspendedAt: null };
    },
  },
  organization: {
    findUnique: async () => {
      events.push("organization");
      return { id: ids.organization, isActive: true };
    },
  },
  qrScanLog: { findMany: async () => { events.push("scan"); return []; } },
  policyAlert: { findMany: async () => { events.push("alert"); return []; } },
  batch: { findMany: async () => { events.push("batch"); return []; } },
};
const database = {
  $transaction: async (callback) => {
    transactionCount += 1;
    events.push("transaction");
    return callback(authTx);
  },
};
mockModule("config/database.js", { __esModule: true, default: database });
mockModule("services/auth/tokenService.js", {
  ACCESS_TOKEN_COOKIE: "mscqr_access",
  verifyAccessToken: () => payload,
  verifyMfaBootstrapToken: () => { throw new Error("not bootstrap"); },
});
mockModule("services/auth/cookieTokenProtectionService.js", { openCookieToken: () => null });
mockModule("services/auth/authService.js", {
  getAdminStepUpWindowMinutes: () => 30,
  getPasswordReauthWindowMinutes: () => 30,
  getSensitiveActionStepUpMethod: () => "PASSWORD_REAUTH",
  isAdminMfaRequiredRole: () => false,
});

const { authenticate } = require("../dist/middleware/auth");
const { getRiskAnalyticsController } = require("../dist/controllers/tracePolicyController");

const authenticateOnce = async () => {
  const req = { headers: { authorization: "Bearer test-token" } };
  const res = response();
  let nextCalled = false;
  await authenticate(req, res, () => { nextCalled = true; });
  return { req, res, nextCalled };
};
const reset = (nextPayload, nextUser, links = []) => {
  payload = nextPayload;
  databaseUser = nextUser;
  databaseLinks = links;
  transactionCount = 0;
  events.length = 0;
};

(async () => {
  reset(basePayload(), baseDatabaseUser());
  let result = await authenticateOnce();
  assert.equal(result.nextCalled, true);
  assert.equal(result.req.user.licenseeId, ids.tenant);
  assert.equal(result.req.user.orgId, ids.organization);
  assert.equal(transactionCount, 1, "normal actor-self hydration remains one transaction");

  reset(basePayload(), baseDatabaseUser({ role: UserRole.ORG_ADMIN }));
  result = await authenticateOnce();
  assert.equal(result.nextCalled, false, "a database role change requires re-authentication");
  assert.equal(result.res.statusCode, 401);

  for (const [name, user, token] of [
    ["removed licensee", baseDatabaseUser({ licenseeId: null }), basePayload()],
    ["removed organization", baseDatabaseUser({ orgId: null }), basePayload()],
    ["licensee mismatch", baseDatabaseUser({ licenseeId: ids.foreign }), basePayload()],
    ["organization mismatch", baseDatabaseUser({ orgId: ids.foreign }), basePayload()],
  ]) {
    reset(token, user);
    result = await authenticateOnce();
    assert.equal(result.nextCalled, false, `${name} must fail closed`);
    assert.equal(result.res.statusCode, 401);
  }

  reset(
    basePayload({
      role: UserRole.MANUFACTURER,
      licenseeId: ids.tenant,
      scopeVersion: new Date("2026-01-02T00:00:00.000Z").toISOString(),
    }),
    baseDatabaseUser({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    [manufacturerLink()]
  );
  result = await authenticateOnce();
  assert.equal(result.nextCalled, true, "database-linked manufacturer scope remains valid");
  assert.deepEqual(result.req.user.linkedLicenseeIds, [ids.tenant]);
  reset(
    basePayload({ role: UserRole.MANUFACTURER, licenseeId: ids.foreign }),
    baseDatabaseUser({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    [manufacturerLink()]
  );
  result = await authenticateOnce();
  assert.equal(result.nextCalled, false, "manufacturer token scope cannot escape database links");

  reset(
    basePayload({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    baseDatabaseUser({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    []
  );
  result = await authenticateOnce();
  assert.equal(result.nextCalled, false, "a legacy or signed manufacturer identity without an active link fails closed");

  reset(
    basePayload({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    baseDatabaseUser({ role: UserRole.MANUFACTURER, licenseeId: null, orgId: null }),
    [
      { ...manufacturerLink(ids.tenant, ids.organization), isPrimary: false },
      { ...manufacturerLink(ids.foreign, ids.foreign), isPrimary: false },
    ]
  );
  result = await authenticateOnce();
  assert.equal(result.nextCalled, true, "an unambiguous membership set remains visible for an explicit later scope choice");
  assert.equal(result.req.user.licenseeId, null, "several links without one primary install no active scope");
  assert.equal(result.req.user.orgId, null, "organization remains blank until a verified scope is selected");
  assert.deepEqual(result.req.user.linkedLicenseeIds, [ids.tenant, ids.foreign]);

  reset(
    basePayload({
      role: UserRole.PLATFORM_SUPER_ADMIN,
      licenseeId: ids.foreign,
      orgId: ids.foreign,
      authAssurance: "ADMIN_MFA",
      mfaVerifiedAt: new Date().toISOString(),
    }),
    baseDatabaseUser({ role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, orgId: null })
  );
  const req = {
    headers: { authorization: "Bearer platform-token" },
    query: { licenseeId: ids.tenant },
    requestId: "request-platform-risk",
  };
  const res = response();
  await authenticate(req, res, () => getRiskAnalyticsController(req, res));
  assert.equal(req.user.licenseeId, null, "platform authentication cannot carry tenant scope");
  assert.equal(req.user.orgId, null, "platform authentication cannot carry organization scope");
  assert.equal(res.statusCode, 200, "fresh-MFA platform access accepts one bounded selector");
  assert.equal(res.body.data.summary.analyzedBatches, 0);
  assert.equal(transactionCount, 2, "platform actor hydration and bounded analytics share no unscoped global query");
  assert(events.includes("actor-self-user"));
  assert(events.includes("licensee"));
  assert(events.includes("organization"));
  assert(events.includes("audit"));

  reset(
    basePayload({
      role: UserRole.PLATFORM_SUPER_ADMIN,
      licenseeId: ids.foreign,
      orgId: ids.foreign,
      authAssurance: "ADMIN_MFA",
      mfaVerifiedAt: new Date().toISOString(),
    }),
    baseDatabaseUser({ role: UserRole.PLATFORM_SUPER_ADMIN, licenseeId: null, orgId: null })
  );
  const unscopedReq = { headers: { authorization: "Bearer platform-token" }, query: {}, requestId: "request-platform-unscoped" };
  const unscopedRes = response();
  await authenticate(unscopedReq, unscopedRes, () => getRiskAnalyticsController(unscopedReq, unscopedRes));
  assert.equal(unscopedRes.statusCode, 403);
  assert.equal(unscopedRes.body.error, "A valid tenant scope is required");
  assert.equal(transactionCount, 1, "blank platform scope denies before the analytics transaction");
  assert(!events.some((event) => ["licensee", "organization", "batch", "scan", "alert", "audit"].includes(event)));

  console.log("risk analytics route-chain and database-scope hydration tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

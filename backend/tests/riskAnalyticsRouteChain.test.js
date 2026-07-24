const assert = require("node:assert/strict");
const path = require("node:path");
const { UserRole, UserStatus } = require("@prisma/client");

process.env.NODE_ENV = "test";

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
  platform: "55555555-5555-4555-8555-555555555555",
};
const response = () => ({
  statusCode: 200,
  body: null,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

let payload;
let databaseUser;
let snapshotCalls = 0;
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

mockModule("services/auth/tokenService.js", {
  ACCESS_TOKEN_COOKIE: "mscqr_access",
  AUTHENTICATED_SESSION_CAPABILITY_COOKIE: "mscqr_db_session",
  verifyAccessToken: () => payload,
  verifyMfaBootstrapToken: () => { throw new Error("not bootstrap"); },
});
mockModule("services/auth/cookieTokenProtectionService.js", { openCookieToken: (value) => value });
mockModule("services/auth/authService.js", {
  getAdminStepUpWindowMinutes: () => 30,
  getPasswordReauthWindowMinutes: () => 30,
  getSensitiveActionStepUpMethod: () => "PASSWORD_REAUTH",
  isAdminMfaRequiredRole: () => false,
});
mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
  isCanonicalAuthDenial: () => false,
  withCanonicalAuthClaims: async (_claims, fn) => fn({}),
  withDatabaseAuthenticatedSession: async (claims, input, fn) => {
    if (input.capability !== "database-capability") throw new Error("AUTH_SESSION_CAPABILITY_DENIED");
    return fn({}, {
      userId: claims.userId,
      role: claims.role,
      organizationId: claims.orgId,
      licenseeId: claims.licenseeId,
      manufacturerId: null,
      authAssurance: claims.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId: input.requestId,
      purpose: input.purpose,
    }).then((value) => ({
      ...value,
      canonicalAssurance: claims.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
    }));
  },
});
mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
  loadAuthenticatedActor: async () => databaseUser,
  isRecentMfaDenial: () => false,
  RecentMfaDenial: class RecentMfaDenial extends Error {},
  requireRecentMfaSession: async () => true,
});
mockModule("rls-waves/session-c/c02/riskAnalyticsRepository.js", {
  RiskAnalyticsBoundaryDenied: class RiskAnalyticsBoundaryDenied extends Error {},
  isRiskAnalyticsBoundaryDenied: () => false,
  readRiskAnalyticsSnapshot: async (input) => {
    snapshotCalls += 1;
    assert.equal(input.capability, "database-capability");
    assert.equal(input.expectedUserId, payload.userId);
    return {
      organizationId: ids.organization,
      policy: { multiScanThreshold: 2, geoDriftThresholdKm: 300, velocitySpikeThresholdPerMin: 80 },
      batches: [],
      scanLogs: [],
      alerts: [],
      qrs: [],
      manufacturers: [],
      manufacturerLinks: [],
      incidents: [],
      policyRules: [],
    };
  },
});

const { authenticate, DATABASE_SESSION_CAPABILITY_HEADER } = require("../dist/middleware/auth");
const { getRiskAnalyticsController } = require("../dist/controllers/tracePolicyController");

const authenticateOnce = async ({ includeCapability = true } = {}) => {
  const headers = { authorization: "Bearer test-token" };
  if (includeCapability) headers[DATABASE_SESSION_CAPABILITY_HEADER] = "database-capability";
  const req = { headers, get(name) { return this.headers[String(name).toLowerCase()]; } };
  const res = response();
  let nextCalled = false;
  await authenticate(req, res, () => { nextCalled = true; });
  return { req, res, nextCalled };
};

(async () => {
  payload = basePayload();
  databaseUser = baseDatabaseUser();
  let result = await authenticateOnce();
  assert.equal(result.nextCalled, true, "bearer authentication with a database capability succeeds");
  assert.equal(result.req.user.licenseeId, ids.tenant);
  assert.equal(result.req.databaseSessionCapability, "database-capability");

  result = await authenticateOnce({ includeCapability: false });
  assert.equal(result.nextCalled, false, "bearer authentication without a database capability fails closed");
  assert.equal(result.res.statusCode, 401);

  databaseUser = baseDatabaseUser({ role: UserRole.ORG_ADMIN });
  result = await authenticateOnce();
  assert.equal(result.nextCalled, false, "a database role change requires re-authentication");
  assert.equal(result.res.statusCode, 401);

  payload = basePayload({
    userId: ids.platform,
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    authAssurance: "ADMIN_MFA",
    mfaVerifiedAt: new Date().toISOString(),
  });
  databaseUser = baseDatabaseUser({
    id: ids.platform,
    role: UserRole.PLATFORM_SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
  });
  const req = {
    headers: {
      authorization: "Bearer platform-token",
      [DATABASE_SESSION_CAPABILITY_HEADER]: "database-capability",
    },
    get(name) { return this.headers[String(name).toLowerCase()]; },
    query: { licenseeId: ids.tenant },
    requestId: "66666666-6666-4666-8666-666666666666",
  };
  const res = response();
  await authenticate(req, res, () => getRiskAnalyticsController(req, res));
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.data.summary.analyzedBatches, 0);
  assert.equal(snapshotCalls, 1, "controller performs one capability-bound snapshot read");

  payload = basePayload();
  databaseUser = baseDatabaseUser();
  const tenantReq = {
    headers: {
      authorization: "Bearer tenant-token",
      [DATABASE_SESSION_CAPABILITY_HEADER]: "database-capability",
    },
    get(name) { return this.headers[String(name).toLowerCase()]; },
    query: { licenseeId: ids.foreign },
    requestId: "77777777-7777-4777-8777-777777777777",
  };
  const tenantRes = response();
  await authenticate(tenantReq, tenantRes, () => getRiskAnalyticsController(tenantReq, tenantRes));
  assert.equal(tenantRes.statusCode, 403);
  assert.equal(snapshotCalls, 1, "foreign selector is denied before PostgreSQL invocation");

  console.log("risk analytics route-chain and capability hydration tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

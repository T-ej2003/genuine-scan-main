const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../../../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

const canonical = require("../../../dist/rls-waves/session-b/b01/canonicalAuthContext");
const security = require("../../../dist/rls-waves/session-b/b01/authenticatedSecurityRepository");

const repositoryInput = {
  sessionId: "session-1",
  checkedAt: new Date(),
  maxAgeMinutes: 30,
};

const run = async () => {
  await assert.rejects(
    security.requireRecentMfaSession(repositoryInput, { $queryRaw: async () => [] }),
    (error) => security.isRecentMfaDenial(error),
    "zero rows must produce only the typed stale-MFA denial"
  );
  await assert.rejects(
    security.requireRecentMfaSession(repositoryInput, {
      $queryRaw: async () => [{ verifiedAt: new Date() }, { verifiedAt: new Date() }],
    }),
    /invalid row count/,
    "an invalid projection cardinality must remain an operational error"
  );

  let canonicalBehavior;
  let recentMfaBehavior;
  mockModule("controllers/authControllerShared.js", {
    clearAuthCookies: (res) => { res.cleared += 1; },
  });
  mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
    ...canonical,
    withCanonicalAuthClaims: (...args) => canonicalBehavior(...args),
    withDatabaseAuthenticatedSession: (...args) => canonicalBehavior(...args),
  });
  mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
    ...security,
    loadAuthenticatedActor: async () => ({}),
    requireRecentMfaSession: (...args) => recentMfaBehavior(...args),
  });
  mockModule("services/auth/tokenService.js", {
    ACCESS_TOKEN_COOKIE: "access",
    verifyAccessToken: () => { throw new Error("not used"); },
    verifyMfaBootstrapToken: () => { throw new Error("not used"); },
  });
  mockModule("services/auth/cookieTokenProtectionService.js", { openCookieToken: () => null });
  mockModule("services/manufacturerScopeService.js", {
    isLicenseeAdminRole: () => false,
    isManufacturerRole: () => false,
    isPlatformRole: () => true,
    resolveManufacturerSessionScope: async () => null,
  });
  mockModule("services/accessControlService.js", { isDisabledUserRecord: () => false });
  mockModule("utils/cookies.js", { readCookie: () => null });
  mockModule("services/auth/authService.js", {
    getAdminStepUpWindowMinutes: () => 30,
    getPasswordReauthWindowMinutes: () => 30,
    getSensitiveActionStepUpMethod: () => "ADMIN_MFA",
    isAdminMfaRequiredRole: () => true,
  });

  const { requireRecentAdminMfa } = require("../../../dist/middleware/auth");
  const request = () => ({
    user: {
      userId: "user-1",
      sessionId: "session-1",
      role: "SUPER_ADMIN",
      sessionStage: "ACTIVE",
    },
    requestId: "request-1",
    databaseSessionCapability: "A".repeat(43),
    get: () => null,
  });
  const response = () => ({
    statusCode: 200,
    body: null,
    cleared: 0,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  });
  const invoke = async () => {
    const res = response();
    const nextCalls = [];
    await requireRecentAdminMfa(request(), res, (error) => { nextCalls.push(error); });
    return { res, nextCalls };
  };

  recentMfaBehavior = async () => ({ verifiedAt: new Date() });
  canonicalBehavior = async () => { throw new canonical.CanonicalAuthDenial(); };
  const inactive = await invoke();
  assert.equal(inactive.res.statusCode, 401);
  assert.equal(inactive.res.cleared, 1);
  assert.deepEqual(inactive.nextCalls, []);

  canonicalBehavior = (_claims, _input, callback) => callback({}, { authAssurance: "password-verified" });
  const lowerAssurance = await invoke();
  assert.equal(lowerAssurance.res.statusCode, 428);
  assert.equal(lowerAssurance.res.body.code, "STEP_UP_REQUIRED");
  assert.equal(lowerAssurance.res.cleared, 0);

  canonicalBehavior = (_claims, _input, callback) => callback({}, { authAssurance: "mfa-verified" });
  recentMfaBehavior = async () => { throw new security.RecentMfaDenial(); };
  const staleMfa = await invoke();
  assert.equal(staleMfa.res.statusCode, 428);
  assert.deepEqual(staleMfa.nextCalls, []);

  const databaseError = new Error("database unavailable");
  canonicalBehavior = async () => { throw databaseError; };
  const operational = await invoke();
  assert.equal(operational.res.statusCode, 200);
  assert.equal(operational.res.cleared, 0);
  assert.deepEqual(operational.nextCalls, [databaseError]);

  const projectionError = new Error("unexpected projection");
  canonicalBehavior = (_claims, _input, callback) => callback({}, { authAssurance: "mfa-verified" });
  recentMfaBehavior = async () => { throw projectionError; };
  const invalidProjection = await invoke();
  assert.deepEqual(invalidProjection.nextCalls, [projectionError]);

  recentMfaBehavior = async () => ({ verifiedAt: new Date() });
  canonicalBehavior = (_claims, _input, callback) => callback({}, { authAssurance: "step-up-verified" });
  const allowed = await invoke();
  assert.equal(allowed.res.statusCode, 200);
  assert.deepEqual(allowed.nextCalls, [undefined]);

  console.log("B01 recent-admin-MFA middleware denial tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

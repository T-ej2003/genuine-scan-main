const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../../../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

mockModule("rls-waves/session-b/b01/runtimeClients.js", {
  getB01AuthenticatedPrisma: () => ({ $transaction: (callback) => callback({}) }),
});
mockModule("rls-waves/session-b/b01/actorRevalidationRepository.js", {
  revalidateAuthenticatedActor: async () => revalidatedActor,
});
mockModule("lib/canonicalDbContext.js", { installCanonicalDbContext: async () => null });

let revalidatedActor = null;
const canonical = require("../../../dist/rls-waves/session-b/b01/canonicalAuthContext");
const claims = {
  userId: "user-1",
  sessionId: "session-1",
  sessionStage: "ACTIVE",
  role: "LICENSEE_ADMIN",
  authAssurance: "PASSWORD",
};

const run = async () => {
let caught;
try {
  await canonical.withCanonicalAuthClaims(
    claims,
    { requestId: "request-1", purpose: "auth-me" },
    async () => assert.fail("denied actor must not reach the protected callback")
  );
} catch (error) {
  caught = error;
}
assert.equal(canonical.isCanonicalAuthDenial(caught), true, "an empty actor revalidation must be a typed denial");

const dbSession = (query) => canonical.withDatabaseAuthenticatedSession(
  claims,
  { capability: "A".repeat(43), requestId: "aaaa5fab-7f42-474f-8014-e735a1fa8803", purpose: "auth-me" },
  async () => "allowed",
  { $transaction: (callback) => callback({ $queryRaw: query }) },
);
const sqlError = (code, sqlstate, message) => Object.assign(new Error(message), { code, meta: { code: sqlstate, message } });
const capabilityDenied = sqlError("P2010", "42501", "AUTH_SESSION_CAPABILITY_DENIED");
let translatedDenial;
await assert.rejects(dbSession(async () => { throw capabilityDenied; }), (error) => {
  translatedDenial = error;
  return canonical.isCanonicalAuthDenial(error);
}, "the exact SQL capability denial must use the existing unauthenticated response path");
for (const unrelated of [
  sqlError("P2010", "42501", "OTHER_RLS_DENIED"),
  sqlError("P2010", "XX000", "AUTH_SESSION_CAPABILITY_DENIED"),
  sqlError("P2028", "42501", "AUTH_SESSION_CAPABILITY_DENIED"),
]) {
  await assert.rejects(dbSession(async () => { throw unrelated; }), (error) => error === unrelated,
    "unrelated database failures must retain their original identity");
}
revalidatedActor = {
  userId: claims.userId, role: claims.role, organizationId: null, licenseeId: null,
  manufacturerId: null, authAssurance: "password-verified",
};
assert.equal(await dbSession(async () => [{ sessionId: claims.sessionId, userId: claims.userId }]), "allowed",
  "valid sessions must still reach the protected callback");
revalidatedActor = null;

let boundaryError = new canonical.CanonicalAuthDenial();
let refreshError = null;
let rawRefresh = null;
let activationSessionError = null;
let activationVerificationCount = 0;
mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
  ...canonical,
  withCanonicalAuthClaims: async () => { throw boundaryError; },
  withDatabaseAuthenticatedSession: async () => { throw boundaryError; },
});

const validSchema = { safeParse: (value) => ({ success: true, data: value || {} }) };
mockModule("controllers/authControllerShared.js", {
  acceptInviteSchema: validSchema,
  authResponseData: (session) => session,
  buildAuthState: async () => ({}),
  clearAuthCookies: (res) => { res.cleared += 1; },
  ensureCsrfCookie: () => null,
  forgotPasswordSchema: validSchema,
  getAuthClaims: (req) => req.user,
  getCurrentRefreshSession: async () => null,
  getRefreshTokenFromRequest: () => rawRefresh,
  getRequestId: () => "request-1",
  hashIp: () => "ip-hash",
  invitePreviewQuerySchema: validSchema,
  inviteActivationVerifySchema: validSchema,
  inviteActivationResendSchema: validSchema,
  inviteSchema: validSchema,
  isAdminMfaRequiredRole: (role) => role === "SUPER_ADMIN",
  loginSchema: validSchema,
  mfaCodeSchema: validSchema,
  normalizeAuthError: () => ({ status: 500, error: "Internal server error" }),
  normalizeUserAgent: () => "agent",
  passwordStepUpSchema: validSchema,
  refreshSessionSchema: validSchema,
  resetPasswordSchema: validSchema,
  setAuthCookies: (res) => { res.cookiesSet += 1; },
  verifyEmailSchema: validSchema,
});
mockModule("rls-waves/session-b/b01/authenticatedSessionProjection.js", {
  buildAuthState: async () => ({}),
  getCurrentRefreshSession: async () => null,
});
mockModule("services/auth/authService.js", {
  issueSessionForUser: async () => ({}),
  issueSessionAfterInviteActivation: async () => {
    if (activationSessionError) throw activationSessionError;
    return { sessionStage: "ACTIVE", auth: { authAssurance: "PASSWORD" } };
  },
  loginWithPassword: async () => ({}),
  logoutSession: async () => null,
  refreshSession: async () => { if (refreshError) throw refreshError; return { ok: false }; },
});
mockModule("services/auth/passwordService.js", { verifyPassword: async () => true });
mockModule("services/auth/refreshTokenService.js", {
  listActiveRefreshTokensForUser: async () => [],
  revokeAllUserRefreshTokens: async () => ({ revokedCount: 0 }),
  revokeRefreshTokenById: async () => true,
});
mockModule("services/auth/mfaService.js", { verifyAdminMfaCode: async () => null });
mockModule("services/auth/authClaimsRlsContext.js", {
  withAdminMfaClaimsTransaction: async () => { throw boundaryError; },
});
mockModule("services/auditLogOutboxService.js", { queueAuditLogOutbox: async () => null });
mockModule("services/auth/sessionSecurityOverview.js", { getSessionSecurityOverview: async () => ({}) });
mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
  loadAuthenticatedActor: async () => ({}),
  loadAuthenticatedPasswordActor: async () => ({}),
  proveAuthenticatedPasswordStepUp: async () => null,
});
mockModule("services/auth/inviteService.js", {
  acceptInvite: async () => ({}),
  createInvite: async (input) => {
    assert.equal(input.databaseCapability, "");
    throw boundaryError;
  },
  getInvitePreview: async () => ({}),
  verifyInviteActivation: async () => {
    activationVerificationCount += 1;
    return { verified: true, userId: "user-1", email: "invite@example.com", role: "LICENSEE_ADMIN" };
  },
  resendInviteActivation: async () => ({}),
});
mockModule("services/auth/passwordResetService.js", {
  requestPasswordReset: async () => null,
  resetPasswordWithToken: async () => null,
});
mockModule("services/auth/emailVerificationService.js", { confirmEmailVerification: async () => ({}) });
mockModule("services/manufacturerScopeService.js", {
  isManufacturerRole: () => false,
  resolveManufacturerSessionScope: async () => null,
});
mockModule("controllers/authAdminSecurityController.js", {});

const sessionControllers = require("../../../dist/controllers/authSessionController");
const authControllers = require("../../../dist/controllers/authController");

const request = (overrides = {}) => ({
  body: { currentPassword: "password", code: "123456", email: "invite@example.com", role: "VIEWER" },
  params: { id: "session-2" },
  user: claims,
  ip: "127.0.0.1",
  get: () => null,
  ...overrides,
});
const response = () => ({
  statusCode: 200,
  body: null,
  cleared: 0,
  cookiesSet: 0,
  status(code) { this.statusCode = code; return this; },
  json(body) { this.body = body; return this; },
});

const deniedRoutes = [
  ["me", authControllers.me, request()],
  ["logout", authControllers.logout, request()],
  ["invite", authControllers.invite, request()],
  ["session list", sessionControllers.listSessions, request()],
  ["session revoke", sessionControllers.revokeSessionController, request()],
  ["session revoke all", sessionControllers.revokeAllSessionsController, request()],
  ["password step-up", sessionControllers.passwordStepUpController, request()],
  ["MFA step-up", sessionControllers.adminMfaStepUpController, request({ user: { ...claims, role: "SUPER_ADMIN" } })],
];

const missingSession = response();
await authControllers.me(request({ user: null }), missingSession);
assert.deepEqual([missingSession.statusCode, missingSession.body], [401, { success: false, error: "Not authenticated" }]);

for (const [name, controller, req] of deniedRoutes) {
  boundaryError = name === "me" ? translatedDenial : new canonical.CanonicalAuthDenial();
  const res = response();
  await controller(req, res);
  assert.equal(res.statusCode, 401, `${name} must map failed revalidation to 401`);
  assert.equal(res.cleared, 1, `${name} must clear unusable session cookies`);
  if (name === "invite") {
    assert.deepEqual(res.body, { success: false, error: "Not authenticated" });
  }
  assert.doesNotMatch(JSON.stringify(res.body), /AUTHENTICATED_SESSION_DENIED|CanonicalAuthDenial|disabled|revoked|expired/i);
}

for (const category of ["MANUFACTURER_SCOPE_DENIED", "MANUFACTURER_SCOPE_STALE"]) {
  boundaryError = new Error(category);
  const res = response();
  await authControllers.me(request(), res);
  assert.equal(res.statusCode, 403, `${category} must map to a scope denial`);
  assert.equal(res.cleared, 0, `${category} must preserve the session for a valid scope switch`);
  assert.equal(res.body.code, "AUTH_SCOPE_UNAVAILABLE");
  assert.doesNotMatch(res.body.error, new RegExp(category));
}

rawRefresh = "refresh-fixture";
refreshError = new Error("MANUFACTURER_SCOPE_DENIED");
const deniedRefresh = response();
await authControllers.refresh(request(), deniedRefresh);
assert.equal(deniedRefresh.statusCode, 403);
assert.equal(deniedRefresh.body.code, "AUTH_SCOPE_UNAVAILABLE");
assert.doesNotMatch(deniedRefresh.body.error, /MANUFACTURER_SCOPE_DENIED/);
refreshError = Object.assign(new Error("Transaction expired"), { code: "P2028" });
const expiredTransaction = response();
await authControllers.refresh(request(), expiredTransaction);
assert.equal(expiredTransaction.statusCode, 503);
assert.equal(expiredTransaction.cleared, 0, "a database timeout must not clear valid refresh cookies");
assert.doesNotMatch(expiredTransaction.body.error, /Transaction expired|P2028/);
refreshError = sqlError("P2010", "42501", "ERROR: B01_REFRESH_BEARER_DENIED");
const boundaryDeniedRefresh = response();
await authControllers.refresh(request(), boundaryDeniedRefresh);
assert.equal(boundaryDeniedRefresh.statusCode, 401);
assert.equal(boundaryDeniedRefresh.cleared, 1, "an exact refresh boundary denial must clear invalid cookies");
refreshError = sqlError("P2010", "42501", "ERROR: B01_SCOPE_SWITCH_ROLE_DENIED");
const forbiddenScopeRefresh = response();
await authControllers.refresh(request(), forbiddenScopeRefresh);
assert.equal(forbiddenScopeRefresh.statusCode, 401);
assert.equal(forbiddenScopeRefresh.cleared, 1);
refreshError = sqlError("P2010", "42501", "ERROR: OTHER_RLS_DENIED");
const unrelatedSqlDenial = response();
await authControllers.refresh(request(), unrelatedSqlDenial);
assert.equal(unrelatedSqlDenial.statusCode, 500);
assert.equal(unrelatedSqlDenial.cleared, 0);
refreshError = new Error("Unexpected database failure");
const unexpectedRefreshFailure = response();
await authControllers.refresh(request(), unexpectedRefreshFailure);
assert.equal(unexpectedRefreshFailure.statusCode, 500);
assert.equal(unexpectedRefreshFailure.cleared, 0);
refreshError = null;
const revokedRefresh = response();
await authControllers.refresh(request(), revokedRefresh);
assert.equal(revokedRefresh.statusCode, 401);
assert.equal(revokedRefresh.cleared, 1, "a genuinely invalid refresh token must clear its cookies");
rawRefresh = null;

activationSessionError = new Error("Activation completed. Please sign in from a trusted network.");
const activatedWithoutSession = response();
await authControllers.verifyInviteActivationController(request({ body: { challengeId: "challenge-1", code: "123456" } }), activatedWithoutSession);
assert.equal(activatedWithoutSession.statusCode, 200);
assert.deepEqual(activatedWithoutSession.body, { success: true, data: { activated: true, loginRequired: true } });
assert.equal(activatedWithoutSession.cookiesSet, 0, "risk denial must not issue authentication cookies");
assert.equal(activationVerificationCount, 1, "activation must not be retried after session denial");

activationSessionError = null;
const activatedWithSession = response();
await authControllers.verifyInviteActivationController(request({ body: { challengeId: "challenge-2", code: "123456" } }), activatedWithSession);
assert.equal(activatedWithSession.statusCode, 200);
assert.equal(activatedWithSession.body.success, true);
assert.equal(activatedWithSession.body.data.sessionStage, "ACTIVE");
assert.equal(activatedWithSession.cookiesSet, 1, "successful session issuance must set authentication cookies");

console.log("B01 authenticated controller denial tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

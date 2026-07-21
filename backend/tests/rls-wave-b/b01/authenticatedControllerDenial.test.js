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
  revalidateAuthenticatedActor: async () => null,
});
mockModule("lib/canonicalDbContext.js", { installCanonicalDbContext: async () => null });

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

let boundaryError = new canonical.CanonicalAuthDenial();
mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
  ...canonical,
  withCanonicalAuthClaims: async () => { throw boundaryError; },
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
  getRefreshTokenFromRequest: () => null,
  getRequestId: () => "request-1",
  hashIp: () => "ip-hash",
  invitePreviewQuerySchema: validSchema,
  inviteSchema: validSchema,
  isAdminMfaRequiredRole: (role) => role === "SUPER_ADMIN",
  loginSchema: validSchema,
  mfaCodeSchema: validSchema,
  normalizeAuthError: () => ({ status: 500, error: "Internal server error" }),
  normalizeUserAgent: () => "agent",
  passwordStepUpSchema: validSchema,
  refreshSessionSchema: validSchema,
  resetPasswordSchema: validSchema,
  setAuthCookies: () => null,
  verifyEmailSchema: validSchema,
});
mockModule("rls-waves/session-b/b01/authenticatedSessionProjection.js", {
  buildAuthState: async () => ({}),
  getCurrentRefreshSession: async () => null,
});
mockModule("services/auth/authService.js", {
  issueSessionForUser: async () => ({}),
  loginWithPassword: async () => ({}),
  logoutSession: async () => null,
  refreshSession: async () => ({ ok: false }),
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
  createInvite: (input) => input.databaseBoundary.run(async () => ({})),
  getInvitePreview: async () => ({}),
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

for (const [name, controller, req] of deniedRoutes) {
  boundaryError = new canonical.CanonicalAuthDenial();
  const res = response();
  await controller(req, res);
  assert.equal(res.statusCode, 401, `${name} must map failed revalidation to 401`);
  assert.equal(res.cleared, 1, `${name} must clear unusable session cookies`);
  assert.doesNotMatch(JSON.stringify(res.body), /AUTHENTICATED_SESSION_DENIED|CanonicalAuthDenial|disabled|revoked|expired/i);
}

for (const category of ["MANUFACTURER_SCOPE_DENIED", "MANUFACTURER_SCOPE_STALE"]) {
  boundaryError = new Error(category);
  const res = response();
  await authControllers.me(request(), res);
  assert.equal(res.statusCode, 403, `${category} must map to a scope denial`);
  assert.equal(res.cleared, 0, `${category} must preserve the session for a valid scope switch`);
  assert.doesNotMatch(JSON.stringify(res.body), new RegExp(category));
}

console.log("B01 authenticated controller denial tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

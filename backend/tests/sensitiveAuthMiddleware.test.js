const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

mockModule("config/database.js", {
  __esModule: true,
  default: {
    user: {
      findUnique: async () => null,
    },
  },
});

mockModule("services/auth/tokenService.js", {
  ACCESS_TOKEN_COOKIE: "aq_access",
  verifyAccessToken: () => {
    throw new Error("not used");
  },
  verifyMfaBootstrapToken: () => {
    throw new Error("not used");
  },
});

mockModule("services/manufacturerScopeService.js", {
  isManufacturerRole: (role) =>
    role === UserRole.MANUFACTURER || role === UserRole.MANUFACTURER_ADMIN || role === UserRole.MANUFACTURER_USER,
  resolveManufacturerSessionScope: async () => ({ selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] }),
});

mockModule("services/auth/authService.js", {
  isAdminMfaRequiredRole: (role) =>
    role === UserRole.SUPER_ADMIN ||
    role === UserRole.PLATFORM_SUPER_ADMIN ||
    role === UserRole.LICENSEE_ADMIN ||
    role === UserRole.ORG_ADMIN ||
    role === UserRole.MANUFACTURER ||
    role === UserRole.MANUFACTURER_ADMIN ||
    role === UserRole.MANUFACTURER_USER,
  getSensitiveActionStepUpMethod: (role) =>
    role === UserRole.SUPER_ADMIN ||
    role === UserRole.PLATFORM_SUPER_ADMIN ||
    role === UserRole.LICENSEE_ADMIN ||
    role === UserRole.ORG_ADMIN ||
    role === UserRole.MANUFACTURER ||
    role === UserRole.MANUFACTURER_ADMIN ||
    role === UserRole.MANUFACTURER_USER
      ? "ADMIN_MFA"
      : "PASSWORD_REAUTH",
  getAdminStepUpWindowMinutes: () => 30,
  getPasswordReauthWindowMinutes: () => 30,
});

class RecentMfaDenial extends Error {}
mockModule("controllers/authControllerShared.js", {
  clearAuthCookies: (res) => { res.cleared = true; },
});
mockModule("rls-waves/session-b/b01/canonicalAuthContext.js", {
  isCanonicalAuthDenial: () => false,
  withCanonicalAuthClaims: (claims, _input, callback) => callback({}, {
    authAssurance: claims.databaseMfaFresh ? "mfa-verified" : "password-verified",
  }),
  withDatabaseAuthenticatedSession: (claims, _input, callback) => callback({}, {
    authAssurance: claims.databaseMfaFresh ? "mfa-verified" : "password-verified",
  }),
});
mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
  isRecentMfaDenial: (error) => error instanceof RecentMfaDenial,
  loadAuthenticatedActor: async () => ({}),
  RecentMfaDenial,
  requireRecentMfaSession: async () => ({ verifiedAt: new Date() }),
});

const { requireRecentAdminMfaForSetup, requireRecentSensitiveAuth } = require("../dist/middleware/auth");

const runMiddleware = (user, middleware = requireRecentSensitiveAuth) =>
  new Promise((resolve) => {
    const req = { user, requestId: "request-1", databaseSessionCapability: "test-capability", get: () => null };
    const res = {
      statusCode: 200,
      body: null,
      status(code) {
        this.statusCode = code;
        return this;
      },
      json(payload) {
        this.body = payload;
        resolve({ next: false, statusCode: this.statusCode, payload });
        return this;
      },
    };

    middleware(req, res, () => resolve({ next: true, statusCode: 200, payload: null }));
  });

const run = async () => {
  const manufacturerBlocked = await runMiddleware({
    userId: "manufacturer-1",
    role: UserRole.MANUFACTURER,
    sessionStage: "ACTIVE",
    authenticatedAt: new Date(Date.now() - 45 * 60_000).toISOString(),
    mfaVerifiedAt: new Date().toISOString(),
    databaseMfaFresh: false,
  });

  assert.strictEqual(manufacturerBlocked.next, false);
  assert.strictEqual(manufacturerBlocked.statusCode, 428);
  assert.strictEqual(manufacturerBlocked.payload.code, "STEP_UP_REQUIRED");
  assert.strictEqual(manufacturerBlocked.payload.data.stepUpMethod, "ADMIN_MFA");

  const manufacturerAllowed = await runMiddleware({
    userId: "manufacturer-1",
    role: UserRole.MANUFACTURER,
    sessionStage: "ACTIVE",
    authenticatedAt: new Date(Date.now() - 5 * 60_000).toISOString(),
    mfaVerifiedAt: new Date(Date.now() - 45 * 60_000).toISOString(),
    databaseMfaFresh: true,
  });

  assert.strictEqual(manufacturerAllowed.next, true);

  const adminBlocked = await runMiddleware({
    userId: "admin-1",
    role: UserRole.SUPER_ADMIN,
    sessionStage: "ACTIVE",
    authenticatedAt: new Date().toISOString(),
    mfaVerifiedAt: new Date().toISOString(),
    databaseMfaFresh: false,
  });

  assert.strictEqual(adminBlocked.next, false);
  assert.strictEqual(adminBlocked.statusCode, 428);
  assert.strictEqual(adminBlocked.payload.data.stepUpMethod, "ADMIN_MFA");

  const bootstrapSetupAllowed = await runMiddleware({
    userId: "admin-1",
    role: UserRole.SUPER_ADMIN,
    sessionStage: "MFA_BOOTSTRAP",
  }, requireRecentAdminMfaForSetup);
  assert.strictEqual(bootstrapSetupAllowed.next, true, "MFA bootstrap must remain able to perform true first enrollment");

  const staleActiveReplacementBlocked = await runMiddleware({
    userId: "admin-1",
    role: UserRole.SUPER_ADMIN,
    sessionStage: "ACTIVE",
    mfaVerifiedAt: new Date().toISOString(),
    databaseMfaFresh: false,
  }, requireRecentAdminMfaForSetup);
  assert.strictEqual(staleActiveReplacementBlocked.next, false);
  assert.strictEqual(staleActiveReplacementBlocked.statusCode, 428);

  const recentActiveReplacementAllowed = await runMiddleware({
    userId: "admin-1",
    role: UserRole.SUPER_ADMIN,
    sessionStage: "ACTIVE",
    mfaVerifiedAt: new Date(Date.now() - 45 * 60_000).toISOString(),
    databaseMfaFresh: true,
  }, requireRecentAdminMfaForSetup);
  assert.strictEqual(recentActiveReplacementAllowed.next, true, "recent admin MFA must allow active-session replacement");

  console.log("sensitive auth middleware tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

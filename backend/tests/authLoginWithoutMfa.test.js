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

let prismaUser = null;

mockModule("config/database.js", {
  __esModule: true,
  default: {
    user: {
      findUnique: async () => prismaUser,
      update: async () => prismaUser,
    },
  },
});

mockModule("services/auth/passwordService.js", {
  verifyPassword: async () => true,
  hashPassword: async () => "rehash",
  shouldRehashPassword: () => false,
});

mockModule("services/auth/tokenService.js", {
  signAccessToken: () => "access-token",
  newCsrfToken: () => "csrf-token",
  newRefreshToken: () => "refresh-token",
});

mockModule("services/auth/refreshTokenService.js", {
  createRefreshToken: async () => ({
    row: { id: "session-1" },
    expiresAt: new Date("2026-03-16T12:00:00.000Z"),
  }),
  rotateRefreshToken: async () => null,
  revokeAllUserRefreshTokens: async () => null,
  revokeRefreshTokenByRaw: async () => null,
});

mockModule("services/auditService.js", {
  createAuditLog: async () => null,
});

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({
    score: 12,
    riskLevel: "LOW",
    reasons: ["Known device"],
    shouldBlock: false,
  }),
});

mockModule("services/manufacturerScopeService.js", {
  listManufacturerLicenseeLinks: async () => [],
  normalizeLinkedLicensees: (links) => links,
});

const { loginWithPassword } = require("../dist/services/auth/authService");

const baseUser = {
  id: "user-1",
  email: "ops@example.com",
  name: "Ops User",
  passwordHash: "hash",
  role: UserRole.MANUFACTURER,
  licenseeId: null,
  orgId: null,
  failedLoginAttempts: 0,
  lockedUntil: null,
  deletedAt: null,
  disabledAt: null,
  isActive: true,
  status: "ACTIVE",
  emailVerifiedAt: new Date("2026-04-01T09:00:00.000Z"),
  licensee: null,
};

const run = async () => {
  prismaUser = { ...baseUser };

  const result = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
  });

  assert.strictEqual(result.accessToken, "access-token", "login should issue a normal access token");
  assert.strictEqual(result.refreshToken, "refresh-token", "login should issue a normal refresh token");
  assert.ok(result.user, "login should return the authenticated user");
  assert.strictEqual("mfaRequired" in result, false, "login should not force an MFA challenge");
  assert.strictEqual("mfaSetupRequired" in result, false, "login should not force MFA setup");

  console.log("auth login without MFA tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

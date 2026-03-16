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
let mfaStatus = null;
let createdChallengeCount = 0;

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
  signMfaBootstrapToken: () => "bootstrap-ticket",
  newCsrfToken: () => "csrf-token",
  newRefreshToken: () => "refresh-token",
  getMfaBootstrapTtlMinutes: () => 10,
});

mockModule("services/auth/refreshTokenService.js", {
  createRefreshToken: async () => ({ expiresAt: new Date("2026-03-16T12:00:00.000Z") }),
  rotateRefreshToken: async () => null,
  revokeAllUserRefreshTokens: async () => null,
  revokeRefreshTokenByRaw: async () => null,
});

mockModule("services/auditService.js", {
  createAuditLog: async () => null,
});

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({
    score: 37,
    level: "MEDIUM",
    reasons: ["Known device"],
  }),
});

mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => mfaStatus,
  createAdminMfaChallenge: async () => {
    createdChallengeCount += 1;
    return {
      ticket: "mfa-ticket",
      expiresAt: new Date("2026-03-16T12:05:00.000Z"),
    };
  },
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
  role: UserRole.SUPER_ADMIN,
  licenseeId: null,
  orgId: null,
  failedLoginAttempts: 0,
  lockedUntil: null,
  deletedAt: null,
  disabledAt: null,
  isActive: true,
  status: "ACTIVE",
  licensee: null,
};

const run = async () => {
  prismaUser = { ...baseUser, role: UserRole.PLATFORM_SUPER_ADMIN };
  mfaStatus = {
    enrolled: false,
    enabled: false,
    verifiedAt: null,
    lastUsedAt: null,
    backupCodesRemaining: 0,
    createdAt: null,
    updatedAt: null,
  };

  const setupResult = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
  });

  assert.strictEqual(setupResult.mfaSetupRequired, true, "privileged roles should be forced into MFA setup");
  assert.strictEqual(setupResult.mfaSetupToken, "bootstrap-ticket", "bootstrap token should be returned");

  prismaUser = { ...baseUser, role: UserRole.MANUFACTURER_ADMIN };
  mfaStatus = {
    enrolled: true,
    enabled: true,
    verifiedAt: new Date("2026-03-15T10:00:00.000Z"),
    lastUsedAt: new Date("2026-03-15T10:00:00.000Z"),
    backupCodesRemaining: 6,
    createdAt: new Date("2026-03-15T10:00:00.000Z"),
    updatedAt: new Date("2026-03-15T10:00:00.000Z"),
  };

  const challengeResult = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
  });

  assert.strictEqual(challengeResult.mfaRequired, true, "enrolled privileged roles should receive MFA challenge");
  assert.strictEqual(challengeResult.mfaTicket, "mfa-ticket", "challenge ticket should be returned");
  assert.strictEqual(createdChallengeCount, 1, "MFA challenge should have been created once");

  console.log("auth MFA enforcement tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

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
let rotateRefreshTokenResult = null;
let passwordOnlyRefreshRevokeCount = 0;

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
  signMfaBootstrapToken: () => "bootstrap-token",
  getMfaBootstrapTtlMinutes: () => 10,
});

mockModule("services/auth/refreshTokenService.js", {
  createRefreshToken: async () => ({
    row: { id: "session-1" },
    expiresAt: new Date("2026-03-16T12:00:00.000Z"),
  }),
  rotateRefreshToken: async () => rotateRefreshTokenResult,
  revokeAllUserRefreshTokens: async () => null,
  revokePasswordOnlyRefreshTokensForUser: async () => {
    passwordOnlyRefreshRevokeCount += 1;
  },
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

mockModule("services/auth/emailVerificationService.js", {
  isVerifiedAccount: () => true,
});

let mockedMfaStatus = { enabled: false, enrolled: false, methods: [], preferredMethod: null, lastUsedAt: null };
mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => mockedMfaStatus,
  createAdminMfaChallenge: async () => null,
});

const { loginWithPassword, refreshSession } = require("../dist/services/auth/authService");

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

  assert.strictEqual(result.sessionStage, "MFA_BOOTSTRAP", "manufacturer password login should require MFA setup");
  assert.strictEqual(result.accessToken, "bootstrap-token", "login should issue only an MFA bootstrap token");
  assert.strictEqual(result.refreshToken, null, "login should not issue a refresh token before MFA");
  assert.ok(result.user, "login should return the authenticated user");
  assert.strictEqual(result.auth?.mfaRequired, true, "manufacturer MFA should be required");
  assert.strictEqual(result.auth?.mfaEnrolled, false, "unenrolled manufacturer should be sent to MFA setup");
  assert.strictEqual(result.auth?.authAssurance, "PASSWORD", "bootstrap remains password-only until MFA is completed");

  mockedMfaStatus = {
    enabled: true,
    enrolled: true,
    methods: ["TOTP"],
    preferredMethod: "TOTP",
    lastUsedAt: new Date(),
  };
  const enrolledResult = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
  });

  assert.strictEqual(enrolledResult.sessionStage, "MFA_BOOTSTRAP", "manufacturer logout/login should require MFA challenge even when MFA was used recently");
  assert.strictEqual(enrolledResult.refreshToken, null, "manufacturer challenge session must not issue refresh before MFA");
  assert.strictEqual(enrolledResult.auth?.mfaEnrolled, true, "enrolled manufacturer should enter challenge mode");

  rotateRefreshTokenResult = {
    ok: true,
    userId: prismaUser.id,
    orgId: prismaUser.orgId,
    newRawToken: "rotated-password-only-refresh",
    newExpiresAt: new Date("2026-03-16T12:00:00.000Z"),
    authenticatedAt: new Date("2026-03-16T11:00:00.000Z"),
    mfaVerifiedAt: null,
  };
  passwordOnlyRefreshRevokeCount = 0;

  const refreshed = await refreshSession({
    rawRefreshToken: "legacy-password-only-refresh",
    ipHash: "ip-hash",
    userAgent: "agent",
  });

  assert.strictEqual(refreshed.ok, true, "valid legacy refresh should convert into a bootstrap session");
  assert.strictEqual(refreshed.sessionStage, "MFA_BOOTSTRAP", "password-only manufacturer refresh must not mint an active session");
  assert.strictEqual(refreshed.accessToken, "bootstrap-token", "refresh should issue only an MFA bootstrap token");
  assert.strictEqual(refreshed.refreshToken, null, "refresh bootstrap must not keep a password-only refresh token");
  assert.strictEqual(refreshed.auth?.authAssurance, "PASSWORD", "bootstrap remains password-only until MFA succeeds");
  assert.strictEqual(refreshed.auth?.stepUpRequired, true, "converted refresh must require MFA step-up");
  assert.strictEqual(passwordOnlyRefreshRevokeCount, 1, "password-only refresh tokens should be revoked on conversion");

  console.log("manufacturer MFA login bootstrap tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

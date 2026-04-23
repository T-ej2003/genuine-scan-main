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

const now = new Date("2026-04-10T12:00:00.000Z");
process.env.ADMIN_LOGIN_MFA_CYCLE_DAYS = "28";

let prismaUser = null;
let auditEvents = [];

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
    expiresAt: new Date("2026-05-01T12:00:00.000Z"),
  }),
  rotateRefreshToken: async () => null,
  revokeAllUserRefreshTokens: async () => null,
  revokeRefreshTokenByRaw: async () => null,
});

mockModule("services/auditService.js", {
  createAuditLog: async (entry) => {
    auditEvents.push(entry);
    return null;
  },
});

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({
    score: 10,
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

let mockedMfaStatus = {
  enabled: true,
  lastUsedAt: new Date("2026-04-01T10:00:00.000Z"),
};
mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => mockedMfaStatus,
});

const { loginWithPassword } = require("../dist/services/auth/authService");

const baseUser = {
  id: "admin-1",
  email: "admin@example.com",
  name: "Admin",
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
  emailVerifiedAt: new Date("2026-04-01T09:00:00.000Z"),
  licensee: null,
};

const run = async () => {
  prismaUser = { ...baseUser };
  auditEvents = [];
  const realNow = Date.now;
  Date.now = () => now.getTime();
  try {
    const recentMfaSession = await loginWithPassword({
      email: prismaUser.email,
      password: "correct-password",
      ipHash: "ip-hash",
      userAgent: "agent",
    });

    assert.strictEqual(recentMfaSession.sessionStage, "ACTIVE", "recent MFA should skip bootstrap challenge");
    assert.strictEqual(recentMfaSession.auth?.authAssurance, "ADMIN_MFA");
    assert.strictEqual(
      String(recentMfaSession.auth?.mfaVerifiedAt || "").startsWith("2026-04-01T10:00:00.000Z"),
      true,
      "session should carry the previous verified-at timestamp when login MFA is still fresh"
    );
    assert(
      auditEvents.some((entry) => entry?.action === "AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA"),
      "recent MFA login should emit dedicated audit action"
    );

    mockedMfaStatus = {
      enabled: true,
      lastUsedAt: new Date("2026-02-01T10:00:00.000Z"),
    };
    auditEvents = [];
    const staleMfaSession = await loginWithPassword({
      email: prismaUser.email,
      password: "correct-password",
      ipHash: "ip-hash",
      userAgent: "agent",
    });

    assert.strictEqual(staleMfaSession.sessionStage, "MFA_BOOTSTRAP", "stale MFA should require a fresh challenge");
    assert.strictEqual(staleMfaSession.auth?.stepUpMethod, "ADMIN_MFA");
    assert(
      auditEvents.some((entry) => entry?.action === "AUTH_LOGIN_MFA_CHALLENGE_REQUIRED"),
      "stale MFA login should emit challenge-required audit action"
    );
  } finally {
    Date.now = realNow;
  }

  console.log("admin login MFA cycle tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

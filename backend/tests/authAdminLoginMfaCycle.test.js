const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
process.env.NODE_ENV = "test";

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

process.env.ADMIN_LOGIN_MFA_CYCLE_DAYS = "28";

let prismaUser = null;
let auditEvents = [];
let riskWrites = [];

const prismaMock = {
  user: {
    findUnique: async () => prismaUser,
    update: async () => prismaUser,
  },
  $transaction: async (callback) => callback({
    user: {
      findUnique: async () => prismaUser,
      update: async () => prismaUser,
    },
    $executeRaw: async () => null,
  }),
};

mockModule("config/database.js", {
  __esModule: true,
  default: prismaMock,
});

mockModule("services/auth/authBootstrapRepository.js", {
  lookupPasswordBootstrapUser: async () => prismaUser,
  recordPasswordLoginFailure: async () => null,
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
    tokenHash: "a".repeat(64),
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

mockModule("services/auditLogOutboxService.js", {
  queueAuditLogOutbox: async (entry) => {
    auditEvents.push(entry);
    return "audit-outbox-1";
  },
});

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => {
    if (failMfaStatusRead) throw new Error("MFA_STATUS_UNAVAILABLE");
    return {
      score: 10,
      riskLevel: "LOW",
      reasons: ["Known device"],
      shouldBlock: false,
      actorState: {
        userId: prismaUser.id, email: prismaUser.email, name: prismaUser.name, role: prismaUser.role,
        legacyLicenseeId: null, legacyOrganizationId: null, emailVerifiedAt: prismaUser.emailVerifiedAt,
        sessionLicenseeId: null, sessionOrganizationId: null, scopeVersion: null,
        selectedLicenseeId: null, selectedLicenseeName: null, selectedLicenseePrefix: null,
        selectedLicenseeBrandName: null, selectedLicenseeOrganizationId: null, linkedLicensees: [],
        mfaRequired: true, mfaEnabled: mockedMfaStatus.enabled, mfaEnrolled: mockedMfaStatus.enabled,
        mfaLastUsedAt: mockedMfaStatus.lastUsedAt, mfaMethods: ["TOTP"], mfaPreferredMethod: "TOTP",
      },
    };
  },
  persistAuthSessionRisk: async (input) => {
    riskWrites.push(input);
    return { recorded: true, challengeCreated: Boolean(input.challenge) };
  },
});

mockModule("services/manufacturerScopeService.js", {
  resolveManufacturerSessionScope: async () => ({ selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] }),
});

mockModule("services/auth/emailVerificationService.js", {
  isVerifiedAccount: () => true,
});

let mockedMfaStatus = {
  enabled: true,
  lastUsedAt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
};
let failMfaStatusRead = false;
mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => {
    if (failMfaStatusRead) throw new Error("MFA_STATUS_UNAVAILABLE");
    return mockedMfaStatus;
  },
  createAdminMfaChallenge: async () => ({
    ticket: "mfa-ticket",
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
  }),
});
mockModule("services/auth/authenticatedSessionCapabilityService.js", {
  createAuthenticatedSessionCapability: async () => ({ rawCapability: "database-capability" }),
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
  riskWrites = [];
  const recentMfaLastUsedAt = mockedMfaStatus.lastUsedAt;
  const recentMfaSession = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
    requestId: "recent-admin-mfa-login",
  });

  assert.strictEqual(recentMfaSession.sessionStage, "ACTIVE", "recent MFA should skip bootstrap challenge");
  assert.strictEqual(recentMfaSession.auth?.authAssurance, "ADMIN_MFA");
  assert.strictEqual(
    recentMfaSession.auth?.mfaVerifiedAt,
    recentMfaLastUsedAt.toISOString(),
    "session should carry the previous verified-at timestamp when login MFA is still fresh"
  );
  assert.equal(riskWrites.length, 1, "recent MFA login should record one database-bound risk result");

  mockedMfaStatus = {
    enabled: true,
    lastUsedAt: new Date(Date.now() - 60 * 24 * 60 * 60 * 1000),
  };
  auditEvents = [];
  riskWrites = [];
  const staleMfaSession = await loginWithPassword({
    email: prismaUser.email,
    password: "correct-password",
    ipHash: "ip-hash",
    userAgent: "agent",
    requestId: "stale-admin-mfa-login",
  });

  assert.strictEqual(staleMfaSession.sessionStage, "MFA_BOOTSTRAP", "stale MFA should require a fresh challenge");
  assert.strictEqual(staleMfaSession.auth?.stepUpMethod, "ADMIN_MFA");
  assert(staleMfaSession.auth?.mfaChallenge?.ticket, "stale MFA login should return an opaque challenge ticket");
  assert(
    new Date(staleMfaSession.auth?.mfaChallenge?.expiresAt || 0).getTime() -
      new Date(staleMfaSession.auth?.authenticatedAt || 0).getTime() >= 60_000,
    "login response MFA challenge expiry should be at least 60 seconds after authenticatedAt"
  );
  assert.equal(riskWrites.length, 1);
  assert(riskWrites[0].challenge, "stale MFA login should create its challenge through the risk boundary");

  failMfaStatusRead = true;
  await assert.rejects(
    loginWithPassword({
      email: prismaUser.email,
      password: "correct-password",
      ipHash: "ip-hash",
      userAgent: "agent",
      requestId: "failed-admin-mfa-status-read",
    }),
    /MFA_STATUS_UNAVAILABLE/,
    "MFA status failures must not be converted into an unenrolled bootstrap session"
  );

  console.log("admin login MFA cycle tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

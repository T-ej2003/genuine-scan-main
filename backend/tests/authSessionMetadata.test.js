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

let prismaUser = null;
const prismaMock = {
  user: {
    findUnique: async () => prismaUser,
  },
};

mockModule("config/database.js", {
  __esModule: true,
  default: prismaMock,
});

mockModule("services/auth/passwordService.js", {
  verifyPassword: async () => true,
  hashPassword: async () => "hashed",
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
    expiresAt: new Date("2026-04-01T12:00:00.000Z"),
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
    score: 0,
    riskLevel: "LOW",
    reasons: [],
    shouldBlock: false,
  }),
});

mockModule("services/manufacturerScopeService.js", {
  resolveManufacturerSessionScope: async () => {
    const selectedLicensee = {
      id: "licensee-1",
      name: "Licensee",
      prefix: "AADS",
      brandName: "MSCQR",
      orgId: "org-1",
      isPrimary: true,
      scopeVersion: "2026-03-01T00:00:00.000Z",
    };
    return { selectedLicensee, linkedLicensees: [selectedLicensee], linkedLicenseeIds: [selectedLicensee.id] };
  },
});

mockModule("services/auth/emailVerificationService.js", {
  isVerifiedAccount: () => true,
});

mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => ({ enabled: true, enrolled: true }),
});

const { issueSessionForUser } = require("../dist/services/auth/authService");

const run = async () => {
  prismaUser = {
    id: "manufacturer-1",
    email: "manufacturer@example.com",
    name: "Manufacturer",
    role: UserRole.MANUFACTURER,
    licenseeId: "licensee-1",
    orgId: "org-1",
    emailVerifiedAt: new Date("2026-03-01T00:00:00.000Z"),
    deletedAt: null,
    disabledAt: null,
    isActive: true,
    status: "ACTIVE",
    licensee: {
      id: "licensee-1",
      name: "Licensee",
      prefix: "AADS",
      brandName: "MSCQR",
      orgId: "org-1",
    },
  };

  const session = await issueSessionForUser({
    userId: prismaUser.id,
    ipHash: "ip-hash",
    userAgent: "Chrome on macOS",
    authAssurance: "PASSWORD",
    authenticatedAt: new Date("2026-03-28T10:00:00.000Z"),
    now: new Date("2026-03-28T10:00:00.000Z"),
  }, prismaMock);

  assert.strictEqual(session.sessionId, "session-1");
  assert.strictEqual(session.auth.sessionId, "session-1");
  assert.strictEqual(session.auth.stepUpMethod, "ADMIN_MFA");
  assert.strictEqual(session.auth.mfaRequired, true);
  assert.strictEqual(session.auth.sessionExpiresAt, "2026-04-01T12:00:00.000Z");

  prismaUser = {
    ...prismaUser,
    id: "admin-1",
    email: "admin@example.com",
    role: UserRole.SUPER_ADMIN,
    licenseeId: null,
    orgId: null,
    licensee: null,
  };

  const adminSession = await issueSessionForUser({
    userId: prismaUser.id,
    ipHash: "ip-hash",
    userAgent: "Chrome on macOS",
    authAssurance: "ADMIN_MFA",
    authenticatedAt: new Date("2026-03-28T10:00:00.000Z"),
    mfaVerifiedAt: new Date("2026-03-28T10:00:00.000Z"),
    now: new Date("2026-03-28T10:00:00.000Z"),
  }, prismaMock);

  assert.strictEqual(adminSession.auth.stepUpMethod, "ADMIN_MFA");

  console.log("auth session metadata tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

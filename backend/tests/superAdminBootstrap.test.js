const assert = require("assert");
const path = require("path");
const { UserRole, UserStatus } = require("@prisma/client");

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

let users = [];
let auditEvents = [];
let updateCalls = 0;

const cloneUser = (user) => (user ? { ...user, licensee: user.licensee || null } : null);

const userStore = {
  findFirst: async ({ where } = {}) => {
    if (where?.role?.in) {
      return cloneUser(users.find((user) => where.role.in.includes(user.role) && user.deletedAt === null));
    }
    return cloneUser(users[0] || null);
  },
  findUnique: async ({ where } = {}) => {
    if (where?.email) return cloneUser(users.find((user) => user.email === where.email) || null);
    if (where?.id) return cloneUser(users.find((user) => user.id === where.id) || null);
    return null;
  },
  create: async ({ data, select } = {}) => {
    if (users.some((user) => user.email === data.email)) {
      throw new Error("Unique constraint failed on email");
    }
    const created = {
      id: `user-${users.length + 1}`,
      name: data.name,
      email: data.email,
      role: data.role,
      passwordHash: data.passwordHash,
      status: data.status || UserStatus.ACTIVE,
      isActive: data.isActive !== false,
      deletedAt: data.deletedAt ?? null,
      disabledAt: data.disabledAt ?? null,
      licenseeId: data.licenseeId ?? null,
      orgId: data.orgId ?? null,
      failedLoginAttempts: 0,
      lockedUntil: null,
      emailVerifiedAt: data.emailVerifiedAt ?? null,
      createdAt: new Date("2026-04-01T00:00:00.000Z"),
      licensee: null,
    };
    users.push(created);
    if (!select) return cloneUser(created);
    return Object.fromEntries(Object.keys(select).map((key) => [key, created[key]]));
  },
  update: async ({ where, data } = {}) => {
    updateCalls += 1;
    const index = users.findIndex((user) => user.id === where.id || user.email === where.email);
    assert(index >= 0, "update target should exist");
    users[index] = { ...users[index], ...data };
    return cloneUser(users[index]);
  },
};

const prismaMock = {
  user: userStore,
  $transaction: async (callback) =>
    callback({
      user: userStore,
      $executeRaw: async () => null,
    }),
};

mockModule("config/database.js", {
  __esModule: true,
  default: prismaMock,
});

mockModule("services/auth/passwordService.js", {
  hashPassword: async (password) => `argon2:${password}`,
  verifyPassword: async (storedHash, password) => storedHash === `argon2:${password}` || storedHash === "hash",
  shouldRehashPassword: () => false,
});

mockModule("services/auditService.js", {
  createAuditLog: async (entry) => {
    auditEvents.push(entry);
    return entry;
  },
  createAuditLogSafely: async (entry) => {
    auditEvents.push(entry);
    return { persisted: true, queued: false, log: entry, outboxId: null };
  },
});

mockModule("utils/logger.js", {
  logger: {
    debug: () => null,
    info: () => null,
    warn: () => null,
    error: () => null,
  },
});

mockModule("services/auth/tokenService.js", {
  signAccessToken: () => "access-token",
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

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({
    score: 5,
    riskLevel: "LOW",
    reasons: ["test"],
    shouldBlock: false,
  }),
});

mockModule("services/manufacturerScopeService.js", {
  listManufacturerLicenseeLinks: async () => [],
  normalizeLinkedLicensees: (links) => links,
});

mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => ({ enabled: false, enrolled: false, methods: [], preferredMethod: null, lastUsedAt: null }),
});

const { bootstrapConfiguredSuperAdmin } = require("../dist/services/auth/superAdminBootstrapService");
const { loginWithPassword } = require("../dist/services/auth/authService");

const resetEnv = () => {
  delete process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED;
  delete process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD;
  delete process.env.SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY;
  delete process.env.SUPER_ADMIN_EMAIL;
  delete process.env.SUPER_ADMIN_NAME;
};

const resetState = () => {
  users = [];
  auditEvents = [];
  updateCalls = 0;
  resetEnv();
};

const run = async () => {
  resetState();
  process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "true";
  process.env.SUPER_ADMIN_EMAIL = " Root.Admin@Example.com ";
  process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD = "correct horse battery staple";
  process.env.SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY = "true";

  const created = await bootstrapConfiguredSuperAdmin();
  assert.strictEqual(created.status, "created", "fresh DB should create a super admin");
  assert.strictEqual(users.length, 1, "fresh bootstrap should create exactly one user");
  assert.strictEqual(users[0].email, "root.admin@example.com", "bootstrap email should be normalized");
  assert.strictEqual(users[0].role, UserRole.SUPER_ADMIN);
  assert.ok(users[0].emailVerifiedAt instanceof Date, "auto-verify should mark only the bootstrap account verified");
  assert.strictEqual(users[0].passwordHash, "argon2:correct horse battery staple");
  assert(auditEvents.some((entry) => entry.action === "AUTH_SUPER_ADMIN_BOOTSTRAPPED"));

  const loginResult = await loginWithPassword({
    email: "root.admin@example.com",
    password: "correct horse battery staple",
    ipHash: "ip",
    userAgent: "ua",
  });
  assert.strictEqual(loginResult.sessionStage, "MFA_BOOTSTRAP", "bootstrap super admin should pass email gate and enter admin MFA setup");

  const repeated = await bootstrapConfiguredSuperAdmin();
  assert.strictEqual(repeated.status, "skipped_existing", "repeated startup should skip existing super admin");
  assert.strictEqual(users.length, 1, "repeated startup should not create duplicate super admins");

  resetState();
  process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "false";
  process.env.SUPER_ADMIN_EMAIL = "root.admin@example.com";
  process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD = "correct horse battery staple";
  const disabled = await bootstrapConfiguredSuperAdmin();
  assert.strictEqual(disabled.status, "disabled", "disabled bootstrap should not create a user");
  assert.strictEqual(users.length, 0);

  resetState();
  users.push({
    id: "licensee-1",
    email: "root.admin@example.com",
    name: "Existing User",
    role: UserRole.LICENSEE_ADMIN,
    passwordHash: "hash",
    status: UserStatus.ACTIVE,
    isActive: true,
    deletedAt: null,
    disabledAt: null,
    licenseeId: null,
    orgId: null,
    failedLoginAttempts: 0,
    lockedUntil: null,
    emailVerifiedAt: new Date("2026-04-01T00:00:00.000Z"),
    createdAt: new Date("2026-04-01T00:00:00.000Z"),
    licensee: null,
  });
  process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED = "true";
  process.env.SUPER_ADMIN_EMAIL = "root.admin@example.com";
  process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD = "correct horse battery staple";
  process.env.SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY = "true";
  const blocked = await bootstrapConfiguredSuperAdmin();
  assert.strictEqual(blocked.status, "blocked", "bootstrap must not promote a non-super-admin email");
  assert.strictEqual(users[0].role, UserRole.LICENSEE_ADMIN, "non-configured privilege escalation must not occur");

  resetState();
  users.push({
    id: "normal-1",
    email: "user@example.com",
    name: "Normal User",
    role: UserRole.MANUFACTURER,
    passwordHash: "hash",
    status: UserStatus.ACTIVE,
    isActive: true,
    deletedAt: null,
    disabledAt: null,
    licenseeId: null,
    orgId: null,
    failedLoginAttempts: 0,
    lockedUntil: null,
    emailVerifiedAt: null,
    createdAt: new Date("2026-04-01T00:00:00.000Z"),
    licensee: null,
  });

  await assert.rejects(
    () =>
      loginWithPassword({
        email: "user@example.com",
        password: "anything",
        ipHash: "ip",
        userAgent: "ua",
      }),
    /Verify your email before signing in/,
    "normal users should still require normal verification"
  );
  assert.strictEqual(updateCalls, 0, "unverified users should be rejected before password mutation");

  console.log("super admin bootstrap tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

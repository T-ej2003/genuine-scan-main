const assert = require("node:assert/strict");
const { randomBytes } = require("node:crypto");
const path = require("node:path");
const { UserRole, UserStatus } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = { id: resolved, filename: resolved, loaded: true, exports: exportsValue };
};

process.env.AUTH_MAX_LOGIN_ATTEMPTS = "2";
process.env.AUTH_LOCKOUT_MINUTES = "15";

const validPassword = randomBytes(32).toString("base64url");
let wrongPassword;
do wrongPassword = randomBytes(32).toString("base64url"); while (wrongPassword === validPassword);

let user = null;
let rehash = false;
let verifyError = null;
let failureError = null;
let transactionCalls = 0;
let contextWrites = 0;
const updates = [];
const auditLogs = [];
const baseUser = () => ({
  id: "manufacturer-1",
  email: "maker@example.com",
  passwordHash: "valid-hash",
  name: "Maker",
  role: UserRole.MANUFACTURER,
  licenseeId: null,
  orgId: null,
  status: UserStatus.ACTIVE,
  isActive: true,
  disabledAt: null,
  deletedAt: null,
  failedLoginAttempts: 0,
  lockedUntil: null,
  lastLoginAt: null,
  emailVerifiedAt: new Date("2026-07-01T00:00:00.000Z"),
  licensee: null,
});

const userStore = {
  findUnique: async () => user,
  update: async ({ data }) => {
    updates.push(data);
    user = { ...user, ...data };
    return user;
  },
};
const tx = { user: userStore, $executeRaw: async () => { contextWrites += 1; } };

mockModule("config/database.js", {
  __esModule: true,
  default: { user: userStore, $transaction: async (callback) => {
    transactionCalls += 1;
    return callback(tx);
  } },
});
mockModule("services/auth/authBootstrapRepository.js", {
  lookupPasswordBootstrapUser: async (email) => (user?.email === email ? user : null),
  recordPasswordLoginFailure: async ({ maxAttempts, lockoutMinutes, attemptedAt }) => {
    if (failureError) throw failureError;
    if (!user) return null;
    const failedLoginAttempts = user.failedLoginAttempts + 1;
    const lockedUntil = failedLoginAttempts >= maxAttempts
      ? new Date(attemptedAt.getTime() + lockoutMinutes * 60_000)
      : null;
    user = { ...user, failedLoginAttempts, lockedUntil };
    return { failedLoginAttempts, lockedUntil };
  },
});
mockModule("services/auth/passwordService.js", {
  verifyPassword: async (_hash, password) => {
    if (verifyError) throw verifyError;
    return password === validPassword;
  },
  hashPassword: async () => "upgraded-hash",
  shouldRehashPassword: () => rehash,
});
mockModule("services/auth/tokenService.js", {
  signAccessToken: () => "access-token",
  newRefreshToken: () => "refresh-token",
  signMfaBootstrapToken: () => "bootstrap-token",
  getMfaBootstrapTtlMinutes: () => 10,
});
mockModule("services/auth/refreshTokenService.js", {
  createRefreshToken: async () => ({ row: { id: "session-1" }, expiresAt: new Date(Date.now() + 60_000) }),
  rotateRefreshToken: async () => null,
  revokeAllUserRefreshTokens: async () => null,
  revokePasswordOnlyRefreshTokensForUser: async () => null,
  revokeRefreshTokenByRaw: async () => null,
});
mockModule("services/auditService.js", { createAuditLog: async (entry) => { auditLogs.push(entry); } });
mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({ score: 0, riskLevel: "LOW", reasons: [], shouldBlock: false }),
});
mockModule("services/manufacturerScopeService.js", {
  resolveManufacturerSessionScope: async () => ({ selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] }),
});
mockModule("services/auth/emailVerificationService.js", {
  isVerifiedAccount: (candidate) => Boolean(candidate.emailVerifiedAt),
});
mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => ({ enabled: false, enrolled: false, methods: [], preferredMethod: null, lastUsedAt: null }),
  createAdminMfaChallenge: async () => null,
});

const { loginWithPassword } = require("../dist/services/auth/authService");
const login = (email, password) => loginWithPassword({ email, password, ipHash: "ip", userAgent: "ua" });
const errorMessage = async (promise) => {
  try {
    await promise;
  } catch (error) {
    return error.message;
  }
  assert.fail("Expected login to fail");
};

const run = async () => {
  user = null;
  transactionCalls = 0;
  contextWrites = 0;
  auditLogs.length = 0;
  const unknown = await errorMessage(login("missing@example.com", wrongPassword));
  const unknownAudit = auditLogs.at(-1);
  assert.equal(transactionCalls, 0, "unknown users must not establish authenticated context");

  user = baseUser();
  const wrong = await errorMessage(login(user.email, wrongPassword));
  const wrongAudit = auditLogs.at(-1);
  assert.equal(wrong, unknown, "wrong password and unknown email must remain indistinguishable");
  assert.deepEqual(wrongAudit, unknownAudit, "wrong-password and unknown-email audit records must remain indistinguishable");
  assert.equal(user.failedLoginAttempts, 1);
  await assert.rejects(login(user.email, wrongPassword), /Invalid email or password/);
  assert.equal(user.failedLoginAttempts, 2);
  assert.ok(user.lockedUntil instanceof Date, "max failures must lock the account");
  assert.equal(transactionCalls, 0, "wrong passwords must not establish authenticated context");

  const scenarios = [
    [{ isActive: false }, /Account is disabled/],
    [{ status: "DISABLED" }, /Account is disabled/],
    [{ emailVerifiedAt: null }, /Verify your email/],
    [{ passwordHash: null }, /Account not activated/],
    [{ lockedUntil: new Date(Date.now() + 60_000) }, /Account temporarily locked/],
  ];
  for (const [overrides, expected] of scenarios) {
    user = { ...baseUser(), ...overrides };
    transactionCalls = 0;
    await assert.rejects(login(user.email, validPassword), expected);
    assert.equal(transactionCalls, 0, `${expected} must not establish authenticated context`);
  }

  user = baseUser();
  verifyError = new Error("verification unavailable");
  transactionCalls = 0;
  await assert.rejects(login(user.email, validPassword), /verification unavailable/);
  assert.equal(transactionCalls, 0, "password verifier exceptions must not establish authenticated context");
  verifyError = null;

  user = baseUser();
  failureError = new Error("failure counter unavailable");
  transactionCalls = 0;
  await assert.rejects(login(user.email, wrongPassword), /failure counter unavailable/);
  assert.equal(transactionCalls, 0, "failure-counter exceptions must not establish authenticated context");
  failureError = null;

  user = { ...baseUser(), failedLoginAttempts: 1 };
  rehash = true;
  updates.length = 0;
  transactionCalls = 0;
  contextWrites = 0;
  const result = await login(user.email, validPassword);
  assert.equal(result.sessionStage, "MFA_BOOTSTRAP");
  assert.equal(user.failedLoginAttempts, 0);
  assert.equal(user.lockedUntil, null);
  assert.ok(user.lastLoginAt instanceof Date);
  assert.equal(user.passwordHash, "upgraded-hash");
  assert.equal(updates.length, 1, "successful auth state must update once inside verified context");
  assert.equal(transactionCalls, 2, "verified login uses transaction-local context for update and MFA bootstrap");
  assert.equal(contextWrites, 12, "each verified transaction establishes all six local context settings");

  console.log("auth RLS bootstrap unit tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

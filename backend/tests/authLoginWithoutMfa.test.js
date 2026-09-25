const assert = require("assert");
const path = require("path");
const { UserRole } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

process.env.NODE_ENV = "test";
process.env.TOKEN_HASH_SECRET_CURRENT = "test-refresh-mfa-token-hash-secret";

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
let refreshDecision = null;
let riskStepUp = false;
let riskBlock = false;
const riskWrites = [];

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
    expiresAt: new Date("2026-03-16T12:00:00.000Z"),
    tokenHash: "refresh-token-hash",
  }),
  rotateRefreshToken: async (input) => {
    refreshDecision = await input.decide({
      tx: prismaMock,
      token: {
        id: "legacy-session",
        userId: prismaUser.id,
        orgId: prismaUser.orgId,
        expiresAt: new Date("2026-03-17T12:00:00.000Z"),
        revokedAt: null,
        replacedByTokenHash: null,
        authenticatedAt: new Date("2026-03-16T11:00:00.000Z"),
        mfaVerifiedAt: null,
      },
      now: new Date("2026-03-16T12:00:00.000Z"),
      tokenHashCandidates: ["legacy-token-hash"],
    });
    assert.strictEqual(refreshDecision.action, "rotate");
    const successor = {
      id: "bootstrap-session-2",
      expiresAt: refreshDecision.expiresAt || new Date("2026-03-17T12:00:00.000Z"),
      tokenHash: "bootstrap-refresh-hash",
    };
    const rotation = await input.afterRotate({
      tx: prismaMock,
      predecessor: { mfaVerifiedAt: null },
      successor,
      now: new Date("2026-03-16T12:00:00.000Z"),
      value: refreshDecision.value,
    });
    return {
      ok: true,
      rotated: true,
      userId: prismaUser.id,
      orgId: refreshDecision.orgId,
      newRawToken: "unreturned-bootstrap-refresh",
      newTokenId: successor.id,
      newTokenHash: successor.tokenHash,
      newExpiresAt: successor.expiresAt,
      authenticatedAt: refreshDecision.authenticatedAt,
      mfaVerifiedAt: null,
      value: refreshDecision.value,
      rotation,
    };
  },
  revokeAllUserRefreshTokens: async () => null,
  revokeRefreshTokenByRaw: async () => null,
});
mockModule("services/auth/authenticatedSessionCapabilityService.js", {
  createAuthenticatedSessionCapability: async (_db, input) => ({
    row: { id: input.refreshTokenId, expiresAt: input.expiresAt },
    rawCapability: "A".repeat(43),
  }),
});

mockModule("services/auditService.js", {
  createAuditLog: async () => null,
});

mockModule("services/auth/sessionRiskService.js", {
  assessAuthSessionRisk: async () => ({
    score: 12,
    riskLevel: "LOW",
    reasons: ["Known device"],
    shouldBlock: riskBlock,
    shouldStepUp: riskStepUp,
    actorState: {
      userId: prismaUser.id,
      email: prismaUser.email,
      name: prismaUser.name,
      role: prismaUser.role,
      legacyLicenseeId: prismaUser.licenseeId,
      legacyOrganizationId: prismaUser.orgId,
      emailVerifiedAt: prismaUser.emailVerifiedAt,
      sessionLicenseeId: null,
      sessionOrganizationId: null,
      scopeVersion: null,
      selectedLicenseeId: "licensee-1",
      selectedLicenseeName: "Local licensee",
      selectedLicenseePrefix: "LCL",
      selectedLicenseeBrandName: null,
      selectedLicenseeOrganizationId: "org-1",
      linkedLicensees: [{ id: "licensee-1", name: "Local licensee", prefix: "LCL", brandName: null, orgId: "org-1" }],
      mfaRequired: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.ORG_ADMIN].includes(prismaUser.role),
      mfaEnabled: mockedMfaStatus.enabled,
      mfaEnrolled: mockedMfaStatus.enrolled,
      mfaLastUsedAt: mockedMfaStatus.lastUsedAt,
      mfaMethods: mockedMfaStatus.methods,
      mfaPreferredMethod: mockedMfaStatus.preferredMethod,
    },
  }),
  persistAuthSessionRisk: async (input) => { riskWrites.push(input); },
});

mockModule("services/manufacturerScopeService.js", {
  resolveManufacturerSessionScope: async () => ({ selectedLicensee: null, linkedLicensees: [], linkedLicenseeIds: [] }),
});

mockModule("services/auth/emailVerificationService.js", {
  isVerifiedAccount: () => true,
});

let mockedMfaStatus = { enabled: false, enrolled: false, methods: [], preferredMethod: null, lastUsedAt: null };
mockModule("rls-waves/session-b/b01/sessionCredentialRepository.js", {
  loadRefreshSessionState: async () => ({
    userId: prismaUser.id,
    email: prismaUser.email,
    name: prismaUser.name,
    role: prismaUser.role,
    legacyLicenseeId: prismaUser.licenseeId,
    legacyOrganizationId: prismaUser.orgId,
    emailVerifiedAt: prismaUser.emailVerifiedAt,
    sessionLicenseeId: null,
    sessionOrganizationId: null,
    scopeVersion: null,
    selectedLicenseeId: "licensee-1",
    selectedLicenseeName: "Local licensee",
    selectedLicenseePrefix: "LCL",
    selectedLicenseeBrandName: null,
    selectedLicenseeOrganizationId: "org-1",
    linkedLicensees: [{ id: "licensee-1", name: "Local licensee", prefix: "LCL", brandName: null, orgId: "org-1" }],
    mfaRequired: [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.ORG_ADMIN].includes(prismaUser.role),
    mfaEnabled: mockedMfaStatus.enabled,
    mfaEnrolled: mockedMfaStatus.enrolled,
    mfaLastUsedAt: mockedMfaStatus.lastUsedAt,
    mfaMethods: mockedMfaStatus.methods,
    mfaPreferredMethod: mockedMfaStatus.preferredMethod,
  }),
  createRefreshMfaChallengeRecord: async () => ({ challengeId: "challenge-1", created: true }),
});
mockModule("services/auth/mfaService.js", {
  getAdminMfaStatus: async () => mockedMfaStatus,
  createAdminMfaChallenge: async () => null,
});

const { issueSessionAfterInviteActivation, loginWithPassword, refreshSession } = require("../dist/services/auth/authService");

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
  for (const role of [UserRole.LICENSEE_ADMIN, UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER]) {
    prismaUser = { ...baseUser, role, licenseeId: "licensee-1", orgId: "org-1" };
    for (const enabled of [false, true]) {
      mockedMfaStatus = { enabled, enrolled: enabled, methods: enabled ? ["TOTP"] : [], preferredMethod: enabled ? "TOTP" : null, lastUsedAt: enabled ? new Date() : null };
      const factorSnapshot = JSON.stringify(mockedMfaStatus);
      const result = await loginWithPassword({ email: prismaUser.email, password: "correct-password", ipHash: "ip-hash", userAgent: "agent", requestId: `login-${role}-${enabled}` });
      assert.strictEqual(result.sessionStage, "ACTIVE", `${role} must have a normal password session`);
      assert.strictEqual(result.auth?.authAssurance, "PASSWORD", `${role} must not claim ADMIN_MFA`);
      assert.strictEqual(result.auth?.mfaRequired, false, `${role} must not be forced to enroll or challenge`);
      assert.ok(result.refreshToken, `${role} must receive a refresh credential`);
      assert.strictEqual(JSON.stringify(mockedMfaStatus), factorSnapshot, `${role} existing factor state must remain unchanged`);
      refreshDecision = null;
      const refreshed = await refreshSession({ rawRefreshToken: "password-refresh", ipHash: "ip-hash", userAgent: "agent", requestId: `refresh-${role}-${enabled}` });
      assert.strictEqual(refreshed.ok, true);
      assert.strictEqual(refreshed.sessionStage, "ACTIVE", `${role} password refresh must remain active`);
      assert.strictEqual(refreshed.auth?.authAssurance, "PASSWORD");
      assert.ok(refreshed.refreshToken && !refreshed.auth?.stepUpRequired, `${role} refresh must not be converted to bootstrap`);
    }
  }

  for (const role of [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN, UserRole.ORG_ADMIN]) {
    prismaUser = { ...baseUser, role, licenseeId: role === UserRole.ORG_ADMIN ? "licensee-1" : null, orgId: role === UserRole.ORG_ADMIN ? "org-1" : null };
    mockedMfaStatus = { enabled: false, enrolled: false, methods: [], preferredMethod: null, lastUsedAt: null };
    const result = await loginWithPassword({ email: prismaUser.email, password: "correct-password", ipHash: "ip-hash", userAgent: "agent", requestId: `login-${role}` });
    assert.strictEqual(result.sessionStage, "MFA_BOOTSTRAP", `${role} must retain MFA enrollment`);
    assert.strictEqual(result.refreshToken, null, `${role} must not receive a normal refresh credential`);
    mockedMfaStatus = { enabled: true, enrolled: true, methods: ["TOTP"], preferredMethod: "TOTP", lastUsedAt: new Date() };
    const enrolled = await loginWithPassword({ email: prismaUser.email, password: "correct-password", ipHash: "ip-hash", userAgent: "agent", requestId: `login-enrolled-${role}` });
    assert.strictEqual(enrolled.sessionStage, "ACTIVE", `${role} enrolled login remains subject to the existing MFA freshness policy`);
    assert.strictEqual(enrolled.auth?.authAssurance, "ADMIN_MFA", `${role} must never receive a PASSWORD active session`);
  }

  prismaUser = { ...baseUser, role: UserRole.LICENSEE_ADMIN, licenseeId: "licensee-1", orgId: "org-1" };
  riskStepUp = true;
  riskWrites.length = 0;
  await assert.rejects(
    loginWithPassword({ email: prismaUser.email, password: "correct-password", ipHash: "ip-hash", userAgent: "agent", requestId: "risk-step-up-denial" }),
    /High-risk login blocked/
  );
  assert.equal(riskWrites.length, 1);
  assert.equal(riskWrites[0].blockedLogin, true, "risk step-up must commit through the audited denial path");
  riskStepUp = false;
  riskBlock = true;
  riskWrites.length = 0;
  await assert.rejects(
    loginWithPassword({ email: prismaUser.email, password: "correct-password", ipHash: "ip-hash", userAgent: "agent", requestId: "risk-block-denial" }),
    /High-risk login blocked/
  );
  assert.equal(riskWrites.length, 1);
  assert.equal(riskWrites[0].blockedLogin, true, "risk block must not depend on the step-up flag");
  riskBlock = false;

  for (const riskFlag of ["stepUp", "block"]) {
    riskStepUp = riskFlag === "stepUp";
    riskBlock = riskFlag === "block";
    riskWrites.length = 0;
    await assert.rejects(
      issueSessionAfterInviteActivation({ userId: prismaUser.id, email: prismaUser.email, role: prismaUser.role,
        ipHash: "ip-hash", userAgent: "agent", requestId: `activation-${riskFlag}-denial` }),
      /trusted network/
    );
    assert.equal(riskWrites.length, 1);
    assert.equal(riskWrites[0].blockedLogin, true, `activation ${riskFlag} denial must use the audited risk path`);
  }
  riskStepUp = false;
  riskBlock = false;

  console.log("temporary-role password login and privileged-role MFA policy tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

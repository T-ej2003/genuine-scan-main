const assert = require("assert");
const { createHmac, randomBytes } = require("crypto");

const {
  dropP2TestDatabase,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
} = require("./helpers/p2TestDb");

const enabled = process.env.MSCQR_AUTH_MFA_POSTGRES_TEST === "true";
const confirmed = process.env.MSCQR_AUTH_MFA_POSTGRES_CONFIRM === "MSCQR_RUN_LOCAL_AUTH_MFA_POSTGRES_TEST";

const assertSafeLocalAdminUrl = (raw) => {
  const parsed = new URL(String(raw || ""));
  const databaseName = decodeURIComponent(parsed.pathname.replace(/^\//, "")).toLowerCase();
  assert(["postgres:", "postgresql:"].includes(parsed.protocol), "MFA PostgreSQL proof requires PostgreSQL");
  assert(["127.0.0.1", "localhost", "::1"].includes(parsed.hostname), "MFA PostgreSQL proof requires loopback PostgreSQL");
  assert(
    databaseName === "mscqr_full_rls_admin" || databaseName === "mscqr_p2_admin_test",
    "MFA PostgreSQL proof requires an approved disposable administrative database"
  );
  assert(!/(prod|production|staging|amazonaws|rds)/i.test(raw), "MFA PostgreSQL proof refuses production or staging targets");
};

const base32Decode = (input) => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const character of input.toUpperCase().replace(/=+$/g, "")) {
    const index = alphabet.indexOf(character);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
};

const totp = (secret, atMs = Date.now()) => {
  const counter = Math.floor(atMs / 30_000);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac("sha1", base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const value =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(value % 1_000_000).padStart(6, "0");
};

const expectError = async (promise, pattern, message) => {
  let error = null;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  assert(error, message || `Expected rejection matching ${pattern}`);
  assert.match(String(error.message || error), pattern, message);
  return error;
};

const installAuditFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe(`
    CREATE OR REPLACE FUNCTION mscqr_test_reject_mfa_audit() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'MSCQR_TEST_AUDIT_REJECT';
    END;
    $$
  `);
  await prisma.$executeRawUnsafe(`
    CREATE TRIGGER mscqr_test_reject_mfa_audit
    BEFORE INSERT ON "AuditLogOutbox"
    FOR EACH ROW EXECUTE FUNCTION mscqr_test_reject_mfa_audit()
  `);
};

const removeAuditFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe('DROP TRIGGER IF EXISTS mscqr_test_reject_mfa_audit ON "AuditLogOutbox"');
  await prisma.$executeRawUnsafe("DROP FUNCTION IF EXISTS mscqr_test_reject_mfa_audit()");
};

const installBackupRotationFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe(`
    CREATE OR REPLACE FUNCTION mscqr_test_reject_backup_rotation() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW."backupCodesHash" IS DISTINCT FROM OLD."backupCodesHash" THEN
        RAISE EXCEPTION 'MSCQR_TEST_BACKUP_ROTATION_REJECT';
      END IF;
      RETURN NEW;
    END;
    $$
  `);
  await prisma.$executeRawUnsafe(`
    CREATE TRIGGER mscqr_test_reject_backup_rotation
    BEFORE UPDATE ON "AdminMfaCredential"
    FOR EACH ROW EXECUTE FUNCTION mscqr_test_reject_backup_rotation()
  `);
};

const removeBackupRotationFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe('DROP TRIGGER IF EXISTS mscqr_test_reject_backup_rotation ON "AdminMfaCredential"');
  await prisma.$executeRawUnsafe("DROP FUNCTION IF EXISTS mscqr_test_reject_backup_rotation()");
};

const installRefreshInsertFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe(`
    CREATE OR REPLACE FUNCTION mscqr_test_reject_refresh_insert() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
      RAISE EXCEPTION 'MSCQR_TEST_REFRESH_INSERT_REJECT';
    END;
    $$
  `);
  await prisma.$executeRawUnsafe(`
    CREATE TRIGGER mscqr_test_reject_refresh_insert
    BEFORE INSERT ON "RefreshToken"
    FOR EACH ROW EXECUTE FUNCTION mscqr_test_reject_refresh_insert()
  `);
};

const removeRefreshInsertFailureTrigger = async (prisma) => {
  await prisma.$executeRawUnsafe('DROP TRIGGER IF EXISTS mscqr_test_reject_refresh_insert ON "RefreshToken"');
  await prisma.$executeRawUnsafe("DROP FUNCTION IF EXISTS mscqr_test_reject_refresh_insert()");
};

const main = async () => {
  if (!enabled) {
    console.log("auth MFA PostgreSQL 18 proof skipped (set MSCQR_AUTH_MFA_POSTGRES_TEST=true)");
    return;
  }
  assert(confirmed, "Set MSCQR_AUTH_MFA_POSTGRES_CONFIRM=MSCQR_RUN_LOCAL_AUTH_MFA_POSTGRES_TEST");

  const adminUrl = String(process.env.MSCQR_AUTH_MFA_POSTGRES_ADMIN_URL || "").trim();
  assert(adminUrl, "Set MSCQR_AUTH_MFA_POSTGRES_ADMIN_URL to the disposable loopback PostgreSQL administrator URL");
  assertSafeLocalAdminUrl(adminUrl);

  process.env.NODE_ENV = "test";
  process.env.P2_TEST_DATABASE_URL = "";
  process.env.P2_TEST_DATABASE_ADMIN_URL = adminUrl;
  process.env.JWT_SECRET = process.env.JWT_SECRET || randomBytes(32).toString("hex");
  process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET;
  process.env.AUTH_COOKIE_SECRET_CURRENT = process.env.AUTH_COOKIE_SECRET_CURRENT || randomBytes(32).toString("hex");
  process.env.AUTH_MFA_ENCRYPTION_KEY = process.env.AUTH_MFA_ENCRYPTION_KEY || randomBytes(32).toString("hex");
  process.env.IP_HASH_SALT_CURRENT = process.env.IP_HASH_SALT_CURRENT || randomBytes(32).toString("hex");

  let databaseInfo = null;
  let prisma = null;
  let connectionA = null;
  let connectionB = null;

  try {
    databaseInfo = resolveP2TestDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);

    const { PrismaClient } = require("@prisma/client");
    const databaseModule = require("../dist/config/database");
    prisma = databaseModule.default || databaseModule;
    connectionA = new PrismaClient();
    connectionB = new PrismaClient();

    const {
      beginAdminMfaSetup,
      confirmAdminMfaSetup,
      createAdminMfaChallenge,
      getAdminMfaStatus,
      rotateAdminMfaBackupCodes,
      verifyAdminMfaCode,
    } = require("../dist/services/auth/mfaService");
    const { hashPassword } = require("../dist/services/auth/passwordService");
    const { hashBackupCode } = require("../dist/services/auth/backupCodeMfaProvider");
    const {
      confirmAdminMfaEnrollmentAndIssueSessionFromClaims,
      confirmAdminMfaReplacementFromClaims,
    } = require("../dist/services/auth/authClaimsRlsContext");
    const {
      completeAdminMfaChallengeController,
      disableAdminMfaController,
    } = require("../dist/controllers/authAdminSecurityController");

    const [{ versionNumber }] = await prisma.$queryRawUnsafe(
      "SELECT current_setting('server_version_num')::int AS \"versionNumber\""
    );
    assert(versionNumber >= 180000 && versionNumber < 190000, `Expected PostgreSQL 18, received ${versionNumber}`);

    const createUser = (label) => prisma.user.create({
      data: {
        email: `${label}-${randomBytes(5).toString("hex")}@example.test`,
        name: `MFA ${label}`,
        role: "SUPER_ADMIN",
        status: "ACTIVE",
        isActive: true,
        emailVerifiedAt: new Date(),
      },
    });
    const claimsFor = (user, sessionStage) => ({
      userId: user.id,
      email: user.email,
      role: user.role,
      orgId: null,
      licenseeId: null,
      linkedLicenseeIds: [],
      sessionId: `mfa-proof-${user.id}`,
      sessionStage,
      authAssurance: sessionStage === "ACTIVE" ? "ADMIN_MFA" : "PASSWORD",
      authenticatedAt: new Date(),
      mfaVerifiedAt: sessionStage === "ACTIVE" ? new Date() : null,
    });
    const invokeDisableController = async (claims, body) => {
      const response = { status: 200, body: null };
      const req = {
        user: claims,
        body,
        ip: "127.0.0.1",
        get: (name) => String(name).toLowerCase() === "user-agent" ? "postgres-18-proof" : "",
      };
      const res = {
        status(code) { response.status = code; return this; },
        json(payload) { response.body = payload; return this; },
        clearCookie() { return this; },
      };
      await disableAdminMfaController(req, res);
      return response;
    };
    const invokeMfaChallengeController = async (claims, body) => {
      const response = { status: 200, body: null, cookies: [] };
      const req = {
        user: claims,
        body,
        ip: "127.0.0.1",
        get: (name) => String(name).toLowerCase() === "user-agent" ? "postgres-18-proof" : "postgres-18-request",
      };
      const res = {
        status(code) { response.status = code; return this; },
        json(payload) { response.body = payload; return this; },
        cookie(name, value, options) { response.cookies.push({ name, value, options }); return this; },
        clearCookie() { return this; },
        setHeader() { return this; },
      };
      await completeAdminMfaChallengeController(req, res);
      return response;
    };

    const bootstrapUser = await createUser("bootstrap-atomicity");
    const bootstrapSetup = await beginAdminMfaSetup({
      userId: bootstrapUser.id,
      email: bootstrapUser.email,
      mode: "FIRST_ENROLLMENT",
    });
    await expectError(
      verifyAdminMfaCode({ userId: bootstrapUser.id, code: bootstrapSetup.backupCodes[0] }),
      /INVALID_MFA_CODE/,
      "pending backup codes must not authenticate"
    );
    await expectError(
      verifyAdminMfaCode({ userId: bootstrapUser.id, code: totp(bootstrapSetup.secret) }),
      /INVALID_MFA_CODE/,
      "pending TOTP must not authenticate"
    );

    await installAuditFailureTrigger(prisma);
    await expectError(
      confirmAdminMfaEnrollmentAndIssueSessionFromClaims(claimsFor(bootstrapUser, "MFA_BOOTSTRAP"), {
        code: totp(bootstrapSetup.secret),
        ipHash: "test-ip-hash",
        userAgent: "postgres-18-proof",
        now: new Date(),
      }),
      /MSCQR_TEST_AUDIT_REJECT/,
      "durable audit failure must abort first enrollment and session issuance"
    );
    assert.strictEqual((await prisma.adminMfaCredential.findUnique({ where: { userId: bootstrapUser.id } })).isEnabled, false);
    assert.strictEqual(await prisma.refreshToken.count({ where: { userId: bootstrapUser.id } }), 0);
    assert.strictEqual(await prisma.auditLogOutbox.count(), 0);
    assert.strictEqual(await prisma.userBackupCode.count({ where: { userId: bootstrapUser.id } }), 0);
    await removeAuditFailureTrigger(prisma);

    const bootstrapSession = await confirmAdminMfaEnrollmentAndIssueSessionFromClaims(
      claimsFor(bootstrapUser, "MFA_BOOTSTRAP"),
      {
        code: totp(bootstrapSetup.secret),
        ipHash: "test-ip-hash",
        userAgent: "postgres-18-proof",
        now: new Date(),
      }
    );
    assert.strictEqual(bootstrapSession.sessionStage, "ACTIVE");
    assert.strictEqual(await prisma.refreshToken.count({ where: { userId: bootstrapUser.id } }), 1);
    const enrollmentAudit = await prisma.auditLogOutbox.findFirst({ orderBy: { createdAt: "desc" } });
    assert.strictEqual(enrollmentAudit.payload.action, "AUTH_MFA_ENROLLED");

    const loginChallenge = await createAdminMfaChallenge({
      userId: bootstrapUser.id,
      sessionId: `mfa-proof-${bootstrapUser.id}`,
      purpose: "admin_login",
      riskScore: 10,
      riskLevel: "LOW",
      reasons: ["PostgreSQL 18 rollback proof"],
      ipHash: "test-ip-hash",
      userAgent: "postgres-18-proof",
    });
    const refreshCountBeforeLogin = await prisma.refreshToken.count({ where: { userId: bootstrapUser.id } });
    const auditCountBeforeLogin = await prisma.auditLogOutbox.count();
    const recoveryHash = hashBackupCode(bootstrapSetup.backupCodes[0]);
    await installRefreshInsertFailureTrigger(prisma);
    const rejectedLogin = await invokeMfaChallengeController(claimsFor(bootstrapUser, "MFA_BOOTSTRAP"), {
      ticket: loginChallenge.ticket,
      method: "backup_code",
      code: bootstrapSetup.backupCodes[0],
    });
    assert.strictEqual(rejectedLogin.status, 409, "refresh insertion failure must fail the application path");
    const loginChallengeAfterRollback = await prisma.mfaLoginChallenge.findFirst({
      where: { userId: bootstrapUser.id },
      orderBy: { createdAt: "desc" },
    });
    assert.strictEqual(loginChallengeAfterRollback.consumedAt, null, "session failure must roll back challenge consumption");
    assert.strictEqual(
      (await prisma.userBackupCode.findUnique({ where: { codeHash: recoveryHash } })).usedAt,
      null,
      "session failure must roll back backup-code consumption"
    );
    assert.strictEqual(await prisma.refreshToken.count({ where: { userId: bootstrapUser.id } }), refreshCountBeforeLogin);
    assert.strictEqual(await prisma.auditLogOutbox.count(), auditCountBeforeLogin, "session failure must roll back completion outbox rows");
    assert.strictEqual(rejectedLogin.cookies.length, 0, "cookies must remain outside the rolled-back transaction");
    await removeRefreshInsertFailureTrigger(prisma);

    const successfulLogin = await invokeMfaChallengeController(claimsFor(bootstrapUser, "MFA_BOOTSTRAP"), {
      ticket: loginChallenge.ticket,
      method: "backup_code",
      code: bootstrapSetup.backupCodes[0],
    });
    assert.strictEqual(successfulLogin.status, 200);
    assert((await prisma.mfaLoginChallenge.findUnique({ where: { id: loginChallengeAfterRollback.id } })).consumedAt);
    assert((await prisma.userBackupCode.findUnique({ where: { codeHash: recoveryHash } })).usedAt);
    assert.strictEqual(await prisma.refreshToken.count({ where: { userId: bootstrapUser.id } }), refreshCountBeforeLogin + 1);
    assert.strictEqual(successfulLogin.cookies.length, 3, "cookies must be set only after the transaction commits");
    const completionActions = (await prisma.auditLogOutbox.findMany({ orderBy: { createdAt: "asc" } }))
      .map((row) => row.payload.action);
    assert(completionActions.includes("AUTH_MFA_BACKUP_CODE_USED"));
    assert(completionActions.includes("AUTH_MFA_LOGIN_COMPLETE"));

    const oldBootstrapFactor = await prisma.userMfaFactor.findFirst({
      where: { userId: bootstrapUser.id, type: "TOTP", disabledAt: null },
    });
    const replacementSetup = await beginAdminMfaSetup({
      userId: bootstrapUser.id,
      email: bootstrapUser.email,
      mode: "REPLACEMENT",
    });
    await installAuditFailureTrigger(prisma);
    await expectError(
      confirmAdminMfaReplacementFromClaims(claimsFor(bootstrapUser, "ACTIVE"), {
        code: totp(replacementSetup.secret),
        ipHash: "test-ip-hash",
        userAgent: "postgres-18-proof",
      }),
      /MSCQR_TEST_AUDIT_REJECT/,
      "durable audit failure must roll back replacement confirmation"
    );
    const activeAfterReplacementRollback = await prisma.userMfaFactor.findMany({
      where: { userId: bootstrapUser.id, type: "TOTP", disabledAt: null },
    });
    assert(activeAfterReplacementRollback.some((factor) => factor.id === oldBootstrapFactor.id));
    assert(activeAfterReplacementRollback.some((factor) => factor.legacySource === "MFA_ENROLLMENT_PENDING"));
    await removeAuditFailureTrigger(prisma);
    await confirmAdminMfaReplacementFromClaims(claimsFor(bootstrapUser, "ACTIVE"), {
      code: totp(replacementSetup.secret),
      ipHash: "test-ip-hash",
      userAgent: "postgres-18-proof",
    });
    const replacementAudit = await prisma.auditLogOutbox.findFirst({ orderBy: { createdAt: "desc" } });
    assert.strictEqual(replacementAudit.payload.action, "AUTH_MFA_REPLACED");
    assert.strictEqual(
      await prisma.userMfaFactor.count({ where: { userId: bootstrapUser.id, type: "TOTP", disabledAt: null } }),
      1
    );

    const raceUser = await createUser("independent-race");
    let backendPidA = null;
    let backendPidB = null;
    const raceParams = { userId: raceUser.id, email: raceUser.email, mode: "FIRST_ENROLLMENT" };
    const race = await Promise.allSettled([
      connectionA.$transaction(async (tx) => {
        const [row] = await tx.$queryRawUnsafe('SELECT pg_backend_pid()::int AS "backendPid"');
        backendPidA = row.backendPid;
        return beginAdminMfaSetup(raceParams, tx);
      }, { timeout: 15_000 }),
      connectionB.$transaction(async (tx) => {
        const [row] = await tx.$queryRawUnsafe('SELECT pg_backend_pid()::int AS "backendPid"');
        backendPidB = row.backendPid;
        return beginAdminMfaSetup(raceParams, tx);
      }, { timeout: 15_000 }),
    ]);
    assert.notStrictEqual(backendPidA, backendPidB, "race proof must use independent PostgreSQL backends");
    assert.strictEqual(race.filter((result) => result.status === "fulfilled").length, 1);
    assert.strictEqual(race.filter((result) => result.status === "rejected").length, 1);
    assert.match(String(race.find((result) => result.status === "rejected").reason.message), /MFA_SETUP_ALREADY_STARTED/);
    assert.strictEqual(
      await prisma.userMfaFactor.count({
        where: { userId: raceUser.id, legacySource: "MFA_ENROLLMENT_PENDING", disabledAt: null },
      }),
      1
    );
    const raceWinner = race.find((result) => result.status === "fulfilled").value;
    await confirmAdminMfaSetup({
      userId: raceUser.id,
      code: totp(raceWinner.secret),
      mode: "FIRST_ENROLLMENT",
    });

    const migrationRaceUser = await createUser("legacy-migration-race");
    const legacySetup = await beginAdminMfaSetup({
      userId: migrationRaceUser.id,
      email: migrationRaceUser.email,
      mode: "FIRST_ENROLLMENT",
    });
    await confirmAdminMfaSetup({
      userId: migrationRaceUser.id,
      code: totp(legacySetup.secret),
      mode: "FIRST_ENROLLMENT",
    });
    await prisma.userMfaFactor.deleteMany({ where: { userId: migrationRaceUser.id } });
    await prisma.userBackupCode.deleteMany({ where: { userId: migrationRaceUser.id } });

    const [legacyVerification, migrationBegin] = await Promise.all([
      connectionA.$transaction(
        (tx) => verifyAdminMfaCode({ userId: migrationRaceUser.id, code: legacySetup.backupCodes[0] }, tx),
        { timeout: 15_000 }
      ),
      connectionB.$transaction(
        (tx) => beginAdminMfaSetup({
          userId: migrationRaceUser.id,
          email: migrationRaceUser.email,
          mode: "REPLACEMENT",
        }, tx),
        { timeout: 15_000 }
      ),
    ]);
    assert.strictEqual(legacyVerification.method, "BACKUP_CODE");
    const pendingCredential = await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } });
    assert.deepStrictEqual(
      [...pendingCredential.backupCodesHash].sort(),
      migrationBegin.backupCodes.map(hashBackupCode).sort(),
      "legacy consumption must not overwrite the pending replacement recovery hashes"
    );
    await confirmAdminMfaSetup({
      userId: migrationRaceUser.id,
      code: totp(migrationBegin.secret),
      mode: "REPLACEMENT",
    });
    await expectError(
      verifyAdminMfaCode({ userId: migrationRaceUser.id, code: legacySetup.backupCodes[1] }),
      /INVALID_MFA_CODE/,
      "replacement confirmation must retire old unused recovery codes"
    );

    const rotationSnapshot = {
      credential: await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } }),
      codes: await prisma.userBackupCode.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
      factors: await prisma.userMfaFactor.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
    };
    await installBackupRotationFailureTrigger(prisma);
    await expectError(
      rotateAdminMfaBackupCodes({ userId: migrationRaceUser.id, code: totp(migrationBegin.secret) }),
      /MSCQR_TEST_BACKUP_ROTATION_REJECT/,
      "legacy credential write failure must roll back normalized recovery-code rotation"
    );
    assert.deepStrictEqual(
      {
        credential: await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } }),
        codes: await prisma.userBackupCode.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
        factors: await prisma.userMfaFactor.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
      },
      rotationSnapshot
    );
    await removeBackupRotationFailureTrigger(prisma);
    const rotated = await rotateAdminMfaBackupCodes({
      userId: migrationRaceUser.id,
      code: totp(migrationBegin.secret),
    });
    await expectError(
      verifyAdminMfaCode({ userId: migrationRaceUser.id, code: migrationBegin.backupCodes[0] }),
      /INVALID_MFA_CODE/,
      "successful rotation must retire the prior recovery set"
    );
    assert.strictEqual(
      (await verifyAdminMfaCode({ userId: migrationRaceUser.id, code: rotated.backupCodes[0] })).method,
      "BACKUP_CODE"
    );

    await prisma.adminWebAuthnCredential.create({
      data: {
        userId: migrationRaceUser.id,
        label: "PostgreSQL proof key",
        credentialId: `legacy-${migrationRaceUser.id}`,
        publicKeySpki: "test-public-key",
        publicKeyAlgorithm: -7,
        transports: ["internal"],
      },
    });
    await prisma.userMfaFactor.create({
      data: {
        userId: migrationRaceUser.id,
        type: "WEBAUTHN",
        label: "PostgreSQL proof passkey",
        credentialId: `normalized-${migrationRaceUser.id}`,
        publicKey: "test-public-key",
        transports: ["internal"],
        lastUsedAt: new Date(),
      },
    });
    const currentPassword = "Mfa-disable-proof-42!";
    await prisma.user.update({
      where: { id: migrationRaceUser.id },
      data: { passwordHash: await hashPassword(currentPassword) },
    });
    const disableSnapshot = {
      credential: await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } }),
      factors: await prisma.userMfaFactor.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
      webAuthn: await prisma.adminWebAuthnCredential.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
      codes: await prisma.userBackupCode.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
      auditCount: await prisma.auditLogOutbox.count(),
    };
    await installAuditFailureTrigger(prisma);
    const rejectedDisable = await invokeDisableController(claimsFor(migrationRaceUser, "ACTIVE"), {
      currentPassword,
      code: totp(migrationBegin.secret),
    });
    assert.strictEqual(rejectedDisable.status, 400, "durable audit failure must fail the application path");
    assert.deepStrictEqual(
      {
        credential: await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } }),
        factors: await prisma.userMfaFactor.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
        webAuthn: await prisma.adminWebAuthnCredential.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
        codes: await prisma.userBackupCode.findMany({ where: { userId: migrationRaceUser.id }, orderBy: { id: "asc" } }),
        auditCount: await prisma.auditLogOutbox.count(),
      },
      disableSnapshot
    );
    await removeAuditFailureTrigger(prisma);
    const successfulDisable = await invokeDisableController(claimsFor(migrationRaceUser, "ACTIVE"), {
      currentPassword,
      code: totp(migrationBegin.secret),
    });
    assert.strictEqual(successfulDisable.status, 200);
    const disabledCredential = await prisma.adminMfaCredential.findUnique({ where: { userId: migrationRaceUser.id } });
    assert.strictEqual(disabledCredential.isEnabled, false);
    assert.deepStrictEqual(disabledCredential.backupCodesHash, []);
    assert.strictEqual(await prisma.userMfaFactor.count({ where: { userId: migrationRaceUser.id, disabledAt: null } }), 0);
    assert.strictEqual(await prisma.adminWebAuthnCredential.count({ where: { userId: migrationRaceUser.id } }), 0);
    assert.strictEqual(await prisma.userBackupCode.count({ where: { userId: migrationRaceUser.id, usedAt: null } }), 0);
    assert.strictEqual((await getAdminMfaStatus(migrationRaceUser.id)).enabled, false);
    await expectError(
      verifyAdminMfaCode({ userId: migrationRaceUser.id, code: totp(migrationBegin.secret) }),
      /INVALID_MFA_CODE/,
      "disabled TOTP must not authenticate"
    );

    const historicalUser = await createUser("historical-unconfirmed");
    const historicalSetup = await beginAdminMfaSetup({
      userId: historicalUser.id,
      email: historicalUser.email,
      mode: "FIRST_ENROLLMENT",
    });
    await prisma.userMfaFactor.updateMany({
      where: { userId: historicalUser.id, type: "TOTP" },
      data: { legacySource: null, lastUsedAt: null },
    });
    assert.strictEqual((await getAdminMfaStatus(historicalUser.id)).enabled, false);
    await expectError(
      verifyAdminMfaCode({ userId: historicalUser.id, code: totp(historicalSetup.secret) }),
      /INVALID_MFA_CODE/,
      "historical unconfirmed normalized TOTP rows must not authenticate"
    );

    console.log(JSON.stringify({
      result: "passed",
      postgresMajor: 18,
      independentBackendPids: [backendPidA, backendPidB],
      proofs: [
        "pending-factor-denial",
        "bootstrap-session-audit-rollback",
        "login-challenge-backup-session-rollback",
        "replacement-audit-rollback",
        "independent-connection-enrollment-race",
        "legacy-backup-migration-race",
        "rotation-rollback",
        "disable-audit-rollback",
        "all-factor-disable",
        "historical-unconfirmed-denial",
      ],
    }));
  } finally {
    if (prisma) {
      await removeAuditFailureTrigger(prisma).catch(() => undefined);
      await removeBackupRotationFailureTrigger(prisma).catch(() => undefined);
      await removeRefreshInsertFailureTrigger(prisma).catch(() => undefined);
    }
    if (connectionA) await connectionA.$disconnect().catch(() => undefined);
    if (connectionB) await connectionB.$disconnect().catch(() => undefined);
    if (prisma) await prisma.$disconnect().catch(() => undefined);
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});

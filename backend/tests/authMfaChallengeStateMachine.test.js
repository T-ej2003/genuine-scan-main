const assert = require("assert");
const path = require("path");
const { createHmac } = require("crypto");

process.env.NODE_ENV = "test";
process.env.JWT_SECRET = process.env.JWT_SECRET || "auth-mfa-state-machine-jwt-secret";
process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET;
process.env.TOKEN_HASH_SECRET_CURRENT = process.env.TOKEN_HASH_SECRET_CURRENT || "auth-mfa-state-machine-token-secret";
process.env.AUTH_MFA_ENCRYPTION_KEY = process.env.AUTH_MFA_ENCRYPTION_KEY || "auth-mfa-state-machine-encryption-secret";
process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES = "5";
process.env.AUTH_MFA_CHALLENGE_MAX_ATTEMPTS = "3";
process.env.AUTH_MFA_BACKUP_CODE_COUNT = "8";

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

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32Decode = (input) => {
  const normalized = String(input || "").toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of normalized) {
    const idx = base32Alphabet.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
};

const hotp = (secret, counter) => {
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac("sha1", secret).update(counterBuf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binCode =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return (binCode % 1_000_000).toString().padStart(6, "0");
};

const totp = (secretBase32) => hotp(base32Decode(secretBase32), Math.floor(Date.now() / 30_000));

let credential = null;
let challenges = [];
let legacyChallenges = [];
let factors = [];
let backupCodeRows = [];
let auditEvents = [];
let loggerEvents = [];

const prismaMock = {
  $transaction: async (operations) => Promise.all(operations),
  adminMfaCredential: {
    upsert: async ({ create, update }) => {
      credential = credential ? { ...credential, ...update, updatedAt: new Date() } : { id: "cred-1", ...create, createdAt: new Date(), updatedAt: new Date() };
      return credential;
    },
    findUnique: async ({ where }) => (where.userId === credential?.userId ? { ...credential } : null),
    update: async ({ where, data }) => {
      if (where.userId !== credential?.userId) throw new Error("credential not found");
      credential = { ...credential, ...data, updatedAt: new Date() };
      return credential;
    },
    updateMany: async ({ where, data }) => {
      if (where.userId !== credential?.userId) return { count: 0 };
      credential = { ...credential, ...data, updatedAt: new Date() };
      return { count: 1 };
    },
  },
  adminWebAuthnCredential: {
    findMany: async () => [],
  },
  userMfaFactor: {
    deleteMany: async ({ where }) => {
      const before = factors.length;
      factors = factors.filter((row) => {
        if (where.userId && row.userId !== where.userId) return true;
        if (where.type && row.type !== where.type) return true;
        if (where.disabledAt === null && row.disabledAt) return true;
        return false;
      });
      return { count: before - factors.length };
    },
    create: async ({ data }) => {
      const row = {
        id: data.id || `factor-${factors.length + 1}`,
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastUsedAt: data.lastUsedAt || null,
        disabledAt: data.disabledAt || null,
      };
      factors.push(row);
      return { ...row };
    },
    findFirst: async ({ where }) => {
      const rows = await prismaMock.userMfaFactor.findMany({ where, orderBy: [{ createdAt: "desc" }] });
      return rows[0] || null;
    },
    findMany: async ({ where }) => {
      return factors
        .filter((row) => {
          if (where.userId && row.userId !== where.userId) return false;
          if (where.type && row.type !== where.type) return false;
          if (where.disabledAt === null && row.disabledAt) return false;
          if (where.secretCiphertext?.not === null && !row.secretCiphertext) return false;
          return true;
        })
        .sort((a, b) => {
          const aTime = (a.lastUsedAt || a.createdAt || new Date(0)).getTime();
          const bTime = (b.lastUsedAt || b.createdAt || new Date(0)).getTime();
          return bTime - aTime;
        })
        .map((row) => ({ ...row }));
    },
    update: async ({ where, data }) => {
      const row = factors.find((entry) => entry.id === where.id);
      if (!row) throw new Error("factor not found");
      Object.assign(row, data, { updatedAt: new Date() });
      return { ...row };
    },
    upsert: async ({ where, update, create }) => {
      const existing = factors.find((entry) => entry.id === where.id);
      if (existing) {
        Object.assign(existing, update, { updatedAt: new Date() });
        return { ...existing };
      }
      const row = {
        ...create,
        createdAt: new Date(),
        updatedAt: new Date(),
        disabledAt: create.disabledAt || null,
      };
      factors.push(row);
      return { ...row };
    },
  },
  userBackupCode: {
    deleteMany: async ({ where }) => {
      const before = backupCodeRows.length;
      backupCodeRows = backupCodeRows.filter((row) => {
        if (where.userId && row.userId !== where.userId) return true;
        if (where.usedAt === null && row.usedAt === null) return false;
        return true;
      });
      return { count: before - backupCodeRows.length };
    },
    createMany: async ({ data }) => {
      for (const entry of data) {
        backupCodeRows.push({
          id: `backup-${backupCodeRows.length + 1}`,
          ...entry,
          usedAt: null,
          createdAt: new Date(),
        });
      }
      return { count: data.length };
    },
    count: async ({ where }) => backupCodeRows.filter((row) => row.userId === where.userId && (where.usedAt !== null || row.usedAt === null)).length,
    updateMany: async ({ where, data }) => {
      let count = 0;
      const hashes = where.codeHash?.in || [];
      for (const row of backupCodeRows) {
        if (where.userId && row.userId !== where.userId) continue;
        if (where.usedAt === null && row.usedAt) continue;
        if (hashes.length && !hashes.includes(row.codeHash)) continue;
        Object.assign(row, data);
        count += 1;
      }
      return { count };
    },
  },
  mfaLoginChallenge: {
    create: async ({ data }) => {
      const row = {
        id: `login-challenge-${challenges.length + 1}`,
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
        consumedAt: data.consumedAt || null,
        retryAfterSeconds: data.retryAfterSeconds || null,
      };
      challenges.push(row);
      return { ...row };
    },
    findFirst: async ({ where }) => {
      const hashes = where.ticketHash?.in || [];
      const row = challenges.find((entry) => hashes.includes(entry.ticketHash));
      return row ? { ...row } : null;
    },
    updateMany: async ({ where, data }) => {
      let count = 0;
      for (const row of challenges) {
        if (where.id && row.id !== where.id) continue;
        if (where.userId && row.userId !== where.userId) continue;
        if (where.consumedAt === null && row.consumedAt) continue;
        if (where.expiresAt?.gt && row.expiresAt.getTime() <= where.expiresAt.gt.getTime()) continue;
        if (data.attempts?.increment) row.attempts += data.attempts.increment;
        if ("retryAfterSeconds" in data) row.retryAfterSeconds = data.retryAfterSeconds;
        if ("consumedAt" in data) row.consumedAt = data.consumedAt;
        row.updatedAt = new Date();
        count += 1;
      }
      return { count };
    },
  },
  authMfaChallenge: {
    create: async ({ data }) => {
      const row = {
        id: `legacy-challenge-${legacyChallenges.length + 1}`,
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
        consumedAt: data.consumedAt || null,
        supersededAt: data.supersededAt || null,
        user: { id: data.userId },
      };
      legacyChallenges.push(row);
      return row;
    },
    findFirst: async ({ where }) => {
      const hashes = where.ticketHash?.in || [];
      const row = legacyChallenges.find((entry) => hashes.includes(entry.ticketHash));
      return row ? { ...row, user: { id: row.userId } } : null;
    },
    updateMany: async ({ where, data }) => {
      let count = 0;
      for (const row of legacyChallenges) {
        if (where.id && row.id !== where.id) continue;
        if (where.userId && row.userId !== where.userId) continue;
        if (where.purpose && row.purpose !== where.purpose) continue;
        if (where.sessionBindingHash && row.sessionBindingHash !== where.sessionBindingHash) continue;
        if (where.consumedAt === null && row.consumedAt) continue;
        if (where.supersededAt === null && row.supersededAt) continue;
        if (where.expiresAt?.gt && row.expiresAt.getTime() <= where.expiresAt.gt.getTime()) continue;
        if (data.attempts?.increment) row.attempts += data.attempts.increment;
        if ("consumedAt" in data) row.consumedAt = data.consumedAt;
        if ("supersededAt" in data) row.supersededAt = data.supersededAt;
        if ("createdIpHash" in data) row.createdIpHash = data.createdIpHash;
        if ("createdUserAgentHash" in data) row.createdUserAgentHash = data.createdUserAgentHash;
        row.updatedAt = new Date();
        count += 1;
      }
      return { count };
    },
  },
};

mockModule("config/database.js", { __esModule: true, default: prismaMock });
mockModule("services/auditService.js", {
  createAuditLogSafely: async (entry) => {
    auditEvents.push(entry);
    return { persisted: true };
  },
});
mockModule("utils/logger.js", {
  logger: {
    debug: (message, meta) => loggerEvents.push({ level: "debug", message, meta }),
    info: (message, meta) => loggerEvents.push({ level: "info", message, meta }),
    warn: (message, meta) => loggerEvents.push({ level: "warn", message, meta }),
    error: (message, meta) => loggerEvents.push({ level: "error", message, meta }),
  },
});

const {
  beginAdminMfaSetup,
  completeAdminMfaChallenge,
  createAdminMfaChallenge,
} = require("../dist/services/auth/mfaService");
const { verifyTotpToken } = require("../dist/services/auth/totpMfaProvider");

const reset = async () => {
  credential = null;
  challenges = [];
  legacyChallenges = [];
  factors = [];
  backupCodeRows = [];
  auditEvents = [];
  loggerEvents = [];
  const setup = await beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com" });
  credential = { ...credential, isEnabled: true, verifiedAt: new Date() };
  return setup;
};

const makeChallenge = (overrides = {}) =>
  createAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    purpose: "admin_login",
    riskScore: 10,
    riskLevel: "LOW",
    reasons: ["test"],
    ipHash: "ip-hash",
    userAgent: "agent",
    ...overrides,
  });

const rejectCode = async (promise) => {
  try {
    await promise;
  } catch (error) {
    return String(error?.message || "");
  }
  throw new Error("Expected promise to reject");
};

const rejectError = async (promise) => {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error("Expected promise to reject");
};

const withAuthMfaChallengeTtl = async (value, fn) => {
  const previous = process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES;
  if (value == null) {
    delete process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES;
  } else {
    process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES = value;
  }
  try {
    return await fn();
  } finally {
    if (previous === undefined) {
      delete process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES;
    } else {
      process.env.AUTH_MFA_CHALLENGE_TTL_MINUTES = previous;
    }
  }
};

const assertSafeFutureExpiry = (expiresAt, beforeMs, label) => {
  const ttlMs = expiresAt.getTime() - beforeMs;
  assert(ttlMs >= 60_000, `${label} should be valid for at least 60 seconds`);
  assert(ttlMs >= 290_000 && ttlMs <= 310_000, `${label} should default to roughly 5 minutes, got ${ttlMs}ms`);
};

const run = async () => {
  await reset();
  const providerSetup = await reset();
  assert.strictEqual(
    await verifyTotpToken({ secret: providerSetup.secret, token: totp(providerSetup.secret) }),
    true,
    "verifyTotpToken should accept otplib boolean true results"
  );

  for (const [value, label] of [
    [undefined, "unset env"],
    ["5", "integer env"],
    ["0", "zero env"],
    ["0.1", "decimal env"],
    ["-1", "negative env"],
    ["abc", "invalid env"],
  ]) {
    await withAuthMfaChallengeTtl(value, async () => {
      const beforeMs = Date.now();
      const challenge = await makeChallenge();
      assertSafeFutureExpiry(challenge.expiresAt, beforeMs, label);
    });
  }

  await withAuthMfaChallengeTtl("0", async () => {
    const beforeMs = Date.now();
    const legacyChallenge = await createAdminMfaChallenge({
      userId: "admin-1",
      sessionId: "bootstrap-session-1",
      purpose: "high_risk_action",
      riskScore: 10,
      riskLevel: "LOW",
      reasons: ["test"],
      ipHash: "ip-hash",
      userAgent: "agent",
    });
    assertSafeFutureExpiry(legacyChallenge.expiresAt, beforeMs, "legacy high-risk challenge");
  });

  const productionEvidenceSetup = await reset();
  await withAuthMfaChallengeTtl(undefined, async () => {
    const beforeMs = Date.now();
    const challenge = await makeChallenge();
    assertSafeFutureExpiry(challenge.expiresAt, beforeMs, "production evidence login ticket");

    const wrong = await rejectError(completeAdminMfaChallenge({
      userId: "admin-1",
      sessionId: "bootstrap-session-1",
      ticket: challenge.ticket,
      method: "totp",
      code: "000000",
    }));
    assert.strictEqual(String(wrong?.message || ""), "INVALID_MFA_CODE");
    assert.strictEqual(wrong.status, 400);
    assert.strictEqual(challenges[challenges.length - 1].consumedAt, null);

    const correct = await completeAdminMfaChallenge({
      userId: "admin-1",
      sessionId: "bootstrap-session-1",
      ticket: challenge.ticket,
      method: "totp",
      code: totp(productionEvidenceSetup.secret),
    });
    assert.strictEqual(correct.method, "TOTP");
    assert(challenges[challenges.length - 1].consumedAt, "same login-returned ticket should complete and be consumed");
  });

  const setup = await reset();
  const invalidChallenge = await makeChallenge();
  const invalid = await rejectError(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: invalidChallenge.ticket,
    method: "totp",
    code: "000000",
  }));
  assert.strictEqual(String(invalid?.message || ""), "INVALID_MFA_CODE");
  assert.strictEqual(invalid.status, 400);
  assert.strictEqual(challenges[0].attempts, 1);
  assert.strictEqual(challenges[0].consumedAt, null);

  const newFactorSetup = await reset();
  credential = { ...credential, isEnabled: false };
  const newFactorChallenge = await makeChallenge();
  const newFactorValid = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: newFactorChallenge.ticket,
    method: "totp",
    code: totp(newFactorSetup.secret),
  });
  assert.strictEqual(newFactorValid.method, "TOTP");
  assert(challenges[0].consumedAt, "new UserMfaFactor TOTP should consume challenge");
  assert(factors.some((factor) => factor.type === "TOTP" && factor.lastUsedAt), "new TOTP factor should record last use");

  const legacyOnlySetup = await reset();
  factors = [];
  const legacyOnlyChallenge = await makeChallenge();
  const legacyOnlyValid = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: legacyOnlyChallenge.ticket,
    method: "totp",
    code: totp(legacyOnlySetup.secret),
  });
  assert.strictEqual(legacyOnlyValid.method, "TOTP");
  assert(challenges[0].consumedAt, "legacy AdminMfaCredential TOTP should consume challenge");
  assert(
    factors.some((factor) => factor.id === "legacy-totp-admin-1" && factor.legacySource === "AdminMfaCredential"),
    "legacy AdminMfaCredential TOTP should promote to UserMfaFactor"
  );

  const decryptFailureSetup = await reset();
  credential = { ...credential, isEnabled: false };
  const decryptFailureChallenge = await makeChallenge();
  const decryptCode = totp(decryptFailureSetup.secret);
  factors[0].secretTag = Buffer.alloc(16, 9).toString("base64");
  const decryptFailure = await rejectError(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: decryptFailureChallenge.ticket,
    method: "totp",
    code: decryptCode,
  }));
  assert.strictEqual(String(decryptFailure?.message || ""), "MFA_VERIFICATION_UNAVAILABLE");
  assert.strictEqual(decryptFailure.status, 409);
  const safeLogBlob = JSON.stringify(loggerEvents);
  assert(safeLogBlob.includes("new_factor"), "decrypt failure log should include safe factor path");
  assert(safeLogBlob.includes("TOTP_SECRET_DECRYPT_FAILED"), "decrypt failure log should include safe category");
  assert(!safeLogBlob.includes(decryptFailureSetup.secret), "logs must not contain raw TOTP secret");
  assert(!safeLogBlob.includes(decryptCode), "logs must not contain submitted TOTP code");
  assert(!safeLogBlob.includes(factors[0].secretCiphertext), "logs must not contain encrypted TOTP secret");
  assert(!safeLogBlob.includes(decryptFailureChallenge.ticket), "logs must not contain MFA ticket");

  await reset();
  const expiredChallenge = await makeChallenge();
  challenges[0].expiresAt = new Date(Date.now() - 1000);
  const expiredError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: expiredChallenge.ticket,
    method: "totp",
    code: totp(setup.secret),
  }));
  assert.strictEqual(expiredError, "MFA_CHALLENGE_NOT_FOUND");

  const validSetup = await reset();
  const validChallenge = await makeChallenge();
  const valid = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: validChallenge.ticket,
    method: "totp",
    code: totp(validSetup.secret),
  });
  assert.strictEqual(valid.method, "TOTP");
  assert(challenges[0].consumedAt, "valid challenge should be consumed");
  const consumedError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: validChallenge.ticket,
    method: "totp",
    code: totp(validSetup.secret),
  }));
  assert.strictEqual(consumedError, "MFA_CHALLENGE_NOT_FOUND");

  await reset();
  const stableSessionSetup = await beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com" });
  credential = { ...credential, isEnabled: true, verifiedAt: new Date() };
  const boundChallenge = await makeChallenge();
  const stableSession = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "other-bootstrap-session",
    ticket: boundChallenge.ticket,
    method: "totp",
    code: totp(stableSessionSetup.secret),
  });
  assert.strictEqual(stableSession.method, "TOTP");
  assert(challenges[0].consumedAt, "ordinary login MFA should not 410 because browser session state refreshed");

  await reset();
  const duplicateSetup = await beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com" });
  credential = { ...credential, isEnabled: true, verifiedAt: new Date() };
  const firstChallenge = await makeChallenge();
  await makeChallenge();
  assert.strictEqual(challenges.length, 2);
  assert.strictEqual(challenges[0].consumedAt, null);
  const firstValidAfterDuplicateBegin = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: firstChallenge.ticket,
    method: "totp",
    code: totp(duplicateSetup.secret),
  });
  assert.strictEqual(firstValidAfterDuplicateBegin.method, "TOTP");
  assert(challenges[0].consumedAt, "duplicate begin must not supersede the first fresh challenge");
  assert.strictEqual(challenges[1].consumedAt, null);

  await reset();
  const lockedChallenge = await makeChallenge({ maxAttempts: 1 });
  const tooMany = await rejectError(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: lockedChallenge.ticket,
    method: "totp",
    code: "000000",
  }));
  assert.strictEqual(String(tooMany?.message || ""), "MFA_TOO_MANY_ATTEMPTS");
  assert.strictEqual(tooMany.retryAfterSeconds, 60);

  const backupSetup = await reset();
  const backupChallenge = await makeChallenge();
  const backup = await completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: backupChallenge.ticket,
    method: "backup_code",
    code: backupSetup.backupCodes[0],
  });
  assert.strictEqual(backup.method, "BACKUP_CODE");
  assert(!credential.backupCodesHash.some((hash) => hash.includes(backupSetup.backupCodes[0])), "backup code hash must not contain plaintext");

  const reuseChallenge = await makeChallenge();
  const reuseError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: reuseChallenge.ticket,
    method: "backup_code",
    code: backupSetup.backupCodes[0],
  }));
  assert.strictEqual(reuseError, "INVALID_MFA_CODE");

  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_CHALLENGE_ISSUED"));
  assert(auditEvents.some((entry) => entry.details?.ttlMs >= 60_000 && entry.details?.ttlMinutes >= 1));
  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_BACKUP_CODE_USED"));
  console.log("auth MFA challenge state machine tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

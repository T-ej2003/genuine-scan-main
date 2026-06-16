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
let auditEvents = [];

const prismaMock = {
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
  authMfaChallenge: {
    create: async ({ data }) => {
      const row = {
        id: `challenge-${challenges.length + 1}`,
        ...data,
        createdAt: new Date(),
        updatedAt: new Date(),
        consumedAt: data.consumedAt || null,
        supersededAt: data.supersededAt || null,
        user: { id: data.userId },
      };
      challenges.push(row);
      return row;
    },
    findFirst: async ({ where }) => {
      const hashes = where.ticketHash?.in || [];
      const row = challenges.find((entry) => hashes.includes(entry.ticketHash));
      return row ? { ...row, user: { id: row.userId } } : null;
    },
    updateMany: async ({ where, data }) => {
      let count = 0;
      for (const row of challenges) {
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

const {
  beginAdminMfaSetup,
  completeAdminMfaChallenge,
  createAdminMfaChallenge,
} = require("../dist/services/auth/mfaService");

const reset = async () => {
  credential = null;
  challenges = [];
  auditEvents = [];
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

const run = async () => {
  const setup = await reset();
  const invalidChallenge = await makeChallenge();
  const invalidError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: invalidChallenge.ticket,
    method: "totp",
    code: "000000",
  }));
  assert.strictEqual(invalidError, "INVALID_MFA_CODE");
  assert.strictEqual(challenges[0].attempts, 1);
  assert.strictEqual(challenges[0].consumedAt, null);

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
  const boundChallenge = await makeChallenge();
  const wrongSessionError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "other-bootstrap-session",
    ticket: boundChallenge.ticket,
    method: "totp",
    code: "000000",
  }));
  assert.strictEqual(wrongSessionError, "MFA_CHALLENGE_NOT_FOUND");
  assert.strictEqual(challenges[0].attempts, 0);

  await reset();
  const lockedChallenge = await makeChallenge({ maxAttempts: 1 });
  const tooManyError = await rejectCode(completeAdminMfaChallenge({
    userId: "admin-1",
    sessionId: "bootstrap-session-1",
    ticket: lockedChallenge.ticket,
    method: "totp",
    code: "000000",
  }));
  assert.strictEqual(tooManyError, "MFA_TOO_MANY_ATTEMPTS");

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
  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_BACKUP_CODE_USED"));
  console.log("auth MFA challenge state machine tests passed");
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

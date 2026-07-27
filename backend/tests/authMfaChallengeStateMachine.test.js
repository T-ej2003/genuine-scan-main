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
let webAuthnCredentials = [];
let refreshTokens = [];
let auditEvents = [];
let loggerEvents = [];
let failMfaStateRead = false;
let failPendingFactorWrite = false;
let failCredentialBackupWrite = false;
let failDisableAuditWrite = false;
let failSessionWrite = false;
let failCompletionAuditWrite = false;
let webAuthnChallengeConsumed = false;
let webAuthnCounter = 0;
let advisoryLockCalls = 0;
let currentStepUpAuditWritten = false;
let transactionTail = Promise.resolve();

const prismaMock = {
  $executeRaw: async () => {
    advisoryLockCalls += 1;
    return 1;
  },
  $queryRaw: async (_query, ...values) => [{
    id: values[0],
    expiresAt: values[4],
  }],
  $transaction: async (input) => {
    if (Array.isArray(input)) return Promise.all(input);
    const run = async () => {
      const snapshot = structuredClone({
        credential,
        challenges,
        legacyChallenges,
        factors,
        backupCodeRows,
        webAuthnCredentials,
        refreshTokens,
        auditEvents,
        webAuthnChallengeConsumed,
        webAuthnCounter,
      });
      try {
        return await input(prismaMock);
      } catch (error) {
        credential = snapshot.credential;
        challenges = snapshot.challenges;
        legacyChallenges = snapshot.legacyChallenges;
        factors = snapshot.factors;
        backupCodeRows = snapshot.backupCodeRows;
        webAuthnCredentials = snapshot.webAuthnCredentials;
        refreshTokens = snapshot.refreshTokens;
        auditEvents = snapshot.auditEvents;
        webAuthnChallengeConsumed = snapshot.webAuthnChallengeConsumed;
        webAuthnCounter = snapshot.webAuthnCounter;
        throw error;
      }
    };
    const result = transactionTail.then(run, run);
    transactionTail = result.then(() => undefined, () => undefined);
    return result;
  },
  adminMfaCredential: {
    upsert: async ({ create, update }) => {
      credential = credential ? { ...credential, ...update, updatedAt: new Date() } : { id: "cred-1", ...create, createdAt: new Date(), updatedAt: new Date() };
      return credential;
    },
    findUnique: async ({ where }) => {
      if (failMfaStateRead) throw new Error("MFA_STATE_DATABASE_UNAVAILABLE");
      return where.userId === credential?.userId ? { ...credential } : null;
    },
    update: async ({ where, data }) => {
      if (where.userId !== credential?.userId) throw new Error("credential not found");
      credential = { ...credential, ...data, updatedAt: new Date() };
      return credential;
    },
    updateMany: async ({ where, data }) => {
      if (where.userId !== credential?.userId) return { count: 0 };
      if (where.isEnabled !== undefined && credential.isEnabled !== where.isEnabled) return { count: 0 };
      if (where.verifiedAt === null && credential.verifiedAt !== null) return { count: 0 };
      if (where.backupCodesHash?.equals && JSON.stringify(credential.backupCodesHash) !== JSON.stringify(where.backupCodesHash.equals)) return { count: 0 };
      if (failCredentialBackupWrite && Array.isArray(data.backupCodesHash)) throw new Error("MFA_BACKUP_WRITE_FAILED");
      credential = { ...credential, ...data, updatedAt: new Date() };
      return { count: 1 };
    },
  },
  adminWebAuthnCredential: {
    findMany: async ({ where } = {}) => webAuthnCredentials.filter((row) => !where?.userId || row.userId === where.userId),
    count: async ({ where }) => webAuthnCredentials.filter((row) => row.userId === where.userId).length,
    deleteMany: async ({ where }) => {
      const before = webAuthnCredentials.length;
      webAuthnCredentials = webAuthnCredentials.filter((row) => row.userId !== where.userId);
      return { count: before - webAuthnCredentials.length };
    },
  },
  user: {
    findUnique: async ({ where }) => where.id === "admin-1"
      ? {
          id: "admin-1",
          email: "admin@example.com",
          name: "Admin",
          passwordHash: "test-password-hash",
          role: "SUPER_ADMIN",
          status: "ACTIVE",
          isActive: true,
          disabledAt: null,
          deletedAt: null,
        }
      : null,
  },
  auditLogOutbox: {
    create: async ({ data }) => {
      if (failDisableAuditWrite) throw new Error("MFA_DISABLE_AUDIT_WRITE_FAILED");
      if (failCompletionAuditWrite && [
        "AUTH_MFA_LOGIN_COMPLETE",
        "AUTH_MFA_STEP_UP_SUCCESS",
        "AUTH_WEBAUTHN_LOGIN_COMPLETE",
        "AUTH_WEBAUTHN_STEP_UP_SUCCESS",
      ].includes(data.payload?.action)) {
        throw new Error("AUTH_COMPLETION_AUDIT_WRITE_FAILED");
      }
      if (data.payload?.action === "AUTH_MFA_STEP_UP_SUCCESS") currentStepUpAuditWritten = true;
      auditEvents.push(data.payload);
      return { id: `audit-${auditEvents.length}`, ...data };
    },
  },
  refreshToken: {
    create: async ({ data }) => {
      if (failSessionWrite) throw new Error("AUTH_SESSION_WRITE_FAILED");
      const row = { id: `refresh-${refreshTokens.length + 1}`, ...data, revokedAt: null, revokedReason: null };
      refreshTokens.push(row);
      return { id: row.id };
    },
    updateMany: async ({ where, data }) => {
      if (where.id === "current-step-up-session" && data.revokedAt && !currentStepUpAuditWritten) {
        throw new Error("AUTH_SESSION_CAPABILITY_DENIED");
      }
      let count = 0;
      for (const row of refreshTokens) {
        if (where.id && row.id !== where.id) continue;
        if (where.userId && row.userId !== where.userId) continue;
        if (where.tokenHash?.in && !where.tokenHash.in.includes(row.tokenHash)) continue;
        if (where.revokedAt === null && row.revokedAt) continue;
        Object.assign(row, data);
        count += 1;
      }
      return { count };
    },
  },
  userMfaFactor: {
    deleteMany: async ({ where }) => {
      const before = factors.length;
      factors = factors.filter((row) => {
        if (where.id?.in && !where.id.in.includes(row.id)) return true;
        if (where.userId && row.userId !== where.userId) return true;
        if (typeof where.type === "string" && row.type !== where.type) return true;
        if (where.disabledAt === null && row.disabledAt) return true;
        return false;
      });
      return { count: before - factors.length };
    },
    create: async ({ data }) => {
      if (failPendingFactorWrite && data.legacySource === "MFA_ENROLLMENT_PENDING") {
        throw new Error("MFA_FACTOR_WRITE_FAILED");
      }
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
          if (typeof where.type === "string" && row.type !== where.type) return false;
          if (where.type?.in && !where.type.in.includes(row.type)) return false;
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
    updateMany: async ({ where, data }) => {
      let count = 0;
      for (const row of factors) {
        if (where.userId && row.userId !== where.userId) continue;
        if (typeof where.type === "string" && row.type !== where.type) continue;
        if (where.disabledAt === null && row.disabledAt) continue;
        if (where.id?.not && row.id === where.id.not) continue;
        Object.assign(row, data, { updatedAt: new Date() });
        count += 1;
      }
      return { count };
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
    createMany: async ({ data, skipDuplicates }) => {
      let count = 0;
      for (const entry of data) {
        if (skipDuplicates && backupCodeRows.some((row) => row.codeHash === entry.codeHash)) continue;
        backupCodeRows.push({
          id: `backup-${backupCodeRows.length + 1}`,
          ...entry,
          usedAt: null,
          createdAt: new Date(),
        });
        count += 1;
      }
      return { count };
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
mockModule("rls-waves/session-b/b01/adminMfaRepository.js", {
  loadAdminMfaState: async () => {
    if (failMfaStateRead) throw new Error("MFA_STATE_DATABASE_UNAVAILABLE");
    return {
      legacyTotp: credential ? { ...credential } : null,
      legacyWebAuthn: webAuthnCredentials.map((row) => ({ ...row })),
      factors: factors.map((row) => ({ ...row })),
      backupCodesRemaining: backupCodeRows.filter((row) => !row.usedAt).length,
    };
  },
  beginAdminTotpEnrollment: async (_db, input) => {
    advisoryLockCalls += 1;
    if (failMfaStateRead) throw new Error("MFA_STATE_DATABASE_UNAVAILABLE");
    const enrolled = Boolean(credential?.isEnabled) ||
      webAuthnCredentials.length > 0 ||
      factors.some((row) => row.legacySource !== "MFA_ENROLLMENT_PENDING");
    if (input.mode === "FIRST_ENROLLMENT" && enrolled) throw new Error("MFA_ALREADY_ENROLLED");
    if (input.mode === "REPLACEMENT" && !enrolled) throw new Error("MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR");
    if (factors.some((row) => row.legacySource === "MFA_ENROLLMENT_PENDING" && row.createdAt > input.pendingCutoff)) {
      throw new Error("MFA_SETUP_ALREADY_STARTED");
    }
    if (failPendingFactorWrite) throw new Error("MFA_FACTOR_WRITE_FAILED");
    factors = factors.filter((row) => row.legacySource !== "MFA_ENROLLMENT_PENDING");
    if (input.mode === "REPLACEMENT" && credential?.isEnabled &&
        !factors.some((row) => row.type === "TOTP" && !row.disabledAt)) {
      factors.push({
        id: "legacy-totp-admin-1",
        userId: "admin-1",
        type: "TOTP",
        label: "Authenticator app",
        secretCiphertext: credential.secretCiphertext,
        secretIv: credential.secretIv,
        secretTag: credential.secretTag,
        legacySource: "AdminMfaCredential",
        createdAt: input.createdAt,
        updatedAt: input.createdAt,
        lastUsedAt: credential.lastUsedAt || credential.verifiedAt,
        disabledAt: null,
      });
    }
    if (input.mode === "REPLACEMENT" && credential?.isEnabled && backupCodeRows.length === 0) {
      backupCodeRows = credential.backupCodesHash.map((codeHash, index) => ({
        id: `legacy-backup-${index + 1}`,
        userId: "admin-1",
        codeHash,
        usedAt: null,
        createdAt: input.createdAt,
      }));
    }
    const factor = {
      id: `factor-${factors.length + 1}`,
      userId: "admin-1",
      type: "TOTP",
      label: "Authenticator app",
      secretCiphertext: input.secretCiphertext,
      secretIv: input.secretIv,
      secretTag: input.secretTag,
      legacySource: "MFA_ENROLLMENT_PENDING",
      createdAt: input.createdAt,
      updatedAt: input.createdAt,
      lastUsedAt: null,
      disabledAt: null,
    };
    factors.push(factor);
    credential = {
      ...(credential || { id: "cred-1", userId: "admin-1", createdAt: input.createdAt }),
      secretCiphertext: input.secretCiphertext,
      secretIv: input.secretIv,
      secretTag: input.secretTag,
      backupCodesHash: [...input.backupHashes],
      isEnabled: false,
      verifiedAt: null,
      updatedAt: input.createdAt,
    };
    return { factorId: factor.id };
  },
  loadAdminTotpEnrollment: async (_db, input) => {
    const enrolled = Boolean(credential?.isEnabled) ||
      webAuthnCredentials.length > 0 ||
      factors.some((row) => row.legacySource !== "MFA_ENROLLMENT_PENDING" && !row.disabledAt);
    if (input.mode === "FIRST_ENROLLMENT" && enrolled) throw new Error("MFA_ALREADY_ENROLLED");
    if (input.mode === "REPLACEMENT" && !enrolled) throw new Error("MFA_REPLACEMENT_REQUIRES_ENROLLED_FACTOR");
    return {
      credential: credential ? { ...credential } : null,
      pending: factors.filter((row) => row.legacySource === "MFA_ENROLLMENT_PENDING" && row.createdAt > input.pendingCutoff).map((row) => ({ ...row })),
    };
  },
  completeAdminTotpEnrollment: async (_db, input) => {
    const factor = factors.find((row) => row.id === input.factorId && row.legacySource === "MFA_ENROLLMENT_PENDING");
    if (!factor || !credential) throw new Error("MFA_SETUP_NOT_STARTED");
    for (const row of factors) {
      if (row.id !== factor.id && row.type === "TOTP" && !row.disabledAt) {
        row.disabledAt = input.completedAt;
        row.updatedAt = input.completedAt;
      }
    }
    factor.legacySource = "AdminMfaCredential";
    factor.lastUsedAt = input.completedAt;
    factor.updatedAt = input.completedAt;
    backupCodeRows = credential.backupCodesHash.map((codeHash, index) => ({
      id: `backup-${index + 1}`,
      userId: "admin-1",
      codeHash,
      usedAt: null,
      createdAt: input.completedAt,
    }));
    credential = { ...credential, isEnabled: true, verifiedAt: input.completedAt, lastUsedAt: input.completedAt, updatedAt: input.completedAt };
    auditEvents.push({ action: input.mode === "REPLACEMENT" ? "AUTH_MFA_REPLACED" : "AUTH_MFA_ENROLLED", userId: "admin-1" });
    return { enabled: true };
  },
  loadAdminMfaVerifiers: async () => ({
    legacy: credential ? { ...credential } : null,
    factors: factors.map((row) => ({ ...row })),
    backupCodes: backupCodeRows.filter((row) => !row.usedAt).map((row) => ({ ...row })),
  }),
  consumeAdminMfaVerifier: async (_db, input) => {
    if (input.method === "BACKUP_CODE") {
      const row = backupCodeRows.find((entry) => entry.id === input.recordId && !entry.usedAt);
      if (!row) return { consumed: false };
      row.usedAt = input.usedAt;
      return { consumed: true };
    }
    if (input.method === "BACKUP_LEGACY") {
      if (!credential || JSON.stringify(credential.backupCodesHash) !== JSON.stringify(input.expectedLegacyHashes)) return { consumed: false };
      credential.backupCodesHash = [...input.nextLegacyHashes];
      credential.lastUsedAt = input.usedAt;
      return { consumed: true };
    }
    if (input.method === "TOTP_FACTOR") {
      const row = factors.find((entry) => entry.id === input.recordId && !entry.disabledAt);
      if (!row) return { consumed: false };
      row.lastUsedAt = input.usedAt;
      return { consumed: true };
    }
    if (!credential?.isEnabled) return { consumed: false };
    credential.lastUsedAt = input.usedAt;
    if (!factors.some((row) => row.id === "legacy-totp-admin-1")) {
      factors.push({
        id: "legacy-totp-admin-1",
        userId: "admin-1",
        type: "TOTP",
        label: "Authenticator app",
        secretCiphertext: credential.secretCiphertext,
        secretIv: credential.secretIv,
        secretTag: credential.secretTag,
        legacySource: "AdminMfaCredential",
        createdAt: input.usedAt,
        updatedAt: input.usedAt,
        lastUsedAt: input.usedAt,
        disabledAt: null,
      });
    }
    return { consumed: true };
  },
  replaceAdminBackupCodes: async (_db, hashes, replacedAt) => {
    if (failCredentialBackupWrite) throw new Error("MFA_BACKUP_WRITE_FAILED");
    backupCodeRows = hashes.map((codeHash, index) => ({
      id: `backup-${index + 1}`,
      userId: "admin-1",
      codeHash,
      usedAt: null,
      createdAt: replacedAt,
    }));
    if (credential) credential.backupCodesHash = [...hashes];
    return { replaced: true };
  },
  disableAdminMfaBoundary: async (_db, input) => {
    if (failDisableAuditWrite) throw new Error("MFA_DISABLE_AUDIT_WRITE_FAILED");
    if (credential) credential = { ...credential, isEnabled: false, verifiedAt: null, backupCodesHash: [], updatedAt: input.disabledAt };
    factors = [];
    backupCodeRows = [];
    webAuthnCredentials = [];
    auditEvents.push({ action: "AUTH_MFA_DISABLED", userId: "admin-1" });
    return { enabled: false };
  },
  createAdminMfaChallengeBoundary: async (_db, input) => {
    const target = input.kind === "LOGIN" ? challenges : legacyChallenges;
    const row = {
      id: `${input.kind.toLowerCase()}-challenge-${target.length + 1}`,
      userId: "admin-1",
      ticketHash: input.ticketHash,
      sessionBindingHash: input.sessionBindingHash,
      purpose: input.purpose,
      riskScore: input.riskScore,
      riskLevel: input.riskLevel,
      reasons: input.reasons,
      createdIpHash: input.ipHash,
      createdUserAgentHash: input.userAgentHash,
      attempts: 0,
      maxAttempts: input.maxAttempts,
      createdAt: input.createdAt,
      updatedAt: input.createdAt,
      expiresAt: input.expiresAt,
      consumedAt: null,
      supersededAt: null,
    };
    target.push(row);
    auditEvents.push({
      action: "AUTH_MFA_CHALLENGE_ISSUED",
      userId: "admin-1",
      details: {
        ttlMs: input.expiresAt.getTime() - input.createdAt.getTime(),
        ttlMinutes: (input.expiresAt.getTime() - input.createdAt.getTime()) / 60_000,
      },
    });
    return { challengeId: row.id };
  },
  loadAdminMfaChallengeBoundary: async (_db, input) => {
    const login = challenges.find((row) => input.ticketHashes.includes(row.ticketHash));
    const session = legacyChallenges.find((row) =>
      input.ticketHashes.includes(row.ticketHash) &&
      input.sessionBindingHashes.includes(row.sessionBindingHash)
    );
    const row = login || session;
    return row ? { ...row, kind: login ? "LOGIN" : "SESSION" } : null;
  },
  recordAdminMfaChallengeFailure: async (_db, input) => {
    const rows = input.kind === "LOGIN" ? challenges : legacyChallenges;
    const row = rows.find((entry) => entry.id === input.challengeId);
    if (!row) throw new Error("MFA_CHALLENGE_NOT_FOUND");
    row.attempts = input.attempts;
    row.updatedAt = input.failedAt;
    auditEvents.push({ action: input.action, userId: "admin-1" });
    return { recorded: true, attempts: input.attempts };
  },
  completeAdminMfaChallengeBoundary: async (_db, input) => {
    if (failCompletionAuditWrite) throw new Error("AUTH_COMPLETION_AUDIT_WRITE_FAILED");
    const rows = input.kind === "LOGIN" ? challenges : legacyChallenges;
    const row = rows.find((entry) => entry.id === input.challengeId && !entry.consumedAt);
    if (!row) throw new Error("MFA_CHALLENGE_NOT_FOUND");
    row.consumedAt = input.completedAt;
    auditEvents.push({ action: input.method === "BACKUP_CODE" ? "AUTH_MFA_BACKUP_CODE_USED" : "AUTH_MFA_SUCCESS", userId: "admin-1" });
    auditEvents.push({ action: "AUTH_MFA_LOGIN_COMPLETE", userId: "admin-1" });
    return { completed: true };
  },
  loadAdminWebAuthnCredentials: async () => ({ factors: [], legacy: webAuthnCredentials.map((row) => ({ ...row })) }),
  createAdminWebAuthnChallengeBoundary: async () => ({ challengeId: "webauthn-challenge-1", credentialIds: [] }),
  loadAdminWebAuthnChallengeBoundary: async () => null,
  completeAdminWebAuthnRegistrationBoundary: async () => ({ ok: true, credentialId: "credential-1" }),
  completeAdminWebAuthnAuthenticationBoundary: async () => ({ ok: true }),
  deleteAdminWebAuthnCredentialBoundary: async () => ({ deleted: true }),
});
mockModule("rls-waves/session-b/b01/sessionCredentialRepository.js", {
  createRefreshTokenRecord: async (db, input) => {
    const row = await db.refreshToken.create({
      data: {
        userId: input.userId,
        orgId: input.orgId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        createdAt: input.createdAt,
        createdIpHash: input.ipHash,
        createdUserAgent: input.userAgent,
        authenticatedAt: input.authenticatedAt,
        mfaVerifiedAt: input.mfaVerifiedAt,
      },
    });
    return { id: row.id, expiresAt: input.expiresAt };
  },
  revokeRefreshTokenByIdentifier: async (db, input) => {
    const result = await db.refreshToken.updateMany({
      where: { id: input.sessionId, userId: input.userId, revokedAt: null },
      data: { revokedAt: input.revokedAt, revokedReason: input.reason },
    });
    return { revoked: result.count === 1 };
  },
  revokeAllRefreshTokenRecords: (db, input) => db.refreshToken.updateMany({
    where: { userId: input.userId, revokedAt: null },
    data: { revokedAt: input.revokedAt, revokedReason: input.reason },
  }),
});
mockModule("rls-waves/session-b/b01/authenticatedSecurityRepository.js", {
  loadAuthenticatedActor: async (db) => {
    const user = await db.user.findUnique({ where: { id: "admin-1" } });
    return {
      ...user,
      licenseeId: null,
      orgId: null,
      emailVerifiedAt: new Date(),
      pendingEmail: null,
      pendingEmailRequestedAt: null,
      disabledAt: null,
      createdAt: new Date(),
      licenseeRecordId: null,
      licenseeName: null,
      licenseePrefix: null,
      licenseeBrandName: null,
      licenseeOrgId: null,
    };
  },
  loadAuthenticatedPasswordActor: (db) => db.user.findUnique({ where: { id: "admin-1" } }),
  requireRecentMfaSession: async () => ({ verifiedAt: new Date() }),
});
mockModule("services/auditService.js", {
  createAuditLogSafely: async (entry) => {
    auditEvents.push(entry);
    return { persisted: true };
  },
  createAuditLog: async (entry) => {
    auditEvents.push(entry);
    return { persisted: true };
  },
});
mockModule("services/auditLogOutboxService.js", {
  queueAuditLogOutbox: async (payload) => {
    if (failCompletionAuditWrite && [
      "AUTH_MFA_LOGIN_COMPLETE",
      "AUTH_MFA_STEP_UP_SUCCESS",
      "AUTH_WEBAUTHN_LOGIN_COMPLETE",
      "AUTH_WEBAUTHN_STEP_UP_SUCCESS",
    ].includes(payload?.action)) {
      throw new Error("AUTH_COMPLETION_AUDIT_WRITE_FAILED");
    }
    if (payload?.action === "AUTH_MFA_STEP_UP_SUCCESS") currentStepUpAuditWritten = true;
    auditEvents.push(payload);
    return `audit-${auditEvents.length}`;
  },
});
let injectedWebAuthnError = null;
const maybeFailWebAuthn = async () => {
  if (injectedWebAuthnError) throw injectedWebAuthnError;
  return { ok: true };
};
mockModule("services/auth/webauthnService.js", {
  beginAdminWebAuthnChallenge: maybeFailWebAuthn,
  beginAdminWebAuthnRegistration: maybeFailWebAuthn,
  completeAdminWebAuthnChallenge: async (_params, db) => {
    assert.strictEqual(db, prismaMock, "WebAuthn completion must use the supplied authentication transaction");
    if (injectedWebAuthnError) throw injectedWebAuthnError;
    webAuthnChallengeConsumed = true;
    webAuthnCounter += 1;
    return { ok: true, purpose: "LOGIN" };
  },
  completeAdminWebAuthnRegistration: maybeFailWebAuthn,
  deleteAdminWebAuthnCredential: maybeFailWebAuthn,
});
mockModule("services/auth/passwordService.js", {
  verifyPassword: async (_hash, password) => password === "correct-password",
});
const activeSession = (claims) => ({
  sessionStage: "ACTIVE",
  accessToken: "active-access-token",
  refreshToken: "active-refresh-token",
  refreshTokenExpiresAt: new Date(Date.now() + 60_000),
  user: { id: claims.userId, email: claims.email, role: claims.role },
  auth: { sessionStage: "ACTIVE", authAssurance: "ADMIN_MFA", mfaEnrolled: true },
});
mockModule("services/auth/authClaimsRlsContext.js", {
  issueAdminMfaSessionFromClaims: async (claims) => activeSession(claims),
  confirmAdminMfaEnrollmentAndIssueSessionFromClaims: async (claims, input) => {
    await confirmAdminMfaSetup({ userId: claims.userId, code: input.code, mode: "FIRST_ENROLLMENT" }, prismaMock);
    auditEvents.push({ action: "AUTH_MFA_ENROLLED", userId: claims.userId });
    return activeSession(claims);
  },
  confirmAdminMfaReplacementFromClaims: async (claims, input) => {
    const result = await confirmAdminMfaSetup({ userId: claims.userId, code: input.code, mode: "REPLACEMENT" }, prismaMock);
    auditEvents.push({ action: "AUTH_MFA_REPLACED", userId: claims.userId });
    return result;
  },
  withAdminMfaClaimsTransaction: (claims, capability, callback, attribution) => {
    assert.equal(capability, "database-capability");
    return prismaMock.$transaction((tx) => callback(tx, {
    userId: claims.userId,
    role: claims.role,
    organizationId: claims.orgId || null,
    licenseeId: claims.licenseeId || null,
    manufacturerId: null,
    authAssurance: claims.sessionStage === "ACTIVE" ? "mfa-verified" : "mfa-bootstrap",
    requestId: attribution.requestId,
    purpose: attribution.purpose,
    }));
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
  beginAdminMfaSetup: beginAdminMfaSetupBoundary,
  completeAdminMfaChallenge: completeAdminMfaChallengeBoundary,
  confirmAdminMfaSetup: confirmAdminMfaSetupBoundary,
  createAdminMfaChallenge: createAdminMfaChallengeBoundary,
  disableAdminMfa: disableAdminMfaBoundary,
  getAdminMfaStatus: getAdminMfaStatusBoundary,
  rotateAdminMfaBackupCodes: rotateAdminMfaBackupCodesBoundary,
  verifyAdminMfaCode: verifyAdminMfaCodeBoundary,
} = require("../dist/services/auth/mfaService");
const beginAdminMfaSetup = (input, db = prismaMock) => beginAdminMfaSetupBoundary(input, db);
const completeAdminMfaChallenge = (input, db = prismaMock) => completeAdminMfaChallengeBoundary(input, db);
const confirmAdminMfaSetup = (input, db = prismaMock) => confirmAdminMfaSetupBoundary(input, db);
const createAdminMfaChallenge = (input, db = prismaMock) => createAdminMfaChallengeBoundary(input, db);
const disableAdminMfa = (userId, db = prismaMock, audit) => disableAdminMfaBoundary(userId, db, audit);
const getAdminMfaStatus = (userId, db = prismaMock) => getAdminMfaStatusBoundary(userId, db);
const rotateAdminMfaBackupCodes = (input, db = prismaMock) => rotateAdminMfaBackupCodesBoundary(input, db);
const verifyAdminMfaCode = (input, db = prismaMock) => verifyAdminMfaCodeBoundary(input, db);
const { verifyTotpToken } = require("../dist/services/auth/totpMfaProvider");
const {
  beginAdminMfaSetupController,
  beginAdminWebAuthnSetupController,
  completeAdminMfaChallengeController,
  completeAdminWebAuthnChallengeController,
  confirmAdminMfaSetupController,
  disableAdminMfaController,
  getAdminMfaStatusController,
} = require("../dist/controllers/authAdminSecurityController");
const { adminMfaStepUpController } = require("../dist/controllers/authSessionController");
const { sealCookieToken } = require("../dist/services/auth/cookieTokenProtectionService");
const { hashRefreshToken } = require("../dist/services/auth/tokenService");

const controllerResponse = () => ({
  statusCode: 200,
  body: null,
  cookies: [],
  clearedCookies: [],
  status(code) {
    this.statusCode = code;
    return this;
  },
  json(body) {
    this.body = body;
    return this;
  },
  cookie(name, value, options) {
    this.cookies.push({ name, value, options });
    return this;
  },
  clearCookie(name, options) {
    this.clearedCookies.push({ name, options });
    return this;
  },
});

const controllerRequest = (sessionStage, body = {}, cookies = {}, sessionId = "bootstrap-session-1") => ({
  body,
  cookies,
  databaseSessionCapability: "database-capability",
  ip: "127.0.0.1",
  user: {
    userId: "admin-1",
    email: "admin@example.com",
    role: "SUPER_ADMIN",
    sessionStage,
    authAssurance: sessionStage === "ACTIVE" ? "ADMIN_MFA" : "PASSWORD",
    mfaVerifiedAt: sessionStage === "ACTIVE" ? new Date() : null,
    sessionId,
  },
  get: (name) => String(name || "").toLowerCase() === "user-agent" ? "test-agent" : "test-request-id",
});

const reset = async () => {
  credential = null;
  challenges = [];
  legacyChallenges = [];
  factors = [];
  backupCodeRows = [];
  webAuthnCredentials = [];
  refreshTokens = [];
  auditEvents = [];
  loggerEvents = [];
  failMfaStateRead = false;
  failPendingFactorWrite = false;
  failCredentialBackupWrite = false;
  failDisableAuditWrite = false;
  failSessionWrite = false;
  failCompletionAuditWrite = false;
  webAuthnChallengeConsumed = false;
  webAuthnCounter = 0;
  injectedWebAuthnError = null;
  transactionTail = Promise.resolve();
  const setup = await beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock);
  await confirmAdminMfaSetup({ userId: "admin-1", code: totp(setup.secret), mode: "FIRST_ENROLLMENT" }, prismaMock);
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
  }, prismaMock);

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
  credential = null;
  factors = [];
  backupCodeRows = [];
  webAuthnCredentials = [];
  transactionTail = Promise.resolve();
  const controllerBeginResponse = controllerResponse();
  await beginAdminMfaSetupController(controllerRequest("MFA_BOOTSTRAP"), controllerBeginResponse);
  assert.strictEqual(controllerBeginResponse.statusCode, 200, JSON.stringify({ body: controllerBeginResponse.body, loggerEvents }));
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: controllerBeginResponse.body.data.backupCodes[0] }, prismaMock)),
    "INVALID_MFA_CODE",
    "pending recovery codes must not authenticate before TOTP confirmation"
  );
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: totp(controllerBeginResponse.body.data.secret) }, prismaMock)),
    "INVALID_MFA_CODE",
    "pending TOTP factors must not authenticate before confirmation"
  );
  const controllerConfirmResponse = controllerResponse();
  await confirmAdminMfaSetupController(
    controllerRequest("MFA_BOOTSTRAP", { code: totp(controllerBeginResponse.body.data.secret) }),
    controllerConfirmResponse
  );
  assert.strictEqual(controllerConfirmResponse.statusCode, 200, JSON.stringify({ body: controllerConfirmResponse.body, loggerEvents }));
  assert.strictEqual(controllerConfirmResponse.body.data.auth.sessionStage, "ACTIVE");
  assert.deepStrictEqual(
    controllerConfirmResponse.cookies.map((entry) => entry.name).sort(),
    ["aq_access", "aq_csrf", "aq_refresh"],
    "successful first enrollment must preserve active-session cookie issuance"
  );
  assert(!("accessToken" in controllerConfirmResponse.body.data), "raw session tokens must remain absent from the response body");
  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_ENROLLED"), "first enrollment must queue durable audit evidence");

  const loginChallenge = await makeChallenge();
  const loginAuditCount = auditEvents.length;
  failSessionWrite = true;
  const failedLoginResponse = controllerResponse();
  await completeAdminMfaChallengeController(controllerRequest("MFA_BOOTSTRAP", {
    ticket: loginChallenge.ticket,
    method: "backup_code",
    code: controllerBeginResponse.body.data.backupCodes[0],
  }), failedLoginResponse);
  assert.strictEqual(failedLoginResponse.statusCode, 409);
  assert.strictEqual(challenges[0].consumedAt, null, "session failure must roll back MFA challenge consumption");
  assert(backupCodeRows.every((row) => row.usedAt === null), "session failure must roll back backup-code consumption");
  assert.strictEqual(refreshTokens.length, 0, "session failure must not leave a refresh token");
  assert.strictEqual(auditEvents.length, loginAuditCount, "session failure must roll back completion outbox events");
  assert.strictEqual(failedLoginResponse.cookies.length, 0, "failed transactions must not set auth cookies");
  failSessionWrite = false;
  const successfulLoginResponse = controllerResponse();
  await completeAdminMfaChallengeController(controllerRequest("MFA_BOOTSTRAP", {
    ticket: loginChallenge.ticket,
    method: "backup_code",
    code: controllerBeginResponse.body.data.backupCodes[0],
  }), successfulLoginResponse);
  assert.strictEqual(successfulLoginResponse.statusCode, 200, JSON.stringify({
    body: successfulLoginResponse.body,
    loggerEvents,
  }));
  assert(challenges[0].consumedAt, "successful retry must consume the same MFA challenge");
  assert.strictEqual(backupCodeRows.filter((row) => row.usedAt).length, 1, "successful retry must consume one backup code");
  assert.strictEqual(refreshTokens.length, 1, "successful retry must create one refresh token");

  const auditFailureChallenge = await makeChallenge();
  const preAuditFailureRefreshCount = refreshTokens.length;
  const preAuditFailureEventCount = auditEvents.length;
  failCompletionAuditWrite = true;
  const auditFailureResponse = controllerResponse();
  await completeAdminMfaChallengeController(controllerRequest("MFA_BOOTSTRAP", {
    ticket: auditFailureChallenge.ticket,
    method: "backup_code",
    code: controllerBeginResponse.body.data.backupCodes[1],
  }), auditFailureResponse);
  assert.strictEqual(auditFailureResponse.statusCode, 409);
  assert.strictEqual(challenges[1].consumedAt, null, "audit failure must roll back MFA challenge consumption");
  assert.strictEqual(backupCodeRows.filter((row) => row.usedAt).length, 1, "audit failure must preserve the next backup code");
  assert.strictEqual(refreshTokens.length, preAuditFailureRefreshCount, "audit failure must roll back the new refresh token");
  assert.strictEqual(auditEvents.length, preAuditFailureEventCount, "audit failure must not leave a partial outbox event");
  failCompletionAuditWrite = false;

  const currentRefresh = "current-step-up-refresh";
  refreshTokens.push({
    id: "current-step-up-session",
    userId: "admin-1",
    tokenHash: hashRefreshToken(currentRefresh),
    revokedAt: null,
    revokedReason: null,
  });
  const stepUpRefreshCount = refreshTokens.length;
  currentStepUpAuditWritten = false;
  failCompletionAuditWrite = true;
  const failedStepUpResponse = controllerResponse();
  await adminMfaStepUpController(controllerRequest("ACTIVE", {
    code: controllerBeginResponse.body.data.backupCodes[2],
  }, {
    aq_refresh: sealCookieToken(currentRefresh, "auth.refresh"),
  }, "current-step-up-session"), failedStepUpResponse);
  assert.strictEqual(failedStepUpResponse.statusCode, 400);
  assert.strictEqual(backupCodeRows.filter((row) => row.usedAt).length, 1, "step-up audit failure must preserve the backup code");
  assert.strictEqual(refreshTokens.length, stepUpRefreshCount, "step-up audit failure must roll back refresh creation");
  assert.strictEqual(refreshTokens.find((row) => row.id === "current-step-up-session").revokedAt, null, "step-up audit failure must preserve the current session");
  failCompletionAuditWrite = false;
  currentStepUpAuditWritten = false;
  const successfulStepUpResponse = controllerResponse();
  await adminMfaStepUpController(controllerRequest("ACTIVE", {
    code: controllerBeginResponse.body.data.backupCodes[2],
  }, {
    aq_refresh: sealCookieToken(currentRefresh, "auth.refresh"),
  }, "current-step-up-session"), successfulStepUpResponse);
  assert.strictEqual(successfulStepUpResponse.statusCode, 200, JSON.stringify({ body: successfulStepUpResponse.body, loggerEvents }));
  assert.strictEqual(backupCodeRows.filter((row) => row.usedAt).length, 2, "successful step-up must consume the backup code once");
  assert(refreshTokens.find((row) => row.id === "current-step-up-session").revokedAt, "successful step-up must replace the current refresh session");
  assert.strictEqual(refreshTokens.length, stepUpRefreshCount + 1, "successful step-up must create exactly one replacement session");

  failSessionWrite = true;
  const failedWebAuthnResponse = controllerResponse();
  await completeAdminWebAuthnChallengeController(controllerRequest("MFA_BOOTSTRAP", {
    ticket: "webauthn-ticket-1",
    credential: {
      id: "credential-1",
      rawId: "credential-1",
      type: "public-key",
      response: {
        clientDataJSON: "client-data",
        authenticatorData: "auth-data",
        signature: "signature",
      },
    },
  }), failedWebAuthnResponse);
  assert.strictEqual(failedWebAuthnResponse.statusCode, 400);
  assert.strictEqual(webAuthnChallengeConsumed, false, "session failure must roll back WebAuthn challenge consumption");
  assert.strictEqual(webAuthnCounter, 0, "session failure must roll back WebAuthn counter advancement");
  assert.strictEqual(failedWebAuthnResponse.cookies.length, 0, "failed WebAuthn transaction must not set cookies");
  failSessionWrite = false;
  const successfulWebAuthnResponse = controllerResponse();
  await completeAdminWebAuthnChallengeController(controllerRequest("MFA_BOOTSTRAP", {
    ticket: "webauthn-ticket-1",
    credential: {
      id: "credential-1",
      rawId: "credential-1",
      type: "public-key",
      response: {
        clientDataJSON: "client-data",
        authenticatorData: "auth-data",
        signature: "signature",
      },
    },
  }), successfulWebAuthnResponse);
  assert.strictEqual(successfulWebAuthnResponse.statusCode, 200);
  assert.strictEqual(webAuthnChallengeConsumed, true);
  assert.strictEqual(webAuthnCounter, 1);

  injectedWebAuthnError = new Error("SENTINEL_WEBAUTHN_SECRET_MATERIAL");
  const webAuthnFailureResponse = controllerResponse();
  await beginAdminWebAuthnSetupController(controllerRequest("ACTIVE"), webAuthnFailureResponse);
  assert.strictEqual(webAuthnFailureResponse.statusCode, 409);
  assert(
    !JSON.stringify(loggerEvents).includes("SENTINEL_WEBAUTHN_SECRET_MATERIAL"),
    "WebAuthn failures must not serialize uncontrolled error messages"
  );
  assert(loggerEvents.some((entry) => entry.message === "auth_webauthn_setup_begin_failed"));
  injectedWebAuthnError = null;

  credential = null;
  factors = [];
  backupCodeRows = [];
  transactionTail = Promise.resolve();
  failMfaStateRead = true;
  const controllerFailureResponse = controllerResponse();
  await beginAdminMfaSetupController(controllerRequest("MFA_BOOTSTRAP"), controllerFailureResponse);
  assert.strictEqual(controllerFailureResponse.statusCode, 503);
  assert.strictEqual(controllerFailureResponse.body.error, "MFA setup is temporarily unavailable.");
  assert.strictEqual(controllerFailureResponse.cookies.length, 0, "database failure must not issue authentication cookies");
  const statusFailureResponse = controllerResponse();
  await getAdminMfaStatusController(controllerRequest("MFA_BOOTSTRAP"), statusFailureResponse);
  assert.strictEqual(statusFailureResponse.statusCode, 503);
  assert.strictEqual(statusFailureResponse.body.error, "MFA status is temporarily unavailable.");
  assert.strictEqual(statusFailureResponse.body.data, undefined, "status failure must not be presented as unenrolled state");
  failMfaStateRead = false;

  const historicalUnconfirmed = await reset();
  credential = { ...credential, isEnabled: false, verifiedAt: null, lastUsedAt: null, backupCodesHash: [] };
  factors = factors.map((factor) => ({ ...factor, legacySource: null, lastUsedAt: null }));
  backupCodeRows = [];
  const historicalStatus = await getAdminMfaStatus("admin-1");
  assert.strictEqual(historicalStatus.enabled, false, "pre-fix unconfirmed TOTP rows must not be reported as enrolled");
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: totp(historicalUnconfirmed.secret) }, prismaMock)),
    "INVALID_MFA_CODE",
    "pre-fix unconfirmed TOTP rows must not authenticate"
  );

  const firstEnrollment = await reset();
  assert.strictEqual(credential.isEnabled, true, "first enrollment should enable TOTP after confirmation");
  assert.strictEqual(
    factors.filter((factor) => factor.type === "TOTP" && !factor.disabledAt).length,
    1,
    "first enrollment should leave exactly one enabled TOTP factor"
  );

  const enrolledSnapshot = JSON.stringify({ credential, factors, backupCodeRows });
  assert.strictEqual(
    String((await rejectError(beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock))).message),
    "MFA_ALREADY_ENROLLED",
    "a bootstrap session must not begin replacement of an enrolled factor"
  );
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows }),
    enrolledSnapshot,
    "enrolled bootstrap begin denial must not mutate MFA state"
  );
  assert.strictEqual(
    String((await rejectError(confirmAdminMfaSetup({ userId: "admin-1", code: totp(firstEnrollment.secret), mode: "FIRST_ENROLLMENT" }, prismaMock))).message),
    "MFA_ALREADY_ENROLLED",
    "a bootstrap session must not confirm replacement of an enrolled factor"
  );
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows }),
    enrolledSnapshot,
    "enrolled bootstrap confirm denial must not mutate MFA state"
  );

  factors = [];
  backupCodeRows = [];
  webAuthnCredentials = [{ id: "webauthn-preserved", userId: "admin-1" }];
  const replacementSetup = await beginAdminMfaSetup({
    userId: "admin-1",
    email: "admin@example.com",
    mode: "REPLACEMENT",
  }, prismaMock);
  assert(
    factors.some((factor) => factor.type === "TOTP" && factor.lastUsedAt && !factor.disabledAt),
    "replacement begin must preserve a legacy-only verified factor"
  );
  assert.strictEqual(
    (await verifyAdminMfaCode({ userId: "admin-1", code: totp(firstEnrollment.secret) }, prismaMock)).method,
    "TOTP",
    "replacement begin must keep the old TOTP usable until confirmation"
  );
  assert.strictEqual(
    (await verifyAdminMfaCode({ userId: "admin-1", code: firstEnrollment.backupCodes[0] }, prismaMock)).method,
    "BACKUP_CODE",
    "replacement begin must preserve legacy-only backup-code recovery until confirmation"
  );
  const replacementConfirmResponse = controllerResponse();
  await confirmAdminMfaSetupController(
    controllerRequest("ACTIVE", { code: totp(replacementSetup.secret) }),
    replacementConfirmResponse
  );
  assert.strictEqual(replacementConfirmResponse.statusCode, 200);
  assert.deepStrictEqual(replacementConfirmResponse.body, { success: true, data: { enabled: true } });
  assert.strictEqual(replacementConfirmResponse.cookies.length, 0, "active replacement must not replace session cookies");
  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_REPLACED"), "replacement must queue durable audit evidence");
  assert.strictEqual(credential.isEnabled, true, "recent-MFA replacement should enable the new factor");
  assert.strictEqual(
    factors.filter((factor) => factor.type === "TOTP" && !factor.disabledAt).length,
    1,
    "replacement confirmation should atomically retire the old TOTP factor"
  );
  const oldTotp = totp(firstEnrollment.secret);
  const newTotp = totp(replacementSetup.secret);
  if (oldTotp !== newTotp) {
    assert.strictEqual(await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: oldTotp }, prismaMock)), "INVALID_MFA_CODE");
  }
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: firstEnrollment.backupCodes[1] }, prismaMock)),
    "INVALID_MFA_CODE",
    "old unused recovery codes must be invalid after replacement confirmation"
  );
  assert.strictEqual(
    (await verifyAdminMfaCode({ userId: "admin-1", code: replacementSetup.backupCodes[0] }, prismaMock)).method,
    "BACKUP_CODE",
    "new recovery codes must become usable exactly after confirmation"
  );
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: replacementSetup.backupCodes[0] }, prismaMock)),
    "INVALID_MFA_CODE",
    "new recovery codes must be one-time"
  );
  assert.strictEqual((await getAdminMfaStatus("admin-1")).hasWebAuthn, true, "TOTP replacement must preserve WebAuthn");

  const disableSetup = await reset();
  webAuthnCredentials = [{ id: "legacy-webauthn-disable", userId: "admin-1" }];
  factors.push({
    id: "factor-webauthn-disable",
    userId: "admin-1",
    type: "WEBAUTHN",
    legacySource: null,
    lastUsedAt: new Date(),
    disabledAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });
  const disableSnapshot = JSON.stringify({ credential, factors, backupCodeRows, webAuthnCredentials });
  failDisableAuditWrite = true;
  const disableFailureResponse = controllerResponse();
  await disableAdminMfaController(
    controllerRequest("ACTIVE", { currentPassword: "correct-password", code: totp(disableSetup.secret) }),
    disableFailureResponse
  );
  assert.strictEqual(disableFailureResponse.statusCode, 400);
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows, webAuthnCredentials }),
    disableSnapshot,
    "durable audit failure must roll back code verification and every MFA disable mutation"
  );
  failDisableAuditWrite = false;
  const disableResponse = controllerResponse();
  await disableAdminMfaController(
    controllerRequest("ACTIVE", { currentPassword: "correct-password", code: totp(disableSetup.secret) }),
    disableResponse
  );
  assert.strictEqual(disableResponse.statusCode, 200);
  assert.deepStrictEqual(disableResponse.body, { success: true, data: { enabled: false } });
  assert(auditEvents.some((entry) => entry.action === "AUTH_MFA_DISABLED"), "disable must append durable audit evidence");
  assert.strictEqual((await getAdminMfaStatus("admin-1")).enabled, false, "disable must remove every MFA method");
  assert.strictEqual(credential.backupCodesHash.length, 0, "disable must clear legacy recovery hashes");
  assert.strictEqual(webAuthnCredentials.length, 0, "disable must remove legacy WebAuthn credentials");
  assert(factors.every((factor) => factor.disabledAt), "disable must retire normalized TOTP and WebAuthn factors");
  assert.strictEqual(backupCodeRows.filter((row) => !row.usedAt).length, 0, "disable must invalidate unused recovery codes");
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: totp(disableSetup.secret) }, prismaMock)),
    "INVALID_MFA_CODE",
    "disabled TOTP must not authenticate"
  );

  const rotationSetup = await reset();
  const rotationSnapshot = JSON.stringify({ credential, factors, backupCodeRows });
  failCredentialBackupWrite = true;
  assert.strictEqual(
    await rejectCode(prismaMock.$transaction((tx) =>
      rotateAdminMfaBackupCodes({ userId: "admin-1", code: totp(rotationSetup.secret) }, tx)
    )),
    "MFA_BACKUP_WRITE_FAILED"
  );
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows }),
    rotationSnapshot,
    "backup rotation failure must roll back verification and both recovery stores"
  );
  failCredentialBackupWrite = false;
  const rotated = await prismaMock.$transaction((tx) =>
    rotateAdminMfaBackupCodes({ userId: "admin-1", code: totp(rotationSetup.secret) }, tx)
  );
  assert.strictEqual(
    await rejectCode(verifyAdminMfaCode({ userId: "admin-1", code: rotationSetup.backupCodes[0] }, prismaMock)),
    "INVALID_MFA_CODE",
    "successful rotation must retire the previous recovery set"
  );
  assert.strictEqual(
    (await verifyAdminMfaCode({ userId: "admin-1", code: rotated.backupCodes[0] }, prismaMock)).method,
    "BACKUP_CODE",
    "successful rotation must publish one consistent recovery set"
  );

  credential = null;
  factors = [];
  backupCodeRows = [];
  webAuthnCredentials = [{ id: "webauthn-1", userId: "admin-1" }];
  transactionTail = Promise.resolve();
  assert.strictEqual(
    String((await rejectError(beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock))).message),
    "MFA_ALREADY_ENROLLED",
    "an existing WebAuthn factor must block bootstrap TOTP setup"
  );
  assert.strictEqual(credential, null, "WebAuthn denial must occur before TOTP mutation");

  webAuthnCredentials = [];
  failMfaStateRead = true;
  transactionTail = Promise.resolve();
  const unavailableSnapshot = JSON.stringify({ credential, factors, backupCodeRows });
  assert.strictEqual(
    String((await rejectError(beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock))).message),
    "MFA_STATE_DATABASE_UNAVAILABLE",
    "MFA state read failures must fail closed"
  );
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows }),
    unavailableSnapshot,
    "MFA state read failure must roll back without mutation"
  );

  failMfaStateRead = false;
  failPendingFactorWrite = true;
  transactionTail = Promise.resolve();
  const writeFailureSnapshot = JSON.stringify({ credential, factors, backupCodeRows });
  assert.strictEqual(
    String((await rejectError(beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock))).message),
    "MFA_FACTOR_WRITE_FAILED"
  );
  assert.strictEqual(
    JSON.stringify({ credential, factors, backupCodeRows }),
    writeFailureSnapshot,
    "a partial enrollment write failure must roll back the credential update"
  );

  failPendingFactorWrite = false;
  credential = null;
  factors = [];
  backupCodeRows = [];
  transactionTail = Promise.resolve();
  const lockCallsBeforeRace = advisoryLockCalls;
  const concurrent = await Promise.allSettled([
    beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock),
    beginAdminMfaSetup({ userId: "admin-1", email: "admin@example.com", mode: "FIRST_ENROLLMENT" }, prismaMock),
  ]);
  assert.strictEqual(concurrent.filter((result) => result.status === "fulfilled").length, 1);
  assert.strictEqual(concurrent.filter((result) => result.status === "rejected").length, 1);
  assert.strictEqual(
    String(concurrent.find((result) => result.status === "rejected").reason?.message || ""),
    "MFA_SETUP_ALREADY_STARTED"
  );
  assert.strictEqual(advisoryLockCalls - lockCallsBeforeRace, 2, "each enrollment transaction must acquire the user lock");
  assert.strictEqual(
    factors.filter((factor) => factor.legacySource === "MFA_ENROLLMENT_PENDING").length,
    1,
    "concurrent first enrollment must leave one confirmable pending factor"
  );
  const raceWinner = concurrent.find((result) => result.status === "fulfilled").value;
  await confirmAdminMfaSetup({ userId: "admin-1", code: totp(raceWinner.secret), mode: "FIRST_ENROLLMENT" }, prismaMock);

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
  }, prismaMock);

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
  }, prismaMock);

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
  }, prismaMock);
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
  }, prismaMock);
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
  const stableSessionSetup = await beginAdminMfaSetup({
    userId: "admin-1",
    email: "admin@example.com",
    mode: "REPLACEMENT",
  });
  await confirmAdminMfaSetup({
    userId: "admin-1",
    code: totp(stableSessionSetup.secret),
    mode: "REPLACEMENT",
  });
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
  const duplicateSetup = await beginAdminMfaSetup({
    userId: "admin-1",
    email: "admin@example.com",
    mode: "REPLACEMENT",
  });
  await confirmAdminMfaSetup({
    userId: "admin-1",
    code: totp(duplicateSetup.secret),
    mode: "REPLACEMENT",
  });
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
  assert(
    backupCodeRows.every((row) => String(row.codeHash || "").startsWith("scrypt-sha256:")),
    "new MFA backup-code rows must use the strengthened backup-code hash format"
  );
  assert(
    credential.backupCodesHash.every((hash) => String(hash || "").startsWith("scrypt-sha256:")),
    "legacy MFA backup-code mirror must use the strengthened backup-code hash format"
  );
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

#!/usr/bin/env node

const crypto = require("crypto");
const argon2 = require("argon2");
const { PrismaClient, UserRole, UserStatus } = require("@prisma/client");

const CONFIRMATION_PHRASE = "MSCQR_CREATE_LAUNCH_SMOKE_USERS";
const MFA_CONFIRMATION_PHRASE = "MSCQR_REFRESH_LAUNCH_SMOKE_ADMIN_MFA";
const PASSWORD_LENGTH = 28;

const ROLE_CONFIGS = [
  {
    key: "superAdmin",
    emailEnv: "LAUNCH_SMOKE_SUPERADMIN_EMAIL",
    passwordEnv: "LAUNCH_SMOKE_SUPERADMIN_PASSWORD",
    name: "MSCQR Launch Smoke Platform",
    role: UserRole.SUPER_ADMIN,
    adminMfaRequired: true,
  },
  {
    key: "licenseeAdmin",
    emailEnv: "LAUNCH_SMOKE_LICENSEE_ADMIN_EMAIL",
    passwordEnv: "LAUNCH_SMOKE_LICENSEE_ADMIN_PASSWORD",
    name: "MSCQR Launch Smoke Licensee",
    role: UserRole.LICENSEE_ADMIN,
    adminMfaRequired: true,
  },
  {
    key: "manufacturer",
    emailEnv: "LAUNCH_SMOKE_MANUFACTURER_EMAIL",
    passwordEnv: "LAUNCH_SMOKE_MANUFACTURER_PASSWORD",
    name: "MSCQR Launch Smoke Manufacturer",
    role: UserRole.MANUFACTURER,
    adminMfaRequired: false,
  },
];

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const print = (payload) => console.log(JSON.stringify(payload, null, 2));

const maskEmail = (value) => {
  const email = String(value || "").trim().toLowerCase();
  const [local, domain] = email.split("@");
  if (!local || !domain) return email ? "[invalid-email]" : "";
  const visible = local.length <= 2 ? `${local[0] || "*"}*` : `${local.slice(0, 2)}***${local.slice(-1)}`;
  return `${visible}@${domain}`;
};

const randomFrom = (alphabet) => alphabet[crypto.randomInt(0, alphabet.length)];

const shuffle = (items) => {
  for (let index = items.length - 1; index > 0; index -= 1) {
    const swapIndex = crypto.randomInt(0, index + 1);
    [items[index], items[swapIndex]] = [items[swapIndex], items[index]];
  }
  return items;
};

const generateStrongPassword = (length = PASSWORD_LENGTH) => {
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const digits = "23456789";
  const symbols = "!@#$%^&*()-_=+[]{}";
  const alphabet = `${lower}${upper}${digits}${symbols}`;
  const chars = [randomFrom(lower), randomFrom(upper), randomFrom(digits), randomFrom(symbols)];
  while (chars.length < Math.max(length, 16)) chars.push(randomFrom(alphabet));
  return shuffle(chars).join("");
};

const validatePassword = (password, envName) => {
  if (password.length < 16) throw new Error(`${envName} must be at least 16 characters.`);
  if (/\s/.test(password)) throw new Error(`${envName} must not contain whitespace.`);
  return password;
};

const readRequiredEmail = (env, name) => {
  const value = String(env[name] || "").trim().toLowerCase();
  if (!value || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
    throw new Error(`${name} must be set to a staging-owned launch-test email address.`);
  }
  return value;
};

const assertSeedGuards = (env = process.env) => {
  if (!isTruthy(env.LAUNCH_SMOKE_SEED_ENABLED)) {
    throw new Error("LAUNCH_SMOKE_SEED_ENABLED=true is required.");
  }
  if (!["production", "staging"].includes(String(env.NODE_ENV || "").trim())) {
    throw new Error("NODE_ENV must be production or staging.");
  }
  if (String(env.LAUNCH_SMOKE_CONFIRM || "").trim() !== CONFIRMATION_PHRASE) {
    throw new Error(`LAUNCH_SMOKE_CONFIRM must equal ${CONFIRMATION_PHRASE}.`);
  }
  if (!String(env.DATABASE_URL || "").trim()) {
    throw new Error("DATABASE_URL must be present in the process environment; it will not be printed.");
  }
};

const readConfig = (env = process.env) => {
  assertSeedGuards(env);
  const refreshAdminMfa = isTruthy(env.LAUNCH_SMOKE_REFRESH_ADMIN_MFA);
  if (refreshAdminMfa && String(env.LAUNCH_SMOKE_MFA_CONFIRM || "").trim() !== MFA_CONFIRMATION_PHRASE) {
    throw new Error(`LAUNCH_SMOKE_MFA_CONFIRM must equal ${MFA_CONFIRMATION_PHRASE} when MFA freshness is requested.`);
  }

  return {
    environment: String(env.NODE_ENV || "").trim(),
    licenseePrefix: String(env.LAUNCH_SMOKE_LICENSEE_PREFIX || "LSMK").trim().toUpperCase(),
    reactivateDeleted: isTruthy(env.LAUNCH_SMOKE_REACTIVATE_DELETED),
    allowExistingNameMismatch: isTruthy(env.LAUNCH_SMOKE_ALLOW_EXISTING_NAME_MISMATCH),
    refreshAdminMfa,
    redactCredentials: isTruthy(env.LAUNCH_SMOKE_REDACT_CREDENTIALS),
    users: ROLE_CONFIGS.map((roleConfig) => {
      const providedPassword = String(env[roleConfig.passwordEnv] || "");
      const generated = !providedPassword;
      const password = validatePassword(providedPassword || generateStrongPassword(), roleConfig.passwordEnv);
      return {
        ...roleConfig,
        email: readRequiredEmail(env, roleConfig.emailEnv),
        password,
        passwordSource: generated ? "generated" : "env",
      };
    }),
  };
};

const assertSmokeOwnedUser = (existingUser, expectedName, options) => {
  if (!existingUser) return;
  if (existingUser.deletedAt && !options.reactivateDeleted) {
    throw new Error(`Existing user ${maskEmail(existingUser.email)} is soft-deleted; set LAUNCH_SMOKE_REACTIVATE_DELETED=true to reactivate intentionally.`);
  }
  if (existingUser.name !== expectedName && !options.allowExistingNameMismatch) {
    throw new Error(
      `Existing user ${maskEmail(existingUser.email)} is not named "${expectedName}"; refusing to mutate a non-launch-smoke account.`
    );
  }
};

const assertSmokeOwnedLicensee = (licensee) => {
  if (!licensee) return;
  if (licensee.name !== "MSCQR Launch Smoke Licensee" && licensee.brandName !== "MSCQR Launch Smoke Licensee") {
    throw new Error(`Licensee prefix ${licensee.prefix} already belongs to a non-launch-smoke tenant; choose LAUNCH_SMOKE_LICENSEE_PREFIX.`);
  }
};

const buildCredentialOutput = (users, redactCredentials) =>
  Object.fromEntries(
    users.map((user) => [
      user.key,
      {
        email: user.email,
        password: redactCredentials ? "[redacted]" : user.password,
        passwordSource: user.passwordSource,
      },
    ])
  );

const buildRedactedEvidence = ({ environment, licenseePrefix, refreshAdminMfa, userResults, auditId }) => ({
  generatedAt: new Date().toISOString(),
  environment,
  queryScope: "launch smoke user seed; operator-triggered DB mutation",
  licenseePrefix,
  users: userResults.map((user) => ({
    roleKey: user.key,
    email: maskEmail(user.email),
    role: user.role,
    userId: user.userId,
    action: user.action,
    adminMfaFreshened: Boolean(user.adminMfaFreshened),
  })),
  adminMfa: refreshAdminMfa
    ? "Fresh admin MFA markers were refreshed only for launch-smoke admin users."
    : "Admin MFA was not modified; manual MFA setup/challenge may be required before real-auth smoke.",
  auditId: auditId || null,
});

const hashPassword = (password) => argon2.hash(password, { type: argon2.argon2id });

const ensureLicensee = async (prisma, config) => {
  const existing = await prisma.licensee.findUnique({ where: { prefix: config.licenseePrefix } });
  assertSmokeOwnedLicensee(existing);
  if (existing) {
    await prisma.organization.update({
      where: { id: existing.orgId },
      data: { name: "MSCQR Launch Smoke Licensee", isActive: true },
    });
    return prisma.licensee.update({
      where: { id: existing.id },
      data: {
        name: "MSCQR Launch Smoke Licensee",
        brandName: "MSCQR Launch Smoke Licensee",
        isActive: true,
        suspendedAt: null,
        suspendedReason: null,
      },
    });
  }

  const org = await prisma.organization.create({
    data: { name: "MSCQR Launch Smoke Licensee", isActive: true },
  });
  return prisma.licensee.create({
    data: {
      orgId: org.id,
      name: "MSCQR Launch Smoke Licensee",
      prefix: config.licenseePrefix,
      brandName: "MSCQR Launch Smoke Licensee",
      isActive: true,
    },
  });
};

const upsertLaunchUser = async (prisma, config, userConfig, licensee) => {
  const existing = await prisma.user.findUnique({ where: { email: userConfig.email } });
  assertSmokeOwnedUser(existing, userConfig.name, config);
  const passwordHash = await hashPassword(userConfig.password);
  const scoped = userConfig.key === "superAdmin" ? { orgId: null, licenseeId: null } : { orgId: licensee.orgId, licenseeId: licensee.id };
  const data = {
    email: userConfig.email,
    passwordHash,
    name: userConfig.name,
    role: userConfig.role,
    status: UserStatus.ACTIVE,
    isActive: true,
    disabledAt: null,
    disabledReason: null,
    deletedAt: null,
    emailVerifiedAt: new Date(),
    failedLoginAttempts: 0,
    lockedUntil: null,
    ...scoped,
  };

  const user = existing
    ? await prisma.user.update({ where: { id: existing.id }, data })
    : await prisma.user.create({ data });

  return { user, action: existing ? "updated" : "created" };
};

const refreshAdminMfaMarker = async (prisma, userId) => {
  const now = new Date();
  await prisma.adminMfaCredential.upsert({
    where: { userId },
    create: {
      userId,
      secretCiphertext: `launch-smoke:${crypto.randomBytes(24).toString("hex")}`,
      secretIv: `launch-smoke:${crypto.randomBytes(12).toString("hex")}`,
      secretTag: `launch-smoke:${crypto.randomBytes(16).toString("hex")}`,
      backupCodesHash: [],
      isEnabled: true,
      verifiedAt: now,
      lastUsedAt: now,
    },
    update: {
      isEnabled: true,
      verifiedAt: now,
      lastUsedAt: now,
      backupCodesHash: [],
    },
  });
};

const seedLaunchSmokeUsers = async (config, prisma = new PrismaClient()) => {
  const licensee = await ensureLicensee(prisma, config);
  const userResults = [];

  for (const userConfig of config.users) {
    const { user, action } = await upsertLaunchUser(prisma, config, userConfig, licensee);
    if (userConfig.key === "manufacturer") {
      await prisma.manufacturerLicenseeLink.upsert({
        where: { manufacturerId_licenseeId: { manufacturerId: user.id, licenseeId: licensee.id } },
        create: { manufacturerId: user.id, licenseeId: licensee.id, isPrimary: true },
        update: { isPrimary: true },
      });
    }
    if (config.refreshAdminMfa && userConfig.adminMfaRequired) {
      await refreshAdminMfaMarker(prisma, user.id);
    }
    userResults.push({
      key: userConfig.key,
      email: user.email,
      role: user.role,
      userId: user.id,
      action,
      adminMfaFreshened: config.refreshAdminMfa && userConfig.adminMfaRequired,
    });
  }

  const audit = await prisma.auditLog.create({
    data: {
      userId: userResults.find((user) => user.key === "superAdmin")?.userId || null,
      orgId: licensee.orgId,
      licenseeId: licensee.id,
      action: "LAUNCH_SMOKE_USERS_SEEDED",
      entityType: "LaunchSmoke",
      entityId: licensee.id,
      details: {
        environment: config.environment,
        licenseePrefix: config.licenseePrefix,
        refreshAdminMfa: config.refreshAdminMfa,
        users: userResults.map((user) => ({
          key: user.key,
          email: maskEmail(user.email),
          role: user.role,
          action: user.action,
          adminMfaFreshened: user.adminMfaFreshened,
        })),
      },
    },
  });

  return {
    ok: true,
    credentials: buildCredentialOutput(config.users, config.redactCredentials),
    redactedEvidence: buildRedactedEvidence({
      environment: config.environment,
      licenseePrefix: config.licenseePrefix,
      refreshAdminMfa: config.refreshAdminMfa,
      userResults,
      auditId: audit.id,
    }),
  };
};

const main = async () => {
  let prisma;
  try {
    const config = readConfig(process.env);
    prisma = new PrismaClient();
    const result = await seedLaunchSmokeUsers(config, prisma);
    print(result);
  } catch (error) {
    print({
      ok: false,
      errorCode: "LAUNCH_SMOKE_SEED_REFUSED",
      diagnostic: error instanceof Error ? error.message : "Launch smoke seed refused.",
    });
    process.exitCode = 1;
  } finally {
    await prisma?.$disconnect?.().catch(() => undefined);
  }
};

if (require.main === module) {
  main();
}

module.exports = {
  CONFIRMATION_PHRASE,
  MFA_CONFIRMATION_PHRASE,
  PASSWORD_LENGTH,
  ROLE_CONFIGS,
  assertSeedGuards,
  buildCredentialOutput,
  buildRedactedEvidence,
  generateStrongPassword,
  isTruthy,
  maskEmail,
  readConfig,
  validatePassword,
};

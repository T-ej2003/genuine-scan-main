#!/usr/bin/env node
import crypto from "node:crypto";
import process from "node:process";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const argon2 = require("argon2");
const { PrismaClient } = require("@prisma/client");

const marker = "production-green-pretraffic-canary-v1";
const uuid = (label) => {
  const hex = crypto.createHash("sha256").update(`mscqr:${marker}:${label}`).digest("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
};
const ids = Object.freeze({
  organization: uuid("organization"),
  licensee: uuid("licensee"),
  isolationOrganization: uuid("isolation-organization"),
  isolationLicensee: uuid("isolation-licensee"),
  ordinaryUser: uuid("ordinary-user"),
  adminUser: uuid("admin-user"),
  ordinaryMfa: uuid("ordinary-mfa"),
  adminMfa: uuid("admin-mfa"),
  audit: uuid("audit"),
});
export const PRODUCTION_GREEN_CANARY_IDS = ids;

const normalizedEmail = (value, name) => {
  const email = String(value || "").trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error(`${name} is missing or invalid.`);
  return email;
};

export function validateCanaryEnvironment(env = process.env) {
  const approval = JSON.parse(String(env.MSCQR_PRODUCTION_RLS_APPROVAL_ARTIFACT || "{}"));
  const value = {
    ordinaryEmail: normalizedEmail(env.MSCQR_CANARY_ORDINARY_EMAIL, "ordinary canary email"),
    ordinaryPassword: String(env.MSCQR_CANARY_ORDINARY_PASSWORD || ""),
    ordinaryMfaSecret: String(env.MSCQR_CANARY_ORDINARY_MFA_SECRET || "").trim(),
    adminEmail: normalizedEmail(env.MSCQR_CANARY_ADMIN_EMAIL, "administrator canary email"),
    adminPassword: String(env.MSCQR_CANARY_ADMIN_PASSWORD || ""),
    adminMfaSecret: String(env.MSCQR_CANARY_ADMIN_MFA_SECRET || "").trim(),
    encryptionKey: String(env.AUTH_MFA_ENCRYPTION_KEY || "").trim(),
    approvalId: String(approval.approvalId || "").trim(),
    ticketId: String(approval.ticketId || "").trim(),
    checker: String(approval.checkerIdentity || approval.independentCheckerIdentity || "").trim(),
  };
  if (value.ordinaryEmail === value.adminEmail
      || value.ordinaryPassword.length < 20
      || value.adminPassword.length < 20
      || !/^[A-Z2-7]{16,128}$/i.test(value.ordinaryMfaSecret)
      || !/^[A-Z2-7]{16,128}$/i.test(value.adminMfaSecret)
      || value.ordinaryMfaSecret === value.adminMfaSecret
      || value.encryptionKey.length < 32
      || !value.approvalId
      || !value.ticketId
      || !value.checker) {
    throw new Error("Production green canary provisioning inputs are incomplete or unsafe.");
  }
  return value;
}

const encrypt = (plaintext, encryptionKey) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    crypto.createHash("sha256").update(encryptionKey).digest(),
    iv
  );
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    secretCiphertext: ciphertext.toString("base64"),
    secretIv: iv.toString("base64"),
    secretTag: cipher.getAuthTag().toString("base64"),
  };
};

const passwordHash = (value) => argon2.hash(value, {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
});

export async function provisionProductionGreenCanaries(prisma, config) {
  const [ordinaryHash, adminHash] = await Promise.all([
    passwordHash(config.ordinaryPassword),
    passwordHash(config.adminPassword),
  ]);
  const now = new Date();
  const metadata = { managedBy: marker, approvalId: config.approvalId };

  return prisma.$transaction(async (tx) => {
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtextextended(${marker}, 0))`;
    const users = await tx.user.findMany({ select: { id: true, email: true, role: true, metadata: true } });
    if (users.some((user) =>
      ![config.ordinaryEmail, config.adminEmail].includes(user.email)
      || user.metadata?.managedBy !== marker
      || (user.email === config.ordinaryEmail && (user.id !== ids.ordinaryUser || user.role !== "LICENSEE_ADMIN"))
      || (user.email === config.adminEmail && (user.id !== ids.adminUser || user.role !== "PLATFORM_SUPER_ADMIN"))
    )) throw new Error("Canary provisioning requires an empty green database or the exact managed canary identities.");

    await tx.organization.upsert({
      where: { id: ids.organization },
      create: { id: ids.organization, name: "MSCQR Green Canary", isActive: true },
      update: { name: "MSCQR Green Canary", isActive: true },
    });
    await tx.licensee.upsert({
      where: { id: ids.licensee },
      create: {
        id: ids.licensee,
        orgId: ids.organization,
        name: "MSCQR Green Canary Licensee",
        prefix: "GRNCANARY",
        metadata,
        isActive: true,
      },
      update: { metadata, isActive: true, suspendedAt: null, suspendedReason: null },
    });
    await tx.organization.upsert({
      where: { id: ids.isolationOrganization },
      create: { id: ids.isolationOrganization, name: "MSCQR Green Isolation Control", isActive: true },
      update: { name: "MSCQR Green Isolation Control", isActive: true },
    });
    await tx.licensee.upsert({
      where: { id: ids.isolationLicensee },
      create: {
        id: ids.isolationLicensee,
        orgId: ids.isolationOrganization,
        name: "MSCQR Green Isolation Control",
        prefix: "GRNISOLATE",
        metadata,
        isActive: true,
      },
      update: { metadata, isActive: true, suspendedAt: null, suspendedReason: null },
    });
    await tx.user.upsert({
      where: { email: config.ordinaryEmail },
      create: {
        id: ids.ordinaryUser,
        email: config.ordinaryEmail,
        passwordHash: ordinaryHash,
        name: "Green Canary Licensee Admin",
        role: "LICENSEE_ADMIN",
        status: "ACTIVE",
        isActive: true,
        orgId: ids.organization,
        licenseeId: ids.licensee,
        emailVerifiedAt: now,
        metadata,
      },
      update: {
        name: "Green Canary Licensee Admin",
        role: "LICENSEE_ADMIN",
        passwordHash: ordinaryHash,
        status: "ACTIVE",
        isActive: true,
        disabledAt: null,
        deletedAt: null,
        orgId: ids.organization,
        licenseeId: ids.licensee,
        emailVerifiedAt: now,
        metadata,
      },
    });
    await tx.user.upsert({
      where: { email: config.adminEmail },
      create: {
        id: ids.adminUser,
        email: config.adminEmail,
        passwordHash: adminHash,
        name: "Green Canary Platform Admin",
        role: "PLATFORM_SUPER_ADMIN",
        status: "ACTIVE",
        isActive: true,
        emailVerifiedAt: now,
        metadata,
      },
      update: {
        name: "Green Canary Platform Admin",
        role: "PLATFORM_SUPER_ADMIN",
        passwordHash: adminHash,
        status: "ACTIVE",
        isActive: true,
        disabledAt: null,
        deletedAt: null,
        orgId: null,
        licenseeId: null,
        emailVerifiedAt: now,
        metadata,
      },
    });
    for (const [id, userId, secret] of [
      [ids.ordinaryMfa, ids.ordinaryUser, config.ordinaryMfaSecret],
      [ids.adminMfa, ids.adminUser, config.adminMfaSecret],
    ]) {
      const encrypted = encrypt(secret, config.encryptionKey);
      await tx.adminMfaCredential.upsert({
        where: { userId },
        create: { id, userId, ...encrypted, backupCodesHash: [], isEnabled: true, verifiedAt: now },
        update: { ...encrypted, backupCodesHash: [], isEnabled: true, verifiedAt: now, lastUsedAt: null },
      });
    }
    await tx.auditLog.upsert({
      where: { id: ids.audit },
      create: {
        id: ids.audit,
        action: "PRODUCTION_GREEN_CANARY_IDENTITIES_PROVISIONED",
        entityType: "ProductionGreenActivation",
        entityId: config.approvalId,
        details: {
          managedBy: marker,
          approvalId: config.approvalId,
          ticketId: config.ticketId,
          independentCheckerIdentity: config.checker,
        },
      },
      update: {
        details: {
          managedBy: marker,
          approvalId: config.approvalId,
          ticketId: config.ticketId,
          independentCheckerIdentity: config.checker,
        },
      },
    });
    return { status: users.length === 0 ? "created" : "reconciled", userCount: 2 };
  }, { isolationLevel: "Serializable" });
}

async function run() {
  if (process.env.NODE_ENV !== "production"
      || process.env.MSCQR_FULL_RLS_MODE !== "full-rls-admin-ownership"
      || process.env.MSCQR_FULL_RLS_CONFIRMATION !== "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS") {
    throw new Error("Canary provisioning is restricted to the approved production green ownership phase.");
  }
  const prisma = new PrismaClient();
  try {
    const result = await provisionProductionGreenCanaries(prisma, validateCanaryEnvironment());
    process.stdout.write(`${JSON.stringify({ status: "passed", operation: "production-green-canary-provision", ...result })}\n`);
  } finally {
    await prisma.$disconnect();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  run().catch(() => {
    process.stderr.write('{"status":"blocked","operation":"production-green-canary-provision"}\n');
    process.exitCode = 1;
  });
}

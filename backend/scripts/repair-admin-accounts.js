#!/usr/bin/env node
"use strict";

const { UserRole, UserStatus } = require("@prisma/client");

const databaseModule = require("../dist/config/database");
const { createAuditLog } = require("../dist/services/auditService");
const { createInvite } = require("../dist/services/auth/inviteService");
const { maskEmailForLog } = require("../dist/services/mailTransportService");
const { normalizeEmailAddress } = require("../dist/utils/email");

const prisma = databaseModule.default || databaseModule.prisma;

const ADMIN_EMAIL = "administration@mscqr.com";
const VICTORIA_EMAIL = "victoria@mscqr.com";

const isApply = process.argv.includes("--apply");

const safeUser = (user) =>
  user
    ? {
        id: user.id,
        email: maskEmailForLog(user.email),
        role: user.role,
        status: user.status,
        hasPassword: Boolean(user.passwordHash),
      }
    : null;

const log = (payload) => {
  console.log(JSON.stringify(payload, null, 2));
};

const ensureAdministrationSuperAdmin = async () => {
  const email = normalizeEmailAddress(ADMIN_EMAIL);
  const existing = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, role: true, status: true, passwordHash: true, isActive: true, deletedAt: true },
  });

  if (!isApply) {
    return {
      action: existing ? "would_update_administration_super_admin" : "would_create_administration_super_admin_invited",
      before: safeUser(existing),
      after: {
        email: maskEmailForLog(email),
        role: UserRole.SUPER_ADMIN,
        status: existing?.status || UserStatus.INVITED,
        isActive: true,
      },
    };
  }

  const user = existing
    ? await prisma.user.update({
        where: { id: existing.id },
        data: {
          role: UserRole.SUPER_ADMIN,
          licenseeId: null,
          orgId: null,
          isActive: true,
          deletedAt: null,
          status: existing.status || UserStatus.INVITED,
        },
        select: { id: true, email: true, role: true, status: true, passwordHash: true },
      })
    : await prisma.user.create({
        data: {
          email,
          name: "MSCQR Super Admin",
          role: UserRole.SUPER_ADMIN,
          status: UserStatus.INVITED,
          isActive: true,
          passwordHash: null,
          licenseeId: null,
          orgId: null,
        },
        select: { id: true, email: true, role: true, status: true, passwordHash: true },
      });

  await createAuditLog({
    userId: user.id,
    action: "ADMIN_ACCOUNT_REPAIR_SUPER_ADMIN",
    entityType: "User",
    entityId: user.id,
    details: {
      email: maskEmailForLog(email),
      role: UserRole.SUPER_ADMIN,
      source: "repair-admin-accounts",
    },
  });

  return { action: existing ? "updated_administration_super_admin" : "created_administration_super_admin_invited", user: safeUser(user) };
};

const ensureVictoriaPlatformAdminInvite = async (actorUserId) => {
  const email = normalizeEmailAddress(VICTORIA_EMAIL);
  const existing = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, role: true, status: true, passwordHash: true, isActive: true, deletedAt: true },
  });

  if (!isApply) {
    return {
      action: existing?.passwordHash ? "would_update_victoria_platform_admin_no_invite_needed" : "would_invite_victoria_platform_admin",
      before: safeUser(existing),
      after: {
        email: maskEmailForLog(email),
        role: UserRole.PLATFORM_SUPER_ADMIN,
        setupEmail: !existing?.passwordHash,
      },
    };
  }

  if (existing && (existing.role !== UserRole.PLATFORM_SUPER_ADMIN || existing.deletedAt || existing.isActive === false)) {
    await prisma.user.update({
      where: { id: existing.id },
      data: {
        role: UserRole.PLATFORM_SUPER_ADMIN,
        licenseeId: null,
        orgId: null,
        isActive: true,
        deletedAt: null,
      },
    });
    await createAuditLog({
      userId: actorUserId,
      action: "ADMIN_ACCOUNT_REPAIR_PLATFORM_ADMIN_ROLE",
      entityType: "User",
      entityId: existing.id,
      details: {
        email: maskEmailForLog(email),
        role: UserRole.PLATFORM_SUPER_ADMIN,
        source: "repair-admin-accounts",
      },
    });
  }

  const current = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, role: true, status: true, passwordHash: true },
  });

  if (current?.passwordHash && current.status !== UserStatus.INVITED) {
    return {
      action: "updated_victoria_platform_admin_no_invite_needed",
      user: safeUser(current),
      emailAttempted: false,
    };
  }

  const invite = await createInvite({
    email,
    name: "Victoria",
    role: UserRole.PLATFORM_SUPER_ADMIN,
    allowExistingInvitedUser: true,
    createdByUserId: actorUserId,
    ipHash: null,
    userAgent: "repair-admin-accounts",
  });

  return {
    action: "invited_victoria_platform_admin",
    inviteId: invite.inviteId,
    email: maskEmailForLog(email),
    role: invite.role,
    emailAttempted: invite.emailAttempted,
    emailDelivered: invite.emailDelivered,
    emailErrorCode: invite.emailErrorCode,
    emailDiagnostic: invite.emailDiagnostic,
  };
};

const main = async () => {
  if (!normalizeEmailAddress(ADMIN_EMAIL) || !normalizeEmailAddress(VICTORIA_EMAIL)) {
    throw new Error("Configured repair emails are invalid.");
  }

  const adminResult = await ensureAdministrationSuperAdmin();
  const admin = await prisma.user.findUnique({
    where: { email: normalizeEmailAddress(ADMIN_EMAIL) },
    select: { id: true },
  });

  const victoriaResult =
    isApply && admin?.id
      ? await ensureVictoriaPlatformAdminInvite(admin.id)
      : {
          action: "would_invite_victoria_platform_admin",
          after: {
            email: maskEmailForLog(VICTORIA_EMAIL),
            role: UserRole.PLATFORM_SUPER_ADMIN,
            setupEmail: true,
          },
        };

  log({
    mode: isApply ? "apply" : "dry-run",
    administration: adminResult,
    victoria: victoriaResult,
    tokenLogged: false,
  });
};

main()
  .catch((error) => {
    console.error("admin account repair failed:", error instanceof Error ? error.message : "Unknown error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

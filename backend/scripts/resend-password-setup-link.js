#!/usr/bin/env node
"use strict";

const { UserRole, UserStatus } = require("@prisma/client");

const databaseModule = require("../dist/config/database");
const { createAuditLog } = require("../dist/services/auditService");
const { createInvite } = require("../dist/services/auth/inviteService");
const { requestPasswordReset } = require("../dist/services/auth/passwordResetService");
const { getMailTransportDiagnostics, maskEmailForLog } = require("../dist/services/mailTransportService");
const { normalizeEmailAddress } = require("../dist/utils/email");

const prisma = databaseModule.default || databaseModule.prisma;

const DEFAULT_EMAIL = "victoria@mscqr.com";
const DEFAULT_ACTOR_EMAIL = "administration@mscqr.com";
const VALID_MODES = new Set(["auto", "setup", "reset"]);

const parseArgs = (argv) => {
  const out = {
    apply: false,
    email: DEFAULT_EMAIL,
    actorEmail: DEFAULT_ACTOR_EMAIL,
    mode: "auto",
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const [key, inlineValue] = arg.includes("=") ? arg.split(/=(.*)/s, 2) : [arg, null];
    const nextValue = () => {
      if (inlineValue !== null) return inlineValue;
      index += 1;
      return argv[index];
    };

    if (arg === "--apply") {
      out.apply = true;
    } else if (key === "--email") {
      out.email = nextValue();
    } else if (key === "--actor-email") {
      out.actorEmail = nextValue();
    } else if (key === "--mode") {
      out.mode = String(nextValue() || "").trim().toLowerCase();
    } else if (arg === "--help" || arg === "-h") {
      out.help = true;
    } else {
      throw new Error(`Unsupported argument: ${arg}`);
    }
  }

  return out;
};

const safeUser = (user) =>
  user
    ? {
        id: user.id,
        email: maskEmailForLog(user.email),
        role: user.role,
        status: user.status,
        hasPassword: Boolean(user.passwordHash),
        isActive: Boolean(user.isActive),
        deleted: Boolean(user.deletedAt),
        licenseeId: user.licenseeId || null,
        orgId: user.orgId || null,
      }
    : null;

const log = (payload) => {
  console.log(JSON.stringify(payload, null, 2));
};

const printHelp = () => {
  console.log(`Usage:
  npm --prefix backend run auth:resend-setup-link -- [--apply] [--email user@example.com] [--actor-email admin@example.com] [--mode auto|setup|reset]

Defaults:
  --email ${DEFAULT_EMAIL}
  --actor-email ${DEFAULT_ACTOR_EMAIL}
  --mode auto

Safety:
  Dry-run by default. No raw invite or reset tokens are printed.`);
};

const resolveOperation = (user, mode) => {
  const hasPassword = Boolean(user.passwordHash);
  const isInvitedWithoutPassword = user.status === UserStatus.INVITED && !hasPassword;

  if (mode === "setup") return "setup_invite";
  if (mode === "reset") return "password_reset";
  return isInvitedWithoutPassword ? "setup_invite" : "password_reset";
};

const findTargetUser = async (email) =>
  prisma.user.findUnique({
    where: { email },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      status: true,
      passwordHash: true,
      isActive: true,
      deletedAt: true,
      licenseeId: true,
      orgId: true,
    },
  });

const findActor = async (actorEmail) =>
  prisma.user.findUnique({
    where: { email: actorEmail },
    select: {
      id: true,
      email: true,
      role: true,
      status: true,
      isActive: true,
      deletedAt: true,
    },
  });

const assertOperationalPreconditions = (target, actor, operation, actorEmail) => {
  if (!target) throw new Error("Target user does not exist; refusing to create a duplicate or replacement user.");
  if (target.deletedAt || target.isActive === false || target.status === UserStatus.DISABLED) {
    throw new Error("Target user is disabled or deleted; reactivate through the audited admin path before resending auth links.");
  }

  if (operation === "setup_invite") {
    if (target.passwordHash || target.status !== UserStatus.INVITED) {
      throw new Error("Setup invite is not applicable because the target already has a password or is not INVITED.");
    }
    if (!actor) throw new Error(`Actor admin ${maskEmailForLog(actorEmail)} was not found.`);
    if (actor.deletedAt || actor.isActive === false) throw new Error("Actor admin is disabled or deleted.");
    if (![UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN].includes(actor.role)) {
      throw new Error("Actor must be SUPER_ADMIN or PLATFORM_SUPER_ADMIN for setup invite resend.");
    }
  }
};

const sendSetupInvite = async ({ target, actor }) => {
  const invite = await createInvite({
    email: target.email,
    name: target.name,
    role: target.role,
    licenseeId: target.licenseeId,
    allowExistingInvitedUser: true,
    requireExistingUser: true,
    createdByUserId: actor.id,
    ipHash: null,
    userAgent: "resend-password-setup-link",
  });

  await createAuditLog({
    userId: actor.id,
    licenseeId: target.licenseeId || undefined,
    orgId: target.orgId || undefined,
    action: "OPERATOR_PASSWORD_SETUP_LINK_RESENT",
    entityType: "User",
    entityId: target.id,
    details: {
      email: maskEmailForLog(target.email),
      inviteId: invite.inviteId,
      source: "resend-password-setup-link",
      tokenLogged: false,
      emailAttempted: invite.emailAttempted,
      emailDelivered: invite.emailDelivered,
      emailErrorCode: invite.emailErrorCode,
      emailDiagnostic: invite.emailDiagnostic,
    },
  });

  return {
    operation: "setup_invite",
    inviteId: invite.inviteId,
    emailAttempted: invite.emailAttempted,
    emailDelivered: invite.emailDelivered,
    emailErrorCode: invite.emailErrorCode,
    emailDiagnostic: invite.emailDiagnostic,
  };
};

const sendPasswordReset = async ({ target }) => {
  await requestPasswordReset({
    email: target.email,
    ipHash: null,
    userAgent: "resend-password-setup-link",
  });

  return {
    operation: "password_reset",
    requested: true,
    emailAttempted: null,
    emailDelivered: null,
    emailDiagnostic: "Password reset request accepted by auth service; inspect AUTH_EMAIL_SENT/AUTH_EMAIL_FAILED audit logs for provider status.",
  };
};

const main = async () => {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  if (!VALID_MODES.has(args.mode)) throw new Error("--mode must be one of: auto, setup, reset");

  const email = normalizeEmailAddress(args.email);
  const actorEmail = normalizeEmailAddress(args.actorEmail);
  if (!email) throw new Error("--email must be a valid email address.");
  if (!actorEmail) throw new Error("--actor-email must be a valid email address.");

  const target = await findTargetUser(email);
  const actor = await findActor(actorEmail);
  const operation = target ? resolveOperation(target, args.mode) : args.mode === "reset" ? "password_reset" : "setup_invite";
  const mail = getMailTransportDiagnostics();

  assertOperationalPreconditions(target, actor, operation, actorEmail);

  const base = {
    mode: args.apply ? "apply" : "dry-run",
    target: safeUser(target),
    actor: actor ? { id: actor.id, email: maskEmailForLog(actor.email), role: actor.role } : null,
    plannedOperation: operation,
    mail,
    tokenLogged: false,
  };

  if (!args.apply) {
    log(base);
    return;
  }

  const result = operation === "setup_invite" ? await sendSetupInvite({ target, actor }) : await sendPasswordReset({ target });
  log({
    ...base,
    result,
  });
};

main()
  .catch((error) => {
    console.error("resend password setup link failed:", error instanceof Error ? error.message : "Unknown error");
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

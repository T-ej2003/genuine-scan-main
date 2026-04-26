import { Prisma, UserRole, UserStatus } from "@prisma/client";

import prisma from "../../config/database";
import { logger } from "../../utils/logger";
import { isValidEmailAddress, normalizeEmailAddress } from "../../utils/email";
import { createAuditLogSafely } from "../auditService";
import { hashPassword } from "./passwordService";

type BootstrapResult =
  | {
      status: "disabled";
      reason: string;
    }
  | {
      status: "skipped_existing";
      userId: string;
      email: string;
      role: UserRole;
    }
  | {
      status: "created";
      userId: string;
      email: string;
      autoVerified: boolean;
    }
  | {
      status: "blocked";
      reason: string;
      email?: string;
    };

const SUPER_ADMIN_ROLES = [UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN];
const BOOTSTRAP_LOCK_KEY = 723_425_101;

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const redacted = (email: string) => {
  const [name, domain] = email.split("@");
  if (!domain) return "configured-email";
  const visible = name.slice(0, 2);
  return `${visible}${name.length > 2 ? "***" : "*"}@${domain}`;
};

const getBootstrapConfig = () => {
  const enabled = parseBool(process.env.SUPER_ADMIN_BOOTSTRAP_ENABLED, false);
  const autoVerify = parseBool(process.env.SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY, false);
  const email = normalizeEmailAddress(process.env.SUPER_ADMIN_EMAIL);
  const password = String(process.env.SUPER_ADMIN_BOOTSTRAP_PASSWORD || "");
  const name = String(process.env.SUPER_ADMIN_NAME || "Super Admin").trim() || "Super Admin";

  return { enabled, autoVerify, email, password, name };
};

const validateBootstrapConfig = (config: ReturnType<typeof getBootstrapConfig>) => {
  if (!config.enabled) return "Super admin bootstrap is disabled.";
  if (!config.email || !isValidEmailAddress(config.email)) {
    return "SUPER_ADMIN_EMAIL must be set to a valid email address.";
  }
  if (!config.password) {
    return "SUPER_ADMIN_BOOTSTRAP_PASSWORD is required when bootstrap is enabled.";
  }
  if (config.password.length < 12) {
    return "SUPER_ADMIN_BOOTSTRAP_PASSWORD must be at least 12 characters.";
  }
  return null;
};

const auditBootstrap = async (result: BootstrapResult) => {
  if (result.status === "disabled") return;

  await createAuditLogSafely({
    userId: result.status === "created" || result.status === "skipped_existing" ? result.userId : undefined,
    action:
      result.status === "created"
        ? "AUTH_SUPER_ADMIN_BOOTSTRAPPED"
        : result.status === "skipped_existing"
          ? "AUTH_SUPER_ADMIN_BOOTSTRAP_SKIPPED_EXISTING"
          : "AUTH_SUPER_ADMIN_BOOTSTRAP_BLOCKED",
    entityType: "User",
    entityId: result.status === "created" || result.status === "skipped_existing" ? result.userId : undefined,
    details: {
      status: result.status,
      email: "email" in result && result.email ? redacted(result.email) : undefined,
      role: "role" in result ? result.role : undefined,
      autoVerified: "autoVerified" in result ? result.autoVerified : undefined,
      reason: "reason" in result ? result.reason : undefined,
      source: "startup",
    },
  });
};

export const bootstrapConfiguredSuperAdmin = async (): Promise<BootstrapResult> => {
  const config = getBootstrapConfig();
  const validationError = validateBootstrapConfig(config);

  if (validationError) {
    const result: BootstrapResult = {
      status: config.enabled ? "blocked" : "disabled",
      reason: validationError,
      email: config.email || undefined,
    };
    if (config.enabled) {
      logger.error("Super admin bootstrap is blocked by unsafe configuration", {
        reason: validationError,
        email: config.email ? redacted(config.email) : null,
      });
      await auditBootstrap(result);
    }
    return result;
  }

  const passwordHash = await hashPassword(config.password);
  const now = new Date();

  const result = await prisma.$transaction(async (tx) => {
    await tx.$executeRaw(Prisma.sql`SELECT pg_advisory_xact_lock(${BOOTSTRAP_LOCK_KEY})`);

    const existingSuperAdmin = await tx.user.findFirst({
      where: {
        role: { in: SUPER_ADMIN_ROLES },
        deletedAt: null,
      },
      orderBy: { createdAt: "asc" },
      select: { id: true, email: true, role: true },
    });

    if (existingSuperAdmin) {
      return {
        status: "skipped_existing" as const,
        userId: existingSuperAdmin.id,
        email: existingSuperAdmin.email,
        role: existingSuperAdmin.role,
      };
    }

    const existingConfiguredEmail = await tx.user.findUnique({
      where: { email: config.email as string },
      select: { id: true, email: true, role: true, deletedAt: true },
    });

    if (existingConfiguredEmail) {
      return {
        status: "blocked" as const,
        reason: "Configured bootstrap email already belongs to a non-super-admin account.",
        email: existingConfiguredEmail.email,
      };
    }

    const created = await tx.user.create({
      data: {
        email: config.email as string,
        passwordHash,
        name: config.name,
        role: UserRole.SUPER_ADMIN,
        status: UserStatus.ACTIVE,
        isActive: true,
        deletedAt: null,
        disabledAt: null,
        emailVerifiedAt: config.autoVerify ? now : null,
      },
      select: { id: true, email: true },
    });

    return {
      status: "created" as const,
      userId: created.id,
      email: created.email,
      autoVerified: config.autoVerify,
    };
  });

  if (result.status === "created") {
    logger.info("Super admin bootstrap completed", {
      userId: result.userId,
      email: redacted(result.email),
      autoVerified: result.autoVerified,
    });
    if (!result.autoVerified) {
      logger.warn(
        "Bootstrap super admin was created without email verification. Set SUPER_ADMIN_BOOTSTRAP_AUTO_VERIFY=true for first production login, or verify the account through the normal email flow."
      );
    }
  } else if (result.status === "skipped_existing") {
    logger.info("Super admin bootstrap skipped because a super admin already exists", {
      userId: result.userId,
      email: redacted(result.email),
      role: result.role,
    });
  } else if (result.status === "blocked") {
    logger.error("Super admin bootstrap blocked", {
      reason: result.reason,
      email: result.email ? redacted(result.email) : null,
    });
  }

  await auditBootstrap(result);
  return result;
};

import { UserRole } from "@prisma/client";

import {
  bootstrapConfiguredSuperAdminProcedure,
  ProcedureDatabase,
} from "../../rls-waves/session-c/operatorProcedureService";
import { logger } from "../../utils/logger";
import { isValidEmailAddress, normalizeEmailAddress } from "../../utils/email";
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

export const bootstrapConfiguredSuperAdmin = async (db?: ProcedureDatabase): Promise<BootstrapResult> => {
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
    }
    return result;
  }

  if (!db) {
    const result: BootstrapResult = {
      status: "blocked",
      reason: "Super-admin bootstrap requires the deployment-only migration database identity.",
      email: config.email || undefined,
    };
    logger.error("Super admin bootstrap blocked", { reason: result.reason, email: redacted(config.email || "") });
    return result;
  }

  const environment = String(process.env.NODE_ENV || "").trim().toLowerCase();
  if (!["development", "staging", "production"].includes(environment)) {
    return { status: "blocked", reason: "NODE_ENV must identify the migration target environment.", email: config.email || undefined };
  }

  const passwordHash = await hashPassword(config.password);
  const procedureResult = await bootstrapConfiguredSuperAdminProcedure(
    {
      email: config.email as string,
      passwordHash,
      name: config.name,
      autoVerify: config.autoVerify,
      purpose: "bootstrap-configured-super-admin",
      assurance: "system-verified",
      environment: environment as "development" | "staging" | "production",
    },
    db
  );

  const result: BootstrapResult =
    procedureResult.status === "created" && procedureResult.userId && procedureResult.email
      ? {
          status: "created",
          userId: procedureResult.userId,
          email: procedureResult.email,
          autoVerified: Boolean(procedureResult.autoVerified),
        }
      : procedureResult.status === "skipped_existing" && procedureResult.userId && procedureResult.email
        ? {
            status: "skipped_existing",
            userId: procedureResult.userId,
            email: procedureResult.email,
            role:
              procedureResult.role === UserRole.PLATFORM_SUPER_ADMIN
                ? UserRole.PLATFORM_SUPER_ADMIN
                : UserRole.SUPER_ADMIN,
          }
        : {
            status: "blocked",
            reason: procedureResult.reason || "Configured super-admin bootstrap was rejected by the database boundary.",
            email: procedureResult.email || config.email || undefined,
          };

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
  return result;
};

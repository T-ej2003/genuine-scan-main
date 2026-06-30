import { Prisma, PrismaClient, UserRole } from "@prisma/client";

import { AuthenticatedSessionClaims } from "../types";
import { isManufacturerRole, isPlatformRole } from "../services/manufacturerScopeService";

export const STAGING_RLS_BATCHES_READ_FLAG = "MSCQR_STAGING_RLS_BATCHES_READ_ENABLED";
export const STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG = "MSCQR_STAGING_RLS_BATCH_ALLOCATION_MAP_ENABLED";
export const STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG =
  "MSCQR_STAGING_RLS_MANUFACTURER_PRINTERS_READ_ENABLED";

export type StagingRlsBatchReadContext = {
  userId: string;
  role: string;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  organizationId?: string | null;
  isPlatformAdmin: boolean;
};

type PrismaTransactionRunner = Pick<PrismaClient, "$transaction">;

const forbiddenRuntimeRoles = new Set(["public_verification", "printer_agent", "background_worker", "system_worker"]);
const emptyIfMissing = (value?: string | null) => value ?? "";

const parseBooleanEnv = (name: string, fallback = false) => {
  const normalized = String(process.env[name] || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const isStagingRlsBatchesReadEnabled = () =>
  parseBooleanEnv(STAGING_RLS_BATCHES_READ_FLAG, false);

export const isStagingRlsBatchAllocationMapEnabled = () =>
  parseBooleanEnv(STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG, false);

export const isStagingRlsManufacturerPrintersReadEnabled = () =>
  parseBooleanEnv(STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG, false);

export const buildStagingRlsBatchReadContext = (
  user: AuthenticatedSessionClaims
): StagingRlsBatchReadContext => {
  const role = String(user.role || "").trim();
  const userId = String(user.userId || "").trim();
  if (!userId) throw new Error("Staging RLS batch read context requires app.user_id");
  if (!role) throw new Error("Staging RLS batch read context requires app.role");

  const normalizedRole = role.toLowerCase();
  if (forbiddenRuntimeRoles.has(normalizedRole)) {
    throw new Error(`Staging RLS batch read context does not allow ${normalizedRole}`);
  }

  const isPlatformAdmin = isPlatformRole(user.role);
  if (isPlatformAdmin) {
    return {
      userId,
      role,
      licenseeId: user.licenseeId || null,
      manufacturerId: null,
      organizationId: user.orgId || null,
      isPlatformAdmin: true,
    };
  }

  if (isManufacturerRole(user.role)) {
    return {
      userId,
      role,
      licenseeId: user.licenseeId || null,
      manufacturerId: userId,
      organizationId: user.orgId || null,
      isPlatformAdmin: false,
    };
  }

  const licenseeId = String(user.licenseeId || "").trim();
  if (!licenseeId) {
    throw new Error("Staging RLS batch read context requires app.licensee_id for tenant users");
  }

  return {
    userId,
    role,
    licenseeId,
    manufacturerId: null,
    organizationId: user.orgId || null,
    isPlatformAdmin: false,
  };
};

export const setStagingRlsBatchReadContext = async (
  tx: Prisma.TransactionClient,
  context: StagingRlsBatchReadContext
) => {
  await tx.$executeRaw`
    SELECT
      set_config('app.user_id', ${context.userId}, true),
      set_config('app.role', ${context.role}, true),
      set_config('app.licensee_id', ${emptyIfMissing(context.licenseeId)}, true),
      set_config('app.manufacturer_id', ${emptyIfMissing(context.manufacturerId)}, true),
      set_config('app.organization_id', ${emptyIfMissing(context.organizationId)}, true),
      set_config('app.is_platform_admin', ${context.isPlatformAdmin ? "true" : "false"}, true)
  `;
};

export const withStagingRlsBatchReadTransaction = async <T>(
  prisma: PrismaTransactionRunner,
  user: AuthenticatedSessionClaims,
  callback: (tx: Prisma.TransactionClient, context: StagingRlsBatchReadContext) => Promise<T>
) =>
  prisma.$transaction(async (tx) => {
    const context = buildStagingRlsBatchReadContext(user);
    await setStagingRlsBatchReadContext(tx, context);
    return callback(tx, context);
  });

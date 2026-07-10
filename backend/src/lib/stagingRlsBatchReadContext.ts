import { Prisma, UserRole } from "@prisma/client";

import {
  getRlsReadPrisma,
  initializeRlsReadPrisma,
  isStagedRlsReadFlagEnabled,
  RlsReadTransactionClient,
  RlsReadTransactionRunner,
  STAGING_RLS_BATCHES_READ_FLAG,
  STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG,
  STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
} from "../config/rlsReadDatabase";
import { AuthenticatedSessionClaims } from "../types";
import { isManufacturerRole, isPlatformRole } from "../services/manufacturerScopeService";

export {
  STAGING_RLS_BATCHES_READ_FLAG,
  STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG,
  STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG,
};

export type StagingRlsBatchReadContext = {
  userId: string;
  role: string;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  organizationId?: string | null;
  isPlatformAdmin: boolean;
};

const forbiddenRuntimeRoles = new Set(["public_verification", "printer_agent", "background_worker", "system_worker"]);
const emptyIfMissing = (value?: string | null) => value ?? "";

// These are deliberately narrower than the compatibility enum. A staged RLS
// route must fail closed for a dormant role until that role has an explicit,
// separately reviewed phase-one activation decision.
export const PHASE_ONE_RLS_ACTIVE_ROLES = [
  UserRole.SUPER_ADMIN,
  UserRole.PLATFORM_SUPER_ADMIN,
  UserRole.LICENSEE_ADMIN,
  UserRole.MANUFACTURER,
] as const;

export const PHASE_ONE_RLS_DORMANT_ROLES = [
  UserRole.ORG_ADMIN,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
] as const;

const phaseOneRlsActiveRoleSet = new Set<UserRole>(PHASE_ONE_RLS_ACTIVE_ROLES);

export const isStagingRlsBatchesReadEnabled = () =>
  isStagedRlsReadFlagEnabled(STAGING_RLS_BATCHES_READ_FLAG);

export const isStagingRlsBatchAllocationMapEnabled = () =>
  isStagedRlsReadFlagEnabled(STAGING_RLS_BATCH_ALLOCATION_MAP_FLAG);

export const isStagingRlsManufacturerPrintersReadEnabled = () =>
  isStagedRlsReadFlagEnabled(STAGING_RLS_MANUFACTURER_PRINTERS_READ_FLAG);

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
  if (!phaseOneRlsActiveRoleSet.has(user.role)) {
    throw new Error("Staged RLS phase-one access is not enabled for this application role");
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
  tx: Pick<Prisma.TransactionClient, "$executeRaw">,
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
  user: AuthenticatedSessionClaims,
  callback: (tx: RlsReadTransactionClient, context: StagingRlsBatchReadContext) => Promise<T>,
  options: { transactionRunner?: RlsReadTransactionRunner } = {}
) => {
  if (options.transactionRunner && process.env.NODE_ENV !== "test") {
    throw new Error("RLS read transaction runner injection is test-only");
  }
  if (!options.transactionRunner) await initializeRlsReadPrisma();
  const transactionRunner = options.transactionRunner || getRlsReadPrisma();
  return transactionRunner.$transaction(async (tx) => {
    const context = buildStagingRlsBatchReadContext(user);
    await setStagingRlsBatchReadContext(tx, context);
    return callback(tx, context);
  });
};

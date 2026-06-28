import { Prisma, PrismaClient } from "@prisma/client";

export type RlsPrototypeTransactionContext = {
  userId?: string | null;
  role: string;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  organizationId?: string | null;
  isPlatformAdmin?: boolean;
};

type PrismaTransactionRunner = Pick<PrismaClient, "$transaction">;

const emptyIfMissing = (value?: string | null) => value ?? "";

const normalizeRole = (role: string) => role.trim();

const validateContext = (context: RlsPrototypeTransactionContext) => {
  const role = normalizeRole(context.role);
  if (!role) throw new Error("RLS prototype context requires an explicit app.role");
  if (role.toLowerCase() === "public_verification" && context.isPlatformAdmin === true) {
    throw new Error("RLS prototype public_verification context cannot be platform admin");
  }
  return role;
};

export const setRlsPrototypeContext = async (
  tx: Prisma.TransactionClient,
  context: RlsPrototypeTransactionContext
) => {
  const role = validateContext(context);

  await tx.$executeRaw`SELECT set_config('app.user_id', ${emptyIfMissing(context.userId)}, true)`;
  await tx.$executeRaw`SELECT set_config('app.role', ${role}, true)`;
  await tx.$executeRaw`SELECT set_config('app.licensee_id', ${emptyIfMissing(context.licenseeId)}, true)`;
  await tx.$executeRaw`SELECT set_config('app.manufacturer_id', ${emptyIfMissing(context.manufacturerId)}, true)`;
  await tx.$executeRaw`SELECT set_config('app.organization_id', ${emptyIfMissing(context.organizationId)}, true)`;
  await tx.$executeRaw`SELECT set_config('app.is_platform_admin', ${context.isPlatformAdmin === true ? "true" : "false"}, true)`;
};

export const withRlsPrototypeTransaction = async <T>(
  prisma: PrismaTransactionRunner,
  context: RlsPrototypeTransactionContext,
  callback: (tx: Prisma.TransactionClient) => Promise<T>
) =>
  prisma.$transaction(async (tx) => {
    await setRlsPrototypeContext(tx, context);
    return callback(tx);
  });

import { Prisma, PrismaClient } from "@prisma/client";

export const canonicalAssuranceLevels = [
  "none",
  "password-verified",
  "mfa-bootstrap",
  "mfa-verified",
  "step-up-verified",
  "system-verified",
  "operator-approved",
  "dual-approved-break-glass",
] as const;

export type CanonicalAssurance = (typeof canonicalAssuranceLevels)[number];

export type CanonicalDbContext = {
  userId: string;
  role: string;
  organizationId?: string | null;
  licenseeId?: string | null;
  manufacturerId?: string | null;
  authAssurance: CanonicalAssurance;
  requestId: string;
  purpose: string;
};

type TransactionRunner = Pick<PrismaClient, "$transaction">;
const allowedKeys = new Set([
  "userId",
  "role",
  "organizationId",
  "licenseeId",
  "manufacturerId",
  "authAssurance",
  "requestId",
  "purpose",
]);
const assuranceLevels = new Set<string>(canonicalAssuranceLevels);

const required = (value: unknown, key: string) => {
  const normalized = typeof value === "string" ? value.trim() : "";
  if (!normalized) throw new Error(`Canonical database context requires ${key}`);
  return normalized;
};

const optional = (context: Record<string, unknown>, key: string, setting: string) => {
  if (!(key in context) || context[key] == null) return "";
  return required(context[key], setting);
};

export const validateCanonicalDbContext = (input: CanonicalDbContext): CanonicalDbContext => {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Canonical database context must be an object");
  }
  const raw = input as unknown as Record<string, unknown>;
  const unknown = Object.keys(raw).filter((key) => !allowedKeys.has(key));
  if (unknown.length) throw new Error(`Canonical database context contains unknown key: ${unknown[0]}`);
  const authAssurance = required(raw.authAssurance, "app.auth_assurance");
  if (!assuranceLevels.has(authAssurance)) throw new Error("Canonical database context has an unsupported app.auth_assurance");

  return {
    userId: required(raw.userId, "app.user_id"),
    role: required(raw.role, "app.role"),
    organizationId: optional(raw, "organizationId", "app.organization_id") || null,
    licenseeId: optional(raw, "licenseeId", "app.licensee_id") || null,
    manufacturerId: optional(raw, "manufacturerId", "app.manufacturer_id") || null,
    authAssurance: authAssurance as CanonicalAssurance,
    requestId: required(raw.requestId, "app.request_id"),
    purpose: required(raw.purpose, "app.purpose"),
  };
};

export const installCanonicalDbContext = async (
  tx: Pick<Prisma.TransactionClient, "$executeRaw">,
  input: CanonicalDbContext
) => {
  const context = validateCanonicalDbContext(input);
  await tx.$executeRaw`
    SELECT
      set_config('app.user_id', ${context.userId}, true),
      set_config('app.role', ${context.role}, true),
      set_config('app.organization_id', ${context.organizationId ?? ""}, true),
      set_config('app.licensee_id', ${context.licenseeId ?? ""}, true),
      set_config('app.manufacturer_id', ${context.manufacturerId ?? ""}, true),
      set_config('app.auth_assurance', ${context.authAssurance}, true),
      set_config('app.request_id', ${context.requestId}, true),
      set_config('app.purpose', ${context.purpose}, true)
  `;
  return context;
};

export const withCanonicalDbContext = async <T>(
  runner: TransactionRunner,
  context: CanonicalDbContext,
  callback: (tx: Prisma.TransactionClient, installedContext: CanonicalDbContext) => Promise<T>
) =>
  runner.$transaction(async (tx) => {
    const installedContext = await installCanonicalDbContext(tx, context);
    return callback(tx, installedContext);
  });

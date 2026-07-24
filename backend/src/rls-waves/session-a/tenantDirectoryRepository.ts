import { Prisma, UserRole } from "@prisma/client";

import { getB01AuthenticatedPrisma } from "../session-b/b01/runtimeClients";

export class TenantDirectoryDenied extends Error {
  constructor() {
    super("TENANT_DIRECTORY_DENIED");
    this.name = "TenantDirectoryDenied";
  }
}

export const isTenantDirectoryDenied = (error: unknown) =>
  error instanceof TenantDirectoryDenied || /TENANT_DIRECTORY_DENIED|AUTH_SESSION_CAPABILITY_DENIED|42501/.test(
    String((error as { meta?: { message?: unknown }; message?: unknown })?.meta?.message || (error as { message?: unknown })?.message || "")
  );

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`Tenant directory requires ${label}`);
  return normalized;
};

const query = async <T>(operation: () => Promise<T>) => {
  try {
    return await operation();
  } catch (error) {
    if (isTenantDirectoryDenied(error)) throw new TenantDirectoryDenied();
    throw error;
  }
};

export const readLicenseeDirectory = async (input: {
  capability: string;
  requestId: string;
}) => query(async () => {
  const rows = await getB01AuthenticatedPrisma().$queryRaw<Array<{ payload: Prisma.JsonValue | null }>>`
    SELECT * FROM app_rls.read_licensee_directory(
      ${required(input.capability, "a capability")},
      ${"tenant-directory-licensees"},
      ${required(input.requestId, "a request ID")},
      ${null},
      ${false}
    )
  `;
  if (rows.length !== 1 || !Array.isArray(rows[0].payload)) {
    throw new Error("Tenant licensee directory returned an invalid projection");
  }
  return rows[0].payload;
});

export const readLicenseeDetail = async (input: {
  capability: string;
  requestId: string;
  requestedLicenseeId: string;
}) => query(async () => {
  const rows = await getB01AuthenticatedPrisma().$queryRaw<Array<{ payload: Prisma.JsonValue | null }>>`
    SELECT * FROM app_rls.read_licensee_directory(
      ${required(input.capability, "a capability")},
      ${"tenant-directory-licensees"},
      ${required(input.requestId, "a request ID")},
      ${required(input.requestedLicenseeId, "a licensee ID")},
      ${true}
    )
  `;
  if (rows.length !== 1 || rows[0].payload !== null && typeof rows[0].payload !== "object") {
    throw new Error("Tenant licensee directory returned an invalid detail projection");
  }
  return rows[0].payload;
});

export const readUserDirectory = async (input: {
  capability: string;
  requestId: string;
  requestedLicenseeId?: string | null;
  includeInactive: boolean;
  roleFilter?: UserRole | null;
  limit: number;
  offset: number;
}) => query(async () => {
  const rows = await getB01AuthenticatedPrisma().$queryRaw<Array<{ payload: Prisma.JsonValue; total: bigint | number }>>`
    SELECT * FROM app_rls.read_user_directory(
      ${required(input.capability, "a capability")},
      ${"tenant-directory-users"},
      ${required(input.requestId, "a request ID")},
      ${input.requestedLicenseeId || null},
      ${input.includeInactive},
      ${input.roleFilter || null},
      ${input.limit},
      ${input.offset}
    )
  `;
  if (rows.length !== 1 || !Array.isArray(rows[0].payload)) {
    throw new Error("Tenant user directory returned an invalid projection");
  }
  const total = Number(rows[0].total);
  if (!Number.isSafeInteger(total) || total < 0) throw new Error("Tenant user directory returned an invalid total");
  return { users: rows[0].payload, total };
});

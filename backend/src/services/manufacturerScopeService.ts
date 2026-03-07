import { Prisma, UserRole } from "@prisma/client";

import prisma from "../config/database";

type DbClient = typeof prisma | Prisma.TransactionClient;

export const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

export const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));

export const isPlatformRole = (role?: UserRole | null) =>
  role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const isLicenseeAdminRole = (role?: UserRole | null) =>
  role === UserRole.LICENSEE_ADMIN || role === UserRole.ORG_ADMIN;

const unique = (values: Array<string | null | undefined>) =>
  Array.from(
    new Set(
      values
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  );

export const listManufacturerLicenseeLinks = async (
  manufacturerId: string,
  db: DbClient = prisma
) =>
  db.manufacturerLicenseeLink.findMany({
    where: { manufacturerId },
    include: {
      licensee: {
        select: {
          id: true,
          name: true,
          prefix: true,
          brandName: true,
          orgId: true,
          isActive: true,
        },
      },
    },
    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }],
  });

export const listManufacturerLinkedLicenseeIds = async (
  manufacturerId: string,
  db: DbClient = prisma
) => {
  const rows = await db.manufacturerLicenseeLink.findMany({
    where: { manufacturerId },
    select: { licenseeId: true },
  });
  return unique(rows.map((row) => row.licenseeId));
};

export const upsertManufacturerLicenseeLink = async (
  db: DbClient,
  params: {
    manufacturerId: string;
    licenseeId: string;
    makePrimary?: boolean;
  }
) => {
  if (params.makePrimary) {
    await db.manufacturerLicenseeLink.updateMany({
      where: {
        manufacturerId: params.manufacturerId,
        isPrimary: true,
        NOT: { licenseeId: params.licenseeId },
      },
      data: { isPrimary: false },
    });
  }

  return db.manufacturerLicenseeLink.upsert({
    where: {
      manufacturerId_licenseeId: {
        manufacturerId: params.manufacturerId,
        licenseeId: params.licenseeId,
      },
    },
    create: {
      manufacturerId: params.manufacturerId,
      licenseeId: params.licenseeId,
      isPrimary: Boolean(params.makePrimary),
    },
    update: params.makePrimary ? { isPrimary: true } : {},
  });
};

export const normalizeLinkedLicensees = (
  rows: Array<{
    licenseeId: string;
    isPrimary?: boolean | null;
    licensee?: {
      id: string;
      name: string;
      prefix: string;
      brandName?: string | null;
      orgId?: string | null;
    } | null;
  }>
) =>
  rows
    .filter((row) => row.licensee)
    .map((row) => ({
      id: row.licensee!.id,
      name: row.licensee!.name,
      prefix: row.licensee!.prefix,
      brandName: row.licensee!.brandName ?? null,
      orgId: row.licensee!.orgId ?? null,
      isPrimary: Boolean(row.isPrimary),
    }));

export const resolveAccessibleLicenseeIdsForUser = async (
  user: {
    role: UserRole;
    userId: string;
    licenseeId?: string | null;
    linkedLicenseeIds?: string[] | null;
  },
  db: DbClient = prisma
) => {
  if (isPlatformRole(user.role)) return [] as string[];
  if (isLicenseeAdminRole(user.role)) {
    return unique([user.licenseeId || null]);
  }
  if (!isManufacturerRole(user.role)) {
    return unique([user.licenseeId || null]);
  }

  const fromPayload = unique([...(user.linkedLicenseeIds || []), user.licenseeId || null]);
  if (fromPayload.length > 0) return fromPayload;

  const fromDb = await listManufacturerLinkedLicenseeIds(user.userId, db);
  return unique([...fromDb, user.licenseeId || null]);
};

export const assertUserCanAccessLicensee = async (
  user: {
    role: UserRole;
    userId: string;
    licenseeId?: string | null;
    linkedLicenseeIds?: string[] | null;
  },
  licenseeId: string,
  db: DbClient = prisma
) => {
  const target = String(licenseeId || "").trim();
  if (!target) return false;
  if (isPlatformRole(user.role)) return true;
  if (isLicenseeAdminRole(user.role)) return String(user.licenseeId || "") === target;
  if (!isManufacturerRole(user.role)) return String(user.licenseeId || "") === target;
  const accessible = await resolveAccessibleLicenseeIdsForUser(user, db);
  return accessible.includes(target);
};

export const resolveScopedLicenseeAccess = async (
  user: {
    role: UserRole;
    userId: string;
    licenseeId?: string | null;
    linkedLicenseeIds?: string[] | null;
  },
  requestedLicenseeId?: string | null,
  db: DbClient = prisma
) => {
  const requested = String(requestedLicenseeId || "").trim() || null;

  if (isPlatformRole(user.role)) {
    return {
      scopeLicenseeId: requested,
      accessibleLicenseeIds: null as string[] | null,
    };
  }

  if (isLicenseeAdminRole(user.role)) {
    const actorLicenseeId = String(user.licenseeId || "").trim() || null;
    if (!actorLicenseeId) {
      throw new Error("No licensee association found");
    }
    if (requested && requested !== actorLicenseeId) {
      throw new Error("Access denied to this licensee");
    }
    return {
      scopeLicenseeId: actorLicenseeId,
      accessibleLicenseeIds: [actorLicenseeId],
    };
  }

  if (isManufacturerRole(user.role)) {
    const accessibleLicenseeIds = await resolveAccessibleLicenseeIdsForUser(user, db);
    if (requested && !accessibleLicenseeIds.includes(requested)) {
      throw new Error("Access denied to this licensee");
    }
    return {
      scopeLicenseeId: requested,
      accessibleLicenseeIds,
    };
  }

  const fallback = String(user.licenseeId || "").trim() || null;
  if (requested && requested !== fallback) {
    throw new Error("Access denied to this licensee");
  }
  return {
    scopeLicenseeId: fallback,
    accessibleLicenseeIds: fallback ? [fallback] : [],
  };
};

export const applyLicenseeScopeToWhere = (
  where: Record<string, any>,
  field: string,
  scopeLicenseeId: string | null,
  accessibleLicenseeIds: string[] | null
) => {
  if (scopeLicenseeId) {
    where[field] = scopeLicenseeId;
    return where;
  }

  if (accessibleLicenseeIds && accessibleLicenseeIds.length > 0) {
    where[field] =
      accessibleLicenseeIds.length === 1
        ? accessibleLicenseeIds[0]
        : { in: accessibleLicenseeIds };
  }

  return where;
};

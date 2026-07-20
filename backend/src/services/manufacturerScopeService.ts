import { Prisma, UserRole } from "@prisma/client";

import prisma from "../config/database";

type DbClient = typeof prisma | Prisma.TransactionClient;
export type ManufacturerScopeReadClient = {
  manufacturerLicenseeLink: Pick<Prisma.TransactionClient["manufacturerLicenseeLink"], "findMany">;
  auditLogOutbox?: Pick<Prisma.TransactionClient["auditLogOutbox"], "create">;
};

const MAX_ELIGIBLE_MANUFACTURER_LINKS = 100;

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
  db: ManufacturerScopeReadClient = prisma
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

export const resolveManufacturerSessionScope = async (
  input: {
    manufacturerId: string;
    legacyLicenseeId?: string | null;
    legacyOrgId?: string | null;
    requestedLicenseeId?: string | null;
    requestedOrgId?: string | null;
    requestedScopeVersion?: string | null;
    audit?: {
      requestId: string;
      purpose: "manufacturer-bootstrap" | "manufacturer-scope-switch";
      assurance: "password-verified" | "mfa-verified";
    };
  },
  db: ManufacturerScopeReadClient
) => {
  const rows = await db.manufacturerLicenseeLink.findMany({
    where: {
      manufacturerId: input.manufacturerId,
      licensee: {
        is: {
          isActive: true,
          suspendedAt: null,
          organization: { is: { isActive: true } },
        },
      },
    },
    select: {
      licenseeId: true,
      isPrimary: true,
      createdAt: true,
      updatedAt: true,
      licensee: {
        select: {
          id: true,
          name: true,
          prefix: true,
          brandName: true,
          orgId: true,
        },
      },
    },
    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }, { licenseeId: "asc" }],
    take: MAX_ELIGIBLE_MANUFACTURER_LINKS + 1,
  });

  if (rows.length > MAX_ELIGIBLE_MANUFACTURER_LINKS) {
    throw new Error("MANUFACTURER_MEMBERSHIP_SET_TOO_LARGE");
  }
  if (rows.length === 0) {
    throw new Error("MANUFACTURER_MEMBERSHIP_REQUIRED");
  }

  const legacyLicenseeId = String(input.legacyLicenseeId || "").trim();
  const legacyOrgId = String(input.legacyOrgId || "").trim();
  if (legacyLicenseeId && !rows.some((row) => row.licenseeId === legacyLicenseeId)) {
    throw new Error("MANUFACTURER_MEMBERSHIP_INCONSISTENT");
  }
  if (legacyOrgId && !rows.some((row) => row.licensee.orgId === legacyOrgId)) {
    throw new Error("MANUFACTURER_MEMBERSHIP_INCONSISTENT");
  }

  const primaryRows = rows.filter((row) => row.isPrimary);
  if (primaryRows.length > 1) {
    throw new Error("MANUFACTURER_MEMBERSHIP_AMBIGUOUS");
  }

  const requestedLicenseeId = String(input.requestedLicenseeId || "").trim();
  const requestedOrgId = String(input.requestedOrgId || "").trim();
  const requestedScopeVersion = String(input.requestedScopeVersion || "").trim();
  const selected = requestedLicenseeId
    ? rows.find((row) => row.licenseeId === requestedLicenseeId) || null
    : requestedOrgId
      ? rows.find((row) => row.licensee.orgId === requestedOrgId) || null
    : rows.length === 1
      ? rows[0]
      : primaryRows[0] || null;

  if (requestedLicenseeId && !selected) {
    throw new Error("MANUFACTURER_SCOPE_DENIED");
  }
  if (requestedOrgId && (!selected || selected.licensee.orgId !== requestedOrgId)) {
    throw new Error("MANUFACTURER_SCOPE_DENIED");
  }
  if (requestedLicenseeId && !requestedScopeVersion) {
    throw new Error("MANUFACTURER_SCOPE_VERSION_REQUIRED");
  }
  if (requestedScopeVersion && (!selected || selected.updatedAt.toISOString() !== requestedScopeVersion)) {
    throw new Error("MANUFACTURER_SCOPE_STALE");
  }

  const linkedLicensees = rows.map((row) => ({
    id: row.licensee.id,
    name: row.licensee.name,
    prefix: row.licensee.prefix,
    brandName: row.licensee.brandName ?? null,
    orgId: row.licensee.orgId,
    isPrimary: row.isPrimary,
    scopeVersion: row.updatedAt.toISOString(),
  }));

  const selectedLicensee = selected
    ? linkedLicensees.find((row) => row.id === selected.licenseeId) || null
    : null;
  if (input.audit) {
    const requestId = String(input.audit.requestId || "").trim();
    if (!requestId) throw new Error("REQUEST_ATTRIBUTION_REQUIRED");
    if (!db.auditLogOutbox?.create) throw new Error("MANUFACTURER_SCOPE_AUDIT_BOUNDARY_REQUIRED");
    await db.auditLogOutbox.create({
      data: {
        payload: {
          userId: input.manufacturerId,
          orgId: selectedLicensee?.orgId || undefined,
          licenseeId: selectedLicensee?.id || undefined,
          action: input.audit.purpose === "manufacturer-scope-switch"
            ? "MANUFACTURER_SCOPE_SWITCH"
            : "MANUFACTURER_BOOTSTRAP_READ",
          entityType: "ManufacturerLicenseeLink",
          entityId: selectedLicensee ? `${input.manufacturerId}:${selectedLicensee.id}` : input.manufacturerId,
          details: {
            requestId,
            manufacturerUserId: input.manufacturerId,
            selectedLicenseeId: selectedLicensee?.id || null,
            selectedOrganizationId: selectedLicensee?.orgId || null,
            scopeVersion: selectedLicensee?.scopeVersion || null,
            assurance: input.audit.assurance,
            purpose: input.audit.purpose,
            outcome: selectedLicensee ? "SELECTED" : "SCOPE_SELECTION_REQUIRED",
          },
        },
      },
    });
  }

  return {
    selectedLicensee,
    linkedLicensees,
    linkedLicenseeIds: linkedLicensees.map((row) => row.id),
  };
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
    updatedAt?: Date | string | null;
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
      scopeVersion: row.updatedAt ? new Date(row.updatedAt).toISOString() : null,
    }));

export const resolveAccessibleLicenseeIdsForUser = async (
  user: {
    role: UserRole;
    userId: string;
    licenseeId?: string | null;
    linkedLicenseeIds?: string[] | null;
  },
  db: ManufacturerScopeReadClient = prisma
) => {
  if (isPlatformRole(user.role)) return [] as string[];
  if (isLicenseeAdminRole(user.role)) {
    return unique([user.licenseeId || null]);
  }
  if (!isManufacturerRole(user.role)) {
    return unique([user.licenseeId || null]);
  }

  const resolved = await resolveManufacturerSessionScope(
    { manufacturerId: user.userId },
    db
  );
  return resolved.linkedLicenseeIds;
};

export const assertUserCanAccessLicensee = async (
  user: {
    role: UserRole;
    userId: string;
    licenseeId?: string | null;
    linkedLicenseeIds?: string[] | null;
  },
  licenseeId: string,
  db: ManufacturerScopeReadClient = prisma
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
  db: ManufacturerScopeReadClient = prisma
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

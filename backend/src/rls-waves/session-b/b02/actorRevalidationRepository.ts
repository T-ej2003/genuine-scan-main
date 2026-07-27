import { Prisma, UserRole, UserStatus } from "@prisma/client";

type B02Db = Prisma.TransactionClient;

const required = (value: unknown, label: string) => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error(`B02 actor revalidation requires ${label}`);
  return normalized;
};

export const loadB02AuthenticatedActorSelf = (tx: B02Db, userId: string) =>
  tx.user.findFirst({
    where: {
      id: required(userId, "a user ID"),
      isActive: true,
      status: UserStatus.ACTIVE,
      disabledAt: null,
      deletedAt: null,
    },
    select: {
      id: true,
      role: true,
      orgId: true,
      licenseeId: true,
    },
  });

export const loadB02ActiveAuthSession = (
  tx: B02Db,
  input: { sessionId: string; userId: string; checkedAt: Date }
) => tx.refreshToken.findFirst({
  where: {
    id: required(input.sessionId, "a session ID"),
    userId: required(input.userId, "a user ID"),
    revokedAt: null,
    expiresAt: { gt: input.checkedAt },
  },
  select: {
    id: true,
    userId: true,
    orgId: true,
    authenticatedAt: true,
    mfaVerifiedAt: true,
    expiresAt: true,
  },
});

export type B02ManufacturerScope = {
  licenseeId: string;
  organizationId: string;
  scopeVersion: string;
};

const manufacturerRoles = new Set<UserRole>([
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
]);

export const isB02ManufacturerRole = (role: UserRole) => manufacturerRoles.has(role);

export const loadB02ManufacturerScope = async (
  tx: B02Db,
  input: {
    manufacturerId: string;
    requestedLicenseeId?: string | null;
    requestedOrganizationId?: string | null;
    requestedScopeVersion?: string | null;
  }
): Promise<B02ManufacturerScope> => {
  const rows = await tx.manufacturerLicenseeLink.findMany({
    where: {
      manufacturerId: required(input.manufacturerId, "a manufacturer user ID"),
      licensee: {
        is: {
          isActive: true,
          suspendedAt: null,
          organization: { is: { isActive: true } },
        },
      },
    },
    orderBy: [{ isPrimary: "desc" }, { createdAt: "asc" }, { licenseeId: "asc" }],
    take: 101,
    select: {
      licenseeId: true,
      isPrimary: true,
      createdAt: true,
      updatedAt: true,
      licensee: { select: { orgId: true } },
    },
  });
  if (rows.length === 0 || rows.length > 100) {
    throw new Error(rows.length ? "B02 manufacturer scope is too large" : "B02 manufacturer scope is unavailable");
  }
  const requestedLicenseeId = String(input.requestedLicenseeId || "").trim();
  const requestedOrganizationId = String(input.requestedOrganizationId || "").trim();
  const selected = requestedLicenseeId
    ? rows.find((row) => row.licenseeId === requestedLicenseeId)
    : requestedOrganizationId
      ? rows.find((row) => row.licensee.orgId === requestedOrganizationId)
      : rows.length === 1
        ? rows[0]
        : rows.find((row) => row.isPrimary);
  if (!selected) throw new Error("B02 manufacturer scope is denied or ambiguous");
  if (requestedOrganizationId && selected.licensee.orgId !== requestedOrganizationId) {
    throw new Error("B02 manufacturer organization scope changed");
  }
  const scopeVersion = selected.updatedAt.toISOString();
  const requestedScopeVersion = String(input.requestedScopeVersion || "").trim();
  if (requestedLicenseeId && !requestedScopeVersion) {
    throw new Error("B02 manufacturer scope version is required");
  }
  if (requestedScopeVersion && requestedScopeVersion !== scopeVersion) {
    throw new Error("B02 manufacturer scope is stale");
  }
  return {
    licenseeId: selected.licenseeId,
    organizationId: selected.licensee.orgId,
    scopeVersion,
  };
};

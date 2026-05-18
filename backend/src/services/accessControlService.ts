import { Response, NextFunction } from "express";
import { Prisma, UserRole, UserStatus } from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import {
  MANUFACTURER_ROLES,
  assertUserCanAccessLicensee,
  isLicenseeAdminRole,
  isManufacturerRole,
  isPlatformRole,
  resolveAccessibleLicenseeIdsForUser,
  resolveScopedLicenseeAccess,
} from "./manufacturerScopeService";

export type AuthenticatedUserScope = {
  userId: string;
  role: UserRole;
  orgId: string | null;
  licenseeId: string | null;
  linkedLicenseeIds: string[];
  isPlatformAdmin: boolean;
  isLicenseeAdmin: boolean;
  isManufacturer: boolean;
  accessibleLicenseeIds: string[] | null;
};

export type ScopedUserWhereOptions = {
  base?: Prisma.UserWhereInput;
  requestedLicenseeId?: string | null;
  manufacturerOnly?: boolean;
  includeInactive?: boolean;
};

export type ScopedIncidentActor = {
  role: UserRole;
  userId?: string | null;
  licenseeId?: string | null;
  linkedLicenseeIds?: string[] | null;
};

export class AccessDeniedError extends Error {
  statusCode: number;

  constructor(message = "Resource not found", statusCode = 404) {
    super(message);
    this.name = "AccessDeniedError";
    this.statusCode = statusCode;
  }
}

type MutableWhere = Record<string, unknown>;

const isObjectRecord = (value: unknown): value is MutableWhere =>
  Boolean(value && typeof value === "object" && !Array.isArray(value));

const disabledStatus = (UserStatus as unknown as { DISABLED?: string })?.DISABLED || "DISABLED";

export const isDisabledUserRecord = (user: {
  isActive?: boolean | null;
  status?: string | null;
  deletedAt?: Date | null;
  disabledAt?: Date | null;
}) =>
  user.isActive === false ||
  Boolean(user.deletedAt) ||
  Boolean(user.disabledAt) ||
  String(user.status || "").toUpperCase() === disabledStatus;

export const getAuthenticatedUser = (req: AuthRequest) => {
  if (!req.user?.userId || !req.user?.role) return null;
  return req.user;
};

export const getUserScope = async (user: NonNullable<AuthRequest["user"]>): Promise<AuthenticatedUserScope> => {
  const accessibleLicenseeIds = isPlatformRole(user.role)
    ? null
    : await resolveAccessibleLicenseeIdsForUser(user);

  return {
    userId: user.userId,
    role: user.role,
    orgId: user.orgId || null,
    licenseeId: user.licenseeId || null,
    linkedLicenseeIds: Array.isArray(user.linkedLicenseeIds) ? user.linkedLicenseeIds.filter(Boolean) : [],
    isPlatformAdmin: isPlatformRole(user.role),
    isLicenseeAdmin: isLicenseeAdminRole(user.role),
    isManufacturer: isManufacturerRole(user.role),
    accessibleLicenseeIds,
  };
};

export const requireAuth = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!getAuthenticatedUser(req)) {
    return res.status(401).json({ success: false, error: "Authentication required" });
  }
  return next();
};

export const requireRole = (...allowedRoles: UserRole[]) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const user = getAuthenticatedUser(req);
    if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
    if (!allowedRoles.includes(user.role)) {
      return res.status(403).json({ success: false, error: "Insufficient permissions" });
    }
    return next();
  };
};

export const requireTenantScope = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (isPlatformRole(user.role)) return next();
  const scope = await getUserScope(user);
  if (!scope.accessibleLicenseeIds?.length) {
    return res.status(403).json({ success: false, error: "No tenant association found" });
  }
  return next();
};

export const requirePlatformScope = (req: AuthRequest, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (!isPlatformRole(user.role)) {
    return res.status(403).json({ success: false, error: "Insufficient permissions" });
  }
  return next();
};

export const requireManufacturerScope = (req: AuthRequest, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (!isManufacturerRole(user.role)) {
    return res.status(403).json({ success: false, error: "Insufficient permissions" });
  }
  return next();
};

export const requireLicenseeScope = (req: AuthRequest, res: Response, next: NextFunction) => {
  const user = getAuthenticatedUser(req);
  if (!user) return res.status(401).json({ success: false, error: "Authentication required" });
  if (!isLicenseeAdminRole(user.role)) {
    return res.status(403).json({ success: false, error: "Insufficient permissions" });
  }
  return next();
};

export const resolveRequestedLicenseeScope = async (
  user: NonNullable<AuthRequest["user"]>,
  requestedLicenseeId?: string | null
) => resolveScopedLicenseeAccess(user, requestedLicenseeId || null);

export const assertCanAccessResource = async (
  user: NonNullable<AuthRequest["user"]>,
  resource: { licenseeId?: string | null; manufacturerId?: string | null; userId?: string | null }
) => {
  const scope = await getUserScope(user);
  if (scope.isPlatformAdmin) return true;

  if (resource.userId && resource.userId === scope.userId) return true;

  if (scope.isManufacturer) {
    if (resource.manufacturerId && resource.manufacturerId !== scope.userId) return false;
    if (resource.licenseeId) return assertUserCanAccessLicensee(user, resource.licenseeId);
    return true;
  }

  if (resource.licenseeId) return assertUserCanAccessLicensee(user, resource.licenseeId);
  return false;
};

const addLicenseeScope = (
  where: MutableWhere,
  field: string,
  scopeLicenseeId: string | null,
  accessibleLicenseeIds: string[] | null
) => {
  if (scopeLicenseeId) {
    where[field] = where[field] ? { equals: scopeLicenseeId } : scopeLicenseeId;
    return where;
  }
  if (accessibleLicenseeIds && accessibleLicenseeIds.length > 0) {
    where[field] = accessibleLicenseeIds.length === 1 ? accessibleLicenseeIds[0] : { in: accessibleLicenseeIds };
  }
  return where;
};

export const buildScopedWhere = async (
  user: NonNullable<AuthRequest["user"]>,
  options: {
    base?: MutableWhere;
    requestedLicenseeId?: string | null;
    licenseeField?: string;
    manufacturerField?: string;
    relationManufacturerField?: string;
  } = {}
) => {
  const where: MutableWhere = { ...(options.base || {}) };
  const scope = await resolveRequestedLicenseeScope(user, options.requestedLicenseeId || null);
  addLicenseeScope(where, options.licenseeField || "licenseeId", scope.scopeLicenseeId, scope.accessibleLicenseeIds);

  if (isManufacturerRole(user.role)) {
    if (options.relationManufacturerField) {
      const currentRelation = where[options.relationManufacturerField];
      where[options.relationManufacturerField] = {
        ...(isObjectRecord(currentRelation) ? currentRelation : {}),
        manufacturerId: user.userId,
      };
    } else if (options.manufacturerField) {
      where[options.manufacturerField] = user.userId;
    }
  }

  return where;
};

const mergeAnd = <T extends MutableWhere>(where: T, condition: unknown) => {
  if (!condition) return where;
  const mutable = where as MutableWhere & { AND?: unknown };
  const existingAnd = Array.isArray(mutable.AND) ? mutable.AND : mutable.AND ? [mutable.AND] : [];
  mutable.AND = [...existingAnd, condition];
  return where;
};

export const buildScopedUserWhere = async (
  user: NonNullable<AuthRequest["user"]>,
  options: ScopedUserWhereOptions = {}
): Promise<Prisma.UserWhereInput> => {
  const where: Prisma.UserWhereInput = { ...(options.base || {}) };

  if (options.manufacturerOnly) {
    where.role = { in: MANUFACTURER_ROLES };
  }
  if (!options.includeInactive) {
    where.isActive = true;
    where.deletedAt = null;
  }
  if (isPlatformRole(user.role)) {
    const requested = String(options.requestedLicenseeId || "").trim();
    if (requested) {
      mergeAnd(where as MutableWhere, {
        OR: [{ licenseeId: requested }, { manufacturerLicenseeLinks: { some: { licenseeId: requested } } }],
      });
    }
    return where;
  }

  const scope = await resolveRequestedLicenseeScope(user, options.requestedLicenseeId || null);
  const accessible = scope.scopeLicenseeId ? [scope.scopeLicenseeId] : scope.accessibleLicenseeIds || [];
  if (!accessible.length) {
    mergeAnd(where as MutableWhere, { id: "__no_accessible_users__" });
    return where;
  }

  mergeAnd(where as MutableWhere, {
    OR: [
      accessible.length === 1 ? { licenseeId: accessible[0] } : { licenseeId: { in: accessible } },
      {
        manufacturerLicenseeLinks: {
          some: accessible.length === 1 ? { licenseeId: accessible[0] } : { licenseeId: { in: accessible } },
        },
      },
    ],
  });

  return where;
};

export const buildIncidentScopeWhere = async (
  actor: ScopedIncidentActor,
  base: Prisma.IncidentWhereInput = {}
): Promise<Prisma.IncidentWhereInput> => {
  const where: Prisma.IncidentWhereInput = { ...base };
  if (isPlatformRole(actor.role)) return where;

  const scope = await resolveScopedLicenseeAccess({
    role: actor.role,
    userId: actor.userId || "",
    licenseeId: actor.licenseeId || null,
    linkedLicenseeIds: actor.linkedLicenseeIds || null,
  });
  const accessible = scope.scopeLicenseeId ? [scope.scopeLicenseeId] : scope.accessibleLicenseeIds || [];
  if (!accessible.length) {
    return { ...where, id: "__no_accessible_incidents__" };
  }

  const licenseeCondition =
    accessible.length === 1 ? { licenseeId: accessible[0] } : { licenseeId: { in: accessible } };

  if (isManufacturerRole(actor.role)) {
    mergeAnd(where as MutableWhere, {
      OR: [
        {
          qrCode: {
            batch: {
              manufacturerId: actor.userId || "__no_manufacturer__",
            },
          },
        },
        {
          scanEvent: {
            batch: {
              manufacturerId: actor.userId || "__no_manufacturer__",
            },
          },
        },
      ],
    });
  }

  mergeAnd(where as MutableWhere, licenseeCondition);
  return where;
};

export const findScopedBatch = async (
  user: NonNullable<AuthRequest["user"]>,
  id: string,
  args: Prisma.BatchFindFirstArgs = {}
) =>
  prisma.batch.findFirst({
    ...args,
    where: await buildScopedWhere(user, {
      base: { id },
      manufacturerField: "manufacturerId",
      ...(args.where ? { base: { ...(args.where as unknown as MutableWhere), id } } : {}),
    }),
  });

export const findScopedQrCode = async (
  user: NonNullable<AuthRequest["user"]>,
  id: string,
  args: Prisma.QRCodeFindFirstArgs = {}
) =>
  prisma.qRCode.findFirst({
    ...args,
    where: await buildScopedWhere(user, {
      base: { id },
      relationManufacturerField: "batch",
      ...(args.where ? { base: { ...(args.where as unknown as MutableWhere), id } } : {}),
    }),
  });

export const scopedNotFound = (message = "Resource not found") => new AccessDeniedError(message, 404);

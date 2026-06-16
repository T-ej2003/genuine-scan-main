import { UserRole } from "@prisma/client";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { buildScopedWhere, resolveRequestedLicenseeScope } from "./accessControlService";
import { summarizeQrStatusCounts } from "./qrStatusMetrics";
import { getOrComputeVersionedCache } from "./versionedCacheService";

const DASHBOARD_CACHE_NAMESPACE = "dashboard-snapshot";
const DASHBOARD_CACHE_TTL_SEC = 20;

type DashboardSnapshot = {
  totalQRCodes: number;
  activeLicensees: number;
  manufacturers: number;
  totalBatches: number;
  qr: {
    total: number;
    byStatus: Record<string, number>;
  };
};

const isManufacturerRole = (role: UserRole) =>
  role === UserRole.MANUFACTURER ||
  role === UserRole.MANUFACTURER_ADMIN ||
  role === UserRole.MANUFACTURER_USER;

const loadInventoryAggregate = async (params: {
  role: UserRole;
  userId: string;
  requestedLicenseeId?: string | null;
  accessibleLicenseeIds?: string[] | null;
}) => {
  const where: Record<string, unknown> = {};
  if (isManufacturerRole(params.role)) {
    where.manufacturerId = params.userId;
  }
  if (params.requestedLicenseeId) {
    where.licenseeId = params.requestedLicenseeId;
  } else if (params.accessibleLicenseeIds && params.accessibleLicenseeIds.length > 0) {
    where.licenseeId =
      params.accessibleLicenseeIds.length === 1 ? params.accessibleLicenseeIds[0] : { in: params.accessibleLicenseeIds };
  }

  const rollupAggregate = await prisma.inventoryStatusRollup.aggregate({
    where,
    _sum: {
      totalCodes: true,
      dormant: true,
      active: true,
      activated: true,
      allocated: true,
      printed: true,
      redeemed: true,
      blocked: true,
      scanned: true,
    },
  });

  const hasRollups = Object.values(rollupAggregate._sum || {}).some((value) => Number(value || 0) > 0);
  if (!hasRollups) return null;

  const byStatus = {
    DORMANT: Number(rollupAggregate._sum?.dormant || 0),
    ACTIVE: Number(rollupAggregate._sum?.active || 0),
    ACTIVATED: Number(rollupAggregate._sum?.activated || 0),
    ALLOCATED: Number(rollupAggregate._sum?.allocated || 0),
    PRINTED: Number(rollupAggregate._sum?.printed || 0),
    REDEEMED: Number(rollupAggregate._sum?.redeemed || 0),
    BLOCKED: Number(rollupAggregate._sum?.blocked || 0),
    SCANNED: Number(rollupAggregate._sum?.scanned || 0),
  } satisfies Record<string, number>;

  return {
    totalQRCodes: Number(rollupAggregate._sum?.totalCodes || 0),
    byStatus,
  };
};

const computeDashboardSnapshot = async (req: AuthRequest): Promise<DashboardSnapshot> => {
  if (!req.user) throw new Error("Not authenticated");

  const role = req.user.role;
  const userId = req.user.userId;
  const requestedLicenseeId = String(req.query?.licenseeId || "").trim() || null;
  const scope = await resolveRequestedLicenseeScope(req.user, requestedLicenseeId);

  const qrWhere: any = await buildScopedWhere(req.user, {
    requestedLicenseeId,
    relationManufacturerField: "batch",
  });
  const batchWhere: any = await buildScopedWhere(req.user, {
    requestedLicenseeId,
    manufacturerField: "manufacturerId",
  });
  const manufacturersWhere: any = {
    role: { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] },
    isActive: true,
  };

  if (isManufacturerRole(role)) {
    manufacturersWhere.id = userId;
  } else if (scope.scopeLicenseeId) {
    manufacturersWhere.OR = [
      { licenseeId: scope.scopeLicenseeId },
      { manufacturerLicenseeLinks: { some: { licenseeId: scope.scopeLicenseeId } } },
    ];
  } else if (scope.accessibleLicenseeIds && scope.accessibleLicenseeIds.length > 0) {
    const licenseeFilter =
      scope.accessibleLicenseeIds.length === 1 ? scope.accessibleLicenseeIds[0] : { in: scope.accessibleLicenseeIds };
    manufacturersWhere.OR = [
      { licenseeId: licenseeFilter },
      { manufacturerLicenseeLinks: { some: { licenseeId: licenseeFilter } } },
    ];
  }

  const inventoryAggregate = await loadInventoryAggregate({
    role,
    userId,
    requestedLicenseeId: scope.scopeLicenseeId,
    accessibleLicenseeIds: scope.accessibleLicenseeIds,
  });

  const [activeLicensees, manufacturers, totalBatches, fallbackQrGrouped, fallbackQrTotal] = await Promise.all([
    role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN
      ? prisma.licensee.count({ where: { ...(scope.scopeLicenseeId ? { id: scope.scopeLicenseeId } : {}), isActive: true } })
      : scope.accessibleLicenseeIds && scope.accessibleLicenseeIds.length > 0
        ? prisma.licensee.count({ where: { id: { in: scope.accessibleLicenseeIds }, isActive: true } })
        : scope.scopeLicenseeId
          ? prisma.licensee.count({ where: { id: scope.scopeLicenseeId, isActive: true } })
          : 0,
    prisma.user.count({ where: manufacturersWhere }),
    prisma.batch.count({ where: batchWhere }),
    inventoryAggregate
      ? Promise.resolve([])
      : prisma.qRCode.groupBy({
          by: ["status"],
          where: qrWhere,
          _count: true,
        }),
    inventoryAggregate ? Promise.resolve(inventoryAggregate.totalQRCodes) : prisma.qRCode.count({ where: qrWhere }),
  ]);

  const byStatus = inventoryAggregate
    ? inventoryAggregate.byStatus
    : fallbackQrGrouped.reduce((acc, row) => {
        acc[row.status] = row._count;
        return acc;
      }, {} as Record<string, number>);

  return {
    totalQRCodes: fallbackQrTotal,
    activeLicensees,
    manufacturers,
    totalBatches,
    qr: {
      total: fallbackQrTotal,
      byStatus,
      ...summarizeQrStatusCounts(byStatus),
    },
  };
};

const makeScopeKey = (req: AuthRequest) => {
  if (!req.user) return "anonymous";
  return [
    req.user.role,
    req.user.userId,
    String(req.query?.licenseeId || "").trim() || "all",
    req.user.licenseeId || "none",
    req.user.orgId || "none",
  ].join(":");
};

export const getDashboardSnapshot = async (req: AuthRequest) => {
  return getOrComputeVersionedCache(DASHBOARD_CACHE_NAMESPACE, makeScopeKey(req), DASHBOARD_CACHE_TTL_SEC, () =>
    computeDashboardSnapshot(req)
  );
};

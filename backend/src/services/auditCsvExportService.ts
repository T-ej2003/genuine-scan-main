import { Prisma, PrismaClient, UserRole } from "@prisma/client";

import prisma from "../config/database";
import { CanonicalDbContext, withCanonicalDbContext } from "../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../types";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { hiddenActionsForNonSuper, isAuditManufacturerUser, isAuditSuperUser } from "./auditExportRedactionService";

type AuditExportFilters = {
  entityType?: string;
  entityId?: string;
  action?: string;
  licenseeId?: string;
  purpose?: string;
  limit: number;
};

type TransactionRunner = Pick<PrismaClient, "$transaction">;

export class AuditCsvExportAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

const tenantAdminRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);

const buildBoundary = (
  user: AuthenticatedSessionClaims,
  filters: AuditExportFilters,
  requestId: string
): { context: CanonicalDbContext; licenseeId?: string; userIds?: string[]; isSuper: boolean } => {
  const userId = String(user.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  if (!userId || !normalizedRequestId || user.sessionStage !== "ACTIVE") {
    throw new AuditCsvExportAccessError("Authenticated actor context is required", 401);
  }

  const isSuper = isAuditSuperUser(user.role);
  const isManufacturer = isAuditManufacturerUser(user.role);
  const requestedLicenseeId = String(filters.licenseeId || "").trim() || undefined;
  const actorLicenseeId = String(user.licenseeId || "").trim() || undefined;
  let licenseeId: string | undefined;
  let userIds: string[] | undefined;
  let purpose = "tenant-audit-csv-export";

  if (isSuper) {
    purpose = String(filters.purpose || "").trim();
    if (user.authAssurance !== "ADMIN_MFA") {
      throw new AuditCsvExportAccessError("Fresh administrator MFA is required");
    }
    const mfaVerifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
    if (!Number.isFinite(mfaVerifiedAt) || Date.now() - mfaVerifiedAt > getAdminStepUpWindowMinutes() * 60_000) {
      throw new AuditCsvExportAccessError("Fresh administrator MFA is required");
    }
    if (!purpose) throw new AuditCsvExportAccessError("An explicit audit export purpose is required");
    if (purpose.length > 240) throw new AuditCsvExportAccessError("Audit export purpose is too long", 400);
    if (!requestedLicenseeId) throw new AuditCsvExportAccessError("A bounded licensee scope is required");
    licenseeId = requestedLicenseeId;
  } else if (tenantAdminRoles.has(user.role)) {
    if (!actorLicenseeId) throw new AuditCsvExportAccessError("A tenant scope is required");
    if (requestedLicenseeId && requestedLicenseeId !== actorLicenseeId) {
      throw new AuditCsvExportAccessError("Access denied to this licensee");
    }
    licenseeId = actorLicenseeId;
  } else if (isManufacturer) {
    const linked = new Set([actorLicenseeId, ...(user.linkedLicenseeIds || [])].filter(Boolean));
    if (requestedLicenseeId && !linked.has(requestedLicenseeId)) {
      throw new AuditCsvExportAccessError("Access denied to this licensee");
    }
    licenseeId = requestedLicenseeId || actorLicenseeId;
    userIds = [userId];
  } else {
    throw new AuditCsvExportAccessError("Insufficient permissions");
  }

  return {
    context: {
      userId,
      role: String(user.role),
      organizationId: user.orgId || null,
      licenseeId: licenseeId || null,
      manufacturerId: isManufacturer ? userId : null,
      authAssurance: user.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId: normalizedRequestId,
      purpose,
    },
    licenseeId: isManufacturer ? undefined : licenseeId,
    userIds,
    isSuper,
  };
};

export const readAuditCsvExport = async (
  input: {
    user: AuthenticatedSessionClaims;
    filters: AuditExportFilters;
    requestId: string;
  },
  options: { transactionRunner?: TransactionRunner } = {}
) => {
  if (options.transactionRunner && process.env.NODE_ENV !== "test") {
    throw new Error("Audit CSV transaction runner injection is test-only");
  }
  const boundary = buildBoundary(input.user, input.filters, input.requestId);
  return withCanonicalDbContext(options.transactionRunner || prisma, boundary.context, async (tx) => {
    let userIds = boundary.userIds;
    if (!boundary.isSuper && !userIds && boundary.licenseeId) {
      const scopedUsers = await tx.user.findMany({
        where: {
          OR: [
            { licenseeId: boundary.licenseeId },
            { manufacturerLicenseeLinks: { some: { licenseeId: boundary.licenseeId } } },
          ],
        },
        select: { id: true },
      });
      userIds = scopedUsers.map((user) => user.id);
    }

    const where: Prisma.AuditLogWhereInput = {
      ...(input.filters.entityType ? { entityType: input.filters.entityType } : {}),
      ...(input.filters.entityId ? { entityId: input.filters.entityId } : {}),
      ...(input.filters.action
        ? { action: input.filters.action }
        : boundary.isSuper
          ? {}
          : { action: { notIn: hiddenActionsForNonSuper } }),
    };
    if (!boundary.isSuper && input.filters.action && hiddenActionsForNonSuper.includes(input.filters.action)) {
      where.id = { in: [] };
    }
    if (boundary.isSuper) {
      where.licenseeId = boundary.licenseeId;
    } else if (boundary.licenseeId || userIds?.length) {
      where.OR = [
        ...(userIds?.length ? [{ userId: { in: userIds } }] : []),
        ...(boundary.licenseeId ? [{ licenseeId: boundary.licenseeId }] : []),
      ];
    } else {
      where.id = { in: [] };
    }

    const logs = await tx.auditLog.findMany({
      where,
      select: {
        id: true,
        createdAt: true,
        action: true,
        entityType: true,
        entityId: true,
        userId: true,
        licenseeId: true,
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: input.filters.limit,
    });

    const actorIds = Array.from(new Set(logs.map((log) => log.userId).filter(Boolean))) as string[];
    const users = actorIds.length
      ? await tx.user.findMany({
          where: { id: { in: actorIds } },
          select: { id: true, name: true },
        })
      : [];
    await tx.auditLog.create({
      data: {
        userId: boundary.context.userId,
        orgId: boundary.context.organizationId,
        licenseeId: boundary.context.licenseeId,
        action: "AUDIT_CSV_EXPORT",
        entityType: "AuditLog",
        entityId: boundary.context.licenseeId,
        details: {
          purpose: boundary.context.purpose,
          requestId: boundary.context.requestId,
          rowCount: logs.length,
          filters: {
            entityType: input.filters.entityType || null,
            entityId: input.filters.entityId || null,
            action: input.filters.action || null,
          },
        },
      },
      select: { id: true },
    });
    return {
      logs,
      userMap: new Map(users.map((user) => [user.id, { ...user, email: "" }])),
      isSuper: boundary.isSuper,
    };
  });
};

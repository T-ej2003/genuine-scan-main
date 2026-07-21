import { Prisma, UserRole } from "@prisma/client";

import { CanonicalDbContext } from "../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../types";
import { decodeDateCursor, encodeDateCursor } from "../utils/cursorPagination";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { hiddenActionsForNonSuper, isAuditManufacturerUser, isAuditSuperUser, redactAuditDetails } from "./auditExportRedactionService";
import { createAuditLogInTransaction } from "./auditService";

export type AuditLogQueryFilters = {
  limit: number;
  offset: number;
  cursor?: string;
  entityType?: string;
  entityId?: string;
  action?: string;
  userId?: string;
  licenseeId?: string;
  organizationId?: string;
  manufacturerId?: string;
  from?: string;
  to?: string;
  purpose?: string;
};

export class AuditLogQueryAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

type AuditLogBoundary = {
  context: CanonicalDbContext;
  isPlatformAdmin: boolean;
  isManufacturer: boolean;
  requestedPurpose: string;
};

const tenantAdminRoles = new Set<UserRole>([UserRole.LICENSEE_ADMIN, UserRole.ORG_ADMIN]);

export const buildAuditLogBoundary = (
  user: AuthenticatedSessionClaims,
  filters: AuditLogQueryFilters,
  requestId: string
): AuditLogBoundary => {
  const userId = String(user?.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  const actorLicenseeId = String(user?.licenseeId || "").trim();
  const requestedLicenseeId = String(filters.licenseeId || "").trim();
  const actorOrgId = String(user?.orgId || "").trim();
  const isPlatformAdmin = isAuditSuperUser(user?.role);
  const isManufacturer = isAuditManufacturerUser(user?.role);

  if (!userId || !normalizedRequestId || user?.sessionStage !== "ACTIVE") {
    throw new AuditLogQueryAccessError("Authenticated actor context is required", 401);
  }
  if (!isPlatformAdmin && !isManufacturer && !tenantAdminRoles.has(user.role)) {
    throw new AuditLogQueryAccessError("Insufficient permissions");
  }
  if (user.authAssurance !== "ADMIN_MFA") throw new AuditLogQueryAccessError("Fresh administrator MFA is required");
  const mfaVerifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
  if (!Number.isFinite(mfaVerifiedAt) || Date.now() - mfaVerifiedAt > getAdminStepUpWindowMinutes() * 60_000) {
    throw new AuditLogQueryAccessError("Fresh administrator MFA is required");
  }

  let licenseeId: string;
  if (isPlatformAdmin) {
    if (!requestedLicenseeId) throw new AuditLogQueryAccessError("A bounded licensee scope is required");
    licenseeId = requestedLicenseeId;
  } else if (isManufacturer) {
    const linked = new Set([actorLicenseeId, ...(user.linkedLicenseeIds || [])].map((value) => String(value || "").trim()).filter(Boolean));
    licenseeId = requestedLicenseeId || actorLicenseeId;
    if (!licenseeId) throw new AuditLogQueryAccessError("A manufacturer tenant scope is required");
    if (!linked.has(licenseeId)) throw new AuditLogQueryAccessError("Access denied to this licensee");
    if (filters.manufacturerId && filters.manufacturerId !== userId) throw new AuditLogQueryAccessError("Access denied to this manufacturer");
    if (filters.userId && filters.userId !== userId) throw new AuditLogQueryAccessError("Access denied to this actor");
  } else {
    if (!actorLicenseeId) throw new AuditLogQueryAccessError("A tenant scope is required");
    if (requestedLicenseeId && requestedLicenseeId !== actorLicenseeId) throw new AuditLogQueryAccessError("Access denied to this licensee");
    licenseeId = actorLicenseeId;
  }
  if (filters.organizationId && filters.organizationId !== actorOrgId) {
    throw new AuditLogQueryAccessError("Access denied to this organization");
  }

  const requestedPurpose = isPlatformAdmin ? String(filters.purpose || "").trim() : String(filters.purpose || "audit-log-read").trim();
  if (!requestedPurpose) throw new AuditLogQueryAccessError("An explicit audit-log purpose is required");
  if (requestedPurpose.length > 240) throw new AuditLogQueryAccessError("Audit-log purpose is too long", 400);
  if (filters.cursor && filters.offset) throw new AuditLogQueryAccessError("Cursor and offset pagination cannot be combined", 400);
  if (filters.cursor && !decodeDateCursor(filters.cursor)) throw new AuditLogQueryAccessError("Invalid audit-log cursor", 400);
  if (Boolean(filters.from) !== Boolean(filters.to)) throw new AuditLogQueryAccessError("Audit-log date range requires both from and to", 400);
  if (filters.from && filters.to) {
    const from = Date.parse(filters.from);
    const to = Date.parse(filters.to);
    if (!Number.isFinite(from) || !Number.isFinite(to) || from > to || to - from > 90 * 24 * 60 * 60 * 1000) {
      throw new AuditLogQueryAccessError("Audit-log date range is invalid or exceeds 90 days", 400);
    }
  }

  return {
    context: {
      userId,
      role: String(user.role),
      organizationId: actorOrgId || null,
      licenseeId,
      manufacturerId: isManufacturer ? userId : null,
      authAssurance: "mfa-verified",
      requestId: normalizedRequestId,
      purpose: isPlatformAdmin ? "platform-audit-log-read" : "audit-log-read",
    },
    isPlatformAdmin,
    isManufacturer,
    requestedPurpose,
  };
};

export const queryAuditLogs = async (
  tx: Prisma.TransactionClient,
  filters: AuditLogQueryFilters,
  boundary: AuditLogBoundary
) => {
  const context = boundary.context;
  if (!context.licenseeId || filters.licenseeId && filters.licenseeId !== context.licenseeId) {
    throw new AuditLogQueryAccessError("Audit-log scope does not match canonical context");
  }
  const clauses: Prisma.AuditLogWhereInput[] = [{ licenseeId: context.licenseeId }];
  if (boundary.isManufacturer) clauses.push({ userId: context.userId });
  if (filters.organizationId) clauses.push({ orgId: filters.organizationId });
  if (filters.userId) clauses.push({ userId: filters.userId });
  if (filters.entityType) clauses.push({ entityType: filters.entityType });
  if (filters.entityId) clauses.push({ entityId: filters.entityId });
  if (filters.action) clauses.push({ action: filters.action });
  else if (!boundary.isPlatformAdmin) clauses.push({ action: { notIn: hiddenActionsForNonSuper } });
  if (!boundary.isPlatformAdmin && filters.action && hiddenActionsForNonSuper.includes(filters.action)) clauses.push({ id: { in: [] } });
  if (filters.from && filters.to) clauses.push({ createdAt: { gte: new Date(filters.from), lte: new Date(filters.to) } });
  const cursor = filters.cursor ? decodeDateCursor(filters.cursor) : null;
  if (cursor) {
    clauses.push({
      OR: [
        { createdAt: { lt: new Date(cursor.createdAt) } },
        { createdAt: new Date(cursor.createdAt), id: { lt: cursor.id } },
      ],
    });
  }
  const where: Prisma.AuditLogWhereInput = { AND: clauses };
  const [logs, total] = await Promise.all([
    tx.auditLog.findMany({
      where,
      select: {
        id: true,
        userId: true,
        orgId: true,
        licenseeId: true,
        action: true,
        entityType: true,
        entityId: true,
        details: true,
        createdAt: true,
      },
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: filters.limit,
      skip: filters.cursor ? 0 : filters.offset,
    }),
    filters.cursor ? Promise.resolve<number | null>(null) : tx.auditLog.count({ where }),
  ]);
  const platformDetails = boundary.isPlatformAdmin && logs.length
    ? await tx.$queryRaw<Array<{ id: string; ipAddress: string | null; userAgent: string | null; userId: string | null; userName: string | null }>>`
        SELECT id,ip_address AS "ipAddress",user_agent AS "userAgent",user_id AS "userId",user_name AS "userName"
        FROM app_rls.platform_audit_log_details(${logs.map((log) => log.id)}::text[])
      `
    : [];
  const platformDetailMap = new Map(platformDetails.map((row) => [row.id, row]));
  if (boundary.isPlatformAdmin && (platformDetailMap.size !== logs.length || logs.some((log) => !platformDetailMap.has(log.id)))) {
    throw new Error("Platform audit detail projection did not match the bounded audit page");
  }
  const actorIds = boundary.isPlatformAdmin ? [] : [...new Set(logs.map((log) => log.userId).filter(Boolean))] as string[];
  const users = actorIds.length
    ? await tx.user.findMany({ where: { id: { in: actorIds } }, select: { id: true, name: true } })
    : [];
  const userMap = new Map(users.map((user) => [user.id, { ...user, email: "" }]));
  const responseLogs = logs.map((log) => {
    const platformDetail = platformDetailMap.get(log.id);
    return {
      ...log,
      details: redactAuditDetails(log.details),
      ipAddress: platformDetail?.ipAddress ?? null,
      userAgent: platformDetail?.userAgent ?? null,
      user: boundary.isPlatformAdmin
        ? platformDetail?.userId && platformDetail.userName ? { id: platformDetail.userId, name: platformDetail.userName, email: "" } : null
        : log.userId ? userMap.get(log.userId) || null : null,
    };
  });
  await createAuditLogInTransaction(tx, context, {
    action: "AUDIT_LOGS_READ",
    entityType: "AuditLog",
    entityId: context.licenseeId,
    details: {
      purpose: boundary.requestedPurpose,
      requestId: context.requestId,
      returnedRows: responseLogs.length,
      filters: {
        action: filters.action || null,
        entityType: filters.entityType || null,
        entityId: filters.entityId || null,
        userId: filters.userId || null,
        from: filters.from || null,
        to: filters.to || null,
      },
    },
  });
  return {
    logs: responseLogs,
    total,
    nextCursor: logs.length === filters.limit ? encodeDateCursor(logs[logs.length - 1]) : null,
  };
};

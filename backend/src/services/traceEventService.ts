import { Prisma, TraceEventType, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { CanonicalDbContext } from "../lib/canonicalDbContext";
import { AuthenticatedSessionClaims } from "../types";
import { buildDateCursorWhere, encodeDateCursor } from "../utils/cursorPagination";
import { getAdminStepUpWindowMinutes } from "./auth/authService";
import { redactAuditDetails } from "./auditExportRedactionService";

const backfillState = new Map<string, number>();
const BACKFILL_COOLDOWN_MS = 5 * 60_000;
const platformRoles = new Set<UserRole>([UserRole.SUPER_ADMIN, UserRole.PLATFORM_SUPER_ADMIN]);
const manufacturerRoles = new Set<UserRole>([UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER]);

export class TraceTimelineAccessError extends Error {
  constructor(message: string, readonly statusCode = 403) {
    super(message);
  }
}

export type TraceTimelineQuery = {
  licenseeId?: string;
  eventType?: TraceEventType;
  batchId?: string;
  manufacturerId?: string;
  qrCodeId?: string;
  limit: number;
  offset: number;
  cursor?: string | null;
  purpose?: string;
};

export const buildTraceTimelineBoundary = (
  user: AuthenticatedSessionClaims,
  query: TraceTimelineQuery,
  requestId: string
): { context: CanonicalDbContext; query: TraceTimelineQuery } => {
  const userId = String(user?.userId || "").trim();
  const normalizedRequestId = String(requestId || "").trim();
  const actorLicenseeId = String(user?.licenseeId || "").trim();
  const requestedLicenseeId = String(query.licenseeId || "").trim();
  const requestedManufacturerId = String(query.manufacturerId || "").trim();
  const isPlatform = platformRoles.has(user?.role);
  const isManufacturer = manufacturerRoles.has(user?.role);
  if (!userId || !normalizedRequestId || user?.sessionStage !== "ACTIVE") {
    throw new TraceTimelineAccessError("Authenticated actor context is required", 401);
  }
  if (user.authAssurance !== "PASSWORD" && user.authAssurance !== "ADMIN_MFA") {
    throw new TraceTimelineAccessError("Unsupported authentication assurance");
  }

  let licenseeId: string;
  let manufacturerId = requestedManufacturerId || undefined;
  if (isPlatform) {
    if (user.authAssurance !== "ADMIN_MFA") throw new TraceTimelineAccessError("Fresh administrator MFA is required");
    const verifiedAt = Date.parse(String(user.mfaVerifiedAt || ""));
    if (!Number.isFinite(verifiedAt) || Date.now() - verifiedAt > getAdminStepUpWindowMinutes() * 60_000) {
      throw new TraceTimelineAccessError("Fresh administrator MFA is required");
    }
    if (!requestedLicenseeId) throw new TraceTimelineAccessError("A bounded licensee scope is required");
    licenseeId = requestedLicenseeId;
  } else if (isManufacturer) {
    const linked = new Set([actorLicenseeId, ...(user.linkedLicenseeIds || [])].map((value) => String(value || "").trim()).filter(Boolean));
    licenseeId = requestedLicenseeId || actorLicenseeId;
    if (!licenseeId || !linked.has(licenseeId)) throw new TraceTimelineAccessError("Access denied to this licensee");
    if (requestedManufacturerId && requestedManufacturerId !== userId) throw new TraceTimelineAccessError("Access denied to this manufacturer");
    manufacturerId = userId;
  } else {
    if (!actorLicenseeId) throw new TraceTimelineAccessError("A tenant scope is required");
    if (requestedLicenseeId && requestedLicenseeId !== actorLicenseeId) throw new TraceTimelineAccessError("Access denied to this licensee");
    licenseeId = actorLicenseeId;
  }

  const purpose = String(query.purpose || (isPlatform ? "" : "trace-timeline-read")).trim();
  if (!purpose) throw new TraceTimelineAccessError("An explicit trace-read purpose is required");
  if (purpose.length > 240) throw new TraceTimelineAccessError("Trace-read purpose is too long", 400);

  return {
    context: {
      userId,
      role: String(user.role),
      organizationId: user.orgId || null,
      licenseeId,
      manufacturerId: isManufacturer ? userId : null,
      authAssurance: user.authAssurance === "ADMIN_MFA" ? "mfa-verified" : "password-verified",
      requestId: normalizedRequestId,
      purpose,
    },
    query: { ...query, licenseeId, manufacturerId },
  };
};

export type TraceEventInput = {
  eventType: TraceEventType;
  licenseeId: string;
  batchId?: string | null;
  qrCodeId?: string | null;
  manufacturerId?: string | null;
  userId?: string | null;
  sourceAction?: string | null;
  details?: any;
  createdAt?: Date;
};

const toUpper = (v: any) => String(v || "").trim().toUpperCase();

const asStringOrNull = (v: any): string | null => {
  if (typeof v !== "string") return null;
  const s = v.trim();
  return s ? s : null;
};

const resolveLicenseeId = (log: {
  licenseeId?: string | null;
  details?: any;
  entityType?: string;
}): string | null => {
  if (log.licenseeId) return log.licenseeId;
  const d: any = log.details || {};
  return asStringOrNull(d.licenseeId) || asStringOrNull(d.licensee_id) || null;
};

const resolveBatchId = (log: {
  entityType?: string;
  entityId?: string | null;
  details?: any;
}): string | null => {
  const d: any = log.details || {};
  if (toUpper(log.entityType) === "BATCH") return asStringOrNull(log.entityId);
  return (
    asStringOrNull(d.batchId) ||
    asStringOrNull(d.batch_id) ||
    asStringOrNull(d.childBatchId) ||
    asStringOrNull(d.parentBatchId) ||
    null
  );
};

const resolveQrCodeId = (log: {
  entityType?: string;
  entityId?: string | null;
  details?: any;
}): string | null => {
  const d: any = log.details || {};
  if (toUpper(log.entityType) === "QRCODE") return asStringOrNull(log.entityId);
  return asStringOrNull(d.qrCodeId) || asStringOrNull(d.qrCode_id) || asStringOrNull(d.qrId) || null;
};

const resolveManufacturerId = (log: { details?: any }): string | null => {
  const d: any = log.details || {};
  return asStringOrNull(d.manufacturerId) || asStringOrNull(d.manufacturer_id) || null;
};

export const deriveTraceEventTypeFromAudit = (log: {
  action?: string;
  details?: any;
}): TraceEventType | null => {
  const action = toUpper(log.action);
  const context = toUpper(log.details?.context);

  if (action === "BLOCKED") return TraceEventType.BLOCKED;

  if (action === "PRINTED" || action === "DOWNLOAD_BATCH_PRINT_PACK") {
    return TraceEventType.PRINTED;
  }

  if (action === "REDEEMED") return TraceEventType.REDEEMED;
  if (action === "VERIFY_SUCCESS" && !!log.details?.isFirstScan) return TraceEventType.REDEEMED;

  if (
    action === "ALLOCATE_QR_RANGE" ||
    action === "ALLOCATE_QR_RANGE_LICENSEE" ||
    context === "ALLOCATE_QR_RANGE" ||
    context === "ALLOCATE_QR_RANGE_LICENSEE"
  ) {
    return TraceEventType.COMMISSIONED;
  }

  if (
    action === "ALLOCATED" ||
    action === "CREATE_BATCH" ||
    context.startsWith("ASSIGN_MANUFACTURER") ||
    context === "CREATE_BATCH"
  ) {
    return TraceEventType.ASSIGNED;
  }

  return null;
};

export const createTraceEvent = async (data: TraceEventInput) => {
  return prisma.traceEvent.create({
    data: {
      eventType: data.eventType,
      licenseeId: data.licenseeId,
      batchId: data.batchId || null,
      qrCodeId: data.qrCodeId || null,
      manufacturerId: data.manufacturerId || null,
      userId: data.userId || null,
      sourceAction: data.sourceAction || null,
      details: data.details ?? null,
      createdAt: data.createdAt,
    },
  });
};

export const createTraceEventFromAuditLog = async (log: {
  id: string;
  action: string;
  entityType: string;
  entityId: string | null;
  userId: string | null;
  licenseeId: string | null;
  details: any;
  createdAt: Date;
}) => {
  const eventType = deriveTraceEventTypeFromAudit(log);
  if (!eventType) return null;

  const licenseeId = resolveLicenseeId(log);
  if (!licenseeId) return null;

  const existing = await prisma.traceEvent.findFirst({
    where: {
      licenseeId,
      details: {
        path: ["auditLogId"],
        equals: log.id,
      },
    },
    select: { id: true },
  });
  if (existing) return null;

  return createTraceEvent({
    eventType,
    licenseeId,
    batchId: resolveBatchId(log),
    qrCodeId: resolveQrCodeId(log),
    manufacturerId: resolveManufacturerId(log),
    userId: log.userId || null,
    sourceAction: log.action,
    details: {
      auditLogId: log.id,
      entityType: log.entityType,
      entityId: log.entityId,
      ...(log.details || {}),
    },
    createdAt: log.createdAt,
  });
};

export const backfillTraceEventsFromAuditLogs = async (opts?: {
  licenseeId?: string;
  limit?: number;
  force?: boolean;
}) => {
  const key = opts?.licenseeId || "__ALL__";
  const nowMs = Date.now();
  const last = backfillState.get(key) || 0;
  if (!opts?.force && nowMs - last < BACKFILL_COOLDOWN_MS) return;
  backfillState.set(key, nowMs);

  const limit = Math.max(100, Math.min(opts?.limit ?? 2000, 10000));
  const where: any = {};
  if (opts?.licenseeId) where.licenseeId = opts.licenseeId;

  const logs = await prisma.auditLog.findMany({
    where,
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: limit,
    select: {
      id: true,
      action: true,
      entityType: true,
      entityId: true,
      userId: true,
      licenseeId: true,
      details: true,
      createdAt: true,
    },
  });

  for (const log of logs.reverse()) {
    try {
      await createTraceEventFromAuditLog(log);
    } catch {
      // keep backfill best-effort
    }
  }
};

export const getTraceTimeline = async (
  tx: Prisma.TransactionClient,
  opts: TraceTimelineQuery,
  context: CanonicalDbContext
) => {
  if (!context.licenseeId || opts.licenseeId !== context.licenseeId) {
    throw new TraceTimelineAccessError("Trace scope does not match canonical context");
  }
  if (context.manufacturerId && opts.manufacturerId !== context.manufacturerId) {
    throw new TraceTimelineAccessError("Manufacturer scope does not match canonical context");
  }
  const where: any = {};
  if (opts.licenseeId) where.licenseeId = opts.licenseeId;
  if (opts.eventType) where.eventType = opts.eventType;
  if (opts.batchId) where.batchId = opts.batchId;
  if (opts.manufacturerId) where.manufacturerId = opts.manufacturerId;
  if (opts.qrCodeId) where.qrCodeId = opts.qrCodeId;

  const cursorWhere = buildDateCursorWhere({
    cursor: opts.cursor,
    createdAtField: "createdAt",
    idField: "id",
  });
  if (cursorWhere) {
    where.AND = [...(Array.isArray(where.AND) ? where.AND : []), cursorWhere];
  }

  const [events, total] = await Promise.all([
    tx.traceEvent.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: opts.limit,
      skip: opts.cursor ? 0 : opts.offset,
      select: {
        id: true,
        eventType: true,
        licenseeId: true,
        batchId: true,
        qrCodeId: true,
        manufacturerId: true,
        userId: true,
        sourceAction: true,
        details: true,
        createdAt: true,
        user: { select: { id: true, name: true, email: true } },
        manufacturer: { select: { id: true, name: true, email: true } },
        batch: { select: { id: true, name: true } },
        qrCode: { select: { id: true, code: true } },
      },
    }),
    opts.cursor ? Promise.resolve<number | null>(null) : tx.traceEvent.count({ where }),
  ]);

  const nextCursor = events.length === opts.limit ? encodeDateCursor(events[events.length - 1]) : null;
  return { events: events.map((event) => ({ ...event, details: redactAuditDetails(event.details) })), total, nextCursor };
};

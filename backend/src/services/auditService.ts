import prisma from "../config/database";
import { Prisma } from "@prisma/client";
import { createTraceEventFromAuditLog } from "./traceEventService";
import { hashIp, normalizeUserAgent } from "../utils/security";
import { queueSecurityEvent } from "./siemOutboxService";
import { appendForensicChainFromAuditLog } from "./forensicChainService";
import { getRedisInstanceId, publishRedisJson, subscribeRedisJson } from "./redisService";
import { bumpCacheNamespaceVersion } from "./versionedCacheService";
import { buildDateCursorWhere, encodeDateCursor } from "../utils/cursorPagination";

export interface AuditLogInput {
  userId?: string;
  orgId?: string;
  licenseeId?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: any;
  ipAddress?: string;
  ipHash?: string;
  userAgent?: string;
}

type Listener = (log: any) => void;

const listeners = new Set<Listener>();
const AUDIT_LOG_CHANNEL = "mscqr:realtime:audit-log";
let auditChannelReady = false;

export const onAuditLog = (cb: Listener) => {
  if (!auditChannelReady) {
    auditChannelReady = true;
    void subscribeRedisJson(AUDIT_LOG_CHANNEL, (payload) => {
      if (!payload || payload.origin === getRedisInstanceId()) return;
      emitAuditLog(payload.log);
    });
  }
  listeners.add(cb);
  return () => listeners.delete(cb);
};

const emitAuditLog = (log: any) => {
  for (const cb of listeners) cb(log);
};

const resolveOrgId = async (input: { orgId?: string; licenseeId?: string }) => {
  const explicitOrgId = String(input.orgId || "").trim();
  if (explicitOrgId) return explicitOrgId;

  const licenseeId = String(input.licenseeId || "").trim();
  if (!licenseeId) return undefined;

  const licensee = await prisma.licensee.findUnique({
    where: { id: licenseeId },
    select: { orgId: true },
  });
  const derived = String(licensee?.orgId || "").trim();
  return derived || undefined;
};

export const createAuditLog = async (data: AuditLogInput) => {
  const storeRawIp = ["1", "true", "yes", "on"].includes(String(process.env.AUDIT_LOG_STORE_RAW_IP || "").trim().toLowerCase());
  const resolvedOrgId = await resolveOrgId({ orgId: data.orgId, licenseeId: data.licenseeId });
  const resolvedIpHash = data.ipHash ?? hashIp(data.ipAddress);
  const resolvedUserAgent = normalizeUserAgent(data.userAgent);

  const payload = {
    ...data,
    orgId: resolvedOrgId,
    ipHash: resolvedIpHash || undefined,
    userAgent: resolvedUserAgent || undefined,
    ipAddress: storeRawIp ? data.ipAddress : undefined,
  } as any;

  let log;
  try {
    log = await prisma.auditLog.create({ data: payload });
  } catch (error) {
    // Graceful fallback: never let audit FK inconsistency break business requests.
    if (
      error instanceof Prisma.PrismaClientKnownRequestError &&
      error.code === "P2003" &&
      String(error.message || "").includes("AuditLog_orgId_fkey")
    ) {
      const retryPayload = { ...payload, orgId: undefined };
      log = await prisma.auditLog.create({ data: retryPayload });
    } else {
      throw error;
    }
  }
  try {
    await createTraceEventFromAuditLog({
      id: log.id,
      action: log.action,
      entityType: log.entityType,
      entityId: log.entityId,
      userId: log.userId,
      licenseeId: log.licenseeId,
      details: log.details,
      createdAt: log.createdAt,
    });
  } catch (e) {
    // audit log creation should not fail if trace projection fails
    console.error("createTraceEventFromAuditLog failed:", e);
  }
  try {
    await appendForensicChainFromAuditLog({
      id: log.id,
      action: log.action,
      entityType: log.entityType,
      entityId: log.entityId,
      userId: log.userId,
      orgId: log.orgId,
      licenseeId: log.licenseeId,
      details: log.details,
      createdAt: log.createdAt,
    });
  } catch (e) {
    // forensic projection is best-effort and must not fail request path
    console.error("appendForensicChainFromAuditLog failed:", e);
  }
  emitAuditLog(log);
  void publishRedisJson(AUDIT_LOG_CHANNEL, {
    origin: getRedisInstanceId(),
    log,
  }).catch(() => undefined);
  void bumpCacheNamespaceVersion("dashboard-snapshot").catch(() => undefined);
  await queueSecurityEvent("AUDIT_LOG", {
    id: log.id,
    action: log.action,
    entityType: log.entityType,
    entityId: log.entityId,
    userId: log.userId,
    orgId: log.orgId,
    licenseeId: log.licenseeId,
    details: log.details ?? null,
    createdAt: log.createdAt instanceof Date ? log.createdAt.toISOString() : String(log.createdAt || ""),
  });
  return log;
};

export const getAuditLogs = async (opts: {
  userId?: string;
  entityType?: string;
  entityId?: string;
  action?: string;
  excludeActions?: string[];
  licenseeId?: string;
  userIds?: string[];
  limit: number;
  offset: number;
  cursor?: string | null;
}) => {
  const where: any = {};
  if (opts.userId) where.userId = opts.userId;
  if (opts.entityType) where.entityType = opts.entityType;
  if (opts.entityId) where.entityId = opts.entityId;
  if (opts.action) where.action = opts.action;
  if (opts.excludeActions?.length) {
    where.action = opts.action
      ? opts.action
      : {
          notIn: opts.excludeActions,
        };
  }
  if (opts.userIds && opts.userIds.length) {
    const or: any[] = [{ userId: { in: opts.userIds } }];
    if (opts.licenseeId) or.push({ licenseeId: opts.licenseeId });
    where.OR = or;
  } else if (opts.licenseeId) {
    where.licenseeId = opts.licenseeId;
  }

  const cursorWhere = buildDateCursorWhere({
    cursor: opts.cursor,
    createdAtField: "createdAt",
    idField: "id",
  });
  if (cursorWhere) {
    where.AND = [...(Array.isArray(where.AND) ? where.AND : []), cursorWhere];
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: opts.limit,
      skip: opts.cursor ? 0 : opts.offset,
    }),
    opts.cursor ? Promise.resolve<number | null>(null) : prisma.auditLog.count({ where }),
  ]);

  const nextCursor = logs.length === opts.limit ? encodeDateCursor(logs[logs.length - 1]) : null;
  return { logs, total, nextCursor };
};

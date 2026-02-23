import prisma from "../config/database";
import { createTraceEventFromAuditLog } from "./traceEventService";
import { hashIp, normalizeUserAgent } from "../utils/security";

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

export const onAuditLog = (cb: Listener) => {
  listeners.add(cb);
  return () => listeners.delete(cb);
};

const emitAuditLog = (log: any) => {
  for (const cb of listeners) cb(log);
};

export const createAuditLog = async (data: AuditLogInput) => {
  const storeRawIp = ["1", "true", "yes", "on"].includes(String(process.env.AUDIT_LOG_STORE_RAW_IP || "").trim().toLowerCase());
  const resolvedOrgId = data.orgId ?? data.licenseeId;
  const resolvedIpHash = data.ipHash ?? hashIp(data.ipAddress);
  const resolvedUserAgent = normalizeUserAgent(data.userAgent);

  const log = await prisma.auditLog.create({
    data: {
      ...data,
      orgId: resolvedOrgId,
      ipHash: resolvedIpHash || undefined,
      userAgent: resolvedUserAgent || undefined,
      ipAddress: storeRawIp ? data.ipAddress : undefined,
    } as any,
  });
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
  emitAuditLog(log);
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

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      take: opts.limit,
      skip: opts.offset,
    }),
    prisma.auditLog.count({ where }),
  ]);

  return { logs, total };
};

import prisma from "../config/database";
import { Prisma } from "@prisma/client";
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

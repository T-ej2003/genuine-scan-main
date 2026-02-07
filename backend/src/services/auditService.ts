import prisma from "../config/database";

export interface AuditLogInput {
  userId?: string;
  licenseeId?: string;
  action: string;
  entityType: string;
  entityId?: string;
  details?: any;
  ipAddress?: string;
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
  const log = await prisma.auditLog.create({ data });
  emitAuditLog(log);
  return log;
};

export const getAuditLogs = async (opts: {
  userId?: string;
  entityType?: string;
  entityId?: string;
  licenseeId?: string;
  userIds?: string[];
  limit: number;
  offset: number;
}) => {
  const where: any = {};
  if (opts.userId) where.userId = opts.userId;
  if (opts.entityType) where.entityType = opts.entityType;
  if (opts.entityId) where.entityId = opts.entityId;
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

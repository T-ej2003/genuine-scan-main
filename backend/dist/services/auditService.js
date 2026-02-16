"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAuditLogs = exports.createAuditLog = exports.onAuditLog = void 0;
const database_1 = __importDefault(require("../config/database"));
const traceEventService_1 = require("./traceEventService");
const security_1 = require("../utils/security");
const listeners = new Set();
const onAuditLog = (cb) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
};
exports.onAuditLog = onAuditLog;
const emitAuditLog = (log) => {
    for (const cb of listeners)
        cb(log);
};
const createAuditLog = async (data) => {
    const storeRawIp = ["1", "true", "yes", "on"].includes(String(process.env.AUDIT_LOG_STORE_RAW_IP || "").trim().toLowerCase());
    const resolvedOrgId = data.orgId ?? data.licenseeId;
    const resolvedIpHash = data.ipHash ?? (0, security_1.hashIp)(data.ipAddress);
    const resolvedUserAgent = (0, security_1.normalizeUserAgent)(data.userAgent);
    const log = await database_1.default.auditLog.create({
        data: {
            ...data,
            orgId: resolvedOrgId,
            ipHash: resolvedIpHash || undefined,
            userAgent: resolvedUserAgent || undefined,
            ipAddress: storeRawIp ? data.ipAddress : undefined,
        },
    });
    try {
        await (0, traceEventService_1.createTraceEventFromAuditLog)({
            id: log.id,
            action: log.action,
            entityType: log.entityType,
            entityId: log.entityId,
            userId: log.userId,
            licenseeId: log.licenseeId,
            details: log.details,
            createdAt: log.createdAt,
        });
    }
    catch (e) {
        // audit log creation should not fail if trace projection fails
        console.error("createTraceEventFromAuditLog failed:", e);
    }
    emitAuditLog(log);
    return log;
};
exports.createAuditLog = createAuditLog;
const getAuditLogs = async (opts) => {
    const where = {};
    if (opts.userId)
        where.userId = opts.userId;
    if (opts.entityType)
        where.entityType = opts.entityType;
    if (opts.entityId)
        where.entityId = opts.entityId;
    if (opts.action)
        where.action = opts.action;
    if (opts.excludeActions?.length) {
        where.action = opts.action
            ? opts.action
            : {
                notIn: opts.excludeActions,
            };
    }
    if (opts.userIds && opts.userIds.length) {
        const or = [{ userId: { in: opts.userIds } }];
        if (opts.licenseeId)
            or.push({ licenseeId: opts.licenseeId });
        where.OR = or;
    }
    else if (opts.licenseeId) {
        where.licenseeId = opts.licenseeId;
    }
    const [logs, total] = await Promise.all([
        database_1.default.auditLog.findMany({
            where,
            orderBy: { createdAt: "desc" },
            take: opts.limit,
            skip: opts.offset,
        }),
        database_1.default.auditLog.count({ where }),
    ]);
    return { logs, total };
};
exports.getAuditLogs = getAuditLogs;
//# sourceMappingURL=auditService.js.map
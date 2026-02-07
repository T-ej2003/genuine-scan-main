"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAuditLogs = exports.createAuditLog = exports.onAuditLog = void 0;
const database_1 = __importDefault(require("../config/database"));
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
    const log = await database_1.default.auditLog.create({ data });
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
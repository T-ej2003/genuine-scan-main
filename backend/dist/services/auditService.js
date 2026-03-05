"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAuditLogs = exports.createAuditLog = exports.onAuditLog = void 0;
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const traceEventService_1 = require("./traceEventService");
const security_1 = require("../utils/security");
const siemOutboxService_1 = require("./siemOutboxService");
const forensicChainService_1 = require("./forensicChainService");
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
const resolveOrgId = async (input) => {
    const explicitOrgId = String(input.orgId || "").trim();
    if (explicitOrgId)
        return explicitOrgId;
    const licenseeId = String(input.licenseeId || "").trim();
    if (!licenseeId)
        return undefined;
    const licensee = await database_1.default.licensee.findUnique({
        where: { id: licenseeId },
        select: { orgId: true },
    });
    const derived = String(licensee?.orgId || "").trim();
    return derived || undefined;
};
const createAuditLog = async (data) => {
    const storeRawIp = ["1", "true", "yes", "on"].includes(String(process.env.AUDIT_LOG_STORE_RAW_IP || "").trim().toLowerCase());
    const resolvedOrgId = await resolveOrgId({ orgId: data.orgId, licenseeId: data.licenseeId });
    const resolvedIpHash = data.ipHash ?? (0, security_1.hashIp)(data.ipAddress);
    const resolvedUserAgent = (0, security_1.normalizeUserAgent)(data.userAgent);
    const payload = {
        ...data,
        orgId: resolvedOrgId,
        ipHash: resolvedIpHash || undefined,
        userAgent: resolvedUserAgent || undefined,
        ipAddress: storeRawIp ? data.ipAddress : undefined,
    };
    let log;
    try {
        log = await database_1.default.auditLog.create({ data: payload });
    }
    catch (error) {
        // Graceful fallback: never let audit FK inconsistency break business requests.
        if (error instanceof client_1.Prisma.PrismaClientKnownRequestError &&
            error.code === "P2003" &&
            String(error.message || "").includes("AuditLog_orgId_fkey")) {
            const retryPayload = { ...payload, orgId: undefined };
            log = await database_1.default.auditLog.create({ data: retryPayload });
        }
        else {
            throw error;
        }
    }
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
    try {
        await (0, forensicChainService_1.appendForensicChainFromAuditLog)({
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
    }
    catch (e) {
        // forensic projection is best-effort and must not fail request path
        console.error("appendForensicChainFromAuditLog failed:", e);
    }
    emitAuditLog(log);
    await (0, siemOutboxService_1.queueSecurityEvent)("AUDIT_LOG", {
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
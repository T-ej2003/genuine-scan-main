"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getTraceTimeline = exports.backfillTraceEventsFromAuditLogs = exports.createTraceEventFromAuditLog = exports.createTraceEvent = exports.deriveTraceEventTypeFromAudit = void 0;
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const backfillState = new Map();
const BACKFILL_COOLDOWN_MS = 5 * 60_000;
const toUpper = (v) => String(v || "").trim().toUpperCase();
const asStringOrNull = (v) => {
    if (typeof v !== "string")
        return null;
    const s = v.trim();
    return s ? s : null;
};
const resolveLicenseeId = (log) => {
    if (log.licenseeId)
        return log.licenseeId;
    const d = log.details || {};
    return asStringOrNull(d.licenseeId) || asStringOrNull(d.licensee_id) || null;
};
const resolveBatchId = (log) => {
    const d = log.details || {};
    if (toUpper(log.entityType) === "BATCH")
        return asStringOrNull(log.entityId);
    return (asStringOrNull(d.batchId) ||
        asStringOrNull(d.batch_id) ||
        asStringOrNull(d.childBatchId) ||
        asStringOrNull(d.parentBatchId) ||
        null);
};
const resolveQrCodeId = (log) => {
    const d = log.details || {};
    if (toUpper(log.entityType) === "QRCODE")
        return asStringOrNull(log.entityId);
    return asStringOrNull(d.qrCodeId) || asStringOrNull(d.qrCode_id) || asStringOrNull(d.qrId) || null;
};
const resolveManufacturerId = (log) => {
    const d = log.details || {};
    return asStringOrNull(d.manufacturerId) || asStringOrNull(d.manufacturer_id) || null;
};
const deriveTraceEventTypeFromAudit = (log) => {
    const action = toUpper(log.action);
    const context = toUpper(log.details?.context);
    if (action === "BLOCKED")
        return client_1.TraceEventType.BLOCKED;
    if (action === "PRINTED" || action === "DOWNLOAD_BATCH_PRINT_PACK") {
        return client_1.TraceEventType.PRINTED;
    }
    if (action === "REDEEMED")
        return client_1.TraceEventType.REDEEMED;
    if (action === "VERIFY_SUCCESS" && !!log.details?.isFirstScan)
        return client_1.TraceEventType.REDEEMED;
    if (action === "ALLOCATE_QR_RANGE" ||
        action === "ALLOCATE_QR_RANGE_LICENSEE" ||
        context === "ALLOCATE_QR_RANGE" ||
        context === "ALLOCATE_QR_RANGE_LICENSEE") {
        return client_1.TraceEventType.COMMISSIONED;
    }
    if (action === "ALLOCATED" ||
        action === "CREATE_BATCH" ||
        context.startsWith("ASSIGN_MANUFACTURER") ||
        context === "CREATE_BATCH") {
        return client_1.TraceEventType.ASSIGNED;
    }
    return null;
};
exports.deriveTraceEventTypeFromAudit = deriveTraceEventTypeFromAudit;
const createTraceEvent = async (data) => {
    return database_1.default.traceEvent.create({
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
exports.createTraceEvent = createTraceEvent;
const createTraceEventFromAuditLog = async (log) => {
    const eventType = (0, exports.deriveTraceEventTypeFromAudit)(log);
    if (!eventType)
        return null;
    const licenseeId = resolveLicenseeId(log);
    if (!licenseeId)
        return null;
    const existing = await database_1.default.traceEvent.findFirst({
        where: {
            licenseeId,
            details: {
                path: ["auditLogId"],
                equals: log.id,
            },
        },
        select: { id: true },
    });
    if (existing)
        return null;
    return (0, exports.createTraceEvent)({
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
exports.createTraceEventFromAuditLog = createTraceEventFromAuditLog;
const backfillTraceEventsFromAuditLogs = async (opts) => {
    const key = opts?.licenseeId || "__ALL__";
    const nowMs = Date.now();
    const last = backfillState.get(key) || 0;
    if (!opts?.force && nowMs - last < BACKFILL_COOLDOWN_MS)
        return;
    backfillState.set(key, nowMs);
    const limit = Math.max(100, Math.min(opts?.limit ?? 2000, 10000));
    const where = {};
    if (opts?.licenseeId)
        where.licenseeId = opts.licenseeId;
    const logs = await database_1.default.auditLog.findMany({
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
            await (0, exports.createTraceEventFromAuditLog)(log);
        }
        catch {
            // keep backfill best-effort
        }
    }
};
exports.backfillTraceEventsFromAuditLogs = backfillTraceEventsFromAuditLogs;
const getTraceTimeline = async (opts) => {
    const where = {};
    if (opts.licenseeId)
        where.licenseeId = opts.licenseeId;
    if (opts.eventType)
        where.eventType = opts.eventType;
    if (opts.batchId)
        where.batchId = opts.batchId;
    if (opts.manufacturerId)
        where.manufacturerId = opts.manufacturerId;
    if (opts.qrCodeId)
        where.qrCodeId = opts.qrCodeId;
    const [events, total] = await Promise.all([
        database_1.default.traceEvent.findMany({
            where,
            orderBy: [{ createdAt: "desc" }, { id: "desc" }],
            take: opts.limit,
            skip: opts.offset,
            include: {
                user: { select: { id: true, name: true, email: true } },
                manufacturer: { select: { id: true, name: true, email: true } },
                batch: { select: { id: true, name: true } },
                qrCode: { select: { id: true, code: true } },
            },
        }),
        database_1.default.traceEvent.count({ where }),
    ]);
    return { events, total };
};
exports.getTraceTimeline = getTraceTimeline;
//# sourceMappingURL=traceEventService.js.map
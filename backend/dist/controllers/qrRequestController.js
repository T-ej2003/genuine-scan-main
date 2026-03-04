"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.rejectQrAllocationRequest = exports.approveQrAllocationRequest = exports.getQrAllocationRequests = exports.createQrAllocationRequest = void 0;
const zod_1 = require("zod");
const client_1 = require("@prisma/client");
const database_1 = __importDefault(require("../config/database"));
const auditService_1 = require("../services/auditService");
const qrAllocationService_1 = require("../services/qrAllocationService");
const notificationService_1 = require("../services/notificationService");
const parsePositiveIntEnv = (name, fallback) => {
    const raw = Number(String(process.env[name] || "").trim());
    return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : fallback;
};
const ALLOCATION_TX_TIMEOUT_MS = parsePositiveIntEnv("ALLOCATION_TX_TIMEOUT_MS", 120000);
const ALLOCATION_TX_MAX_WAIT_MS = parsePositiveIntEnv("ALLOCATION_TX_MAX_WAIT_MS", 15000);
const createRequestSchema = zod_1.z
    .object({
    quantity: zod_1.z.number().int().positive().max(5_000_000),
    batchName: zod_1.z.string().trim().min(2).max(120),
    note: zod_1.z.string().trim().max(500).optional(),
});
const approveSchema = zod_1.z.object({
    decisionNote: zod_1.z.string().trim().max(500).optional(),
});
const rejectSchema = zod_1.z.object({
    decisionNote: zod_1.z.string().trim().max(500).optional(),
});
const ensureAuth = (req) => {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId)
        return null;
    return { role, userId };
};
const createQrAllocationRequest = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (auth.role !== client_1.UserRole.LICENSEE_ADMIN &&
            auth.role !== client_1.UserRole.ORG_ADMIN &&
            auth.role !== client_1.UserRole.SUPER_ADMIN &&
            auth.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = createRequestSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const licenseeId = auth.role === client_1.UserRole.SUPER_ADMIN || auth.role === client_1.UserRole.PLATFORM_SUPER_ADMIN
            ? req.body?.licenseeId
            : req.user?.licenseeId;
        if (!licenseeId) {
            return res.status(403).json({ success: false, error: "No licensee association" });
        }
        const created = await database_1.default.qrAllocationRequest.create({
            data: {
                licenseeId,
                requestedByUserId: auth.userId,
                quantity: parsed.data.quantity,
                startNumber: null,
                endNumber: null,
                batchName: parsed.data.batchName.trim(),
                note: parsed.data.note?.trim() || null,
                status: client_1.QrAllocationRequestStatus.PENDING,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            licenseeId,
            action: "CREATE_QR_ALLOCATION_REQUEST",
            entityType: "QrAllocationRequest",
            entityId: created.id,
            details: {
                quantity: created.quantity,
                batchName: created.batchName || null,
            },
            ipAddress: req.ip,
        });
        await Promise.all([
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.SUPER_ADMIN,
                type: "qr_request_created",
                title: "New QR inventory request",
                body: `${created.quantity || 0} QR codes requested${created.batchName ? ` for batch "${created.batchName}"` : ""}. Pending review.`,
                data: {
                    requestId: created.id,
                    licenseeId,
                    quantity: created.quantity,
                    batchName: created.batchName || null,
                    status: created.status,
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.LICENSEE_ADMIN,
                licenseeId,
                type: "qr_request_created",
                title: "QR inventory request submitted",
                body: `Your request for ${created.quantity || 0} QR codes is in review${created.batchName ? ` (${created.batchName})` : ""}.`,
                data: {
                    requestId: created.id,
                    licenseeId,
                    quantity: created.quantity,
                    batchName: created.batchName || null,
                    status: created.status,
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
        ]);
        return res.status(201).json({ success: true, data: created });
    }
    catch (e) {
        console.error("createQrAllocationRequest error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.createQrAllocationRequest = createQrAllocationRequest;
const getQrAllocationRequests = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (auth.role !== client_1.UserRole.LICENSEE_ADMIN &&
            auth.role !== client_1.UserRole.ORG_ADMIN &&
            auth.role !== client_1.UserRole.SUPER_ADMIN &&
            auth.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const status = req.query.status || undefined;
        const qLicenseeId = req.query.licenseeId || undefined;
        const where = {};
        if (status)
            where.status = status;
        if (auth.role === client_1.UserRole.SUPER_ADMIN || auth.role === client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            if (qLicenseeId)
                where.licenseeId = qLicenseeId;
        }
        else {
            if (!req.user?.licenseeId) {
                return res.status(403).json({ success: false, error: "No licensee association" });
            }
            where.licenseeId = req.user.licenseeId;
        }
        const rows = await database_1.default.qrAllocationRequest.findMany({
            where,
            orderBy: { createdAt: "desc" },
            include: {
                licensee: { select: { id: true, name: true, prefix: true } },
                requestedByUser: { select: { id: true, name: true, email: true } },
                approvedByUser: { select: { id: true, name: true, email: true } },
                rejectedByUser: { select: { id: true, name: true, email: true } },
            },
        });
        return res.json({ success: true, data: rows });
    }
    catch (e) {
        console.error("getQrAllocationRequests error:", e);
        return res.status(500).json({ success: false, error: "Internal server error" });
    }
};
exports.getQrAllocationRequests = getQrAllocationRequests;
const approveQrAllocationRequest = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (auth.role !== client_1.UserRole.SUPER_ADMIN && auth.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = approveSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const id = req.params.id;
        const requestRow = await database_1.default.qrAllocationRequest.findUnique({
            where: { id },
            include: { licensee: { select: { id: true, prefix: true } } },
        });
        if (!requestRow)
            return res.status(404).json({ success: false, error: "Request not found" });
        if (requestRow.status !== client_1.QrAllocationRequestStatus.PENDING) {
            return res.status(409).json({ success: false, error: "Request already processed" });
        }
        // Backward compatibility: derive quantity for old range-based rows.
        const quantityRequested = requestRow.quantity && requestRow.quantity > 0
            ? requestRow.quantity
            : requestRow.startNumber && requestRow.endNumber
                ? requestRow.endNumber - requestRow.startNumber + 1
                : null;
        if (!quantityRequested || quantityRequested <= 0) {
            return res.status(400).json({ success: false, error: "Request quantity is missing or invalid." });
        }
        const result = await database_1.default.$transaction(async (tx) => {
            await (0, qrAllocationService_1.lockLicenseeAllocation)(tx, requestRow.licenseeId);
            const startNumber = await (0, qrAllocationService_1.getNextLicenseeQrNumber)(tx, requestRow.licenseeId);
            const endNumber = startNumber + quantityRequested - 1;
            const alloc = await (0, qrAllocationService_1.allocateQrRange)({
                licenseeId: requestRow.licenseeId,
                startNumber,
                endNumber,
                createdByUserId: auth.userId,
                source: "REQUEST_APPROVAL",
                requestId: requestRow.id,
                createReceivedBatch: true,
                receivedBatchName: requestRow.batchName || null,
                tx,
            });
            const updated = await tx.qrAllocationRequest.update({
                where: { id: requestRow.id },
                data: {
                    status: client_1.QrAllocationRequestStatus.APPROVED,
                    approvedByUserId: auth.userId,
                    approvedAt: new Date(),
                    decisionNote: parsed.data.decisionNote?.trim() || null,
                    startNumber,
                    endNumber,
                    quantity: quantityRequested,
                },
            });
            return { alloc, updated, startNumber, endNumber };
        }, {
            maxWait: ALLOCATION_TX_MAX_WAIT_MS,
            timeout: ALLOCATION_TX_TIMEOUT_MS,
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            licenseeId: requestRow.licenseeId,
            action: "APPROVE_QR_ALLOCATION_REQUEST",
            entityType: "QrAllocationRequest",
            entityId: requestRow.id,
            details: {
                startNumber: result.startNumber,
                endNumber: result.endNumber,
                quantity: quantityRequested,
                batchName: requestRow.batchName || null,
                rangeId: result.alloc.range.id,
                receivedBatchId: result.alloc.receivedBatch?.id || null,
                receivedBatchName: result.alloc.receivedBatch?.name || null,
            },
            ipAddress: req.ip,
        });
        await Promise.all([
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.SUPER_ADMIN,
                type: "qr_request_approved",
                title: "QR request approved",
                body: `${quantityRequested} QR codes approved${requestRow.batchName ? ` for "${requestRow.batchName}"` : ""}.`,
                data: {
                    requestId: requestRow.id,
                    licenseeId: requestRow.licenseeId,
                    quantity: quantityRequested,
                    batchName: requestRow.batchName || null,
                    status: "APPROVED",
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.LICENSEE_ADMIN,
                licenseeId: requestRow.licenseeId,
                type: "qr_request_approved",
                title: "QR request approved",
                body: `Inventory was allocated for ${quantityRequested} QR codes${requestRow.batchName ? ` (${requestRow.batchName})` : ""}.`,
                data: {
                    requestId: requestRow.id,
                    licenseeId: requestRow.licenseeId,
                    quantity: quantityRequested,
                    batchName: requestRow.batchName || null,
                    status: "APPROVED",
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createUserNotification)({
                userId: requestRow.requestedByUserId,
                licenseeId: requestRow.licenseeId,
                type: "qr_request_approved",
                title: "Your QR request was approved",
                body: `${quantityRequested} QR codes were approved${requestRow.batchName ? ` for "${requestRow.batchName}"` : ""}.`,
                data: {
                    requestId: requestRow.id,
                    licenseeId: requestRow.licenseeId,
                    quantity: quantityRequested,
                    batchName: requestRow.batchName || null,
                    status: "APPROVED",
                    targetRoute: "/qr-requests",
                },
                channel: client_1.NotificationChannel.WEB,
            }),
        ]);
        return res.json({ success: true, data: result.updated });
    }
    catch (e) {
        console.error("approveQrAllocationRequest error:", e);
        const msg = e?.message || "Bad request";
        if (String(msg).includes("BATCH_BUSY") || String(msg).toLowerCase().includes("concurrency issue")) {
            return res.status(409).json({ success: false, error: "Please retry — batch busy." });
        }
        return res.status(400).json({ success: false, error: msg });
    }
};
exports.approveQrAllocationRequest = approveQrAllocationRequest;
const rejectQrAllocationRequest = async (req, res) => {
    try {
        const auth = ensureAuth(req);
        if (!auth)
            return res.status(401).json({ success: false, error: "Not authenticated" });
        if (auth.role !== client_1.UserRole.SUPER_ADMIN && auth.role !== client_1.UserRole.PLATFORM_SUPER_ADMIN) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = rejectSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const id = req.params.id;
        const requestRow = await database_1.default.qrAllocationRequest.findUnique({ where: { id } });
        if (!requestRow)
            return res.status(404).json({ success: false, error: "Request not found" });
        if (requestRow.status !== client_1.QrAllocationRequestStatus.PENDING) {
            return res.status(409).json({ success: false, error: "Request already processed" });
        }
        const updated = await database_1.default.qrAllocationRequest.update({
            where: { id },
            data: {
                status: client_1.QrAllocationRequestStatus.REJECTED,
                rejectedByUserId: auth.userId,
                rejectedAt: new Date(),
                decisionNote: parsed.data.decisionNote?.trim() || null,
            },
        });
        await (0, auditService_1.createAuditLog)({
            userId: auth.userId,
            licenseeId: requestRow.licenseeId,
            action: "REJECT_QR_ALLOCATION_REQUEST",
            entityType: "QrAllocationRequest",
            entityId: id,
            details: { decisionNote: parsed.data.decisionNote?.trim() || null },
            ipAddress: req.ip,
        });
        await Promise.all([
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.SUPER_ADMIN,
                type: "qr_request_rejected",
                title: "QR request rejected",
                body: `A QR inventory request was rejected.`,
                data: {
                    requestId: id,
                    licenseeId: requestRow.licenseeId,
                    status: "REJECTED",
                    decisionNote: parsed.data.decisionNote?.trim() || null,
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.LICENSEE_ADMIN,
                licenseeId: requestRow.licenseeId,
                type: "qr_request_rejected",
                title: "QR request rejected",
                body: "A QR inventory request was rejected. Review the decision note and resubmit if needed.",
                data: {
                    requestId: id,
                    licenseeId: requestRow.licenseeId,
                    status: "REJECTED",
                    decisionNote: parsed.data.decisionNote?.trim() || null,
                    targetRoute: "/qr-requests",
                },
                channels: [client_1.NotificationChannel.WEB],
            }),
            (0, notificationService_1.createUserNotification)({
                userId: requestRow.requestedByUserId,
                licenseeId: requestRow.licenseeId,
                type: "qr_request_rejected",
                title: "Your QR request was rejected",
                body: "Your QR inventory request was rejected. Review notes and resubmit when ready.",
                data: {
                    requestId: id,
                    licenseeId: requestRow.licenseeId,
                    status: "REJECTED",
                    decisionNote: parsed.data.decisionNote?.trim() || null,
                    targetRoute: "/qr-requests",
                },
                channel: client_1.NotificationChannel.WEB,
            }),
        ]);
        return res.json({ success: true, data: updated });
    }
    catch (e) {
        console.error("rejectQrAllocationRequest error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.rejectQrAllocationRequest = rejectQrAllocationRequest;
//# sourceMappingURL=qrRequestController.js.map
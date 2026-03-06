"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.confirmPrintJob = exports.reportDirectPrintFailure = exports.confirmDirectPrintItem = exports.resolveDirectPrintToken = exports.issueDirectPrintTokens = exports.downloadPrintJobPack = exports.createPrintJob = void 0;
const crypto_1 = require("crypto");
const client_1 = require("@prisma/client");
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const qrTokenService_1 = require("../services/qrTokenService");
const auditService_1 = require("../services/auditService");
const notificationService_1 = require("../services/notificationService");
const printerConnectionService_1 = require("../services/printerConnectionService");
const idempotencyService_1 = require("../services/idempotencyService");
const MANUFACTURER_ROLES = [
    client_1.UserRole.MANUFACTURER,
    client_1.UserRole.MANUFACTURER_ADMIN,
    client_1.UserRole.MANUFACTURER_USER,
];
const OPEN_PRINT_STATES = [
    client_1.PrintItemState.RESERVED,
    client_1.PrintItemState.ISSUED,
    client_1.PrintItemState.AGENT_ACKED,
];
const CLOSABLE_PRINT_STATES = [client_1.PrintItemState.PRINT_CONFIRMED];
const isManufacturerRole = (role) => Boolean(role && MANUFACTURER_ROLES.includes(role));
const createPrintJobSchema = zod_1.z.object({
    batchId: zod_1.z.string().uuid(),
    quantity: zod_1.z.number().int().positive().max(200000),
    rangeStart: zod_1.z.string().optional(),
    rangeEnd: zod_1.z.string().optional(),
});
const confirmSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
});
const issueDirectPrintTokensSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
    count: zod_1.z.number().int().min(1).max(500).optional(),
});
const resolveDirectPrintTokenSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
    renderToken: zod_1.z.string().min(16),
});
const confirmDirectPrintItemSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
    printItemId: zod_1.z.string().uuid(),
    agentMetadata: zod_1.z.any().optional(),
});
const reportDirectPrintFailureSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
    reason: zod_1.z.string().trim().min(3).max(500),
    printItemId: zod_1.z.string().uuid().optional(),
    retries: zod_1.z.number().int().min(0).max(20).optional(),
    agentMetadata: zod_1.z.any().optional(),
});
const hashLockToken = (raw) => (0, crypto_1.createHash)("sha256").update(raw).digest("hex");
const parsePositiveIntEnv = (name, fallback, hardMax) => {
    const raw = Number(String(process.env[name] || "").trim());
    if (!Number.isFinite(raw) || raw <= 0)
        return fallback;
    return Math.max(1, Math.min(hardMax, Math.floor(raw)));
};
const DIRECT_PRINT_LOCK_TTL_MINUTES = parsePositiveIntEnv("PRINT_JOB_LOCK_TTL_MINUTES", 45, 24 * 60);
const DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS = parsePositiveIntEnv("DIRECT_PRINT_TOKEN_TTL_SECONDS", 90, 900);
const DIRECT_PRINT_MAX_BATCH = parsePositiveIntEnv("DIRECT_PRINT_MAX_BATCH", 250, 500);
const getLockExpiresAt = (createdAt) => new Date(createdAt.getTime() + DIRECT_PRINT_LOCK_TTL_MINUTES * 60 * 1000);
const isLockExpired = (createdAt, now = new Date()) => getLockExpiresAt(createdAt).getTime() <= now.getTime();
const ensureManufacturerUser = (req, res) => {
    if (!req.user || !isManufacturerRole(req.user.role)) {
        res.status(403).json({ success: false, error: "Access denied" });
        return null;
    }
    return req.user;
};
const getManufacturerPrintJob = async (jobId, userId) => database_1.default.printJob.findFirst({
    where: { id: jobId, manufacturerId: userId },
    include: { batch: { select: { id: true, name: true, licenseeId: true } } },
});
const ensureTrustedPrinterConnected = async (userId) => {
    const printerStatus = await (0, printerConnectionService_1.getPrinterConnectionStatusForUser)(userId);
    if (!printerStatus.connected || !printerStatus.eligibleForPrinting) {
        throw Object.assign(new Error("PRINTER_NOT_TRUSTED"), { printerStatus });
    }
    return printerStatus;
};
const notifySystemPrintEvent = async (params) => {
    const channels = params.channels && params.channels.length > 0 ? params.channels : [client_1.NotificationChannel.WEB];
    await Promise.allSettled([
        (0, notificationService_1.createRoleNotifications)({
            audience: client_1.NotificationAudience.SUPER_ADMIN,
            type: params.type,
            title: params.title,
            body: params.body,
            licenseeId: params.licenseeId || null,
            orgId: params.orgId || null,
            data: params.data || null,
            channels,
        }),
        params.licenseeId
            ? (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.LICENSEE_ADMIN,
                licenseeId: params.licenseeId,
                type: params.type,
                title: params.title,
                body: params.body,
                data: params.data || null,
                channels: [client_1.NotificationChannel.WEB],
            })
            : Promise.resolve([]),
        params.orgId
            ? (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.MANUFACTURER,
                orgId: params.orgId,
                type: params.type,
                title: params.title,
                body: params.body,
                data: params.data || null,
                channels: [client_1.NotificationChannel.WEB],
            })
            : Promise.resolve([]),
    ]);
};
const handleIdempotencyError = (error, res) => {
    const message = String(error?.message || "");
    if (message.includes("IDEMPOTENCY_KEY_REQUIRED")) {
        res.status(400).json({ success: false, error: "Missing x-idempotency-key header" });
        return true;
    }
    if (message.includes("IDEMPOTENCY_KEY_IN_PROGRESS")) {
        res.status(409).json({ success: false, error: "Request with this idempotency key is already in progress" });
        return true;
    }
    if (message.includes("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH")) {
        res.status(409).json({ success: false, error: "Idempotency key was already used for a different payload" });
        return true;
    }
    return false;
};
const beginPrintActionIdempotency = async (params) => {
    return (0, idempotencyService_1.beginIdempotentAction)({
        action: params.action,
        scope: params.scope,
        idempotencyKey: (0, idempotencyService_1.extractIdempotencyKey)(params.req.headers, params.req.body),
        requestPayload: params.payload ?? null,
        required: true,
    });
};
const replayIdempotentResponseIfAny = (idempotency, res) => {
    if (!idempotency.replayed)
        return false;
    return res.status(idempotency.statusCode || 200).json(idempotency.responsePayload || { success: true });
};
const mapLegacyPrintItemState = (status) => {
    if (status === client_1.QRStatus.PRINTED || status === client_1.QRStatus.REDEEMED || status === client_1.QRStatus.SCANNED) {
        return client_1.PrintItemState.CLOSED;
    }
    if (status === client_1.QRStatus.BLOCKED) {
        return client_1.PrintItemState.FROZEN;
    }
    return client_1.PrintItemState.RESERVED;
};
const getOrCreatePrintSession = async (job) => {
    const existing = await database_1.default.printSession.findUnique({ where: { printJobId: job.id } });
    if (existing)
        return existing;
    return database_1.default.$transaction(async (tx) => {
        const stillExisting = await tx.printSession.findUnique({ where: { printJobId: job.id } });
        if (stillExisting)
            return stillExisting;
        const qrRows = await tx.qRCode.findMany({
            where: { printJobId: job.id },
            orderBy: { code: "asc" },
            select: { id: true, code: true, status: true },
        });
        const totalItems = qrRows.length || job.quantity;
        const created = await tx.printSession.create({
            data: {
                printJobId: job.id,
                batchId: job.batchId,
                manufacturerId: job.manufacturerId,
                status: job.status === "CONFIRMED" ? client_1.PrintSessionStatus.COMPLETED : client_1.PrintSessionStatus.ACTIVE,
                totalItems,
                issuedItems: qrRows.filter((row) => row.status !== client_1.QRStatus.ACTIVATED && row.status !== client_1.QRStatus.ALLOCATED).length,
                confirmedItems: qrRows.filter((row) => row.status === client_1.QRStatus.PRINTED || row.status === client_1.QRStatus.REDEEMED || row.status === client_1.QRStatus.SCANNED).length,
                completedAt: job.status === "CONFIRMED" ? new Date() : null,
            },
        });
        if (qrRows.length > 0) {
            await tx.printItem.createMany({
                data: qrRows.map((row) => ({
                    printSessionId: created.id,
                    qrCodeId: row.id,
                    code: row.code,
                    state: mapLegacyPrintItemState(row.status),
                    issuedAt: row.status === client_1.QRStatus.ACTIVATED ? null : new Date(),
                    printConfirmedAt: row.status === client_1.QRStatus.PRINTED || row.status === client_1.QRStatus.REDEEMED || row.status === client_1.QRStatus.SCANNED
                        ? new Date()
                        : null,
                    closedAt: row.status === client_1.QRStatus.PRINTED || row.status === client_1.QRStatus.REDEEMED || row.status === client_1.QRStatus.SCANNED
                        ? new Date()
                        : null,
                })),
                skipDuplicates: true,
            });
        }
        return created;
    });
};
const countRemainingToPrint = async (tx, printSessionId) => {
    return tx.printItem.count({
        where: {
            printSessionId,
            state: { in: OPEN_PRINT_STATES },
        },
    });
};
const finalizePrintSessionIfReady = async (params) => {
    const remainingToPrint = await countRemainingToPrint(params.tx, params.printSessionId);
    let confirmedAt = null;
    if (remainingToPrint > 0) {
        return {
            remainingToPrint,
            jobConfirmed: false,
            confirmedAt,
        };
    }
    const closableItems = await params.tx.printItem.findMany({
        where: {
            printSessionId: params.printSessionId,
            state: { in: CLOSABLE_PRINT_STATES },
        },
        select: { id: true },
    });
    if (closableItems.length > 0) {
        await params.tx.printItem.updateMany({
            where: {
                id: { in: closableItems.map((item) => item.id) },
                state: { in: CLOSABLE_PRINT_STATES },
            },
            data: {
                state: client_1.PrintItemState.CLOSED,
                closedAt: params.now,
            },
        });
        await params.tx.printItemEvent.createMany({
            data: closableItems.map((item) => ({
                printItemId: item.id,
                eventType: client_1.PrintItemEventType.CLOSED,
                previousState: client_1.PrintItemState.PRINT_CONFIRMED,
                nextState: client_1.PrintItemState.CLOSED,
                actorUserId: params.actorUserId,
                details: {
                    reason: "session_completed",
                },
            })),
        });
    }
    await params.tx.printSession.update({
        where: { id: params.printSessionId },
        data: {
            status: client_1.PrintSessionStatus.COMPLETED,
            completedAt: params.now,
        },
    });
    const jobUpdate = await params.tx.printJob.updateMany({
        where: { id: params.printJobId, status: "PENDING" },
        data: { status: "CONFIRMED", confirmedAt: params.now },
    });
    if (jobUpdate.count > 0) {
        await params.tx.batch.update({
            where: { id: params.batchId },
            data: { printedAt: params.now },
        });
        confirmedAt = params.now;
    }
    else {
        const currentJob = await params.tx.printJob.findUnique({ where: { id: params.printJobId }, select: { confirmedAt: true } });
        confirmedAt = currentJob?.confirmedAt || null;
    }
    return {
        remainingToPrint: 0,
        jobConfirmed: true,
        confirmedAt,
    };
};
const createFailStopIncident = async (params) => {
    const incident = await params.tx.incident.create({
        data: {
            qrCodeValue: `PRINT_JOB:${params.printJobId}`,
            licenseeId: params.licenseeId,
            reportedBy: "ADMIN",
            incidentType: client_1.IncidentType.OTHER,
            severity: client_1.IncidentSeverity.CRITICAL,
            priority: client_1.IncidentPriority.P1,
            description: `Direct-print fail-stop triggered for session ${params.printSessionId}: ${params.reason}`,
            tags: ["print_fail_stop", "direct_print", `print_job_${params.printJobId}`],
        },
    });
    await params.tx.incidentEvent.create({
        data: {
            incidentId: incident.id,
            actorType: client_1.IncidentActorType.SYSTEM,
            actorUserId: params.actorUserId || null,
            eventType: client_1.IncidentEventType.CREATED,
            eventPayload: {
                reason: params.reason,
                diagnostics: params.diagnostics,
                context: "DIRECT_PRINT_FAIL_STOP",
            },
        },
    });
    return incident;
};
const failStopPrintSession = async (params) => {
    const now = new Date();
    const result = await database_1.default.$transaction(async (tx) => {
        const session = await tx.printSession.findUnique({
            where: { id: params.printSessionId },
            select: { id: true, status: true },
        });
        if (!session)
            throw new Error("PRINT_SESSION_NOT_FOUND");
        const toFreeze = await tx.printItem.findMany({
            where: {
                printSessionId: params.printSessionId,
                state: { in: [client_1.PrintItemState.RESERVED, client_1.PrintItemState.ISSUED, client_1.PrintItemState.AGENT_ACKED, client_1.PrintItemState.PRINT_CONFIRMED] },
            },
            select: { id: true, code: true, qrCodeId: true, state: true },
        });
        let failedItem = null;
        if (params.printItemId) {
            const updated = await tx.printItem.updateMany({
                where: {
                    id: params.printItemId,
                    printSessionId: params.printSessionId,
                    state: { in: [client_1.PrintItemState.ISSUED, client_1.PrintItemState.AGENT_ACKED, client_1.PrintItemState.PRINT_CONFIRMED] },
                },
                data: {
                    state: client_1.PrintItemState.FAILED,
                    failedAt: now,
                    failureReason: params.reason,
                    deadLetterReason: params.reason,
                },
            });
            if (updated.count > 0) {
                const row = await tx.printItem.findUnique({ where: { id: params.printItemId }, select: { id: true, code: true } });
                failedItem = row || null;
            }
        }
        const freezeTargets = toFreeze.filter((item) => item.id !== params.printItemId);
        if (freezeTargets.length > 0) {
            await tx.printItem.updateMany({
                where: { id: { in: freezeTargets.map((item) => item.id) } },
                data: {
                    state: client_1.PrintItemState.FROZEN,
                    frozenAt: now,
                    failureReason: params.reason,
                },
            });
            await tx.qRCode.updateMany({
                where: {
                    id: { in: freezeTargets.map((item) => item.qrCodeId) },
                    status: { in: [client_1.QRStatus.ACTIVATED, client_1.QRStatus.PRINTED] },
                },
                data: {
                    status: client_1.QRStatus.BLOCKED,
                    blockedAt: now,
                    underInvestigationAt: now,
                    underInvestigationReason: `Print fail-stop: ${params.reason}`,
                },
            });
        }
        if (failedItem) {
            await tx.printItemEvent.create({
                data: {
                    printItemId: failedItem.id,
                    eventType: client_1.PrintItemEventType.FAILED,
                    nextState: client_1.PrintItemState.FAILED,
                    actorUserId: params.actorUserId,
                    details: {
                        reason: params.reason,
                        retries: params.retries ?? 0,
                        metadata: params.metadata ?? null,
                    },
                },
            });
        }
        if (freezeTargets.length > 0) {
            await tx.printItemEvent.createMany({
                data: freezeTargets.map((item) => ({
                    printItemId: item.id,
                    eventType: client_1.PrintItemEventType.FROZEN,
                    previousState: item.state,
                    nextState: client_1.PrintItemState.FROZEN,
                    actorUserId: params.actorUserId,
                    details: {
                        reason: params.reason,
                        metadata: params.metadata ?? null,
                    },
                })),
            });
        }
        await tx.printSession.update({
            where: { id: params.printSessionId },
            data: {
                status: client_1.PrintSessionStatus.FAILED,
                failedReason: params.reason,
                frozenItems: freezeTargets.length,
            },
        });
        await tx.printJob.updateMany({
            where: { id: params.printJobId, status: "PENDING" },
            data: { status: "CANCELLED" },
        });
        const incident = await createFailStopIncident({
            tx,
            printJobId: params.printJobId,
            printSessionId: params.printSessionId,
            licenseeId: params.licenseeId,
            actorUserId: params.actorUserId,
            reason: params.reason,
            diagnostics: {
                printItemId: params.printItemId || null,
                retries: params.retries ?? 0,
                failedItemCode: failedItem?.code || null,
                frozenCount: freezeTargets.length,
                metadata: params.metadata ?? null,
            },
        });
        return {
            incident,
            failedItem,
            frozenCount: freezeTargets.length,
        };
    });
    await (0, auditService_1.createAuditLog)({
        userId: params.actorUserId,
        licenseeId: params.licenseeId || undefined,
        action: "DIRECT_PRINT_FAIL_STOP",
        entityType: "PrintSession",
        entityId: params.printSessionId,
        details: {
            printJobId: params.printJobId,
            reason: params.reason,
            printItemId: params.printItemId || null,
            retries: params.retries ?? 0,
            frozenCount: result.frozenCount,
            incidentId: result.incident.id,
            metadata: params.metadata ?? null,
        },
    });
    return result;
};
const createPrintJob = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = createPrintJobSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        let idempotency;
        try {
            idempotency = await beginPrintActionIdempotency({
                req,
                action: "print_job_create",
                scope: `user:${user.userId}:batch:${parsed.data.batchId}`,
                payload: parsed.data,
            });
        }
        catch (error) {
            if (handleIdempotencyError(error, res))
                return;
            throw error;
        }
        if (replayIdempotentResponseIfAny(idempotency, res))
            return;
        const printerStatus = await ensureTrustedPrinterConnected(user.userId);
        const { batchId, quantity, rangeStart, rangeEnd } = parsed.data;
        const batch = await database_1.default.batch.findFirst({
            where: { id: batchId, manufacturerId: user.userId },
            select: { id: true, name: true, licenseeId: true, manufacturerId: true },
        });
        if (!batch) {
            return res.status(404).json({ success: false, error: "Batch not found or not assigned to you" });
        }
        const printLockToken = (0, crypto_1.randomBytes)(24).toString("base64url");
        const printLockTokenHash = hashLockToken(printLockToken);
        const now = new Date();
        const expAt = (0, qrTokenService_1.getQrTokenExpiryDate)(now);
        const created = await database_1.default.$transaction(async (tx) => {
            const rangeFilter = rangeStart && rangeEnd
                ? client_1.Prisma.sql `AND q."code" >= ${rangeStart} AND q."code" <= ${rangeEnd}`
                : client_1.Prisma.empty;
            const reservedRows = await tx.$queryRaw(client_1.Prisma.sql `
        SELECT q."id", q."code", q."licenseeId", q."batchId"
        FROM "QRCode" q
        WHERE q."batchId" = ${batch.id}
          AND q."status" = CAST(${client_1.QRStatus.ALLOCATED} AS "QRStatus")
          AND q."printJobId" IS NULL
          ${rangeFilter}
        ORDER BY q."code" ASC
        FOR UPDATE SKIP LOCKED
        LIMIT ${quantity};
      `);
            if (reservedRows.length < quantity) {
                throw new Error(`NOT_ENOUGH_CODES:${reservedRows.length}`);
            }
            const prepared = reservedRows.map((qr) => {
                const nonce = (0, qrTokenService_1.randomNonce)();
                const payload = {
                    qr_id: qr.id,
                    batch_id: qr.batchId,
                    licensee_id: qr.licenseeId,
                    manufacturer_id: batch.manufacturerId || null,
                    iat: Math.floor(now.getTime() / 1000),
                    exp: Math.floor(expAt.getTime() / 1000),
                    nonce,
                };
                const token = (0, qrTokenService_1.signQrPayload)(payload);
                const tokenHash = (0, qrTokenService_1.hashToken)(token);
                return { qr, nonce, tokenHash };
            });
            const createdJob = await tx.printJob.create({
                data: {
                    batchId: batch.id,
                    manufacturerId: user.userId,
                    quantity,
                    rangeStart: rangeStart || null,
                    rangeEnd: rangeEnd || null,
                    printLockTokenHash,
                    status: "PENDING",
                },
            });
            const values = prepared.map((item) => client_1.Prisma.sql `(${item.qr.id}, ${item.nonce}, ${item.tokenHash}, ${now}, ${expAt})`);
            const updatedCount = await tx.$executeRaw(client_1.Prisma.sql `
        UPDATE "QRCode" AS q
        SET
          "status" = CAST(${client_1.QRStatus.ACTIVATED} AS "QRStatus"),
          "tokenNonce" = v."tokenNonce",
          "tokenIssuedAt" = v."tokenIssuedAt",
          "tokenExpiresAt" = v."tokenExpiresAt",
          "tokenHash" = v."tokenHash",
          "printJobId" = ${createdJob.id}
        FROM (
          VALUES ${client_1.Prisma.join(values)}
        ) AS v("id", "tokenNonce", "tokenHash", "tokenIssuedAt", "tokenExpiresAt")
        WHERE q."id" = v."id"
          AND q."status" = CAST(${client_1.QRStatus.ALLOCATED} AS "QRStatus")
          AND q."printJobId" IS NULL;
      `);
            if (Number(updatedCount) !== prepared.length) {
                throw new Error("BATCH_BUSY");
            }
            const session = await tx.printSession.create({
                data: {
                    printJobId: createdJob.id,
                    batchId: batch.id,
                    manufacturerId: user.userId,
                    printerRegistrationId: printerStatus.registrationId || null,
                    status: client_1.PrintSessionStatus.ACTIVE,
                    totalItems: prepared.length,
                },
            });
            await tx.printItem.createMany({
                data: prepared.map((item) => ({
                    printSessionId: session.id,
                    qrCodeId: item.qr.id,
                    code: item.qr.code,
                    state: client_1.PrintItemState.RESERVED,
                })),
            });
            return {
                job: createdJob,
                session,
                preparedCount: prepared.length,
            };
        }, { timeout: 30000, maxWait: 10000 });
        await (0, auditService_1.createAuditLog)({
            userId: user.userId,
            licenseeId: batch.licenseeId,
            action: "CREATED",
            entityType: "PrintJob",
            entityId: created.job.id,
            details: {
                batchId: batch.id,
                quantity,
                rangeStart: rangeStart || null,
                rangeEnd: rangeEnd || null,
                mode: "DIRECT_PRINT",
                printSessionId: created.session.id,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        const responsePayload = {
            success: true,
            data: {
                printJobId: created.job.id,
                printSessionId: created.session.id,
                printLockToken,
                quantity,
                tokenCount: created.preparedCount,
                mode: "DIRECT_PRINT",
                lockExpiresAt: getLockExpiresAt(created.job.createdAt).toISOString(),
                printerStatus,
            },
        };
        await (0, idempotencyService_1.completeIdempotentAction)({
            keyHash: idempotency.keyHash,
            statusCode: 201,
            responsePayload,
        });
        try {
            await (0, notificationService_1.createUserNotification)({
                userId: user.userId,
                licenseeId: batch.licenseeId,
                type: "manufacturer_print_job_created",
                title: "Direct-print job prepared",
                body: `Direct-print session ready for ${batch.name} (${quantity} codes).`,
                data: {
                    printJobId: created.job.id,
                    printSessionId: created.session.id,
                    batchId: batch.id,
                    batchName: batch.name,
                    quantity,
                    mode: "DIRECT_PRINT",
                    targetRoute: "/batches",
                },
            });
            await notifySystemPrintEvent({
                licenseeId: batch.licenseeId,
                orgId: user.orgId || null,
                type: "system_print_job_created",
                title: "System print job created",
                body: `Direct-print job created for ${batch.name} (${quantity} codes).`,
                data: {
                    printJobId: created.job.id,
                    printSessionId: created.session.id,
                    batchId: batch.id,
                    batchName: batch.name,
                    quantity,
                    mode: "DIRECT_PRINT",
                    targetRoute: "/batches",
                },
            });
        }
        catch (notifyError) {
            console.error("createPrintJob notification error:", notifyError);
        }
        return res.status(201).json(responsePayload);
    }
    catch (e) {
        console.error("createPrintJob error:", e);
        const msg = String(e?.message || "");
        if (msg.includes("BATCH_BUSY")) {
            return res.status(409).json({ success: false, error: "Please retry — batch busy." });
        }
        if (msg.startsWith("NOT_ENOUGH_CODES:")) {
            const available = Number(msg.split(":")[1] || "0");
            return res.status(400).json({
                success: false,
                error: `Not enough unprinted codes. Available: ${available}`,
            });
        }
        if (msg.includes("PRINTER_NOT_TRUSTED")) {
            const printerStatus = e?.printerStatus || null;
            return res.status(409).json({
                success: false,
                error: "Printer is not ready for secure issuance. Reconnect print agent or switch to compatibility-ready local printer profile.",
                data: { printerStatus },
            });
        }
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.createPrintJob = createPrintJob;
const downloadPrintJobPack = async (_req, res) => {
    return res.status(410).json({
        success: false,
        error: "Print-pack download is disabled. Use the direct-print pipeline (one-time short-lived render tokens) via authenticated print agent.",
    });
};
exports.downloadPrintJobPack = downloadPrintJobPack;
const issueDirectPrintTokens = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = issueDirectPrintTokensSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        let idempotency;
        try {
            idempotency = await beginPrintActionIdempotency({
                req,
                action: "print_job_issue_tokens",
                scope: `job:${jobId}`,
                payload: parsed.data,
            });
        }
        catch (error) {
            if (handleIdempotencyError(error, res))
                return;
            throw error;
        }
        if (replayIdempotentResponseIfAny(idempotency, res))
            return;
        const job = await getManufacturerPrintJob(jobId, user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        if (job.status === "CONFIRMED") {
            return res.status(409).json({ success: false, error: "Print job already confirmed" });
        }
        await ensureTrustedPrinterConnected(user.userId);
        const now = new Date();
        if (isLockExpired(job.createdAt, now)) {
            return res.status(410).json({
                success: false,
                error: "Print lock token expired. Create a new print job to continue secure direct printing.",
            });
        }
        const tokenHash = hashLockToken(parsed.data.printLockToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const session = await getOrCreatePrintSession({
            id: job.id,
            batchId: job.batchId,
            manufacturerId: job.manufacturerId,
            quantity: job.quantity,
            status: job.status,
        });
        if (session.status !== client_1.PrintSessionStatus.ACTIVE) {
            return res.status(409).json({
                success: false,
                error: `Print session is not active (${session.status}).`,
            });
        }
        const requestedCount = Math.max(1, Math.min(DIRECT_PRINT_MAX_BATCH, parsed.data.count || 1));
        const renderTokenExpiresAt = new Date(now.getTime() + DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS * 1000);
        const txResult = await database_1.default.$transaction(async (tx) => {
            const reservedItems = await tx.printItem.findMany({
                where: {
                    printSessionId: session.id,
                    state: client_1.PrintItemState.RESERVED,
                },
                orderBy: { code: "asc" },
                take: requestedCount,
                select: { id: true, qrCodeId: true, code: true },
            });
            if (reservedItems.length === 0) {
                const remainingToPrint = await countRemainingToPrint(tx, session.id);
                return {
                    items: [],
                    remainingToPrint,
                };
            }
            const rowsWithTokens = reservedItems.map((row, index) => {
                const renderToken = (0, crypto_1.randomBytes)(24).toString("base64url");
                return {
                    printItemId: row.id,
                    qrId: row.qrCodeId,
                    code: row.code,
                    renderToken,
                    tokenHash: (0, qrTokenService_1.hashToken)(renderToken),
                    issueSequence: session.issuedItems + index + 1,
                };
            });
            await tx.printRenderToken.deleteMany({
                where: {
                    printJobId: job.id,
                    qrCodeId: { in: rowsWithTokens.map((item) => item.qrId) },
                    usedAt: null,
                },
            });
            await tx.printRenderToken.createMany({
                data: rowsWithTokens.map((item) => ({
                    tokenHash: item.tokenHash,
                    printJobId: job.id,
                    qrCodeId: item.qrId,
                    expiresAt: renderTokenExpiresAt,
                })),
            });
            for (const item of rowsWithTokens) {
                const updated = await tx.printItem.updateMany({
                    where: {
                        id: item.printItemId,
                        state: client_1.PrintItemState.RESERVED,
                    },
                    data: {
                        state: client_1.PrintItemState.ISSUED,
                        issuedAt: now,
                        issueSequence: item.issueSequence,
                        currentRenderTokenHash: item.tokenHash,
                    },
                });
                if (updated.count === 0) {
                    throw new Error("PRINT_ITEM_STATE_CONFLICT");
                }
            }
            await tx.printItemEvent.createMany({
                data: rowsWithTokens.map((item) => ({
                    printItemId: item.printItemId,
                    eventType: client_1.PrintItemEventType.ISSUED,
                    previousState: client_1.PrintItemState.RESERVED,
                    nextState: client_1.PrintItemState.ISSUED,
                    actorUserId: user.userId,
                    details: {
                        expiresAt: renderTokenExpiresAt.toISOString(),
                    },
                })),
            });
            await tx.printSession.update({
                where: { id: session.id },
                data: {
                    issuedItems: { increment: rowsWithTokens.length },
                },
            });
            const remainingToPrint = await countRemainingToPrint(tx, session.id);
            return {
                items: rowsWithTokens,
                remainingToPrint,
            };
        });
        await (0, auditService_1.createAuditLog)({
            userId: user.userId,
            licenseeId: job.batch.licenseeId,
            action: "DIRECT_PRINT_TOKEN_ISSUED",
            entityType: "PrintSession",
            entityId: session.id,
            details: {
                printJobId: job.id,
                issuedCount: txResult.items.length,
                expiresAt: renderTokenExpiresAt.toISOString(),
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        const responsePayload = {
            success: true,
            data: {
                printJobId: job.id,
                printSessionId: session.id,
                lockExpiresAt: getLockExpiresAt(job.createdAt).toISOString(),
                directPrintTokenExpiresAt: renderTokenExpiresAt.toISOString(),
                remainingToPrint: txResult.remainingToPrint,
                items: txResult.items.map((item) => ({
                    printItemId: item.printItemId,
                    qrId: item.qrId,
                    code: item.code,
                    renderToken: item.renderToken,
                    expiresAt: renderTokenExpiresAt.toISOString(),
                })),
            },
        };
        await (0, idempotencyService_1.completeIdempotentAction)({
            keyHash: idempotency.keyHash,
            statusCode: 200,
            responsePayload,
        });
        return res.json(responsePayload);
    }
    catch (e) {
        console.error("issueDirectPrintTokens error:", e);
        const msg = String(e?.message || "");
        if (msg.includes("PRINT_ITEM_STATE_CONFLICT")) {
            return res.status(409).json({ success: false, error: "Print item state conflict. Retry token issuance." });
        }
        if (msg.includes("PRINTER_NOT_TRUSTED")) {
            const printerStatus = e?.printerStatus || null;
            return res.status(409).json({
                success: false,
                error: "Printer readiness validation failed. Token issuance blocked until printer is eligible for printing.",
                data: { printerStatus },
            });
        }
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.issueDirectPrintTokens = issueDirectPrintTokens;
const resolveDirectPrintToken = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = resolveDirectPrintTokenSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        let idempotency;
        try {
            idempotency = await beginPrintActionIdempotency({
                req,
                action: "print_job_resolve_token",
                scope: `job:${jobId}`,
                payload: parsed.data,
            });
        }
        catch (error) {
            if (handleIdempotencyError(error, res))
                return;
            throw error;
        }
        if (replayIdempotentResponseIfAny(idempotency, res))
            return;
        const job = await getManufacturerPrintJob(jobId, user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        const session = await getOrCreatePrintSession({
            id: job.id,
            batchId: job.batchId,
            manufacturerId: job.manufacturerId,
            quantity: job.quantity,
            status: job.status,
        });
        if (session.status !== client_1.PrintSessionStatus.ACTIVE) {
            return res.status(409).json({ success: false, error: `Print session is ${session.status}` });
        }
        const now = new Date();
        if (isLockExpired(job.createdAt, now)) {
            return res.status(410).json({
                success: false,
                error: "Print lock token expired. Create a new print job to continue secure direct printing.",
            });
        }
        const lockHash = hashLockToken(parsed.data.printLockToken);
        if (lockHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const renderTokenHash = (0, qrTokenService_1.hashToken)(parsed.data.renderToken);
        const renderTokenRow = await database_1.default.printRenderToken.findUnique({
            where: { tokenHash: renderTokenHash },
            include: {
                qrCode: {
                    select: {
                        id: true,
                        code: true,
                        status: true,
                        batchId: true,
                        licenseeId: true,
                        printJobId: true,
                        tokenNonce: true,
                        tokenIssuedAt: true,
                        tokenExpiresAt: true,
                        tokenHash: true,
                    },
                },
            },
        });
        if (!renderTokenRow || renderTokenRow.printJobId !== job.id) {
            return res.status(404).json({ success: false, error: "Render token not found for this print job" });
        }
        if (renderTokenRow.usedAt) {
            return res.status(409).json({ success: false, error: "Render token already used" });
        }
        if (renderTokenRow.expiresAt.getTime() <= now.getTime()) {
            return res.status(410).json({ success: false, error: "Render token expired" });
        }
        const qr = renderTokenRow.qrCode;
        if (!qr || qr.printJobId !== job.id) {
            return res.status(409).json({ success: false, error: "QR code is not bound to this print job" });
        }
        if (qr.status !== client_1.QRStatus.ACTIVATED) {
            return res.status(409).json({ success: false, error: "QR code is not ready for direct-print rendering" });
        }
        if (!qr.tokenNonce || !qr.tokenIssuedAt || !qr.tokenExpiresAt) {
            return res.status(409).json({
                success: false,
                error: "QR token metadata missing. Regenerate print job to re-initialize secure token state.",
            });
        }
        const printItem = await database_1.default.printItem.findUnique({
            where: { qrCodeId: qr.id },
            select: { id: true, printSessionId: true, state: true, currentRenderTokenHash: true },
        });
        if (!printItem || printItem.printSessionId !== session.id) {
            return res.status(409).json({ success: false, error: "Print item not found for this session" });
        }
        if (printItem.state !== client_1.PrintItemState.ISSUED) {
            return res.status(409).json({ success: false, error: `Print item is ${printItem.state}, expected ISSUED` });
        }
        if (printItem.currentRenderTokenHash && printItem.currentRenderTokenHash !== renderTokenHash) {
            return res.status(409).json({ success: false, error: "Render token no longer valid for this print item" });
        }
        const payload = {
            qr_id: qr.id,
            batch_id: qr.batchId,
            licensee_id: qr.licenseeId,
            manufacturer_id: job.manufacturerId,
            iat: Math.floor(qr.tokenIssuedAt.getTime() / 1000),
            exp: Math.floor(qr.tokenExpiresAt.getTime() / 1000),
            nonce: qr.tokenNonce,
        };
        const signedQrToken = (0, qrTokenService_1.signQrPayload)(payload);
        const signedQrHash = (0, qrTokenService_1.hashToken)(signedQrToken);
        if (qr.tokenHash && signedQrHash !== qr.tokenHash) {
            return res.status(409).json({
                success: false,
                error: "Token integrity mismatch for this QR. Create a new print job to continue.",
            });
        }
        const txResult = await database_1.default.$transaction(async (tx) => {
            const markRenderTokenUsed = await tx.printRenderToken.updateMany({
                where: {
                    id: renderTokenRow.id,
                    usedAt: null,
                    expiresAt: { gt: now },
                },
                data: { usedAt: now },
            });
            if (markRenderTokenUsed.count === 0) {
                throw new Error("RENDER_TOKEN_ALREADY_USED");
            }
            const markAcked = await tx.printItem.updateMany({
                where: {
                    id: printItem.id,
                    state: client_1.PrintItemState.ISSUED,
                },
                data: {
                    state: client_1.PrintItemState.AGENT_ACKED,
                    agentAckedAt: now,
                    attemptCount: { increment: 1 },
                },
            });
            if (markAcked.count === 0) {
                throw new Error("PRINT_ITEM_ALREADY_ACKED");
            }
            await tx.printItemEvent.create({
                data: {
                    printItemId: printItem.id,
                    eventType: client_1.PrintItemEventType.AGENT_ACKED,
                    previousState: client_1.PrintItemState.ISSUED,
                    nextState: client_1.PrintItemState.AGENT_ACKED,
                    actorUserId: user.userId,
                    details: {
                        renderTokenId: renderTokenRow.id,
                    },
                },
            });
            const remainingToPrint = await countRemainingToPrint(tx, session.id);
            return {
                remainingToPrint,
            };
        });
        await (0, auditService_1.createAuditLog)({
            userId: user.userId,
            licenseeId: job.batch.licenseeId,
            action: "DIRECT_PRINT_ITEM_ACKED",
            entityType: "PrintItem",
            entityId: printItem.id,
            details: {
                mode: "DIRECT_PRINT",
                printJobId: job.id,
                printSessionId: session.id,
                code: qr.code,
                remainingToPrint: txResult.remainingToPrint,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        const responsePayload = {
            success: true,
            data: {
                printJobId: job.id,
                printSessionId: session.id,
                printItemId: printItem.id,
                qrId: qr.id,
                code: qr.code,
                renderResolvedAt: now.toISOString(),
                remainingToPrint: txResult.remainingToPrint,
                jobConfirmed: false,
                confirmedAt: null,
                scanToken: signedQrToken,
                scanUrl: (0, qrTokenService_1.buildScanUrl)(signedQrToken),
            },
        };
        await (0, idempotencyService_1.completeIdempotentAction)({
            keyHash: idempotency.keyHash,
            statusCode: 200,
            responsePayload,
        });
        return res.json(responsePayload);
    }
    catch (e) {
        const msg = String(e?.message || "");
        if (msg.includes("RENDER_TOKEN_ALREADY_USED")) {
            return res.status(409).json({ success: false, error: "Render token already used" });
        }
        if (msg.includes("PRINT_ITEM_ALREADY_ACKED")) {
            return res.status(409).json({ success: false, error: "Print item already acknowledged" });
        }
        console.error("resolveDirectPrintToken error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.resolveDirectPrintToken = resolveDirectPrintToken;
const confirmDirectPrintItem = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = confirmDirectPrintItemSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        let idempotency;
        try {
            idempotency = await beginPrintActionIdempotency({
                req,
                action: "print_job_confirm_item",
                scope: `job:${jobId}:item:${parsed.data.printItemId}`,
                payload: parsed.data,
            });
        }
        catch (error) {
            if (handleIdempotencyError(error, res))
                return;
            throw error;
        }
        if (replayIdempotentResponseIfAny(idempotency, res))
            return;
        const job = await getManufacturerPrintJob(jobId, user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        const now = new Date();
        if (isLockExpired(job.createdAt, now)) {
            return res.status(410).json({
                success: false,
                error: "Print lock token expired. Create a new print job to continue secure direct printing.",
            });
        }
        const tokenHash = hashLockToken(parsed.data.printLockToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const session = await getOrCreatePrintSession({
            id: job.id,
            batchId: job.batchId,
            manufacturerId: job.manufacturerId,
            quantity: job.quantity,
            status: job.status,
        });
        if (session.status !== client_1.PrintSessionStatus.ACTIVE && session.status !== client_1.PrintSessionStatus.COMPLETED) {
            return res.status(409).json({ success: false, error: `Print session is ${session.status}` });
        }
        const printItem = await database_1.default.printItem.findFirst({
            where: {
                id: parsed.data.printItemId,
                printSessionId: session.id,
            },
            include: {
                qrCode: {
                    select: {
                        id: true,
                        code: true,
                        status: true,
                        printJobId: true,
                    },
                },
            },
        });
        if (!printItem) {
            return res.status(404).json({ success: false, error: "Print item not found for this session" });
        }
        if (printItem.state === client_1.PrintItemState.CLOSED) {
            const responsePayload = {
                success: true,
                data: {
                    printJobId: job.id,
                    printSessionId: session.id,
                    printItemId: printItem.id,
                    qrId: printItem.qrCodeId,
                    code: printItem.code,
                    printConfirmedAt: printItem.printConfirmedAt?.toISOString?.() || null,
                    remainingToPrint: 0,
                    jobConfirmed: true,
                    confirmedAt: job.confirmedAt ? job.confirmedAt.toISOString() : null,
                },
            };
            await (0, idempotencyService_1.completeIdempotentAction)({
                keyHash: idempotency.keyHash,
                statusCode: 200,
                responsePayload,
            });
            return res.json(responsePayload);
        }
        if (printItem.state !== client_1.PrintItemState.AGENT_ACKED) {
            return res.status(409).json({ success: false, error: `Print item is ${printItem.state}, expected AGENT_ACKED` });
        }
        const txResult = await database_1.default.$transaction(async (tx) => {
            const markConfirmed = await tx.printItem.updateMany({
                where: {
                    id: printItem.id,
                    state: client_1.PrintItemState.AGENT_ACKED,
                },
                data: {
                    state: client_1.PrintItemState.PRINT_CONFIRMED,
                    printConfirmedAt: now,
                },
            });
            if (markConfirmed.count === 0) {
                throw new Error("PRINT_ITEM_CONFIRM_CONFLICT");
            }
            await tx.printItemEvent.create({
                data: {
                    printItemId: printItem.id,
                    eventType: client_1.PrintItemEventType.PRINT_CONFIRMED,
                    previousState: client_1.PrintItemState.AGENT_ACKED,
                    nextState: client_1.PrintItemState.PRINT_CONFIRMED,
                    actorUserId: user.userId,
                    details: {
                        agentMetadata: parsed.data.agentMetadata ?? null,
                    },
                },
            });
            const qrUpdated = await tx.qRCode.updateMany({
                where: {
                    id: printItem.qrCodeId,
                    printJobId: job.id,
                    status: client_1.QRStatus.ACTIVATED,
                },
                data: {
                    status: client_1.QRStatus.PRINTED,
                    printedAt: now,
                    printedByUserId: user.userId,
                },
            });
            if (qrUpdated.count === 0 && printItem.qrCode.status !== client_1.QRStatus.PRINTED) {
                throw new Error("QR_NOT_PRINTABLE");
            }
            await tx.printSession.update({
                where: { id: session.id },
                data: {
                    confirmedItems: { increment: 1 },
                },
            });
            const finalize = await finalizePrintSessionIfReady({
                tx,
                printSessionId: session.id,
                printJobId: job.id,
                batchId: job.batchId,
                now,
                actorUserId: user.userId,
            });
            return finalize;
        });
        await (0, auditService_1.createAuditLog)({
            userId: user.userId,
            licenseeId: job.batch.licenseeId,
            action: "DIRECT_PRINT_ITEM_CONFIRMED",
            entityType: "PrintItem",
            entityId: printItem.id,
            details: {
                printJobId: job.id,
                printSessionId: session.id,
                qrId: printItem.qrCodeId,
                code: printItem.code,
                remainingToPrint: txResult.remainingToPrint,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        if (txResult.jobConfirmed) {
            try {
                await (0, notificationService_1.createUserNotification)({
                    userId: user.userId,
                    licenseeId: job.batch.licenseeId,
                    type: "manufacturer_print_job_confirmed",
                    title: "Direct-print job confirmed",
                    body: `All secure direct-print items were confirmed for ${job.batch.name}.`,
                    data: {
                        printJobId: job.id,
                        printSessionId: session.id,
                        batchId: job.batch.id,
                        batchName: job.batch.name,
                        printedCodes: job.quantity,
                        mode: "DIRECT_PRINT",
                        targetRoute: "/batches",
                    },
                });
                await notifySystemPrintEvent({
                    licenseeId: job.batch.licenseeId,
                    orgId: user.orgId || null,
                    type: "system_print_job_completed",
                    title: "System print job completed",
                    body: `Direct-print job completed for ${job.batch.name}.`,
                    data: {
                        printJobId: job.id,
                        printSessionId: session.id,
                        batchId: job.batch.id,
                        batchName: job.batch.name,
                        printedCodes: job.quantity,
                        mode: "DIRECT_PRINT",
                        targetRoute: "/batches",
                    },
                });
            }
            catch (notifyError) {
                console.error("confirmDirectPrintItem notification error:", notifyError);
            }
        }
        const responsePayload = {
            success: true,
            data: {
                printJobId: job.id,
                printSessionId: session.id,
                printItemId: printItem.id,
                qrId: printItem.qrCodeId,
                code: printItem.code,
                printConfirmedAt: now.toISOString(),
                remainingToPrint: txResult.remainingToPrint,
                jobConfirmed: txResult.jobConfirmed,
                confirmedAt: txResult.confirmedAt ? txResult.confirmedAt.toISOString() : null,
            },
        };
        await (0, idempotencyService_1.completeIdempotentAction)({
            keyHash: idempotency.keyHash,
            statusCode: 200,
            responsePayload,
        });
        return res.json(responsePayload);
    }
    catch (e) {
        const msg = String(e?.message || "");
        if (msg.includes("PRINT_ITEM_CONFIRM_CONFLICT")) {
            return res.status(409).json({ success: false, error: "Print item confirmation conflict" });
        }
        if (msg.includes("QR_NOT_PRINTABLE")) {
            return res.status(409).json({ success: false, error: "QR is not in printable state" });
        }
        console.error("confirmDirectPrintItem error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.confirmDirectPrintItem = confirmDirectPrintItem;
const reportDirectPrintFailure = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = reportDirectPrintFailureSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        let idempotency;
        try {
            idempotency = await beginPrintActionIdempotency({
                req,
                action: "print_job_fail_stop",
                scope: `job:${jobId}`,
                payload: parsed.data,
            });
        }
        catch (error) {
            if (handleIdempotencyError(error, res))
                return;
            throw error;
        }
        if (replayIdempotentResponseIfAny(idempotency, res))
            return;
        const job = await getManufacturerPrintJob(jobId, user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        const now = new Date();
        if (isLockExpired(job.createdAt, now)) {
            return res.status(410).json({
                success: false,
                error: "Print lock token expired. Create a new print job to continue secure direct printing.",
            });
        }
        const tokenHash = hashLockToken(parsed.data.printLockToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const session = await getOrCreatePrintSession({
            id: job.id,
            batchId: job.batchId,
            manufacturerId: job.manufacturerId,
            quantity: job.quantity,
            status: job.status,
        });
        const failed = await failStopPrintSession({
            printSessionId: session.id,
            printJobId: job.id,
            batchId: job.batchId,
            licenseeId: job.batch.licenseeId || null,
            actorUserId: user.userId,
            reason: parsed.data.reason,
            printItemId: parsed.data.printItemId,
            retries: parsed.data.retries,
            metadata: parsed.data.agentMetadata,
        });
        const alertBody = `Direct-print fail-stop activated for ${job.batch.name}. Reason: ${parsed.data.reason}`;
        await Promise.allSettled([
            notifySystemPrintEvent({
                licenseeId: job.batch.licenseeId,
                orgId: user.orgId || null,
                type: "system_print_job_failed",
                title: "Direct-print fail-stop triggered",
                body: alertBody,
                data: {
                    printJobId: job.id,
                    printSessionId: session.id,
                    incidentId: failed.incident.id,
                    frozenCount: failed.frozenCount,
                    failedItemId: parsed.data.printItemId || null,
                    reason: parsed.data.reason,
                    retries: parsed.data.retries ?? 0,
                    targetRoute: "/incidents",
                },
                channels: [client_1.NotificationChannel.WEB, client_1.NotificationChannel.EMAIL],
            }),
            (0, notificationService_1.createRoleNotifications)({
                audience: client_1.NotificationAudience.SUPER_ADMIN,
                type: "print_fail_stop_incident",
                title: "Print fail-stop incident created",
                body: alertBody,
                licenseeId: job.batch.licenseeId || null,
                orgId: user.orgId || null,
                incidentId: failed.incident.id,
                data: {
                    incidentId: failed.incident.id,
                    printJobId: job.id,
                    printSessionId: session.id,
                    frozenCount: failed.frozenCount,
                    reason: parsed.data.reason,
                    targetRoute: "/incidents",
                },
                channels: [client_1.NotificationChannel.WEB, client_1.NotificationChannel.EMAIL],
            }),
        ]);
        const responsePayload = {
            success: true,
            data: {
                printJobId: job.id,
                printSessionId: session.id,
                incidentId: failed.incident.id,
                frozenCount: failed.frozenCount,
                reason: parsed.data.reason,
            },
        };
        await (0, idempotencyService_1.completeIdempotentAction)({
            keyHash: idempotency.keyHash,
            statusCode: 202,
            responsePayload,
        });
        return res.status(202).json(responsePayload);
    }
    catch (e) {
        console.error("reportDirectPrintFailure error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.reportDirectPrintFailure = reportDirectPrintFailure;
const confirmPrintJob = async (req, res) => {
    try {
        const user = ensureManufacturerUser(req, res);
        if (!user)
            return;
        const parsed = confirmSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "");
        if (!jobId)
            return res.status(400).json({ success: false, error: "Missing print job id" });
        const job = await getManufacturerPrintJob(jobId, user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        const tokenHash = hashLockToken(parsed.data.printLockToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const session = await getOrCreatePrintSession({
            id: job.id,
            batchId: job.batchId,
            manufacturerId: job.manufacturerId,
            quantity: job.quantity,
            status: job.status,
        });
        const remainingToPrint = await database_1.default.printItem.count({
            where: {
                printSessionId: session.id,
                state: { in: OPEN_PRINT_STATES },
            },
        });
        if (remainingToPrint > 0) {
            return res.status(409).json({
                success: false,
                error: `Cannot confirm job while ${remainingToPrint} items are not print-confirmed. Use per-item confirm or fail-stop.`,
            });
        }
        const now = new Date();
        const finalize = await database_1.default.$transaction((tx) => finalizePrintSessionIfReady({
            tx,
            printSessionId: session.id,
            printJobId: job.id,
            batchId: job.batchId,
            now,
            actorUserId: user.userId,
        }));
        await (0, auditService_1.createAuditLog)({
            userId: user.userId,
            licenseeId: job.batch.licenseeId,
            action: "PRINT_CONFIRMED",
            entityType: "PrintJob",
            entityId: job.id,
            details: {
                printSessionId: session.id,
                remainingToPrint: finalize.remainingToPrint,
            },
            ipAddress: req.ip,
            userAgent: req.get("user-agent") || undefined,
        });
        return res.json({
            success: true,
            data: {
                printJobId: job.id,
                printSessionId: session.id,
                confirmedAt: finalize.confirmedAt,
                remainingToPrint: finalize.remainingToPrint,
                jobConfirmed: finalize.jobConfirmed,
            },
        });
    }
    catch (e) {
        console.error("confirmPrintJob error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.confirmPrintJob = confirmPrintJob;
//# sourceMappingURL=printJobController.js.map
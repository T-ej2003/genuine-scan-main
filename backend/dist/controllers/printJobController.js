"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.confirmPrintJob = exports.resolveDirectPrintToken = exports.issueDirectPrintTokens = exports.downloadPrintJobPack = exports.createPrintJob = void 0;
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const crypto_1 = require("crypto");
const qrTokenService_1 = require("../services/qrTokenService");
const auditService_1 = require("../services/auditService");
const notificationService_1 = require("../services/notificationService");
const printerConnectionService_1 = require("../services/printerConnectionService");
const MANUFACTURER_ROLES = [
    client_1.UserRole.MANUFACTURER,
    client_1.UserRole.MANUFACTURER_ADMIN,
    client_1.UserRole.MANUFACTURER_USER,
];
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
const getManufacturerPrintJob = async (jobId, userId) => database_1.default.printJob.findFirst({
    where: { id: jobId, manufacturerId: userId },
    include: { batch: { select: { id: true, name: true, licenseeId: true } } },
});
const notifySystemPrintEvent = async (params) => {
    await Promise.allSettled([
        (0, notificationService_1.createRoleNotifications)({
            audience: client_1.NotificationAudience.SUPER_ADMIN,
            type: params.type,
            title: params.title,
            body: params.body,
            licenseeId: params.licenseeId || null,
            orgId: params.orgId || null,
            data: params.data || null,
            channels: [client_1.NotificationChannel.WEB],
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
const createPrintJob = async (req, res) => {
    try {
        if (!req.user ||
            !isManufacturerRole(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const printerStatus = (0, printerConnectionService_1.getPrinterConnectionStatusForUser)(req.user.userId);
        if (!printerStatus.connected) {
            return res.status(409).json({
                success: false,
                error: "Printer is not connected. Start the authenticated print agent and connect a printer before creating a print job.",
                data: { printerStatus },
            });
        }
        const parsed = createPrintJobSchema.safeParse(req.body);
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const { batchId, quantity, rangeStart, rangeEnd } = parsed.data;
        const batch = await database_1.default.batch.findFirst({
            where: { id: batchId, manufacturerId: req.user.userId },
            select: { id: true, name: true, licenseeId: true, manufacturerId: true },
        });
        if (!batch) {
            return res.status(404).json({ success: false, error: "Batch not found or not assigned to you" });
        }
        const where = {
            batchId: batch.id,
            status: client_1.QRStatus.ALLOCATED,
        };
        if (rangeStart && rangeEnd) {
            where.code = { gte: rangeStart, lte: rangeEnd };
        }
        const candidates = await database_1.default.qRCode.findMany({
            where,
            orderBy: { code: "asc" },
            take: quantity,
            select: { id: true, code: true, licenseeId: true, batchId: true },
        });
        if (candidates.length < quantity) {
            return res.status(400).json({
                success: false,
                error: `Not enough unprinted codes. Available: ${candidates.length}, requested: ${quantity}`,
            });
        }
        const printLockToken = (0, crypto_1.randomBytes)(24).toString("base64url");
        const printLockTokenHash = hashLockToken(printLockToken);
        const now = new Date();
        const expAt = (0, qrTokenService_1.getQrTokenExpiryDate)(now);
        const prepared = candidates.map((qr) => {
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
        const job = await database_1.default.$transaction(async (tx) => {
            const createdJob = await tx.printJob.create({
                data: {
                    batchId: batch.id,
                    manufacturerId: req.user.userId,
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
            return createdJob;
        }, { timeout: 20000, maxWait: 10000 });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: batch.licenseeId,
            action: "CREATED",
            entityType: "PrintJob",
            entityId: job.id,
            details: {
                batchId: batch.id,
                quantity,
                rangeStart: rangeStart || null,
                rangeEnd: rangeEnd || null,
                mode: "DIRECT_PRINT",
            },
            ipAddress: req.ip,
        });
        try {
            await (0, notificationService_1.createUserNotification)({
                userId: req.user.userId,
                licenseeId: batch.licenseeId,
                type: "manufacturer_print_job_created",
                title: "Direct-print job prepared",
                body: `Direct-print session ready for ${batch.name} (${quantity} codes).`,
                data: {
                    printJobId: job.id,
                    batchId: batch.id,
                    batchName: batch.name,
                    quantity,
                    mode: "DIRECT_PRINT",
                    targetRoute: "/batches",
                },
            });
            await notifySystemPrintEvent({
                licenseeId: batch.licenseeId,
                orgId: req.user.orgId || null,
                type: "system_print_job_created",
                title: "System print job created",
                body: `Direct-print job created for ${batch.name} (${quantity} codes).`,
                data: {
                    printJobId: job.id,
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
        return res.status(201).json({
            success: true,
            data: {
                printJobId: job.id,
                printLockToken,
                quantity,
                tokenCount: prepared.length,
                mode: "DIRECT_PRINT",
                lockExpiresAt: getLockExpiresAt(job.createdAt).toISOString(),
                printerStatus,
            },
        });
    }
    catch (e) {
        console.error("createPrintJob error:", e);
        const msg = String(e?.message || "");
        if (msg.includes("BATCH_BUSY")) {
            return res.status(409).json({ success: false, error: "Please retry — batch busy." });
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
        if (!req.user || !isManufacturerRole(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = issueDirectPrintTokensSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        const job = await getManufacturerPrintJob(jobId, req.user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        if (job.status === "CONFIRMED") {
            return res.status(409).json({ success: false, error: "Print job already confirmed" });
        }
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
        const requestedCount = Math.max(1, Math.min(DIRECT_PRINT_MAX_BATCH, parsed.data.count || 1));
        const qrRows = await database_1.default.qRCode.findMany({
            where: { printJobId: job.id, status: client_1.QRStatus.ACTIVATED },
            orderBy: { code: "asc" },
            take: requestedCount,
            select: { id: true, code: true },
        });
        if (qrRows.length === 0) {
            const remainingToPrint = await database_1.default.qRCode.count({ where: { printJobId: job.id, status: client_1.QRStatus.ACTIVATED } });
            if (remainingToPrint === 0) {
                await database_1.default.$transaction(async (tx) => {
                    const updated = await tx.printJob.updateMany({
                        where: { id: job.id, status: "PENDING" },
                        data: { status: "CONFIRMED", confirmedAt: now },
                    });
                    if (updated.count > 0) {
                        await tx.batch.update({ where: { id: job.batchId }, data: { printedAt: now } });
                    }
                });
            }
            return res.json({
                success: true,
                data: {
                    printJobId: job.id,
                    items: [],
                    remainingToPrint,
                    jobConfirmed: remainingToPrint === 0,
                    lockExpiresAt: getLockExpiresAt(job.createdAt).toISOString(),
                },
            });
        }
        const renderTokenExpiresAt = new Date(now.getTime() + DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS * 1000);
        const rowsWithTokens = qrRows.map((row) => {
            const renderToken = (0, crypto_1.randomBytes)(24).toString("base64url");
            return {
                qrId: row.id,
                code: row.code,
                renderToken,
                tokenHash: (0, qrTokenService_1.hashToken)(renderToken),
            };
        });
        await database_1.default.$transaction(async (tx) => {
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
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: job.batch.licenseeId,
            action: "DIRECT_PRINT_TOKEN_ISSUED",
            entityType: "PrintJob",
            entityId: job.id,
            details: {
                issuedCount: rowsWithTokens.length,
                expiresAt: renderTokenExpiresAt.toISOString(),
            },
            ipAddress: req.ip,
        });
        const remainingToPrint = await database_1.default.qRCode.count({ where: { printJobId: job.id, status: client_1.QRStatus.ACTIVATED } });
        return res.json({
            success: true,
            data: {
                printJobId: job.id,
                lockExpiresAt: getLockExpiresAt(job.createdAt).toISOString(),
                directPrintTokenExpiresAt: renderTokenExpiresAt.toISOString(),
                remainingToPrint,
                items: rowsWithTokens.map((item) => ({
                    qrId: item.qrId,
                    code: item.code,
                    renderToken: item.renderToken,
                    expiresAt: renderTokenExpiresAt.toISOString(),
                })),
            },
        });
    }
    catch (e) {
        console.error("issueDirectPrintTokens error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.issueDirectPrintTokens = issueDirectPrintTokens;
const resolveDirectPrintToken = async (req, res) => {
    try {
        if (!req.user || !isManufacturerRole(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = resolveDirectPrintTokenSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "").trim();
        if (!jobId) {
            return res.status(400).json({ success: false, error: "Missing print job id" });
        }
        const job = await getManufacturerPrintJob(jobId, req.user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
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
        if (qr.status === client_1.QRStatus.PRINTED) {
            return res.status(409).json({ success: false, error: "QR code already printed" });
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
            const markPrinted = await tx.qRCode.updateMany({
                where: { id: qr.id, printJobId: job.id, status: client_1.QRStatus.ACTIVATED },
                data: {
                    status: client_1.QRStatus.PRINTED,
                    printedAt: now,
                    printedByUserId: req.user.userId,
                },
            });
            if (markPrinted.count === 0) {
                throw new Error("QR_ALREADY_PRINTED");
            }
            const remainingToPrint = await tx.qRCode.count({
                where: { printJobId: job.id, status: client_1.QRStatus.ACTIVATED },
            });
            let confirmedAt = null;
            if (remainingToPrint === 0) {
                const update = await tx.printJob.updateMany({
                    where: { id: job.id, status: "PENDING" },
                    data: { status: "CONFIRMED", confirmedAt: now },
                });
                if (update.count > 0) {
                    await tx.batch.update({
                        where: { id: job.batchId },
                        data: { printedAt: now },
                    });
                    confirmedAt = now;
                }
                else {
                    const current = await tx.printJob.findUnique({
                        where: { id: job.id },
                        select: { confirmedAt: true },
                    });
                    confirmedAt = current?.confirmedAt || null;
                }
            }
            return { remainingToPrint, confirmedAt };
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: job.batch.licenseeId,
            action: "PRINTED",
            entityType: "QRCode",
            entityId: qr.id,
            details: {
                mode: "DIRECT_PRINT",
                printJobId: job.id,
                code: qr.code,
                remainingToPrint: txResult.remainingToPrint,
            },
            ipAddress: req.ip,
        });
        if (txResult.remainingToPrint === 0) {
            try {
                await (0, notificationService_1.createUserNotification)({
                    userId: req.user.userId,
                    licenseeId: job.batch.licenseeId,
                    type: "manufacturer_print_job_confirmed",
                    title: "Direct-print job confirmed",
                    body: `All secure direct-print tokens consumed for ${job.batch.name}.`,
                    data: {
                        printJobId: job.id,
                        batchId: job.batch.id,
                        batchName: job.batch.name,
                        printedCodes: job.quantity,
                        mode: "DIRECT_PRINT",
                        targetRoute: "/batches",
                    },
                });
                await notifySystemPrintEvent({
                    licenseeId: job.batch.licenseeId,
                    orgId: req.user.orgId || null,
                    type: "system_print_job_completed",
                    title: "System print job completed",
                    body: `Direct-print job completed for ${job.batch.name}.`,
                    data: {
                        printJobId: job.id,
                        batchId: job.batch.id,
                        batchName: job.batch.name,
                        printedCodes: job.quantity,
                        mode: "DIRECT_PRINT",
                        targetRoute: "/batches",
                    },
                });
            }
            catch (notifyError) {
                console.error("resolveDirectPrintToken notification error:", notifyError);
            }
        }
        return res.json({
            success: true,
            data: {
                printJobId: job.id,
                qrId: qr.id,
                code: qr.code,
                renderResolvedAt: now.toISOString(),
                remainingToPrint: txResult.remainingToPrint,
                jobConfirmed: txResult.remainingToPrint === 0,
                confirmedAt: txResult.confirmedAt ? txResult.confirmedAt.toISOString() : null,
                scanToken: signedQrToken,
                scanUrl: (0, qrTokenService_1.buildScanUrl)(signedQrToken),
            },
        });
    }
    catch (e) {
        const msg = String(e?.message || "");
        if (msg.includes("RENDER_TOKEN_ALREADY_USED")) {
            return res.status(409).json({ success: false, error: "Render token already used" });
        }
        if (msg.includes("QR_ALREADY_PRINTED")) {
            return res.status(409).json({ success: false, error: "QR code already printed" });
        }
        console.error("resolveDirectPrintToken error:", e);
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.resolveDirectPrintToken = resolveDirectPrintToken;
const confirmPrintJob = async (req, res) => {
    try {
        if (!req.user ||
            !isManufacturerRole(req.user.role)) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = confirmSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "");
        if (!jobId)
            return res.status(400).json({ success: false, error: "Missing print job id" });
        const job = await getManufacturerPrintJob(jobId, req.user.userId);
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        if (job.status === "CONFIRMED") {
            const printedCount = await database_1.default.qRCode.count({
                where: { printJobId: job.id, status: client_1.QRStatus.PRINTED },
            });
            return res.json({
                success: true,
                data: {
                    printJobId: job.id,
                    confirmedAt: job.confirmedAt,
                    printedCodes: printedCount,
                },
            });
        }
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
        const result = await database_1.default.$transaction(async (tx) => {
            const updatedJob = await tx.printJob.update({
                where: { id: job.id },
                data: { status: "CONFIRMED", confirmedAt: now },
            });
            const updatedCodes = await tx.qRCode.updateMany({
                where: { printJobId: job.id, status: client_1.QRStatus.ACTIVATED },
                data: {
                    status: client_1.QRStatus.PRINTED,
                    printedAt: now,
                    printedByUserId: req.user.userId,
                },
            });
            await tx.batch.update({
                where: { id: job.batchId },
                data: { printedAt: now },
            });
            return { updatedJob, updatedCodes };
        });
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: job.batch.licenseeId,
            action: "PRINTED",
            entityType: "PrintJob",
            entityId: job.id,
            details: { printedCodes: result.updatedCodes.count },
            ipAddress: req.ip,
        });
        try {
            await (0, notificationService_1.createUserNotification)({
                userId: req.user.userId,
                licenseeId: job.batch.licenseeId,
                type: "manufacturer_print_job_confirmed",
                title: "Printing confirmed",
                body: `Printing confirmed for ${job.batch.name} (${result.updatedCodes.count} codes).`,
                data: {
                    printJobId: job.id,
                    batchId: job.batch.id,
                    batchName: job.batch.name,
                    printedCodes: result.updatedCodes.count,
                    targetRoute: "/batches",
                },
            });
            await notifySystemPrintEvent({
                licenseeId: job.batch.licenseeId,
                orgId: req.user.orgId || null,
                type: "system_print_job_completed",
                title: "System print job completed",
                body: `Printing confirmed for ${job.batch.name} (${result.updatedCodes.count} codes).`,
                data: {
                    printJobId: job.id,
                    batchId: job.batch.id,
                    batchName: job.batch.name,
                    printedCodes: result.updatedCodes.count,
                    mode: "DIRECT_PRINT",
                    targetRoute: "/batches",
                },
            });
        }
        catch (notifyError) {
            console.error("confirmPrintJob notification error:", notifyError);
        }
        return res.json({
            success: true,
            data: {
                printJobId: job.id,
                confirmedAt: result.updatedJob.confirmedAt,
                printedCodes: result.updatedCodes.count,
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
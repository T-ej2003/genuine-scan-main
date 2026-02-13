"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.confirmPrintJob = exports.downloadPrintJobPack = exports.createPrintJob = void 0;
const zod_1 = require("zod");
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const crypto_1 = require("crypto");
const qrTokenService_1 = require("../services/qrTokenService");
const auditService_1 = require("../services/auditService");
const qrZipStreamService_1 = require("../services/qrZipStreamService");
const createPrintJobSchema = zod_1.z.object({
    batchId: zod_1.z.string().uuid(),
    quantity: zod_1.z.number().int().positive().max(200000),
    rangeStart: zod_1.z.string().optional(),
    rangeEnd: zod_1.z.string().optional(),
});
const confirmSchema = zod_1.z.object({
    printLockToken: zod_1.z.string().min(10),
});
const hashLockToken = (raw) => (0, crypto_1.createHash)("sha256").update(raw).digest("hex");
const getTokenExp = () => {
    const days = Number(process.env.QR_TOKEN_EXP_DAYS || "3650");
    return Date.now() + Math.max(days, 30) * 24 * 60 * 60 * 1000;
};
const INLINE_PRINT_JOB_TOKENS_LIMIT = (() => {
    const raw = Number(process.env.PRINT_JOB_INLINE_TOKENS_LIMIT || "2500");
    if (!Number.isFinite(raw))
        return 2500;
    return Math.max(0, Math.min(20_000, Math.floor(raw)));
})();
const createPrintJob = async (req, res) => {
    try {
        if (!req.user || req.user.role !== client_1.UserRole.MANUFACTURER) {
            return res.status(403).json({ success: false, error: "Access denied" });
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
        const expAt = new Date(getTokenExp());
        const tokens = [];
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
            if (tokens.length < INLINE_PRINT_JOB_TOKENS_LIMIT) {
                tokens.push({ qrId: qr.id, token });
            }
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
            },
            ipAddress: req.ip,
        });
        return res.status(201).json({
            success: true,
            data: {
                printJobId: job.id,
                printLockToken,
                quantity,
                tokenCount: prepared.length,
                tokensTruncated: prepared.length > tokens.length,
                tokens,
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
const downloadPrintJobPack = async (req, res) => {
    try {
        if (!req.user || req.user.role !== client_1.UserRole.MANUFACTURER) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const jobId = String(req.params.id || "");
        const rawToken = String(req.query.token || "").trim();
        if (!jobId || !rawToken) {
            return res.status(400).json({ success: false, error: "Missing job id or token" });
        }
        const job = await database_1.default.printJob.findFirst({
            where: { id: jobId, manufacturerId: req.user.userId },
            include: { batch: { select: { id: true, name: true, licenseeId: true } } },
        });
        if (!job)
            return res.status(404).json({ success: false, error: "Print job not found" });
        if (job.status === "CONFIRMED") {
            return res.status(409).json({ success: false, error: "Print job already confirmed" });
        }
        const tokenHash = hashLockToken(rawToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const totalCodes = await database_1.default.qRCode.count({
            where: { printJobId: job.id },
        });
        if (!totalCodes) {
            return res.status(404).json({ success: false, error: "No QR codes assigned to this print job" });
        }
        const profile = (0, qrZipStreamService_1.resolveQrZipProfile)(totalCodes);
        const now = new Date();
        const confirmed = await database_1.default.$transaction(async (tx) => {
            const updatedJob = await tx.printJob.updateMany({
                where: { id: job.id, status: "PENDING" },
                data: { status: "CONFIRMED", confirmedAt: now },
            });
            if (updatedJob.count === 0) {
                return { updated: false, printed: 0 };
            }
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
            return { updated: true, printed: updatedCodes.count };
        });
        if (!confirmed.updated) {
            return res.status(409).json({ success: false, error: "Print job already confirmed" });
        }
        await (0, auditService_1.createAuditLog)({
            userId: req.user.userId,
            licenseeId: job.batch.licenseeId,
            action: "PRINTED",
            entityType: "PrintJob",
            entityId: job.id,
            details: { printedCodes: confirmed.printed },
            ipAddress: req.ip,
        });
        const fileName = `print-job-${job.id}.zip`;
        const entries = (async function* () {
            let cursorCode;
            while (true) {
                const rows = await database_1.default.qRCode.findMany({
                    where: { printJobId: job.id },
                    orderBy: { code: "asc" },
                    take: profile.dbChunkSize,
                    ...(cursorCode ? { cursor: { code: cursorCode }, skip: 1 } : {}),
                    select: {
                        id: true,
                        code: true,
                        licenseeId: true,
                        batchId: true,
                        tokenNonce: true,
                        tokenIssuedAt: true,
                        tokenExpiresAt: true,
                    },
                });
                if (rows.length === 0)
                    break;
                for (const qr of rows) {
                    const payload = {
                        qr_id: qr.id,
                        batch_id: qr.batchId,
                        licensee_id: qr.licenseeId,
                        manufacturer_id: req.user.userId,
                        iat: Math.floor((qr.tokenIssuedAt?.getTime?.() || Date.now()) / 1000),
                        exp: qr.tokenExpiresAt ? Math.floor(qr.tokenExpiresAt.getTime() / 1000) : undefined,
                        nonce: qr.tokenNonce || "",
                    };
                    const token = (0, qrTokenService_1.signQrPayload)(payload);
                    const urlInsideQr = (0, qrTokenService_1.buildScanUrl)(token);
                    yield {
                        code: qr.code,
                        url: urlInsideQr,
                        manifestValues: [qr.id, qr.code, token, urlInsideQr],
                    };
                }
                cursorCode = rows[rows.length - 1].code;
            }
        })();
        await (0, qrZipStreamService_1.streamQrZipToResponse)({
            res,
            fileName,
            totalCount: totalCodes,
            profile,
            manifestHeader: ["qr_id", "code", "token", "url"],
            entries,
        });
        return;
    }
    catch (e) {
        console.error("downloadPrintJobPack error:", e);
        if (res.headersSent) {
            res.destroy(e instanceof Error ? e : new Error(String(e?.message || "Download failed")));
            return;
        }
        return res.status(400).json({ success: false, error: e?.message || "Bad request" });
    }
};
exports.downloadPrintJobPack = downloadPrintJobPack;
const confirmPrintJob = async (req, res) => {
    try {
        if (!req.user || req.user.role !== client_1.UserRole.MANUFACTURER) {
            return res.status(403).json({ success: false, error: "Access denied" });
        }
        const parsed = confirmSchema.safeParse(req.body || {});
        if (!parsed.success) {
            return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
        }
        const jobId = String(req.params.id || "");
        if (!jobId)
            return res.status(400).json({ success: false, error: "Missing print job id" });
        const job = await database_1.default.printJob.findFirst({
            where: { id: jobId, manufacturerId: req.user.userId },
            include: { batch: { select: { id: true, licenseeId: true } } },
        });
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
        const tokenHash = hashLockToken(parsed.data.printLockToken);
        if (tokenHash !== job.printLockTokenHash) {
            return res.status(403).json({ success: false, error: "Invalid print lock token" });
        }
        const now = new Date();
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
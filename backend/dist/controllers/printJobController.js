"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.confirmPrintJob = exports.downloadPrintJobPack = exports.createPrintJob = void 0;
const zod_1 = require("zod");
const jszip_1 = __importDefault(require("jszip"));
const qrcode_1 = __importDefault(require("qrcode"));
const database_1 = __importDefault(require("../config/database"));
const client_1 = require("@prisma/client");
const crypto_1 = require("crypto");
const qrTokenService_1 = require("../services/qrTokenService");
const auditService_1 = require("../services/auditService");
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
            for (const qr of candidates) {
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
                await tx.qRCode.update({
                    where: { id: qr.id },
                    data: {
                        status: client_1.QRStatus.ACTIVATED,
                        tokenNonce: nonce,
                        tokenIssuedAt: now,
                        tokenExpiresAt: expAt,
                        tokenHash,
                        printJobId: createdJob.id,
                    },
                });
                tokens.push({ qrId: qr.id, token });
            }
            return createdJob;
        });
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
                tokens,
            },
        });
    }
    catch (e) {
        console.error("createPrintJob error:", e);
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
            include: { batch: { select: { id: true, name: true } } },
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
        const qrCodes = await database_1.default.qRCode.findMany({
            where: { printJobId: job.id },
            orderBy: { code: "asc" },
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
        if (!qrCodes.length) {
            return res.status(404).json({ success: false, error: "No QR codes assigned to this print job" });
        }
        const zip = new jszip_1.default();
        const folder = zip.folder("png");
        const csvLines = ["qr_id,code,token,url"];
        for (let i = 0; i < qrCodes.length; i += 1) {
            const qr = qrCodes[i];
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
            const pngBuffer = await qrcode_1.default.toBuffer(urlInsideQr, {
                width: 768,
                margin: 2,
                errorCorrectionLevel: "M",
            });
            folder.file(`${qr.code}.png`, pngBuffer);
            const esc = (v) => {
                const s = String(v ?? "");
                return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
            };
            csvLines[i + 1] = `${esc(qr.id)},${esc(qr.code)},${esc(token)},${esc(urlInsideQr)}`;
        }
        zip.file("manifest.csv", csvLines.join("\n"));
        const out = await zip.generateAsync({ type: "nodebuffer" });
        const fileName = `print-job-${job.id}.zip`;
        res.setHeader("Content-Type", "application/zip");
        res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
        return res.status(200).send(out);
    }
    catch (e) {
        console.error("downloadPrintJobPack error:", e);
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
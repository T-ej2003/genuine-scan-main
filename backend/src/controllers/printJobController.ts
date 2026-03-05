import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import prisma from "../config/database";
import {
  NotificationAudience,
  NotificationChannel,
  Prisma,
  QRStatus,
  UserRole,
} from "@prisma/client";
import { randomBytes, createHash } from "crypto";
import { buildScanUrl, getQrTokenExpiryDate, hashToken, randomNonce, signQrPayload } from "../services/qrTokenService";
import { createAuditLog } from "../services/auditService";
import {
  createRoleNotifications,
  createUserNotification,
} from "../services/notificationService";
import { getPrinterConnectionStatusForUser } from "../services/printerConnectionService";

const MANUFACTURER_ROLES: UserRole[] = [
  UserRole.MANUFACTURER,
  UserRole.MANUFACTURER_ADMIN,
  UserRole.MANUFACTURER_USER,
];

const isManufacturerRole = (role?: UserRole | null) =>
  Boolean(role && MANUFACTURER_ROLES.includes(role));

const createPrintJobSchema = z.object({
  batchId: z.string().uuid(),
  quantity: z.number().int().positive().max(200000),
  rangeStart: z.string().optional(),
  rangeEnd: z.string().optional(),
});

const confirmSchema = z.object({
  printLockToken: z.string().min(10),
});

const issueDirectPrintTokensSchema = z.object({
  printLockToken: z.string().min(10),
  count: z.number().int().min(1).max(500).optional(),
});

const resolveDirectPrintTokenSchema = z.object({
  printLockToken: z.string().min(10),
  renderToken: z.string().min(16),
});

const hashLockToken = (raw: string) =>
  createHash("sha256").update(raw).digest("hex");

const parsePositiveIntEnv = (name: string, fallback: number, hardMax: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(1, Math.min(hardMax, Math.floor(raw)));
};

const DIRECT_PRINT_LOCK_TTL_MINUTES = parsePositiveIntEnv("PRINT_JOB_LOCK_TTL_MINUTES", 45, 24 * 60);
const DIRECT_PRINT_RENDER_TOKEN_TTL_SECONDS = parsePositiveIntEnv("DIRECT_PRINT_TOKEN_TTL_SECONDS", 90, 900);
const DIRECT_PRINT_MAX_BATCH = parsePositiveIntEnv("DIRECT_PRINT_MAX_BATCH", 250, 500);

const getLockExpiresAt = (createdAt: Date) =>
  new Date(createdAt.getTime() + DIRECT_PRINT_LOCK_TTL_MINUTES * 60 * 1000);

const isLockExpired = (createdAt: Date, now: Date = new Date()) =>
  getLockExpiresAt(createdAt).getTime() <= now.getTime();

const getManufacturerPrintJob = async (jobId: string, userId: string) =>
  prisma.printJob.findFirst({
    where: { id: jobId, manufacturerId: userId },
    include: { batch: { select: { id: true, name: true, licenseeId: true } } },
  });

const notifySystemPrintEvent = async (params: {
  licenseeId?: string | null;
  orgId?: string | null;
  type: string;
  title: string;
  body: string;
  data?: any;
}) => {
  await Promise.allSettled([
    createRoleNotifications({
      audience: NotificationAudience.SUPER_ADMIN,
      type: params.type,
      title: params.title,
      body: params.body,
      licenseeId: params.licenseeId || null,
      orgId: params.orgId || null,
      data: params.data || null,
      channels: [NotificationChannel.WEB],
    }),
    params.licenseeId
      ? createRoleNotifications({
          audience: NotificationAudience.LICENSEE_ADMIN,
          licenseeId: params.licenseeId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
    params.orgId
      ? createRoleNotifications({
          audience: NotificationAudience.MANUFACTURER,
          orgId: params.orgId,
          type: params.type,
          title: params.title,
          body: params.body,
          data: params.data || null,
          channels: [NotificationChannel.WEB],
        })
      : Promise.resolve([] as any[]),
  ]);
};

export const createPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    if (
      !req.user ||
      !isManufacturerRole(req.user.role)
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const printerStatus = getPrinterConnectionStatusForUser(req.user.userId);
    if (!printerStatus.connected) {
      return res.status(409).json({
        success: false,
        error:
          "Printer is not connected. Start the authenticated print agent and connect a printer before creating a print job.",
        data: { printerStatus },
      });
    }

    const parsed = createPrintJobSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { batchId, quantity, rangeStart, rangeEnd } = parsed.data;

    const batch = await prisma.batch.findFirst({
      where: { id: batchId, manufacturerId: req.user.userId },
      select: { id: true, name: true, licenseeId: true, manufacturerId: true },
    });
    if (!batch) {
      return res.status(404).json({ success: false, error: "Batch not found or not assigned to you" });
    }

    const where: any = {
      batchId: batch.id,
      status: QRStatus.ALLOCATED,
    };

    if (rangeStart && rangeEnd) {
      where.code = { gte: rangeStart, lte: rangeEnd };
    }

    const candidates = await prisma.qRCode.findMany({
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

    const printLockToken = randomBytes(24).toString("base64url");
    const printLockTokenHash = hashLockToken(printLockToken);
    const now = new Date();
    const expAt = getQrTokenExpiryDate(now);

    const prepared = candidates.map((qr) => {
      const nonce = randomNonce();
      const payload = {
        qr_id: qr.id,
        batch_id: qr.batchId,
        licensee_id: qr.licenseeId,
        manufacturer_id: batch.manufacturerId || null,
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(expAt.getTime() / 1000),
        nonce,
      };
      const token = signQrPayload(payload);
      const tokenHash = hashToken(token);
      return { qr, nonce, tokenHash };
    });

    const job = await prisma.$transaction(async (tx) => {
      const createdJob = await tx.printJob.create({
        data: {
          batchId: batch.id,
          manufacturerId: req.user!.userId,
          quantity,
          rangeStart: rangeStart || null,
          rangeEnd: rangeEnd || null,
          printLockTokenHash,
          status: "PENDING",
        },
      });

      const values = prepared.map((item) =>
        Prisma.sql`(${item.qr.id}, ${item.nonce}, ${item.tokenHash}, ${now}, ${expAt})`
      );

      const updatedCount = await tx.$executeRaw(Prisma.sql`
        UPDATE "QRCode" AS q
        SET
          "status" = CAST(${QRStatus.ACTIVATED} AS "QRStatus"),
          "tokenNonce" = v."tokenNonce",
          "tokenIssuedAt" = v."tokenIssuedAt",
          "tokenExpiresAt" = v."tokenExpiresAt",
          "tokenHash" = v."tokenHash",
          "printJobId" = ${createdJob.id}
        FROM (
          VALUES ${Prisma.join(values)}
        ) AS v("id", "tokenNonce", "tokenHash", "tokenIssuedAt", "tokenExpiresAt")
        WHERE q."id" = v."id"
          AND q."status" = CAST(${QRStatus.ALLOCATED} AS "QRStatus")
          AND q."printJobId" IS NULL;
      `);

      if (Number(updatedCount) !== prepared.length) {
        throw new Error("BATCH_BUSY");
      }

      return createdJob;
    }, { timeout: 20000, maxWait: 10000 });

    await createAuditLog({
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
      await createUserNotification({
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
    } catch (notifyError) {
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
  } catch (e: any) {
    console.error("createPrintJob error:", e);
    const msg = String(e?.message || "");
    if (msg.includes("BATCH_BUSY")) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const downloadPrintJobPack = async (_req: AuthRequest, res: Response) => {
  return res.status(410).json({
    success: false,
    error:
      "Print-pack download is disabled. Use the direct-print pipeline (one-time short-lived render tokens) via authenticated print agent.",
  });
};

export const issueDirectPrintTokens = async (req: AuthRequest, res: Response) => {
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
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

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

    const qrRows = await prisma.qRCode.findMany({
      where: { printJobId: job.id, status: QRStatus.ACTIVATED },
      orderBy: { code: "asc" },
      take: requestedCount,
      select: { id: true, code: true },
    });

    if (qrRows.length === 0) {
      const remainingToPrint = await prisma.qRCode.count({ where: { printJobId: job.id, status: QRStatus.ACTIVATED } });
      if (remainingToPrint === 0) {
        await prisma.$transaction(async (tx) => {
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
      const renderToken = randomBytes(24).toString("base64url");
      return {
        qrId: row.id,
        code: row.code,
        renderToken,
        tokenHash: hashToken(renderToken),
      };
    });

    await prisma.$transaction(async (tx) => {
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

    await createAuditLog({
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

    const remainingToPrint = await prisma.qRCode.count({ where: { printJobId: job.id, status: QRStatus.ACTIVATED } });

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
  } catch (e: any) {
    console.error("issueDirectPrintTokens error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const resolveDirectPrintToken = async (req: AuthRequest, res: Response) => {
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
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

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

    const renderTokenHash = hashToken(parsed.data.renderToken);
    const renderTokenRow = await prisma.printRenderToken.findUnique({
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

    if (qr.status === QRStatus.PRINTED) {
      return res.status(409).json({ success: false, error: "QR code already printed" });
    }

    if (qr.status !== QRStatus.ACTIVATED) {
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

    const signedQrToken = signQrPayload(payload);
    const signedQrHash = hashToken(signedQrToken);
    if (qr.tokenHash && signedQrHash !== qr.tokenHash) {
      return res.status(409).json({
        success: false,
        error: "Token integrity mismatch for this QR. Create a new print job to continue.",
      });
    }

    const txResult = await prisma.$transaction(async (tx) => {
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
        where: { id: qr.id, printJobId: job.id, status: QRStatus.ACTIVATED },
        data: {
          status: QRStatus.PRINTED,
          printedAt: now,
          printedByUserId: req.user!.userId,
        },
      });

      if (markPrinted.count === 0) {
        throw new Error("QR_ALREADY_PRINTED");
      }

      const remainingToPrint = await tx.qRCode.count({
        where: { printJobId: job.id, status: QRStatus.ACTIVATED },
      });

      let confirmedAt: Date | null = null;
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
        } else {
          const current = await tx.printJob.findUnique({
            where: { id: job.id },
            select: { confirmedAt: true },
          });
          confirmedAt = current?.confirmedAt || null;
        }
      }

      return { remainingToPrint, confirmedAt };
    });

    await createAuditLog({
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
        await createUserNotification({
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
      } catch (notifyError) {
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
        scanUrl: buildScanUrl(signedQrToken),
      },
    });
  } catch (e: any) {
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

export const confirmPrintJob = async (req: AuthRequest, res: Response) => {
  try {
    if (
      !req.user ||
      !isManufacturerRole(req.user.role)
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = confirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const jobId = String(req.params.id || "");
    if (!jobId) return res.status(400).json({ success: false, error: "Missing print job id" });

    const job = await getManufacturerPrintJob(jobId, req.user.userId);
    if (!job) return res.status(404).json({ success: false, error: "Print job not found" });

    if (job.status === "CONFIRMED") {
      const printedCount = await prisma.qRCode.count({
        where: { printJobId: job.id, status: QRStatus.PRINTED },
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

    const result = await prisma.$transaction(async (tx) => {
      const updatedJob = await tx.printJob.update({
        where: { id: job.id },
        data: { status: "CONFIRMED", confirmedAt: now },
      });

      const updatedCodes = await tx.qRCode.updateMany({
        where: { printJobId: job.id, status: QRStatus.ACTIVATED },
        data: {
          status: QRStatus.PRINTED,
          printedAt: now,
          printedByUserId: req.user!.userId,
        },
      });

      await tx.batch.update({
        where: { id: job.batchId },
        data: { printedAt: now },
      });

      return { updatedJob, updatedCodes };
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: job.batch.licenseeId,
      action: "PRINTED",
      entityType: "PrintJob",
      entityId: job.id,
      details: { printedCodes: result.updatedCodes.count },
      ipAddress: req.ip,
    });

    try {
      await createUserNotification({
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
    } catch (notifyError) {
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
  } catch (e: any) {
    console.error("confirmPrintJob error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

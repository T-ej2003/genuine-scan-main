//File: backend/src/controllers/qrController.ts  
import { Response } from "express";
import { z } from "zod";
import { QRStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { generateQRCode, markBatchAsPrinted, buildVerifyUrl, getQRStats } from "../services/qrService";
import { allocateQrRange } from "../services/qrAllocationService";
import { createHash, randomBytes } from "crypto";
import JSZip from "jszip";
import QRCode from "qrcode";

/* ===================== SCHEMAS ===================== */

const allocateRangeSchema = z
  .object({
    licenseeId: z.string().uuid(),
    startNumber: z.number().int().positive(),
    endNumber: z.number().int().positive(),
  })
  .refine((d) => d.endNumber >= d.startNumber, {
    message: "End number must be >= start number",
  });

const createBatchSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    quantity: z.number().int().positive().max(500000),
    manufacturerId: z.string().uuid().optional(),
  });

const assignManufacturerSchema = z.object({
  manufacturerId: z.string().uuid(),
  quantity: z.number().int().positive().max(500000),
});

const bulkDeleteQRCodesSchema = z
  .object({
    ids: z.array(z.string().uuid()).optional(),
    codes: z.array(z.string().min(1)).optional(),
  })
  .refine((d) => (d.ids && d.ids.length) || (d.codes && d.codes.length), {
    message: "Provide ids or codes to delete",
  });

const bulkDeleteBatchesSchema = z.object({
  ids: z.array(z.string().uuid()).min(1, "Provide batch ids"),
});

const adminAllocateBatchSchema = z.object({
  licenseeId: z.string().uuid(),
  manufacturerId: z.string().uuid(),
  quantity: z.number().int().positive().max(500000),
  name: z.string().trim().min(2).max(120).optional(),
  requestNote: z.string().trim().max(500).optional(),
});

/* ===================== HELPERS ===================== */

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const safeFilePart = (s: string) => {
  return (
    String(s || "")
      .trim()
      .replace(/[^\w.-]+/g, "_")
      .replace(/^_+|_+$/g, "")
      .slice(0, 80) || "file"
  );
};

const buildPublicQrUrl = (code: string, baseUrl?: string) => {
  const base = String(baseUrl || "").trim().replace(/\/+$/, "");
  if (base) return `${base}/verify/${encodeURIComponent(code)}`;
  return buildVerifyUrl(code);
};

const escapeCsv = (v: any) => {
  if (v === null || v === undefined) return "";
  const s = String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

/* ===================== QR RANGE (SUPER ADMIN route) ===================== */

export const allocateQRRange = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = allocateRangeSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, startNumber, endNumber } = parsed.data;

    const result = await prisma.$transaction((tx) =>
      allocateQrRange({
        licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "ADMIN_TOPUP",
        createReceivedBatch: true,
        tx,
      })
    );

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATE_QR_RANGE",
      entityType: "QRRange",
      entityId: result.range.id,
      details: {
        startCode: result.startCode,
        endCode: result.endCode,
        created: result.createdCount,
        receivedBatchId: result.receivedBatch?.id || null,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: result.range });
  } catch (e) {
    console.error("allocateQRRange error:", e);
    const msg = (e as any)?.message || "Internal server error";
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== QR RANGE (SUPER ADMIN, by licensee) ===================== */

export const allocateQRRangeForLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = allocateRangeSchema.safeParse({
      ...(req.body || {}),
      licenseeId: req.params.licenseeId,
    });
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, startNumber, endNumber } = parsed.data;

    const result = await prisma.$transaction((tx) =>
      allocateQrRange({
        licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "ADMIN_TOPUP",
        createReceivedBatch: true,
        tx,
      })
    );

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATE_QR_RANGE_LICENSEE",
      entityType: "QRRange",
      entityId: result.range.id,
      details: {
        licenseeId,
        startCode: result.startCode,
        endCode: result.endCode,
        created: result.createdCount,
        receivedBatchId: result.receivedBatch?.id || null,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: result.range });
  } catch (e: any) {
    console.error("allocateQRRangeForLicensee error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

/* ===================== QR CODES DELETE ===================== */

export const bulkDeleteQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = bulkDeleteQRCodesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const where: any = {};
    if (parsed.data.ids?.length) where.id = { in: parsed.data.ids };
    if (parsed.data.codes?.length) where.code = { in: parsed.data.codes };

    if (auth.role !== UserRole.SUPER_ADMIN) {
      const licenseeId = req.user?.licenseeId;
      if (!licenseeId) return res.status(403).json({ success: false, error: "No licensee association" });
      where.licenseeId = licenseeId;
    }

    const deleted = await prisma.qRCode.deleteMany({ where });

    await createAuditLog({
      userId: auth.userId,
      action: "BULK_DELETE_QR_CODES",
      entityType: "QRCode",
      entityId: undefined,
      details: { ...parsed.data, deleted: deleted.count },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { deleted: deleted.count } });
  } catch (e: any) {
    console.error("bulkDeleteQRCodes error:", e);
    return res.status(500).json({ success: false, error: e.message || "Internal server error" });
  }
};

/* ===================== BATCH (LICENSEE ADMIN) ===================== */

export const createBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createBatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const licenseeId = req.user?.licenseeId;
    if (!licenseeId) return res.status(403).json({ success: false, error: "No licensee association" });

    const licensee = await prisma.licensee.findUnique({
      where: { id: licenseeId },
      select: { id: true, prefix: true },
    });
    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });

    const { name, quantity, manufacturerId } = parsed.data;

    // manufacturer is optional but must belong to same tenant if provided
    let mfgId: string | null = null;
    if (manufacturerId) {
      const m = await prisma.user.findFirst({
        where: { id: manufacturerId, role: UserRole.MANUFACTURER, licenseeId, isActive: true },
        select: { id: true },
      });
      if (!m) return res.status(404).json({ success: false, error: "Manufacturer invalid" });
      mfgId = m.id;
    }

    const batch = await prisma.$transaction(async (tx) => {
      const pool = await tx.qRCode.findMany({
        where: { licenseeId, batchId: null, status: QRStatus.DORMANT },
        orderBy: { code: "asc" },
        take: quantity,
        select: { id: true, code: true },
      });

      if (pool.length < quantity) {
        throw new Error(`Not enough available codes. Available: ${pool.length}, requested: ${quantity}.`);
      }

      const startCode = pool[0].code;
      const endCode = pool[pool.length - 1].code;

      const createdBatch = await tx.batch.create({
        data: {
          name,
          licenseeId,
          startCode,
          endCode,
          totalCodes: pool.length,
          manufacturerId: mfgId,
        },
      });

      const updated = await tx.qRCode.updateMany({
        where: { id: { in: pool.map((p) => p.id) } },
        data: { batchId: createdBatch.id, status: QRStatus.ALLOCATED },
      });

      if (updated.count !== pool.length) {
        throw new Error(`Concurrency issue: assigned ${updated.count}/${pool.length}. Please retry.`);
      }

      return createdBatch;
    });

    await createAuditLog({
      userId: auth.userId,
      action: "CREATE_BATCH",
      entityType: "Batch",
      entityId: batch.id,
      details: { name, quantity, manufacturerId: mfgId },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: batch });
  } catch (e: any) {
    const msg = e?.message || "Internal server error";
    console.error("createBatch error:", e);
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== BATCH (SUPER ADMIN) ===================== */

export const adminAllocateBatch = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = adminAllocateBatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, manufacturerId, quantity, name, requestNote } = parsed.data;

    const licensee = await prisma.licensee.findUnique({
      where: { id: licenseeId },
      select: { id: true, prefix: true },
    });
    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });

    const manufacturer = await prisma.user.findFirst({
      where: { id: manufacturerId, role: UserRole.MANUFACTURER, licenseeId, isActive: true },
      select: { id: true },
    });
    if (!manufacturer) {
      return res.status(404).json({ success: false, error: "Manufacturer not found / inactive / wrong licensee" });
    }

    const poolWhere = {
      licenseeId,
      status: QRStatus.DORMANT,
      OR: [
        { batchId: null },
        { batch: { manufacturerId: null, printedAt: null } },
      ],
    } as const;

    const unassignedBefore = await prisma.qRCode.count({ where: poolWhere as any });

    if (unassignedBefore < quantity) {
      return res.status(400).json({
        success: false,
        error: `Not enough unassigned codes. Available: ${unassignedBefore}, requested: ${quantity}`,
      });
    }

    // deterministic: smallest codes first
    const pool = await prisma.qRCode.findMany({
      where: poolWhere as any,
      select: { id: true, code: true },
      orderBy: { code: "asc" },
      take: quantity,
    });

    if (!pool.length) {
      return res.status(400).json({ success: false, error: "No unassigned pool available" });
    }

    const startCode = pool[0].code;
    const endCode = pool[pool.length - 1].code;

    const createdBatch = await prisma.$transaction(async (tx) => {
      const batch = await tx.batch.create({
        data: {
          name: (name?.trim() || `Batch ${startCode} → ${endCode}`).slice(0, 120),
          licenseeId,
          manufacturerId,
          startCode,
          endCode,
          totalCodes: pool.length,
        },
      });

      const updated = await tx.qRCode.updateMany({
        where: { id: { in: pool.map((p) => p.id) } },
        data: { batchId: batch.id, status: QRStatus.ALLOCATED },
      });

      if (updated.count !== pool.length) {
        throw new Error(`Concurrency issue: assigned ${updated.count}/${pool.length}. Please retry.`);
      }

      return batch;
    });

    await createAuditLog({
      userId: req.user.userId,
      action: "ADMIN_ALLOCATE_BATCH",
      entityType: "Batch",
      entityId: createdBatch.id,
      details: {
        licenseeId,
        manufacturerId,
        quantity: pool.length,
        startCode,
        endCode,
        requestNote: requestNote?.trim() || null,
      },
      ipAddress: req.ip,
    });

    const unassignedAfter = await prisma.qRCode.count({ where: poolWhere as any });

    return res.status(201).json({
      success: true,
      data: { batch: createdBatch, unassignedBefore, unassignedAfter },
    });
  } catch (e: any) {
    const msg = e?.message || "Internal server error";
    console.error("adminAllocateBatch error:", e);
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== DELETE ONE BATCH ===================== */

export const deleteBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const batchId = req.params.id;

    const batch = await prisma.batch.findUnique({
      where: { id: batchId },
      select: { id: true, name: true, licenseeId: true, printedAt: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    if (auth.role === UserRole.MANUFACTURER) {
      return res.status(403).json({ success: false, error: "Manufacturers cannot delete batches" });
    }

    if (auth.role === UserRole.LICENSEE_ADMIN) {
      if (!req.user?.licenseeId || req.user.licenseeId !== batch.licenseeId) {
        return res.status(403).json({ success: false, error: "Access denied" });
      }
    }

    if (batch.printedAt) {
      return res.status(400).json({ success: false, error: "Cannot delete a printed batch" });
    }

    const result = await prisma.$transaction(async (tx) => {
      const unassigned = await tx.qRCode.updateMany({
        where: { batchId: batch.id },
        data: { batchId: null, status: QRStatus.DORMANT },
      });

      await tx.batch.delete({ where: { id: batch.id } });

      return { unassignedCount: unassigned.count };
    });

    await createAuditLog({
      userId: auth.userId,
      action: "DELETE_BATCH",
      entityType: "Batch",
      entityId: batch.id,
      details: { batchName: batch.name, unassignedCount: result.unassignedCount },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { deletedBatchId: batch.id, ...result } });
  } catch (e) {
    console.error("deleteBatch error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== BULK DELETE BATCHES ===================== */

export const bulkDeleteBatches = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (auth.role === UserRole.MANUFACTURER) {
      return res.status(403).json({ success: false, error: "Manufacturers cannot delete batches" });
    }

    const parsed = bulkDeleteBatchesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const batchIds = parsed.data.ids;

    if (auth.role === UserRole.LICENSEE_ADMIN) {
      const licId = req.user?.licenseeId;
      if (!licId) return res.status(403).json({ success: false, error: "No licensee association" });

      const bad = await prisma.batch.findFirst({
        where: { id: { in: batchIds }, licenseeId: { not: licId } },
        select: { id: true },
      });

      if (bad) return res.status(403).json({ success: false, error: "Some batches are outside your tenant" });
    }

    // disallow deleting printed batches
    const printed = await prisma.batch.findFirst({
      where: { id: { in: batchIds }, printedAt: { not: null } },
      select: { id: true },
    });
    if (printed) {
      return res.status(400).json({ success: false, error: "Cannot bulk delete: some batches are printed" });
    }

    const txResult = await prisma.$transaction(async (tx) => {
      const unassigned = await tx.qRCode.updateMany({
        where: { batchId: { in: batchIds } },
        data: { batchId: null, status: QRStatus.DORMANT },
      });

      const deleted = await tx.batch.deleteMany({
        where: { id: { in: batchIds } },
      });

      return { unassignedCount: unassigned.count, deletedCount: deleted.count };
    });

    await createAuditLog({
      userId: auth.userId,
      action: "BULK_DELETE_BATCHES",
      entityType: "Batch",
      entityId: undefined,
      details: { batchIds, ...txResult },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: txResult });
  } catch (e) {
    console.error("bulkDeleteBatches error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

/* ===================== MANUFACTURER ASSIGN ===================== */

export const assignManufacturer = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = assignManufacturerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const batchId = req.params.id;

    const batch = await prisma.batch.findUnique({
      where: { id: batchId },
      select: { id: true, name: true, licenseeId: true, printedAt: true, manufacturerId: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    if (batch.printedAt) {
      return res.status(400).json({ success: false, error: "Already printed; cannot reassign" });
    }

    if (batch.manufacturerId) {
      return res.status(400).json({ success: false, error: "Batch already assigned to a manufacturer" });
    }

    if (auth.role === UserRole.LICENSEE_ADMIN) {
      if (!req.user?.licenseeId || req.user.licenseeId !== batch.licenseeId) {
        return res.status(403).json({ success: false, error: "Access denied" });
      }
    }

    const manufacturer = await prisma.user.findFirst({
      where: {
        id: parsed.data.manufacturerId,
        role: UserRole.MANUFACTURER,
        licenseeId: batch.licenseeId,
        isActive: true,
      },
      select: { id: true, name: true },
    });
    if (!manufacturer) return res.status(404).json({ success: false, error: "Manufacturer invalid" });

    const quantity = parsed.data.quantity;

    const result = await prisma.$transaction(async (tx) => {
      const eligible = await tx.qRCode.findMany({
        where: {
          batchId: batch.id,
          status: { in: [QRStatus.DORMANT, QRStatus.ACTIVE, QRStatus.ALLOCATED] },
        },
        orderBy: { code: "asc" },
        take: quantity,
        select: { id: true, code: true },
      });

      if (eligible.length < quantity) {
        throw new Error(
          `Not enough available codes in this batch. Available: ${eligible.length}, requested: ${quantity}.`
        );
      }

      const startCode = eligible[0].code;
      const endCode = eligible[eligible.length - 1].code;
      const totalCodes = eligible.length;

      const newName = `${batch.name} → ${manufacturer.name} (${totalCodes})`
        .replace(/\s+/g, " ")
        .slice(0, 120);

      const newBatch = await tx.batch.create({
        data: {
          name: newName,
          licenseeId: batch.licenseeId,
          manufacturerId: manufacturer.id,
          startCode,
          endCode,
          totalCodes,
        },
      });

      await tx.qRCode.updateMany({
        where: { id: { in: eligible.map((e) => e.id) } },
        data: { batchId: newBatch.id, status: QRStatus.ALLOCATED },
      });

      const remaining = await tx.qRCode.findMany({
        where: { batchId: batch.id },
        orderBy: { code: "asc" },
        select: { code: true },
      });

      if (remaining.length === 0) {
        await tx.batch.delete({ where: { id: batch.id } });
      } else {
        await tx.batch.update({
          where: { id: batch.id },
          data: {
            startCode: remaining[0].code,
            endCode: remaining[remaining.length - 1].code,
            totalCodes: remaining.length,
          },
        });
      }

      return { newBatchId: newBatch.id, allocated: totalCodes };
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ASSIGN_MANUFACTURER_QUANTITY",
      entityType: "Batch",
      entityId: batch.id,
      details: { manufacturerId: manufacturer.id, quantity: result.allocated },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: result });
  } catch (e) {
    console.error("assignManufacturer error:", e);
    return res.status(400).json({ success: false, error: (e as any)?.message || "Internal server error" });
  }
};

/* ===================== PRINT ===================== */

export const markPrinted = async (req: AuthRequest, res: Response) => {
  try {
    const code = String(req.params.code || "").trim();
    if (!code) return res.status(400).json({ success: false, error: "Missing code" });

    const qr = await prisma.qRCode.findUnique({
      where: { code },
      include: { batch: true },
    });

    if (!qr?.batch) return res.status(404).json({ success: false, error: "QR or batch not found" });

    const count = await markBatchAsPrinted(qr.batch.id, req.user!.userId);
    return res.json({ success: true, data: { count } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e.message || "Bad request" });
  }
};

export const confirmBatchPrint = async (req: AuthRequest, res: Response) => {
  try {
    const batchId = req.params.id;

    const batch = await prisma.batch.findFirst({
      where: { id: batchId, manufacturerId: req.user!.userId },
      select: { id: true },
    });

    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    const count = await markBatchAsPrinted(batch.id, req.user!.userId);
    return res.json({ success: true, data: { count } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e.message || "Bad request" });
  }
};

/* ===================== MANUFACTURER PRINT PACK (BATCH) ===================== */

export const createBatchPrintToken = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const id = req.params.id;
    const batch = await prisma.batch.findFirst({
      where: { id, manufacturerId: userId },
      select: { id: true, printedAt: true, printPackDownloadedAt: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    if (batch.printPackDownloadedAt || batch.printedAt) {
      return res.status(409).json({ success: false, error: "Print pack already downloaded/printed" });
    }

    const token = randomBytes(32).toString("base64url");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await prisma.$transaction(async (tx) => {
      await tx.batchPrintPackToken.deleteMany({
        where: { batchId: batch.id, usedAt: null },
      });
      await tx.batchPrintPackToken.create({
        data: {
          tokenHash,
          batchId: batch.id,
          createdByUserId: userId,
          expiresAt,
        },
      });
    });

    return res.json({ success: true, data: { token, expiresAt } });
  } catch (e: any) {
    console.error("createBatchPrintToken error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const downloadBatchPrintPack = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const rawToken = String(req.params.token || "").trim().replace(/\.zip$/i, "");
    if (!rawToken) return res.status(400).json({ success: false, error: "Missing token" });

    const tokenHash = createHash("sha256").update(rawToken).digest("hex");
    const now = new Date();

    const tokenRow = await prisma.batchPrintPackToken.findUnique({
      where: { tokenHash },
      include: {
        batch: { include: { licensee: { select: { id: true, prefix: true } } } },
      },
    });

    if (!tokenRow) return res.status(404).json({ success: false, error: "Token not found" });
    if (tokenRow.usedAt) return res.status(409).json({ success: false, error: "Token already used" });
    if (tokenRow.expiresAt.getTime() <= now.getTime()) {
      return res.status(410).json({ success: false, error: "Token expired" });
    }

    const batch = tokenRow.batch;
    if (!batch || batch.manufacturerId !== userId) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const markUsed = await prisma.batchPrintPackToken.updateMany({
      where: { tokenHash, usedAt: null, expiresAt: { gt: now } },
      data: { usedAt: now },
    });
    if (markUsed.count === 0) {
      return res.status(409).json({ success: false, error: "Token already used" });
    }

    const codes = await prisma.qRCode.findMany({
      where: { batchId: batch.id },
      select: { code: true },
      orderBy: { code: "asc" },
    });
    if (codes.length === 0) {
      return res.status(404).json({ success: false, error: "No QR codes found for this batch" });
    }

    const publicBaseUrl = String(req.query.publicBaseUrl || "").trim();

    const zip = new JSZip();
    const folder = zip.folder("png")!;
    const csvLines: string[] = ["code,url"];

    for (let i = 0; i < codes.length; i += 1) {
      const code = codes[i].code;
      const urlInsideQr = buildPublicQrUrl(code, publicBaseUrl);
      const pngBuffer = await QRCode.toBuffer(urlInsideQr, {
        width: 768,
        margin: 2,
        errorCorrectionLevel: "M",
      });
      folder.file(`${code}.png`, pngBuffer);
      const esc = (v: string) => {
        const s = String(v ?? "");
        return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
      };
      csvLines[i + 1] = `${esc(code)},${esc(urlInsideQr)}`;
    }

    zip.file("manifest.csv", csvLines.join("\n"));
    const out = await zip.generateAsync({ type: "nodebuffer" });

    await prisma.$transaction(async (tx) => {
      await tx.batch.update({
        where: { id: batch.id },
        data: {
          printPackDownloadedAt: now,
          printPackDownloadedByUserId: userId,
          printedAt: batch.printedAt || now,
        },
      });

      await tx.qRCode.updateMany({
        where: { batchId: batch.id, status: { in: [QRStatus.ALLOCATED, QRStatus.ACTIVE, QRStatus.DORMANT] } },
        data: { status: QRStatus.PRINTED },
      });
    });

    await createAuditLog({
      userId,
      licenseeId: batch.licenseeId,
      action: "DOWNLOAD_BATCH_PRINT_PACK",
      entityType: "Batch",
      entityId: batch.id,
      details: { codes: codes.length },
      ipAddress: req.ip,
    });

    const fileName = `batch-${safeFilePart(batch.name || batch.id)}-print-pack.zip`;
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
    return res.status(200).send(out);
  } catch (e: any) {
    console.error("downloadBatchPrintPack error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

/* ===================== READ ===================== */

export const getBatches = async (req: AuthRequest, res: Response) => {
  try {
    const where: any = {};

    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      if (req.user?.licenseeId) where.licenseeId = req.user.licenseeId;
    } else {
      const qLicenseeId = (req.query.licenseeId as string | undefined) || undefined;
      if (qLicenseeId) where.licenseeId = qLicenseeId;
    }

    if (req.user?.role === UserRole.MANUFACTURER) {
      where.manufacturerId = req.user.userId;
    }

    const batches = await prisma.batch.findMany({
      where,
      orderBy: { createdAt: "desc" },
      include: {
        licensee: { select: { id: true, name: true, prefix: true } },
        manufacturer: { select: { id: true, name: true, email: true } },
        _count: { select: { qrCodes: true } },
      },
    });

    if (!batches.length) {
      return res.json({ success: true, data: batches });
    }

    const batchIds = batches.map((b) => b.id);

    const remainingGroups = await prisma.qRCode.groupBy({
      by: ["batchId"],
      where: {
        batchId: { in: batchIds },
      },
      _count: { _all: true },
      _min: { code: true },
      _max: { code: true },
    });

    const remainingMap = new Map<
      string,
      { availableCodes: number; remainingStartCode: string | null; remainingEndCode: string | null }
    >();
    for (const g of remainingGroups) {
      if (!g.batchId) continue;
      remainingMap.set(g.batchId, {
        availableCodes: g._count?._all || 0,
        remainingStartCode: g._min?.code || null,
        remainingEndCode: g._max?.code || null,
      });
    }

    const enriched = batches.map((b) => ({
      ...b,
      availableCodes: remainingMap.get(b.id)?.availableCodes ?? 0,
      remainingStartCode: remainingMap.get(b.id)?.remainingStartCode ?? null,
      remainingEndCode: remainingMap.get(b.id)?.remainingEndCode ?? null,
    }));

    return res.json({ success: true, data: enriched });
  } catch (e) {
    console.error("getBatches error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;

    const q = (req.query.q as string | undefined)?.trim();
    const status = (req.query.status as QRStatus | undefined) || undefined;

    const limit = Math.min(parseInt(String(req.query.limit ?? "500"), 10) || 500, 2000);
    const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;

    const licenseeId: string | undefined =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : (req.user?.licenseeId ?? undefined) || undefined;

    const where: any = {};
    if (licenseeId) where.licenseeId = licenseeId;
    if (status) where.status = status;
    if (q) where.code = { contains: q, mode: "insensitive" };

    if (role === UserRole.MANUFACTURER && userId) {
      where.batch = { manufacturerId: userId };
    }

    const [total, qrCodes] = await Promise.all([
      prisma.qRCode.count({ where }),
      prisma.qRCode.findMany({
        where,
        orderBy: { code: "asc" },
        take: limit,
        skip: offset,
        include: {
          batch: { select: { id: true, name: true, printedAt: true } },
        },
      }),
    ]);

    return res.json({ success: true, data: { qrCodes, total, limit, offset } });
  } catch (e: any) {
    console.error("getQRCodes error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getStats = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;

    const licenseeId: string | undefined =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : (req.user?.licenseeId ?? undefined) || undefined;

    const stats = await getQRStats(licenseeId);
    return res.json({ success: true, data: stats });
  } catch (e) {
    console.error("getStats error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const exportQRCodesCsv = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;
    if (!role || !userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const q = (req.query.q as string | undefined)?.trim();
    const status = (req.query.status as QRStatus | undefined) || undefined;

    const licenseeId =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : req.user?.licenseeId;

    const where: any = {};
    if (licenseeId) where.licenseeId = licenseeId;
    if (status) where.status = status;
    if (q) where.code = { contains: q, mode: "insensitive" };

    if (role === UserRole.MANUFACTURER) {
      where.batch = { manufacturerId: userId };
    }

    const rows = await prisma.qRCode.findMany({
      where,
      orderBy: { code: "asc" },
      include: {
        licensee: { select: { name: true, prefix: true } },
        batch: { select: { id: true, name: true, printedAt: true } },
      },
    });

    const header = [
      "code",
      "verifyUrl",
      "status",
      "licenseeName",
      "licenseePrefix",
      "batchId",
      "batchName",
      // "productBatchId",
      "productName",
      "productCode",
      "printedAt",
      "scanCount",
      "createdAt",
      "scannedAt",
    ];

    const csv =
      header.join(",") +
      "\n" +
      rows
        .map((r) =>
          [
            r.code,
            buildVerifyUrl(r.code),
            r.status,
            r.licensee?.name ?? "",
            r.licensee?.prefix ?? "",
            r.batchId ?? "",
            r.batch?.name ?? "",
            "",
            "",
            "",
            r.batch?.printedAt ?? "",
            r.scanCount ?? 0,
            r.createdAt,
            r.scannedAt ?? "",
          ]
            .map(escapeCsv)
            .join(",")
        )
        .join("\n");

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="qr-codes.csv"`);
    return res.status(200).send(csv);
  } catch (e) {
    console.error("exportQRCodesCsv error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

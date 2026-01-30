//File: backend/src/controllers/qrController.ts  
import { Response } from "express";
import { z } from "zod";
import { QRStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import {
  generateQRCode,
  generateQRCodesForRange,
  markBatchAsPrinted,
  buildVerifyUrl,
  getQRStats,
} from "../services/qrService";

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
    startNumber: z.number().int().positive(),
    endNumber: z.number().int().positive(),
    manufacturerId: z.string().uuid().optional(),
  })
  .refine((d) => d.endNumber >= d.startNumber, {
    message: "End number must be >= start number",
  });

const assignManufacturerSchema = z.object({
  manufacturerId: z.string().uuid(),
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

    const licensee = await prisma.licensee.findUnique({
      where: { id: licenseeId },
      select: { id: true, prefix: true },
    });
    if (!licensee) return res.status(404).json({ success: false, error: "Licensee not found" });

    const startCode = generateQRCode(licensee.prefix, startNumber);
    const endCode = generateQRCode(licensee.prefix, endNumber);

    const range = await prisma.qRRange.create({
      data: {
        licenseeId,
        startCode,
        endCode,
        totalCodes: endNumber - startNumber + 1,
      },
    });

    const created = await generateQRCodesForRange(licenseeId, licensee.prefix, startNumber, endNumber);

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATE_QR_RANGE",
      entityType: "QRRange",
      entityId: range.id,
      details: { startCode, endCode, created },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: range });
  } catch (e) {
    console.error("allocateQRRange error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
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
      entityId: null,
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

    const { name, startNumber, endNumber, manufacturerId } = parsed.data;
    const startCode = generateQRCode(licensee.prefix, startNumber);
    const endCode = generateQRCode(licensee.prefix, endNumber);
    const expectedQty = endNumber - startNumber + 1;

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
      // Ensure full range is available (unbatched + dormant)
      const available = await tx.qRCode.count({
        where: {
          licenseeId,
          code: { gte: startCode, lte: endCode },
          batchId: null,
          status: QRStatus.DORMANT,
        },
      });

      if (available !== expectedQty) {
        throw new Error(
          `Range not fully available. Expected ${expectedQty}, but only ${available} are available (already used or missing).`
        );
      }

      const createdBatch = await tx.batch.create({
        data: {
          name,
          licenseeId,
          startCode,
          endCode,
          totalCodes: expectedQty,
          manufacturerId: mfgId,
        },
      });

      const updated = await tx.qRCode.updateMany({
        where: {
          licenseeId,
          code: { gte: startCode, lte: endCode },
          batchId: null,
          status: QRStatus.DORMANT,
        },
        data: { batchId: createdBatch.id, status: QRStatus.ALLOCATED },
      });

      if (updated.count !== expectedQty) {
        throw new Error(`Concurrency issue: assigned ${updated.count}/${expectedQty}. Please retry.`);
      }

      return createdBatch;
    });

    await createAuditLog({
      userId: auth.userId,
      action: "CREATE_BATCH",
      entityType: "Batch",
      entityId: batch.id,
      details: { name, startCode, endCode, manufacturerId: mfgId },
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

    const unassignedBefore = await prisma.qRCode.count({
      where: { licenseeId, batchId: null, status: QRStatus.DORMANT },
    });

    if (unassignedBefore < quantity) {
      return res.status(400).json({
        success: false,
        error: `Not enough unassigned codes. Available: ${unassignedBefore}, requested: ${quantity}`,
      });
    }

    // deterministic: smallest codes first
    const pool = await prisma.qRCode.findMany({
      where: { licenseeId, batchId: null, status: QRStatus.DORMANT },
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

    const unassignedAfter = await prisma.qRCode.count({
      where: { licenseeId, batchId: null, status: QRStatus.DORMANT },
    });

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
      entityId: null,
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
      select: { id: true, licenseeId: true, printedAt: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    if (batch.printedAt) {
      return res.status(400).json({ success: false, error: "Already printed; cannot reassign" });
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
      select: { id: true },
    });
    if (!manufacturer) return res.status(404).json({ success: false, error: "Manufacturer invalid" });

    const updated = await prisma.batch.update({
      where: { id: batch.id },
      data: { manufacturerId: manufacturer.id },
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ASSIGN_MANUFACTURER",
      entityType: "Batch",
      entityId: batch.id,
      details: { manufacturerId: manufacturer.id },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("assignManufacturer error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
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

    return res.json({ success: true, data: batches });
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

    const licenseeId =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : req.user?.licenseeId;

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
          productBatch: { select: { id: true, productName: true, productCode: true, printedAt: true } },
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

    const licenseeId =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : req.user?.licenseeId;

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
        productBatch: { select: { id: true, productName: true, productCode: true, printedAt: true } },
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
      "productBatchId",
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
            r.productBatchId ?? "",
            r.productBatch?.productName ?? "",
            r.productBatch?.productCode ?? "",
            r.batch?.printedAt ?? r.productBatch?.printedAt ?? "",
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


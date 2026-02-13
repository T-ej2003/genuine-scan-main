//File: backend/src/controllers/qrController.ts  
import { Response } from "express";
import { z } from "zod";
import { QRStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { generateQRCode, markBatchAsPrinted, buildVerifyUrl, getQRStats } from "../services/qrService";
import { allocateQrRange, getNextLicenseeQrNumber, lockLicenseeAllocation } from "../services/qrAllocationService";
import { createHash, randomBytes } from "crypto";
import { hashToken, randomNonce, signQrPayload } from "../services/qrTokenService";
import { resolveQrZipProfile, streamQrZipToResponse } from "../services/qrZipStreamService";

/* ===================== SCHEMAS ===================== */

const allocateRangeSchema = z
  .object({
    licenseeId: z.string().uuid(),
    startNumber: z.number().int().positive(),
    endNumber: z.number().int().positive(),
    receivedBatchName: z.string().trim().min(2).max(120).optional(),
  })
  .refine((d) => d.endNumber >= d.startNumber, {
    message: "End number must be >= start number",
  });

const allocateLicenseeTopupSchema = z
  .object({
    startNumber: z.number().int().positive().optional(),
    endNumber: z.number().int().positive().optional(),
    quantity: z.number().int().positive().max(500000).optional(),
    receivedBatchName: z.string().trim().min(2).max(120).optional(),
  })
  .refine(
    (d) => {
      const hasRange = d.startNumber != null || d.endNumber != null;
      const hasQuantity = d.quantity != null;
      if (hasRange && hasQuantity) return false;
      if (!hasRange && !hasQuantity) return false;
      if (hasRange && (d.startNumber == null || d.endNumber == null)) return false;
      return true;
    },
    { message: "Provide either quantity or both startNumber and endNumber." }
  )
  .refine((d) => (d.startNumber != null && d.endNumber != null ? d.endNumber >= d.startNumber : true), {
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
  name: z.string().trim().min(2).max(120).optional(),
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

const generateQRCodesSchema = z.object({
  licenseeId: z.string().uuid(),
  quantity: z.number().int().positive().max(200000),
});

const blockQRSschema = z.object({
  reason: z.string().trim().max(500).optional(),
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

const isBatchBusyError = (msg: string) =>
  msg.includes("BATCH_BUSY") || msg.toLowerCase().includes("concurrency issue");

/* ===================== QR RANGE (SUPER ADMIN route) ===================== */

export const allocateQRRange = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = allocateRangeSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, startNumber, endNumber, receivedBatchName } = parsed.data;

    const result = await prisma.$transaction(async (tx) => {
      await lockLicenseeAllocation(tx, licenseeId);
      return allocateQrRange({
        licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "ADMIN_TOPUP",
        createReceivedBatch: true,
        receivedBatchName: receivedBatchName || null,
        tx,
      });
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATED",
      entityType: "QRRange",
      entityId: result.range.id,
      details: {
        context: "ALLOCATE_QR_RANGE",
        startCode: result.startCode,
        endCode: result.endCode,
        created: result.createdCount,
        receivedBatchId: result.receivedBatch?.id || null,
        receivedBatchName: result.receivedBatch?.name || null,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({
      success: true,
      data: {
        range: result.range,
        startCode: result.startCode,
        endCode: result.endCode,
        totalCodes: result.totalCodes,
        receivedBatchId: result.receivedBatch?.id || null,
        receivedBatchName: result.receivedBatch?.name || null,
      },
    });
  } catch (e) {
    console.error("allocateQRRange error:", e);
    const msg = (e as any)?.message || "Internal server error";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== QR RANGE (SUPER ADMIN, by licensee) ===================== */

export const allocateQRRangeForLicensee = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const licenseeIdParsed = z.string().uuid().safeParse(req.params.licenseeId);
    if (!licenseeIdParsed.success) {
      return res.status(400).json({ success: false, error: "Invalid licenseeId" });
    }
    const licenseeId = licenseeIdParsed.data;

    const parsed = allocateLicenseeTopupSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const result = await prisma.$transaction(async (tx) => {
      await lockLicenseeAllocation(tx, licenseeId);

      const startNumber =
        parsed.data.quantity != null
          ? await getNextLicenseeQrNumber(tx, licenseeId)
          : (parsed.data.startNumber as number);
      const endNumber =
        parsed.data.quantity != null
          ? startNumber + parsed.data.quantity - 1
          : (parsed.data.endNumber as number);

      const allocation = await allocateQrRange({
        licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "ADMIN_TOPUP",
        createReceivedBatch: true,
        receivedBatchName: parsed.data.receivedBatchName || null,
        tx,
      });

      return { allocation, startNumber, endNumber };
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATED",
      entityType: "QRRange",
      entityId: result.allocation.range.id,
      details: {
        context: "ALLOCATE_QR_RANGE_LICENSEE",
        licenseeId,
        startCode: result.allocation.startCode,
        endCode: result.allocation.endCode,
        created: result.allocation.createdCount,
        receivedBatchId: result.allocation.receivedBatch?.id || null,
        receivedBatchName: result.allocation.receivedBatch?.name || null,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({
      success: true,
      data: {
        range: result.allocation.range,
        startCode: result.allocation.startCode,
        endCode: result.allocation.endCode,
        startNumber: result.startNumber,
        endNumber: result.endNumber,
        totalCodes: result.allocation.totalCodes,
        receivedBatchId: result.allocation.receivedBatch?.id || null,
        receivedBatchName: result.allocation.receivedBatch?.name || null,
      },
    });
  } catch (e: any) {
    console.error("allocateQRRangeForLicensee error:", e);
    const msg = e?.message || "Bad request";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
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
        data: {
          batchId: createdBatch.id,
          status: QRStatus.ALLOCATED,
          printJobId: null,
          tokenNonce: null,
          tokenIssuedAt: null,
          tokenExpiresAt: null,
          tokenHash: null,
          printedAt: null,
          printedByUserId: null,
          redeemedAt: null,
          redeemedDeviceFingerprint: null,
        },
      });

      if (updated.count !== pool.length) {
        throw new Error("BATCH_BUSY");
      }

      return createdBatch;
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATED",
      entityType: "Batch",
      entityId: batch.id,
      details: { context: "CREATE_BATCH", name, quantity, manufacturerId: mfgId },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: batch });
  } catch (e: any) {
    const msg = e?.message || "Internal server error";
    console.error("createBatch error:", e);
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== BATCH (SUPER ADMIN) ===================== */

export const adminAllocateBatch = async (req: AuthRequest, res: Response) => {
  if (req.user?.role !== UserRole.SUPER_ADMIN) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  return res.status(403).json({
    success: false,
    error:
      "Direct super admin allocation to manufacturer is disabled. Allocate dormant pool to licensee only; licensee admin must assign batches to manufacturers.",
  });
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
        data: {
          batchId: null,
          status: QRStatus.DORMANT,
          printJobId: null,
          tokenNonce: null,
          tokenIssuedAt: null,
          tokenExpiresAt: null,
          tokenHash: null,
          printedAt: null,
          printedByUserId: null,
          redeemedAt: null,
          redeemedDeviceFingerprint: null,
        },
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
        data: {
          batchId: null,
          status: QRStatus.DORMANT,
          printJobId: null,
          tokenNonce: null,
          tokenIssuedAt: null,
          tokenExpiresAt: null,
          tokenHash: null,
          printedAt: null,
          printedByUserId: null,
          redeemedAt: null,
          redeemedDeviceFingerprint: null,
        },
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
    const requestedChildBatchName = String(parsed.data.name || "").trim();

    const result = await prisma.$transaction(async (tx) => {
      const eligible = await tx.qRCode.findMany({
        where: {
          batchId: batch.id,
          status: { in: [QRStatus.DORMANT, QRStatus.ACTIVE, QRStatus.ALLOCATED] },
          printJobId: null,
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

      const newName = (
        requestedChildBatchName ||
        `${batch.name} -> ${manufacturer.name} (${totalCodes})`
      )
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

      const updated = await tx.qRCode.updateMany({
        where: { id: { in: eligible.map((e) => e.id) } },
        data: {
          batchId: newBatch.id,
          status: QRStatus.ALLOCATED,
          printJobId: null,
          tokenNonce: null,
          tokenIssuedAt: null,
          tokenExpiresAt: null,
          tokenHash: null,
          printedAt: null,
          printedByUserId: null,
          redeemedAt: null,
          redeemedDeviceFingerprint: null,
        },
      });
      if (updated.count !== eligible.length) {
        throw new Error("BATCH_BUSY");
      }

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

      return { newBatchId: newBatch.id, newBatchName: newBatch.name, allocated: totalCodes, startCode, endCode };
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATED",
      entityType: "Batch",
      entityId: batch.id,
      details: {
        context: "ASSIGN_MANUFACTURER_QUANTITY_PARENT",
        manufacturerId: manufacturer.id,
        quantity: result.allocated,
        childBatchId: result.newBatchId,
        childBatchName: result.newBatchName,
      },
      ipAddress: req.ip,
    });

    await createAuditLog({
      userId: auth.userId,
      action: "ALLOCATED",
      entityType: "Batch",
      entityId: result.newBatchId,
      details: {
        context: "ASSIGN_MANUFACTURER_QUANTITY_CHILD",
        manufacturerId: manufacturer.id,
        quantity: result.allocated,
        parentBatchId: batch.id,
        childBatchName: result.newBatchName,
        startCode: result.startCode,
        endCode: result.endCode,
      },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: result });
  } catch (e) {
    console.error("assignManufacturer error:", e);
    const msg = (e as any)?.message || "Internal server error";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
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

    const totalCodes = await prisma.qRCode.count({
      where: { batchId: batch.id },
    });
    if (totalCodes === 0) {
      return res.status(404).json({ success: false, error: "No QR codes found for this batch" });
    }

    const publicBaseUrl = String(req.query.publicBaseUrl || "").trim();
    const profile = resolveQrZipProfile(totalCodes);

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
        data: { status: QRStatus.PRINTED, printedAt: now, printedByUserId: userId },
      });
    });

    await createAuditLog({
      userId,
      licenseeId: batch.licenseeId,
      action: "DOWNLOAD_BATCH_PRINT_PACK",
      entityType: "Batch",
      entityId: batch.id,
      details: { codes: totalCodes },
      ipAddress: req.ip,
    });

    const fileName = `batch-${safeFilePart(batch.name || batch.id)}-print-pack.zip`;
    const entries = (async function* () {
      let cursorCode: string | undefined;
      while (true) {
        const rows = await prisma.qRCode.findMany({
          where: { batchId: batch.id },
          orderBy: { code: "asc" },
          take: profile.dbChunkSize,
          ...(cursorCode ? { cursor: { code: cursorCode }, skip: 1 } : {}),
          select: { code: true },
        });

        if (rows.length === 0) break;

        for (const row of rows) {
          const urlInsideQr = buildPublicQrUrl(row.code, publicBaseUrl);
          yield {
            code: row.code,
            url: urlInsideQr,
            manifestValues: [row.code, urlInsideQr],
          };
        }

        cursorCode = rows[rows.length - 1].code;
      }
    })();

    await streamQrZipToResponse({
      res,
      fileName,
      totalCount: totalCodes,
      profile,
      manifestHeader: ["code", "url"],
      entries,
    });
    return;
  } catch (e: any) {
    console.error("downloadBatchPrintPack error:", e);
    if (res.headersSent) {
      res.destroy(e instanceof Error ? e : new Error(String(e?.message || "Download failed")));
      return;
    }
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

/* ===================== ADMIN GENERATE SIGNED QRS ===================== */

export const generateQRCodes = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = generateQRCodesSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const { licenseeId, quantity } = parsed.data;

    const result = await prisma.$transaction(async (tx) => {
      await lockLicenseeAllocation(tx, licenseeId);
      const startNumber = await getNextLicenseeQrNumber(tx, licenseeId);
      const endNumber = startNumber + quantity - 1;

      const allocation = await allocateQrRange({
        licenseeId,
        startNumber,
        endNumber,
        createdByUserId: req.user?.userId,
        source: "ADMIN_GENERATE",
        createReceivedBatch: true,
        tx,
      });

      return { allocation, startNumber, endNumber };
    });

    const rows = await prisma.qRCode.findMany({
      where: { licenseeId, code: { gte: result.allocation.startCode, lte: result.allocation.endCode } },
      select: { id: true, licenseeId: true, batchId: true, tokenNonce: true, tokenIssuedAt: true, tokenExpiresAt: true },
      orderBy: { code: "asc" },
    });

    const now = new Date();
    const expAt = new Date(now.getTime() + 3650 * 24 * 60 * 60 * 1000);

    const tokens: { qrId: string; token: string }[] = [];
    for (const qr of rows) {
      const nonce = qr.tokenNonce || randomNonce();
      const payload = {
        qr_id: qr.id,
        batch_id: qr.batchId ?? null,
        licensee_id: qr.licenseeId,
        manufacturer_id: null,
        iat: Math.floor(now.getTime() / 1000),
        exp: Math.floor(expAt.getTime() / 1000),
        nonce,
      };
      const token = signQrPayload(payload);
      const tokenHash = hashToken(token);
      tokens.push({ qrId: qr.id, token });

      await prisma.qRCode.update({
        where: { id: qr.id },
        data: {
          tokenNonce: nonce,
          tokenIssuedAt: now,
          tokenExpiresAt: expAt,
          tokenHash,
        },
      });
    }

    await createAuditLog({
      userId: req.user.userId,
      licenseeId,
      action: "CREATED",
      entityType: "QRCode",
      details: { startNumber: result.startNumber, endNumber: result.endNumber, quantity },
      ipAddress: req.ip,
    });

    return res.status(201).json({
      success: true,
      data: {
        range: result.allocation.range,
        receivedBatch: result.allocation.receivedBatch,
        tokens,
      },
    });
  } catch (e: any) {
    console.error("generateQRCodes error:", e);
    const msg = e?.message || "Bad request";
    if (isBatchBusyError(msg)) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

/* ===================== ADMIN BLOCK ===================== */

export const blockQRCode = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = blockQRSschema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing QR id" });

    const updated = await prisma.qRCode.update({
      where: { id },
      data: { status: QRStatus.BLOCKED, blockedAt: new Date() },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: updated.licenseeId,
      action: "BLOCKED",
      entityType: "QRCode",
      entityId: updated.id,
      details: { reason: parsed.data.reason || null, batchId: updated.batchId || null },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { id: updated.id } });
  } catch (e: any) {
    console.error("blockQRCode error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const blockBatch = async (req: AuthRequest, res: Response) => {
  try {
    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = blockQRSschema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const id = String(req.params.id || "").trim();
    if (!id) return res.status(400).json({ success: false, error: "Missing batch id" });

    const batch = await prisma.batch.findUnique({
      where: { id },
      select: { id: true, licenseeId: true },
    });
    if (!batch) return res.status(404).json({ success: false, error: "Batch not found" });

    const updated = await prisma.qRCode.updateMany({
      where: { batchId: batch.id },
      data: { status: QRStatus.BLOCKED, blockedAt: new Date() },
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: batch.licenseeId,
      action: "BLOCKED",
      entityType: "Batch",
      entityId: batch.id,
      details: { blockedCodes: updated.count, reason: parsed.data.reason || null },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: { batchId: batch.id, blocked: updated.count } });
  } catch (e: any) {
    console.error("blockBatch error:", e);
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

    const allocatableStatuses = [QRStatus.DORMANT, QRStatus.ACTIVE, QRStatus.ALLOCATED];

    const remainingGroups = await prisma.qRCode.groupBy({
      by: ["batchId"],
      where: {
        batchId: { in: batchIds },
        status: { in: allocatableStatuses },
      },
      _count: { _all: true },
      _min: { code: true },
      _max: { code: true },
    });

    const allocatedGroups = await prisma.qRCode.groupBy({
      by: ["batchId"],
      where: {
        batchId: { in: batchIds },
        status: { in: allocatableStatuses },
      },
      _count: { _all: true },
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

    const allocatedMap = new Map<string, number>();
    for (const g of allocatedGroups) {
      if (!g.batchId) continue;
      allocatedMap.set(g.batchId, g._count?._all || 0);
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
    const userId = req.user?.userId;

    const licenseeId: string | undefined =
      role === UserRole.SUPER_ADMIN
        ? ((req.query.licenseeId as string | undefined) || undefined)
        : (req.user?.licenseeId ?? undefined) || undefined;

    if (role === UserRole.MANUFACTURER && userId) {
      const where: any = {
        batch: { manufacturerId: userId },
      };
      if (licenseeId) where.licenseeId = licenseeId;

      const grouped = await prisma.qRCode.groupBy({
        by: ["status"],
        where,
        _count: true,
      });
      const total = await prisma.qRCode.count({ where });

      return res.json({
        success: true,
        data: {
          total,
          byStatus: grouped.reduce((acc, s) => {
            acc[s.status] = s._count;
            return acc;
          }, {} as Record<string, number>),
        },
      });
    }

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

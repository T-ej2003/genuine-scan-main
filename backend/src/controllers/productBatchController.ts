import { Response } from "express";
import { z } from "zod";
import { QRStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { generateQRCode, makeProductCode, markProductBatchAsPrinted } from "../services/qrService";

const createProductBatchSchema = z
  .object({
    parentBatchId: z.string().uuid(),
    productName: z.string().trim().min(2).max(140),
    productCode: z.string().trim().min(2).max(40).optional(), // optional override, else generated
    description: z.string().trim().max(500).optional(),

    // QR sub-range inside parent batch (numbers are based on licensee prefix)
    startNumber: z.number().int().positive(),
    endNumber: z.number().int().positive(),

    // serial allocation for product items
    serialStart: z.number().int().positive(),
    serialEnd: z.number().int().positive(),
    serialFormat: z.string().trim().max(80).optional(), // default "{LIC}-{PROD}-{NNNNNN}"
  })
  .refine((d) => d.endNumber >= d.startNumber, { message: "endNumber must be >= startNumber" })
  .refine((d) => d.serialEnd >= d.serialStart, { message: "serialEnd must be >= serialStart" });

const assignManufacturerSchema = z.object({
  manufacturerId: z.string().uuid(),
});

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

export const createProductBatch = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = createProductBatchSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const licenseeId = req.user?.licenseeId;
    if (!licenseeId) return res.status(403).json({ success: false, error: "No licensee association" });

    const lic = await prisma.licensee.findUnique({
      where: { id: licenseeId },
      select: { id: true, prefix: true },
    });
    if (!lic) return res.status(404).json({ success: false, error: "Licensee not found" });

    const {
      parentBatchId,
      productName,
      productCode: productCodeInput,
      description,
      startNumber,
      endNumber,
      serialStart,
      serialEnd,
      serialFormat,
    } = parsed.data;

    const parent = await prisma.batch.findUnique({
      where: { id: parentBatchId },
      select: {
        id: true,
        licenseeId: true,
        startCode: true,
        endCode: true,
        printedAt: true,
        manufacturerId: true,
      },
    });
    if (!parent) return res.status(404).json({ success: false, error: "Parent batch not found" });
    if (parent.licenseeId !== licenseeId) return res.status(403).json({ success: false, error: "Access denied" });

    // ✅ recommended: to keep logic clean, a received batch used for product splitting must NOT be assigned/printed
    if (parent.printedAt) {
      return res.status(400).json({ success: false, error: "Parent batch already printed; cannot split" });
    }
    if (parent.manufacturerId) {
      return res.status(400).json({
        success: false,
        error: "Parent batch is already assigned to a manufacturer. Keep parent batches unassigned and assign manufacturers on ProductBatches.",
      });
    }

    const startCode = generateQRCode(lic.prefix, startNumber);
    const endCode = generateQRCode(lic.prefix, endNumber);

    // Ensure requested QR range sits inside parent range
    if (startCode < parent.startCode || endCode > parent.endCode) {
      return res.status(400).json({
        success: false,
        error: "Requested range is outside the parent batch range",
      });
    }

    const finalProductCode = makeProductCode(productCodeInput || productName);

    const expectedQty = endNumber - startNumber + 1;

    const created = await prisma.$transaction(async (tx) => {
      // Ensure those QR codes exist + belong to parentBatch + not already used by another productBatch
      const availableCount = await tx.qRCode.count({
        where: {
          licenseeId,
          batchId: parentBatchId,
          productBatchId: null,
          code: { gte: startCode, lte: endCode },
          status: QRStatus.ALLOCATED,
        },
      });

      if (availableCount !== expectedQty) {
        throw new Error(
          `Range not fully available. Expected ${expectedQty} codes, but only ${availableCount} are available (already used or missing).`
        );
      }

      const pb = await tx.productBatch.create({
        data: {
          licenseeId,
          parentBatchId,
          productName: productName.trim(),
          productCode: finalProductCode,
          description: description?.trim() ? description.trim() : null,
          serialStart,
          serialEnd,
          serialFormat: (serialFormat?.trim() || "{LIC}-{PROD}-{NNNNNN}").slice(0, 80),
          startCode,
          endCode,
          totalCodes: expectedQty,
        },
      });

      const updated = await tx.qRCode.updateMany({
        where: {
          licenseeId,
          batchId: parentBatchId,
          productBatchId: null,
          code: { gte: startCode, lte: endCode },
          status: QRStatus.ALLOCATED,
        },
        data: { productBatchId: pb.id },
      });

      if (updated.count !== expectedQty) {
        throw new Error(`Concurrency issue: assigned ${updated.count}/${expectedQty}. Please retry.`);
      }

      return pb;
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId,
      action: "CREATE_PRODUCT_BATCH",
      entityType: "ProductBatch",
      entityId: created.id,
      details: {
        parentBatchId,
        productName: created.productName,
        productCode: created.productCode,
        startCode: created.startCode,
        endCode: created.endCode,
        serialStart,
        serialEnd,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: created });
  } catch (e: any) {
    const msg = e?.message || "Internal server error";
    // Prisma unique productCode per parent
    if (String(msg).includes("Unique constraint")) {
      return res.status(409).json({ success: false, error: "Product code already exists in this parent batch" });
    }
    console.error("createProductBatch error:", e);
    return res.status(400).json({ success: false, error: msg });
  }
};

export const getProductBatches = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const where: any = {};

    if (req.user?.role !== UserRole.SUPER_ADMIN) {
      if (!req.user?.licenseeId) return res.status(403).json({ success: false, error: "No licensee association" });
      where.licenseeId = req.user.licenseeId;
    } else {
      const qLicenseeId = (req.query.licenseeId as string | undefined) || undefined;
      if (qLicenseeId) where.licenseeId = qLicenseeId;
    }

    if (req.user?.role === UserRole.MANUFACTURER) {
      where.manufacturerId = req.user.userId;
    }

    const rows = await prisma.productBatch.findMany({
      where,
      orderBy: { createdAt: "desc" },
      include: {
        licensee: { select: { id: true, name: true, prefix: true } },
        parentBatch: { select: { id: true, name: true, startCode: true, endCode: true } },
        manufacturer: { select: { id: true, name: true, email: true } },
        _count: { select: { qrCodes: true } },
      },
    });

    return res.json({ success: true, data: rows });
  } catch (e) {
    console.error("getProductBatches error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const assignProductBatchManufacturer = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = assignManufacturerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const licenseeId = req.user?.licenseeId;
    if (!licenseeId) return res.status(403).json({ success: false, error: "No licensee association" });

    const id = req.params.id;

    const pb = await prisma.productBatch.findUnique({
      where: { id },
      select: { id: true, licenseeId: true, printedAt: true },
    });
    if (!pb) return res.status(404).json({ success: false, error: "Product batch not found" });
    if (pb.licenseeId !== licenseeId) return res.status(403).json({ success: false, error: "Access denied" });
    if (pb.printedAt) return res.status(400).json({ success: false, error: "Already printed; cannot reassign" });

    const m = await prisma.user.findFirst({
      where: {
        id: parsed.data.manufacturerId,
        role: UserRole.MANUFACTURER,
        licenseeId,
        isActive: true,
      },
      select: { id: true },
    });
    if (!m) return res.status(404).json({ success: false, error: "Manufacturer invalid" });

    const updated = await prisma.productBatch.update({
      where: { id },
      data: { manufacturerId: m.id },
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId,
      action: "ASSIGN_PRODUCT_BATCH_MANUFACTURER",
      entityType: "ProductBatch",
      entityId: id,
      details: { manufacturerId: m.id },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e) {
    console.error("assignProductBatchManufacturer error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const confirmProductBatchPrint = async (req: AuthRequest, res: Response) => {
  try {
    const userId = req.user?.userId;
    if (!userId) return res.status(401).json({ success: false, error: "Not authenticated" });

    const id = req.params.id;

    const pb = await prisma.productBatch.findFirst({
      where: { id, manufacturerId: userId },
      select: { id: true },
    });
    if (!pb) return res.status(404).json({ success: false, error: "Product batch not found" });

    const count = await markProductBatchAsPrinted(id, userId);

    return res.json({ success: true, data: { count } });
  } catch (e: any) {
    return res.status(400).json({ success: false, error: e.message || "Bad request" });
  }
};


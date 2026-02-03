import { Response } from "express";
import { z } from "zod";
import { QrAllocationRequestStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { allocateQrRange } from "../services/qrAllocationService";
import { parseQRCode } from "../services/qrService";

const createRequestSchema = z
  .object({
    quantity: z.number().int().positive().max(5_000_000).optional(),
    startNumber: z.number().int().positive().optional(),
    endNumber: z.number().int().positive().optional(),
    note: z.string().trim().max(500).optional(),
  })
  .refine((d) => d.quantity || (d.startNumber && d.endNumber), {
    message: "Provide quantity or a start/end range",
  })
  .refine((d) => (d.startNumber && d.endNumber ? d.endNumber >= d.startNumber : true), {
    message: "End number must be >= start number",
  });

const approveSchema = z
  .object({
    startNumber: z.number().int().positive().optional(),
    endNumber: z.number().int().positive().optional(),
    decisionNote: z.string().trim().max(500).optional(),
  })
  .refine((d) => (d.startNumber && d.endNumber ? d.endNumber >= d.startNumber : true), {
    message: "End number must be >= start number",
  });

const rejectSchema = z.object({
  decisionNote: z.string().trim().max(500).optional(),
});

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

export const createQrAllocationRequest = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (auth.role !== UserRole.LICENSEE_ADMIN && auth.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const licenseeId =
      auth.role === UserRole.SUPER_ADMIN
        ? (req.body?.licenseeId as string | undefined)
        : req.user?.licenseeId;

    if (!licenseeId) {
      return res.status(403).json({ success: false, error: "No licensee association" });
    }

    const quantity =
      parsed.data.quantity ??
      (parsed.data.startNumber && parsed.data.endNumber
        ? parsed.data.endNumber - parsed.data.startNumber + 1
        : null);

    const created = await prisma.qrAllocationRequest.create({
      data: {
        licenseeId,
        requestedByUserId: auth.userId,
        quantity: quantity || null,
        startNumber: parsed.data.startNumber ?? null,
        endNumber: parsed.data.endNumber ?? null,
        note: parsed.data.note?.trim() || null,
        status: QrAllocationRequestStatus.PENDING,
      },
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId,
      action: "CREATE_QR_ALLOCATION_REQUEST",
      entityType: "QrAllocationRequest",
      entityId: created.id,
      details: {
        quantity: created.quantity,
        startNumber: created.startNumber,
        endNumber: created.endNumber,
      },
      ipAddress: req.ip,
    });

    return res.status(201).json({ success: true, data: created });
  } catch (e: any) {
    console.error("createQrAllocationRequest error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const getQrAllocationRequests = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (auth.role !== UserRole.LICENSEE_ADMIN && auth.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const status = (req.query.status as QrAllocationRequestStatus | undefined) || undefined;
    const qLicenseeId = (req.query.licenseeId as string | undefined) || undefined;

    const where: any = {};
    if (status) where.status = status;

    if (auth.role === UserRole.SUPER_ADMIN) {
      if (qLicenseeId) where.licenseeId = qLicenseeId;
    } else {
      if (!req.user?.licenseeId) {
        return res.status(403).json({ success: false, error: "No licensee association" });
      }
      where.licenseeId = req.user.licenseeId;
    }

    const rows = await prisma.qrAllocationRequest.findMany({
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
  } catch (e) {
    console.error("getQrAllocationRequests error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const approveQrAllocationRequest = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (auth.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = approveSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const id = req.params.id;
    const requestRow = await prisma.qrAllocationRequest.findUnique({
      where: { id },
      include: { licensee: { select: { id: true, prefix: true } } },
    });
    if (!requestRow) return res.status(404).json({ success: false, error: "Request not found" });
    if (requestRow.status !== QrAllocationRequestStatus.PENDING) {
      return res.status(409).json({ success: false, error: "Request already processed" });
    }

    let startNumber: number | null = requestRow.startNumber ?? null;
    let endNumber: number | null = requestRow.endNumber ?? null;

    if (startNumber && endNumber) {
      if (parsed.data.startNumber || parsed.data.endNumber) {
        if (parsed.data.startNumber !== startNumber || parsed.data.endNumber !== endNumber) {
          return res.status(400).json({
            success: false,
            error: "Request already has a range; approve using the same range or leave empty.",
          });
        }
      }
    } else if (parsed.data.startNumber && parsed.data.endNumber) {
      startNumber = parsed.data.startNumber;
      endNumber = parsed.data.endNumber;
    }

    if (!startNumber || !endNumber) {
      const quantity = requestRow.quantity;
      if (!quantity || quantity <= 0) {
        return res.status(400).json({ success: false, error: "Quantity missing; provide a range to approve." });
      }

      const last = await prisma.qRCode.findFirst({
        where: { licenseeId: requestRow.licenseeId },
        orderBy: { code: "desc" },
        select: { code: true },
      });

      let nextNumber = 1;
      if (last?.code) {
        const parsedCode = parseQRCode(last.code);
        if (parsedCode) nextNumber = parsedCode.number + 1;
      }

      startNumber = nextNumber;
      endNumber = nextNumber + quantity - 1;
    }

    if (!startNumber || !endNumber) {
      return res.status(400).json({ success: false, error: "Failed to determine allocation range" });
    }

    const quantityFinal = endNumber - startNumber + 1;

    const result = await prisma.$transaction(async (tx) => {
      const alloc = await allocateQrRange({
        licenseeId: requestRow.licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "REQUEST_APPROVAL",
        requestId: requestRow.id,
        createReceivedBatch: true,
        tx,
      });

      const updated = await tx.qrAllocationRequest.update({
        where: { id: requestRow.id },
        data: {
          status: QrAllocationRequestStatus.APPROVED,
          approvedByUserId: auth.userId,
          approvedAt: new Date(),
          decisionNote: parsed.data.decisionNote?.trim() || null,
          startNumber,
          endNumber,
          quantity: quantityFinal,
        },
      });

      return { alloc, updated };
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId: requestRow.licenseeId,
      action: "APPROVE_QR_ALLOCATION_REQUEST",
      entityType: "QrAllocationRequest",
      entityId: requestRow.id,
      details: {
        startNumber,
        endNumber,
        quantity: quantityFinal,
        rangeId: result.alloc.range.id,
        receivedBatchId: result.alloc.receivedBatch?.id || null,
      },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: result.updated });
  } catch (e: any) {
    console.error("approveQrAllocationRequest error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

export const rejectQrAllocationRequest = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (auth.role !== UserRole.SUPER_ADMIN) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = rejectSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const id = req.params.id;
    const requestRow = await prisma.qrAllocationRequest.findUnique({ where: { id } });
    if (!requestRow) return res.status(404).json({ success: false, error: "Request not found" });
    if (requestRow.status !== QrAllocationRequestStatus.PENDING) {
      return res.status(409).json({ success: false, error: "Request already processed" });
    }

    const updated = await prisma.qrAllocationRequest.update({
      where: { id },
      data: {
        status: QrAllocationRequestStatus.REJECTED,
        rejectedByUserId: auth.userId,
        rejectedAt: new Date(),
        decisionNote: parsed.data.decisionNote?.trim() || null,
      },
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId: requestRow.licenseeId,
      action: "REJECT_QR_ALLOCATION_REQUEST",
      entityType: "QrAllocationRequest",
      entityId: id,
      details: { decisionNote: parsed.data.decisionNote?.trim() || null },
      ipAddress: req.ip,
    });

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    console.error("rejectQrAllocationRequest error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

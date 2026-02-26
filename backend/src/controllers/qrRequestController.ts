import { Response } from "express";
import { z } from "zod";
import { NotificationAudience, NotificationChannel, QrAllocationRequestStatus, UserRole } from "@prisma/client";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { createAuditLog } from "../services/auditService";
import { allocateQrRange, getNextLicenseeQrNumber, lockLicenseeAllocation } from "../services/qrAllocationService";
import { createRoleNotifications, createUserNotification } from "../services/notificationService";

const createRequestSchema = z
  .object({
    quantity: z.number().int().positive().max(5_000_000),
    batchName: z.string().trim().min(2).max(120).optional(),
    note: z.string().trim().max(500).optional(),
  });

const approveSchema = z.object({
  decisionNote: z.string().trim().max(500).optional(),
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

    if (
      auth.role !== UserRole.LICENSEE_ADMIN &&
      auth.role !== UserRole.ORG_ADMIN &&
      auth.role !== UserRole.SUPER_ADMIN &&
      auth.role !== UserRole.PLATFORM_SUPER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = createRequestSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0].message });
    }

    const licenseeId =
      auth.role === UserRole.SUPER_ADMIN || auth.role === UserRole.PLATFORM_SUPER_ADMIN
        ? (req.body?.licenseeId as string | undefined)
        : req.user?.licenseeId;

    if (!licenseeId) {
      return res.status(403).json({ success: false, error: "No licensee association" });
    }

    const created = await prisma.qrAllocationRequest.create({
      data: {
        licenseeId,
        requestedByUserId: auth.userId,
        quantity: parsed.data.quantity,
        startNumber: null,
        endNumber: null,
        batchName: parsed.data.batchName?.trim() || null,
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
        batchName: created.batchName || null,
      },
      ipAddress: req.ip,
    });

    await Promise.all([
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_created",
        title: "New QR inventory request",
        body: `Request ${created.id.slice(0, 8)} for ${created.quantity || 0} codes is pending review.`,
        data: {
          requestId: created.id,
          licenseeId,
          quantity: created.quantity,
          batchName: created.batchName || null,
          status: created.status,
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
      createRoleNotifications({
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId,
        type: "qr_request_created",
        title: "QR inventory request submitted",
        body: `Request ${created.id.slice(0, 8)} was submitted for ${created.quantity || 0} codes.`,
        data: {
          requestId: created.id,
          licenseeId,
          quantity: created.quantity,
          batchName: created.batchName || null,
          status: created.status,
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
    ]);

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

    if (
      auth.role !== UserRole.LICENSEE_ADMIN &&
      auth.role !== UserRole.ORG_ADMIN &&
      auth.role !== UserRole.SUPER_ADMIN &&
      auth.role !== UserRole.PLATFORM_SUPER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const status = (req.query.status as QrAllocationRequestStatus | undefined) || undefined;
    const qLicenseeId = (req.query.licenseeId as string | undefined) || undefined;

    const where: any = {};
    if (status) where.status = status;

    if (auth.role === UserRole.SUPER_ADMIN || auth.role === UserRole.PLATFORM_SUPER_ADMIN) {
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
    if (auth.role !== UserRole.SUPER_ADMIN && auth.role !== UserRole.PLATFORM_SUPER_ADMIN) {
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

    // Backward compatibility: derive quantity for old range-based rows.
    const quantityRequested =
      requestRow.quantity && requestRow.quantity > 0
        ? requestRow.quantity
        : requestRow.startNumber && requestRow.endNumber
          ? requestRow.endNumber - requestRow.startNumber + 1
          : null;
    if (!quantityRequested || quantityRequested <= 0) {
      return res.status(400).json({ success: false, error: "Request quantity is missing or invalid." });
    }

    const result = await prisma.$transaction(async (tx) => {
      await lockLicenseeAllocation(tx, requestRow.licenseeId);
      const startNumber = await getNextLicenseeQrNumber(tx, requestRow.licenseeId);
      const endNumber = startNumber + quantityRequested - 1;

      const alloc = await allocateQrRange({
        licenseeId: requestRow.licenseeId,
        startNumber,
        endNumber,
        createdByUserId: auth.userId,
        source: "REQUEST_APPROVAL",
        requestId: requestRow.id,
        createReceivedBatch: true,
        receivedBatchName: requestRow.batchName || null,
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
          quantity: quantityRequested,
        },
      });

      return { alloc, updated, startNumber, endNumber };
    });

    await createAuditLog({
      userId: auth.userId,
      licenseeId: requestRow.licenseeId,
      action: "APPROVE_QR_ALLOCATION_REQUEST",
      entityType: "QrAllocationRequest",
      entityId: requestRow.id,
      details: {
        startNumber: result.startNumber,
        endNumber: result.endNumber,
        quantity: quantityRequested,
        batchName: requestRow.batchName || null,
        rangeId: result.alloc.range.id,
        receivedBatchId: result.alloc.receivedBatch?.id || null,
        receivedBatchName: result.alloc.receivedBatch?.name || null,
      },
      ipAddress: req.ip,
    });

    await Promise.all([
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_approved",
        title: "QR request approved",
        body: `Request ${requestRow.id.slice(0, 8)} approved for ${quantityRequested} codes.`,
        data: {
          requestId: requestRow.id,
          licenseeId: requestRow.licenseeId,
          quantity: quantityRequested,
          batchName: requestRow.batchName || null,
          status: "APPROVED",
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
      createRoleNotifications({
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_approved",
        title: "QR request approved",
        body: `Request ${requestRow.id.slice(0, 8)} is approved and inventory has been allocated.`,
        data: {
          requestId: requestRow.id,
          licenseeId: requestRow.licenseeId,
          quantity: quantityRequested,
          batchName: requestRow.batchName || null,
          status: "APPROVED",
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
      createUserNotification({
        userId: requestRow.requestedByUserId,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_approved",
        title: "Your QR request was approved",
        body: `Request ${requestRow.id.slice(0, 8)} was approved for ${quantityRequested} codes.`,
        data: {
          requestId: requestRow.id,
          licenseeId: requestRow.licenseeId,
          quantity: quantityRequested,
          batchName: requestRow.batchName || null,
          status: "APPROVED",
          targetRoute: "/qr-requests",
        },
        channel: NotificationChannel.WEB,
      }),
    ]);

    return res.json({ success: true, data: result.updated });
  } catch (e: any) {
    console.error("approveQrAllocationRequest error:", e);
    const msg = e?.message || "Bad request";
    if (String(msg).includes("BATCH_BUSY") || String(msg).toLowerCase().includes("concurrency issue")) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return res.status(400).json({ success: false, error: msg });
  }
};

export const rejectQrAllocationRequest = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (auth.role !== UserRole.SUPER_ADMIN && auth.role !== UserRole.PLATFORM_SUPER_ADMIN) {
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

    await Promise.all([
      createRoleNotifications({
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_rejected",
        title: "QR request rejected",
        body: `Request ${id.slice(0, 8)} was rejected.`,
        data: {
          requestId: id,
          licenseeId: requestRow.licenseeId,
          status: "REJECTED",
          decisionNote: parsed.data.decisionNote?.trim() || null,
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
      createRoleNotifications({
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_rejected",
        title: "QR request rejected",
        body: `Request ${id.slice(0, 8)} was rejected. Review decision note and resubmit if needed.`,
        data: {
          requestId: id,
          licenseeId: requestRow.licenseeId,
          status: "REJECTED",
          decisionNote: parsed.data.decisionNote?.trim() || null,
          targetRoute: "/qr-requests",
        },
        channels: [NotificationChannel.WEB],
      }),
      createUserNotification({
        userId: requestRow.requestedByUserId,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_rejected",
        title: "Your QR request was rejected",
        body: `Request ${id.slice(0, 8)} was rejected. Review notes and update your request.`,
        data: {
          requestId: id,
          licenseeId: requestRow.licenseeId,
          status: "REJECTED",
          decisionNote: parsed.data.decisionNote?.trim() || null,
          targetRoute: "/qr-requests",
        },
        channel: NotificationChannel.WEB,
      }),
    ]);

    return res.json({ success: true, data: updated });
  } catch (e: any) {
    console.error("rejectQrAllocationRequest error:", e);
    return res.status(400).json({ success: false, error: e?.message || "Bad request" });
  }
};

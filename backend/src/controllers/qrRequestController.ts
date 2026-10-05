import { Response } from "express";
import { z } from "zod";
import { NotificationAudience, NotificationChannel, QrAllocationRequestStatus, UserRole } from "@prisma/client";
import { AuthRequest } from "../middleware/auth";
import { createRoleNotifications, createUserNotification } from "../services/notificationService";
import { approveAllocationRequest, createAllocationRequest, listAllocationRequests, rejectAllocationRequest, isQrBoundaryDenied } from "../rls-waves/session-c/c01/qrSystemRepository";
import { hashIp } from "../utils/security";
import { b03BoundaryForRequest } from "../rls-waves/session-b/b03/requestBoundary";

const createRequestSchema = z
  .object({
    licenseeId: z.string().uuid().optional(),
    quantity: z.number().int().positive().max(200_000),
    batchName: z.string().trim().min(2).max(120),
    note: z.string().trim().max(500).optional(),
  })
  .strict();

const decisionNoteSchema = z.string().trim().max(500).refine(value => !value.includes("\u0000"), "Invalid decision note").optional();
const approveSchema = z.object({
  decisionNote: decisionNoteSchema,
}).strict();

const rejectSchema = z.object({
  decisionNote: decisionNoteSchema,
}).strict();

const requestIdParamSchema = z.object({
  id: z.string().uuid("Invalid request id"),
}).strict();

const ensureAuth = (req: AuthRequest) => {
  const role = req.user?.role;
  const userId = req.user?.userId;
  if (!role || !userId) return null;
  return { role, userId };
};

const boundary = (req: AuthRequest) => ({
  capability: req.databaseSessionCapability || "",
  requestId: (req as AuthRequest & { requestId?: string }).requestId || "",
});
const requestFailure = (res: Response, error: unknown) => {
  if (isQrBoundaryDenied(error)) return res.status(403).json({ success: false, error: "Access denied" });
  const message = String((error as any)?.meta?.message || (error as any)?.message || "");
  if (message.includes("QR_REQUEST_ALREADY_PROCESSED")) return res.status(409).json({ success: false, error: "Request already processed" });
  if (message.includes("QR_INVALID_INPUT")) return res.status(400).json({ success: false, error: "Invalid request" });
  return res.status(500).json({ success: false, error: "Unable to process QR request" });
};
const notifyAfterCommit = async (notifications: Promise<unknown>[]) => {
  const results = await Promise.allSettled(notifications);
  const failed = results.filter(result => result.status === "rejected").length;
  if (failed) console.warn("[qr-allocation] committed operation has undelivered notifications", { failed });
};

export const createQrAllocationRequest = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (
      auth.role !== UserRole.LICENSEE_ADMIN &&
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
        ? parsed.data.licenseeId
        : req.user?.licenseeId;

    if (!licenseeId) {
      return res.status(403).json({ success: false, error: "No licensee association" });
    }

    const created = await createAllocationRequest({ ...boundary(req), ...parsed.data,
      licenseeId: parsed.data.licenseeId || licenseeId, ipHash: hashIp(req.ip) });

    await notifyAfterCommit([
      createRoleNotifications({
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_created",
        title: "New QR inventory request",
        body: `${created.quantity || 0} QR codes requested${created.batchName ? ` for batch "${created.batchName}"` : ""}. Pending review.`,
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
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId,
        type: "qr_request_created",
        title: "QR inventory request submitted",
        body: `Your request for ${created.quantity || 0} QR codes is in review${created.batchName ? ` (${created.batchName})` : ""}.`,
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
    return requestFailure(res, e);
  }
};

export const getQrAllocationRequests = async (req: AuthRequest, res: Response) => {
  try {
    const auth = ensureAuth(req);
    if (!auth) return res.status(401).json({ success: false, error: "Not authenticated" });

    if (
      auth.role !== UserRole.LICENSEE_ADMIN &&
      auth.role !== UserRole.SUPER_ADMIN &&
      auth.role !== UserRole.PLATFORM_SUPER_ADMIN
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const parsed = z.object({
      status: z.nativeEnum(QrAllocationRequestStatus).optional(),
      licenseeId: z.string().uuid().optional(),
      limit: z.coerce.number().int().min(1).max(200).default(100),
      offset: z.coerce.number().int().min(0).max(10000).default(0),
    }).strict().safeParse(req.query);
    if (!parsed.success) return res.status(400).json({ success: false, error: "Invalid request filters" });
    const rows = await listAllocationRequests({ ...boundary(req), ...parsed.data });

    return res.json({ success: true, data: rows });
  } catch (e) {
    console.error("getQrAllocationRequests error:", e);
    return requestFailure(res, e);
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

    const paramsParsed = requestIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid request id" });
    }
    const id = paramsParsed.data.id;
    const result = await approveAllocationRequest<{
      request: {
        id: string;
        licenseeId: string;
        requestedByUserId: string;
        quantity: number;
        batchName: string | null;
        status: QrAllocationRequestStatus;
      };
    }>({
      capability: String(req.databaseSessionCapability || ""),
      requestId: String((req as AuthRequest & { requestId?: string }).requestId || req.get("x-request-id") || "").trim(),
      allocationRequestId: id,
      decisionNote: parsed.data.decisionNote,
    });
    const requestRow = result.request;
    const quantityRequested = requestRow.quantity;

    await notifyAfterCommit([
      createRoleNotifications({
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_approved",
        title: "QR request approved",
        body: `${quantityRequested} QR codes approved${requestRow.batchName ? ` for "${requestRow.batchName}"` : ""}.`,
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
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_approved",
        title: "QR request approved",
        body: `Inventory was allocated for ${quantityRequested} QR codes${requestRow.batchName ? ` (${requestRow.batchName})` : ""}.`,
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
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        userId: requestRow.requestedByUserId,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_approved",
        title: "Your QR request was approved",
        body: `${quantityRequested} QR codes were approved${requestRow.batchName ? ` for "${requestRow.batchName}"` : ""}.`,
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

    return res.json({ success: true, data: requestRow });
  } catch (e: any) {
    console.error("approveQrAllocationRequest error:", e);
    const msg = e?.message || "Bad request";
    if (String(msg).includes("BATCH_BUSY") || String(msg).toLowerCase().includes("concurrency issue")) {
      return res.status(409).json({ success: false, error: "Please retry — batch busy." });
    }
    return requestFailure(res, e);
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

    const paramsParsed = requestIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) {
      return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Invalid request id" });
    }
    const id = paramsParsed.data.id;
    const updated = await rejectAllocationRequest({ ...boundary(req), allocationRequestId: id, ...parsed.data, ipHash: hashIp(req.ip) });
    const requestRow = updated;

    await notifyAfterCommit([
      createRoleNotifications({
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.SUPER_ADMIN,
        type: "qr_request_rejected",
        title: "QR request rejected",
        body: `A QR inventory request was rejected.`,
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
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        audience: NotificationAudience.LICENSEE_ADMIN,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_rejected",
        title: "QR request rejected",
        body: "A QR inventory request was rejected. Review the decision note and resubmit if needed.",
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
        databaseBoundary: b03BoundaryForRequest(req, "notification-write"),
        userId: requestRow.requestedByUserId,
        licenseeId: requestRow.licenseeId,
        type: "qr_request_rejected",
        title: "Your QR request was rejected",
        body: "Your QR inventory request was rejected. Review notes and resubmit when ready.",
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
    return requestFailure(res, e);
  }
};

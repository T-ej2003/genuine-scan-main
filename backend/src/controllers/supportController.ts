import { IncidentActorType, SupportTicketStatus, UserRole } from "@prisma/client";
import { Request, Response } from "express";
import { z } from "zod";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { addSupportTicketMessage, ensureIncidentWorkflowArtifacts, ticketSlaSnapshot } from "../services/supportWorkflowService";
import { createAuditLog } from "../services/auditService";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";

const toInt = (value: unknown, fallback: number, min: number, max: number) => {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
};

const listSchema = z.object({
  status: z.nativeEnum(SupportTicketStatus).optional(),
  priority: z.enum(["P1", "P2", "P3", "P4"]).optional(),
  licenseeId: z.string().uuid().optional(),
  search: z.string().trim().max(120).optional(),
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(2000).optional(),
}).strict();

const patchSchema = z.object({
  status: z.nativeEnum(SupportTicketStatus).optional(),
  assignedToUserId: z.string().uuid().nullable().optional(),
}).strict();

const messageSchema = z.object({
  message: z.string().trim().min(2).max(4000),
  isInternal: z.boolean().optional().default(false),
}).strict();

const publicTrackParamsSchema = z.object({
  reference: z.string().trim().min(4).max(64).regex(/^[a-z0-9_-]+$/i, "Invalid reference format"),
}).strict();

const supportTicketIdParamSchema = z.object({
  id: z.string().uuid("Invalid support ticket id"),
}).strict();

const publicTrackQuerySchema = z.object({
  email: z.string().trim().email().max(160).optional(),
}).strict();

const isPlatform = (role: UserRole) => role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN;

export const listSupportTickets = async (req: AuthRequest, res: Response) => {
  const fallbackLimit = toInt(req.query.limit, 50, 1, 200);
  const fallbackOffset = toInt(req.query.offset, 0, 0, 2000);
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const parsed = listSchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }
    const limit = parsed.data.limit ?? fallbackLimit;
    const offset = parsed.data.offset ?? fallbackOffset;

    const where: any = {};
    if (parsed.data.status) where.status = parsed.data.status;
    if (parsed.data.priority) where.priority = parsed.data.priority;

    if (!isPlatform(req.user.role)) {
      where.licenseeId = req.user.licenseeId || "__none__";
    } else if (parsed.data.licenseeId) {
      where.licenseeId = parsed.data.licenseeId;
    }

    if (parsed.data.search) {
      const q = parsed.data.search;
      where.OR = [
        { referenceCode: { contains: q, mode: "insensitive" } },
        { subject: { contains: q, mode: "insensitive" } },
        { incident: { qrCodeValue: { contains: q.toUpperCase(), mode: "insensitive" } } },
      ];
    }

    const [tickets, total] = await Promise.all([
      prisma.supportTicket.findMany({
        where,
        orderBy: [{ createdAt: "desc" }],
        take: limit,
        skip: offset,
        include: {
          incident: {
            select: {
              id: true,
              qrCodeValue: true,
              status: true,
              severity: true,
              slaDueAt: true,
            },
          },
          assignedToUser: { select: { id: true, name: true, email: true } },
        },
      }),
      prisma.supportTicket.count({ where }),
    ]);

    return res.json({
      success: true,
      data: {
        tickets: tickets.map((ticket) => ({
          ...ticket,
          sla: ticketSlaSnapshot(ticket.slaDueAt || ticket.incident?.slaDueAt || null),
        })),
        total,
        limit,
        offset,
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportticket", "supportticketmessage", "incidenthandoff"])) {
      warnStorageUnavailableOnce(
        "support-ticket-storage",
        "[support] Support workflow tables are unavailable. Returning empty support ticket list."
      );
      return res.json({
        success: true,
        data: {
          tickets: [],
          total: 0,
          limit: fallbackLimit,
          offset: fallbackOffset,
          storageUnavailable: true,
        },
      });
    }
    console.error("listSupportTickets error:", error);
    return res.status(500).json({ success: false, error: "Failed to load support tickets" });
  }
};

export const getSupportTicket = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = supportTicketIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Ticket ID is required" });
    const id = paramsParsed.data.id;

    const where: any = { id };
    if (!isPlatform(req.user.role)) {
      where.licenseeId = req.user.licenseeId || "__none__";
    }

    const ticket = await prisma.supportTicket.findFirst({
      where,
      include: {
        incident: {
          include: {
            handoff: true,
          },
        },
        assignedToUser: { select: { id: true, name: true, email: true } },
        messages: {
          orderBy: { createdAt: "asc" },
          include: {
            actorUser: {
              select: {
                id: true,
                name: true,
                email: true,
              },
            },
          },
        },
      },
    });

    if (!ticket) return res.status(404).json({ success: false, error: "Support ticket not found" });

    return res.json({
      success: true,
      data: {
        ...ticket,
        sla: ticketSlaSnapshot(ticket.slaDueAt || ticket.incident?.slaDueAt || null),
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportticket", "supportticketmessage", "incidenthandoff"])) {
      warnStorageUnavailableOnce(
        "support-ticket-detail-storage",
        "[support] Support workflow tables are unavailable. Ticket detail is not available."
      );
      return res.status(404).json({ success: false, error: "Support ticket storage unavailable" });
    }
    console.error("getSupportTicket error:", error);
    return res.status(500).json({ success: false, error: "Failed to load support ticket" });
  }
};

export const patchSupportTicket = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = supportTicketIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Ticket ID is required" });
    const id = paramsParsed.data.id;

    const parsed = patchSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid payload" });
    }

    const where: any = { id };
    if (!isPlatform(req.user.role)) {
      where.licenseeId = req.user.licenseeId || "__none__";
    }

    const existing = await prisma.supportTicket.findFirst({ where });
    if (!existing) return res.status(404).json({ success: false, error: "Support ticket not found" });

    const updateData: any = {};
    if (parsed.data.status && parsed.data.status !== existing.status) {
      updateData.status = parsed.data.status;
      if ((parsed.data.status === SupportTicketStatus.RESOLVED || parsed.data.status === SupportTicketStatus.CLOSED) && !existing.resolvedAt) {
        updateData.resolvedAt = new Date();
      }
      if (parsed.data.status !== SupportTicketStatus.RESOLVED && parsed.data.status !== SupportTicketStatus.CLOSED) {
        updateData.resolvedAt = null;
      }
    }

    if (parsed.data.assignedToUserId !== undefined && parsed.data.assignedToUserId !== existing.assignedToUserId) {
      updateData.assignedToUserId = parsed.data.assignedToUserId || null;
    }

    if (Object.keys(updateData).length === 0) {
      return res.json({ success: true, data: existing });
    }

    const updated = await prisma.supportTicket.update({
      where: { id: existing.id },
      data: updateData,
      include: {
        incident: true,
      },
    });

    if (parsed.data.status) {
      await ensureIncidentWorkflowArtifacts({
        incidentId: updated.incidentId,
        actorUserId: req.user.userId,
        actorType: IncidentActorType.ADMIN,
        emitEvents: true,
      });
    }

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: updated.licenseeId || undefined,
      action: "SUPPORT_TICKET_UPDATED",
      entityType: "SupportTicket",
      entityId: updated.id,
      ipAddress: req.ip,
      details: {
        status: updated.status,
        assignedToUserId: updated.assignedToUserId,
      },
    });

    return res.json({
      success: true,
      data: {
        ...updated,
        sla: ticketSlaSnapshot(updated.slaDueAt || updated.incident?.slaDueAt || null),
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportticket", "supportticketmessage", "incidenthandoff"])) {
      warnStorageUnavailableOnce(
        "support-ticket-update-storage",
        "[support] Support workflow tables are unavailable. Update operation skipped."
      );
      return res.status(503).json({ success: false, error: "Support ticket storage unavailable" });
    }
    console.error("patchSupportTicket error:", error);
    return res.status(500).json({ success: false, error: "Failed to update support ticket" });
  }
};

export const addSupportMessage = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const paramsParsed = supportTicketIdParamSchema.safeParse(req.params || {});
    if (!paramsParsed.success) return res.status(400).json({ success: false, error: paramsParsed.error.errors[0]?.message || "Ticket ID is required" });
    const id = paramsParsed.data.id;

    const parsed = messageSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid message" });
    }

    const where: any = { id };
    if (!isPlatform(req.user.role)) {
      where.licenseeId = req.user.licenseeId || "__none__";
    }

    const ticket = await prisma.supportTicket.findFirst({ where, select: { id: true, licenseeId: true } });
    if (!ticket) return res.status(404).json({ success: false, error: "Support ticket not found" });

    const message = await addSupportTicketMessage({
      ticketId: ticket.id,
      actorType: IncidentActorType.ADMIN,
      actorUserId: req.user.userId,
      message: parsed.data.message,
      isInternal: parsed.data.isInternal,
    });

    await createAuditLog({
      userId: req.user.userId,
      licenseeId: ticket.licenseeId || undefined,
      action: "SUPPORT_TICKET_MESSAGE_ADDED",
      entityType: "SupportTicket",
      entityId: ticket.id,
      ipAddress: req.ip,
      details: {
        isInternal: parsed.data.isInternal,
        messageLength: parsed.data.message.length,
      },
    });

    return res.status(201).json({ success: true, data: message });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportticket", "supportticketmessage"])) {
      warnStorageUnavailableOnce(
        "support-ticket-message-storage",
        "[support] Support message tables are unavailable. Add message operation skipped."
      );
      return res.status(503).json({ success: false, error: "Support ticket storage unavailable" });
    }
    console.error("addSupportMessage error:", error);
    return res.status(500).json({ success: false, error: "Failed to add support message" });
  }
};

export const trackSupportTicketPublic = async (req: Request, res: Response) => {
  try {
    const paramsParsed = publicTrackParamsSchema.safeParse(req.params || {});
    const queryParsed = publicTrackQuerySchema.safeParse(req.query || {});
    if (!paramsParsed.success || !queryParsed.success) {
      const firstError = paramsParsed.success ? queryParsed.error?.errors[0] : paramsParsed.error?.errors[0];
      return res.status(400).json({ success: false, error: firstError?.message || "Invalid tracking request" });
    }

    const reference = paramsParsed.data.reference.trim().toUpperCase();
    const contactEmail = String(queryParsed.data.email || "").trim().toLowerCase();

    const ticket = await prisma.supportTicket.findFirst({
      where: {
        referenceCode: reference,
      },
      include: {
        incident: {
          select: {
            id: true,
            status: true,
            severity: true,
            handoff: {
              select: {
                currentStage: true,
                slaDueAt: true,
              },
            },
          },
        },
      },
    });

    if (!ticket) return res.status(404).json({ success: false, error: "Support ticket not found" });

    if (ticket.customerEmail && contactEmail && ticket.customerEmail.toLowerCase() !== contactEmail) {
      return res.status(403).json({ success: false, error: "Email does not match ticket contact" });
    }

    return res.json({
      success: true,
      data: {
        referenceCode: ticket.referenceCode,
        status: ticket.status,
        priority: ticket.priority,
        updatedAt: ticket.updatedAt,
        incidentId: ticket.incidentId,
        handoffStage: ticket.incident?.handoff?.currentStage || null,
        sla: ticketSlaSnapshot(ticket.slaDueAt || ticket.incident?.handoff?.slaDueAt || null),
      },
    });
  } catch (error) {
    if (isPrismaMissingTableError(error, ["supportticket", "supportticketmessage", "incidenthandoff"])) {
      warnStorageUnavailableOnce(
        "support-ticket-track-storage",
        "[support] Support workflow tables are unavailable. Public tracking is temporarily unavailable."
      );
      return res.status(404).json({ success: false, error: "Support ticket tracking unavailable" });
    }
    console.error("trackSupportTicketPublic error:", error);
    return res.status(500).json({ success: false, error: "Failed to track support ticket" });
  }
};

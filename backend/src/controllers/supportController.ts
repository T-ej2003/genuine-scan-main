import { createHash, randomUUID } from "crypto";
import { SupportTicketStatus } from "@prisma/client";
import { Request, Response } from "express";
import { z } from "zod";

import { AuthRequest } from "../middleware/auth";
import { ticketSlaSnapshot } from "../services/supportWorkflowService";
import { isPrismaMissingTableError, warnStorageUnavailableOnce } from "../utils/prismaStorageGuard";
import {
  addSupportTicketMessage as addSupportTicketMessageBoundary,
  getSupportTicket as getSupportTicketBoundary,
  listSupportTickets as listSupportTicketsBoundary,
  updateSupportTicket as updateSupportTicketBoundary,
} from "../rls-waves/session-b/b03/repositoryFunctions";
import { b03BoundaryForRequest } from "../rls-waves/session-b/b03/requestBoundary";
import { trackSupportStatus } from "../rls-waves/session-b/b02/publicBoundaryRepository";
import { getB01PreAuthPrisma } from "../rls-waves/session-b/b01/runtimeClients";

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

const publicTrackQuerySchema = z.object({
  email: z.string().trim().email().max(160).optional(),
}).strict();

const supportTicketIdParamSchema = z.object({
  id: z.string().uuid("Invalid support ticket id"),
}).strict();

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

    const boundary = b03BoundaryForRequest(req, "support-ticket-read");
    const data = await boundary.run(async (db) => {
      const result = await listSupportTicketsBoundary(db, {
          licenseeId: parsed.data.licenseeId,
          status: parsed.data.status,
          priority: parsed.data.priority,
          search: parsed.data.search,
          limit,
          offset,
          requestId: boundary.requestId,
        });
      const tickets = result.tickets as Array<Record<string, any>>;
      return {
        tickets: tickets.map((ticket) => ({
          ...ticket,
          sla: ticketSlaSnapshot(ticket.slaDueAt || ticket.incident?.slaDueAt || null),
        })),
        total: result.total,
        limit,
        offset,
      };
    });
    return res.json({ success: true, data });
  } catch (error) {
    if (error instanceof Error && /B03_|RECENT_MFA_DENIED|AUTH_SESSION_CAPABILITY/.test(error.message)) {
      return res.status(403).json({ success: false, error: "Support ticket authorization is stale or insufficient." });
    }
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

    const boundary = b03BoundaryForRequest(req, "support-ticket-read");
    const ticket = await boundary.run((db) => getSupportTicketBoundary(db, {
      ticketId: id,
      requestId: boundary.requestId,
    })) as Record<string, any> | null;
    if (!ticket) return res.status(404).json({ success: false, error: "Support ticket not found" });
    return res.json({
      success: true,
      data: {
        ...ticket,
        sla: ticketSlaSnapshot(ticket.slaDueAt || ticket.incident?.slaDueAt || null),
      },
    });
  } catch (error) {
    if (error instanceof Error && /B03_|RECENT_MFA_DENIED|AUTH_SESSION_CAPABILITY/.test(error.message)) {
      return res.status(403).json({ success: false, error: "Support ticket authorization is stale or insufficient." });
    }
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

    const boundary = b03BoundaryForRequest(req, "support-ticket-update");
    const updated = await boundary.run((db) => updateSupportTicketBoundary(db, {
          ticketId: id,
          status: parsed.data.status,
          assignedToUserId: parsed.data.assignedToUserId,
          changedAt: new Date(),
          requestId: boundary.requestId,
    })) as Record<string, any> | null;
    if (!updated) return res.status(409).json({ success: false, error: "Support ticket changed; reload and retry" });

    return res.json({
      success: true,
      data: {
        ...updated,
        sla: ticketSlaSnapshot(updated.slaDueAt || updated.incident?.slaDueAt || null),
      },
    });
  } catch (error) {
    if (error instanceof Error && /B03_|RECENT_MFA_DENIED|AUTH_SESSION_CAPABILITY/.test(error.message)) {
      return res.status(403).json({ success: false, error: "Support ticket authorization is stale or insufficient." });
    }
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

    const boundary = b03BoundaryForRequest(req, "support-ticket-message");
    const message = await boundary.run((db) => addSupportTicketMessageBoundary(db, {
          ticketId: id,
          message: parsed.data.message,
          isInternal: parsed.data.isInternal,
          createdAt: new Date(),
          requestId: boundary.requestId,
    }));
    if (!message) return res.status(404).json({ success: false, error: "Support ticket not found" });
    return res.status(201).json({ success: true, data: message });
  } catch (error) {
    if (error instanceof Error && /B03_|RECENT_MFA_DENIED|AUTH_SESSION_CAPABILITY/.test(error.message)) {
      return res.status(403).json({ success: false, error: "Support ticket authorization is stale or insufficient." });
    }
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

    const proofSubject = queryParsed.data.email?.toLowerCase() || "missing-support-contact-proof";
    const ticket = await trackSupportStatus(getB01PreAuthPrisma(), {
      referenceCode: paramsParsed.data.reference.toUpperCase(),
      proofDigest: `sha256-v1:${createHash("sha256").update(proofSubject).digest("hex")}`,
      proofVersion: 1,
      checkedAt: new Date(),
      requestId: String((req as Request & { requestId?: string }).requestId || randomUUID()),
    });
    if (!ticket) return res.status(404).json({ success: false, error: "Support ticket not found" });

    return res.json({
      success: true,
      data: {
        referenceCode: ticket.referenceCode,
        status: ticket.customerFacingStatus,
        priority: ticket.priority,
        updatedAt: ticket.updatedAt,
        handoffStage: ticket.handoffStage,
        sla: ticketSlaSnapshot(ticket.slaDueAt),
      },
    });
  } catch (error) {
    console.error("trackSupportTicketPublic error:", error);
    return res.status(500).json({ success: false, error: "Failed to track support ticket" });
  }
};

import { Prisma, TraceEventType } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { isCanonicalAuthDenial, withDatabaseAuthenticatedSelection } from "../rls-waves/session-b/b01/canonicalAuthContext";
import { createAuditLogInTransaction } from "../services/auditService";
import { buildTraceTimelineBoundary, getTraceTimeline, TraceTimelineAccessError } from "../services/traceEventService";
import { decodeDateCursor } from "../utils/cursorPagination";

const traceTimelineQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).optional(),
  offset: z.coerce.number().int().min(0).max(100000).optional(),
  cursor: z.string().trim().max(512).optional(),
  licenseeId: z.string().uuid().optional(),
  eventType: z.nativeEnum(TraceEventType).optional(),
  batchId: z.string().uuid().optional(),
  manufacturerId: z.string().uuid().optional(),
  qrCodeId: z.string().uuid().optional(),
  purpose: z.string().trim().min(1).max(240).optional(),
}).strict();

export const getTraceTimelineController = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const parsed = traceTimelineQuerySchema.safeParse(req.query || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid filters" });
    }

    const limit = parsed.data.limit ?? 50;
    const offset = parsed.data.offset ?? 0;
    const cursor = parsed.data.cursor;
    if (cursor && !decodeDateCursor(cursor)) {
      return res.status(400).json({ success: false, error: "Invalid trace cursor" });
    }
    const query = {
      licenseeId: parsed.data.licenseeId,
      eventType: parsed.data.eventType,
      batchId: parsed.data.batchId,
      manufacturerId: parsed.data.manufacturerId,
      qrCodeId: parsed.data.qrCodeId,
      limit,
      offset,
      cursor,
      purpose: parsed.data.purpose,
    };
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "").trim();
    const boundary = buildTraceTimelineBoundary(req.user, query, requestId);
    const result = await withDatabaseAuthenticatedSelection(
      req.user,
      { capability: String(req.databaseSessionCapability || ""), requestId, purpose: boundary.context.purpose, context: boundary.context },
      async (tx) => {
        const timeline = await getTraceTimeline(tx, boundary.query, boundary.context);
        await createAuditLogInTransaction(tx, boundary.context, {
          action: "TRACE_TIMELINE_READ",
          entityType: "TraceEvent",
          entityId: boundary.context.licenseeId || undefined,
          details: {
            requestId: boundary.context.requestId,
            purposeCode: boundary.context.purpose,
            requestedPurpose: boundary.query.purpose || null,
            returnedRows: timeline.events.length,
          },
          ipAddress: req.ip,
          userAgent: req.get("user-agent"),
        });
        return timeline;
      },
      prisma,
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead }
    );

    return res.json({
      success: true,
      data: {
        events: result.events,
        total: result.total,
        limit,
        offset: cursor ? 0 : offset,
        cursor: cursor || null,
        nextCursor: result.nextCursor || null,
      },
    });
  } catch (e) {
    if (isCanonicalAuthDenial(e)) return res.status(401).json({ success: false, error: "Authenticated session is no longer valid" });
    if (e instanceof TraceTimelineAccessError) {
      return res.status(e.statusCode).json({ success: false, error: e.message });
    }
    console.error("getTraceTimelineController error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

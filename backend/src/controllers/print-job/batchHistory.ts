import { UserRole } from "@prisma/client";
import { Response } from "express";
import { z } from "zod";
import type { AuthRequest } from "../../middleware/auth";
import { getEffectiveLicenseeId } from "../../middleware/tenantIsolation";
import { readManufacturerBatchHistory } from "../../rls-waves/session-c/c02/printingLifecycleRepository";
import { decodeDateCursor, encodeDateCursor } from "../../utils/cursorPagination";

const filters = z.object({
  licenseeId: z.string().uuid(),
  cursor: z.string().max(512).optional(),
}).strict();
const batchIdSchema = z.string().uuid();
const pageSize = 50;

export const listManufacturerBatchHistory = async (req: AuthRequest, res: Response) => {
  res.set("Cache-Control", "no-store");
  if (req.user?.role !== UserRole.MANUFACTURER_ADMIN) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  const query = filters.safeParse(req.query);
  const batchId = batchIdSchema.safeParse(req.params.batchId);
  if (!query.success || !batchId.success) {
    return res.status(400).json({ success: false, error: "Invalid batch history filters" });
  }

  const cursor = decodeDateCursor(query.data.cursor);
  if (query.data.cursor && (!cursor || !/^[apt]:[0-9a-f-]{36}$/i.test(cursor.id))) {
    return res.status(400).json({ success: false, error: "Invalid batch history cursor" });
  }
  if (getEffectiveLicenseeId(req) !== query.data.licenseeId) {
    return res.status(403).json({ success: false, error: "Access denied" });
  }

  try {
    const history = await readManufacturerBatchHistory({
      capability: String(req.databaseSessionCapability || ""),
      requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
      batchId: batchId.data,
      licenseeId: query.data.licenseeId,
      options: { limit: pageSize, beforeAt: cursor?.createdAt, beforeId: cursor?.id },
    });
    const events = history.events.slice(0, pageSize);
    return res.json({ success: true, data: {
      events,
      incomplete: history.incomplete,
      nextCursor: history.events.length > pageSize ? encodeDateCursor(events[events.length - 1]) : null,
    } });
  } catch (error) {
    if (error instanceof Error && /PRINTING_BOUNDARY_DENIED|AUTH_SESSION_CAPABILITY_DENIED/.test(error.message)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    console.error("listManufacturerBatchHistory error:", error);
    return res.status(500).json({ success: false, error: "Batch history could not be loaded." });
  }
};

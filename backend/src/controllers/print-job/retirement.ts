import { Response } from "express";
import { z } from "zod";
import type { AuthRequest } from "../../middleware/auth";
import { operatePrintingRetirement } from "../../rls-waves/session-c/c02/printingLifecycleRepository";

const routeParams = z.object({ id: z.string().uuid() });
const mutationBody = z.object({
  action: z.enum(["REQUEST", "APPROVE", "REJECT"]),
  itemId: z.string().uuid(),
  reason: z.string().trim().min(8).max(500),
}).strict();

export const manufacturerPrintRetirement = async (req: AuthRequest, res: Response) => {
  res.set("Cache-Control", "no-store");
  const params = routeParams.safeParse(req.params);
  const query = z.object({ cursor: z.string().uuid().optional() }).strict().safeParse(req.query);
  const body = req.method === "POST" ? mutationBody.safeParse(req.body) : null;
  if (!params.success || !query.success || body?.success === false) {
    return res.status(400).json({ success: false, error: "Select a label and enter a reason of at least eight characters." });
  }

  try {
    const data = await operatePrintingRetirement({
      capability: String(req.databaseSessionCapability || ""),
      requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
      jobId: params.data.id,
      operation: body?.data.action ?? "LIST",
      itemId: body?.data.itemId ?? query.data.cursor,
      reason: body?.data.reason,
    });
    return res.json({ success: true, data });
  } catch (error) {
    const message = error instanceof Error ? error.message : "";
    if (/PRINTING_BOUNDARY_DENIED|AUTH_SESSION_CAPABILITY_DENIED/.test(message)) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }
    if (/INVALID_STATE_TRANSITION|PHYSICAL_OUTCOME_UNCONFIRMED/.test(message)) {
      return res.status(409).json({ success: false, error: "The label or its approval changed. Verify the current print run before trying again." });
    }
    console.error("manufacturerPrintRetirement error:", error);
    return res.status(500).json({ success: false, error: "Retirement information could not be processed." });
  }
};

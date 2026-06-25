import { Response } from "express";

import { AuthRequest } from "../middleware/auth";
import { getPrintJobOperationalView } from "../services/networkDirectPrintService";
import { canUserReceivePrintJobEvent, onPrintJobRealtimeEvent } from "../services/printJobRealtimeService";
import { writeSseRealtimeEnvelope } from "../utils/realtime";

export const printJobEvents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    const printJobId = String(req.params.id || "").trim();
    if (!printJobId) return res.status(400).json({ success: false, error: "Invalid print job id" });

    const scope = {
      role: req.user.role,
      userId: req.user.userId,
      licenseeId: req.user.licenseeId || null,
    };
    const initial = await getPrintJobOperationalView({ jobId: printJobId, scope });
    if (!initial) return res.status(404).json({ success: false, error: "Print job not found" });

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    writeSseRealtimeEnvelope(res, {
      channel: "printJob",
      type: "snapshot",
      payload: {
        reason: "initial",
        printJobId,
        view: initial,
        serverTime: new Date().toISOString(),
      },
    });

    const keepAlive = setInterval(() => {
      writeSseRealtimeEnvelope(res, {
        channel: "printJob",
        type: "keepalive",
        payload: {
          printJobId,
          serverTime: new Date().toISOString(),
        },
      });
    }, 25_000);

    const off = onPrintJobRealtimeEvent((event) => {
      if (event.printJobId !== printJobId) return;
      if (!canUserReceivePrintJobEvent(req, event)) return;
      writeSseRealtimeEnvelope(res, {
        channel: "printJob",
        type: event.type,
        payload: {
          reason: event.reason,
          printJobId,
          view: event.view || null,
          patch: event.patch || null,
          serverTime: event.occurredAt,
        },
        occurredAt: event.occurredAt,
      });
    });

    req.on("close", () => {
      clearInterval(keepAlive);
      off();
      res.end();
    });
  } catch (error) {
    console.error("printJobEvents error:", error);
    return res.status(500).end();
  }
};

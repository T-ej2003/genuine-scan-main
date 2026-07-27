import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { onAuditLog } from "../services/auditService";
import { canDeliverDashboardAuditDelta, getDashboardSnapshot } from "../services/dashboardSnapshotService";
import { writeSseRealtimeEnvelope } from "../utils/realtime";

/**
 * SSE stream for dashboard updates.
 * Browser sessions use secure cookies, so EventSource connects without query tokens.
 */
export const dashboardEvents = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    // SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders?.();

    // Send initial payload
    const initial = await getDashboardSnapshot(req);
    writeSseRealtimeEnvelope(res, {
      channel: "dashboard",
      type: "snapshot",
      payload: {
        reason: "initial",
        summary: {
          totalQRCodes: initial.totalQRCodes,
          activeLicensees: initial.activeLicensees,
          manufacturers: initial.manufacturers,
          totalBatches: initial.totalBatches,
        },
        qrStats: initial.qr,
      },
    });

    // Keepalive ping (prevents proxies killing connection)
    const keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 25000);

    // Listen for audit log emits (in-process)
    const off = onAuditLog(async (log) => {
      try {
        if (!await canDeliverDashboardAuditDelta(req, log.licenseeId)) return;

        writeSseRealtimeEnvelope(res, {
          channel: "dashboard",
          type: "audit.delta",
          payload: {
            log,
          },
        });
        writeSseRealtimeEnvelope(res, {
          channel: "dashboard",
          type: "summary.refresh",
          payload: {
            reason: "audit",
          },
        });
      } catch (e) {
        // ignore single event errors
      }
    });

    req.on("close", () => {
      clearInterval(keepAlive);
      off();
      res.end();
    });
  } catch (err) {
    console.error("dashboardEvents error:", err);
    return res.status(500).end();
  }
};

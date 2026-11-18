import { UserRole } from "@prisma/client";
import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { onAuditLog } from "../services/auditService";
import { canUserReceivePrintJobEvent, onPrintJobRealtimeEvent } from "../services/printJobRealtimeService";
import { canDeliverDashboardAuditDelta, getDashboardSnapshot } from "../services/dashboardSnapshotService";
import { closeSseAtTokenExpiry, writeSseRealtimeEnvelope } from "../utils/realtime";

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

    let closed = false;
    let ready = false;
    let changedWhileLoading = false;
    const closeExpiry = closeSseAtTokenExpiry(req, res, "dashboard");
    const offAudit = onAuditLog(async (log) => {
      try {
        if (closed) return;
        if (!ready) { changedWhileLoading = true; return; }
        if (!await canDeliverDashboardAuditDelta(req, log.licenseeId) || closed) return;
        if (req.user!.role === UserRole.SUPER_ADMIN || req.user!.role === UserRole.PLATFORM_SUPER_ADMIN || req.user!.role === UserRole.LICENSEE_ADMIN) {
          writeSseRealtimeEnvelope(res, { channel: "dashboard", type: "audit.delta", payload: { log } });
        }
        writeSseRealtimeEnvelope(res, {
          channel: "dashboard", type: "summary.refresh",
          payload: { reason: "audit", entityType: log.entityType, action: log.action },
        });
      } catch {
        // A single audit event must not terminate the stream.
      }
    });
    const offPrintJob = onPrintJobRealtimeEvent((event) => {
      if (closed || !canUserReceivePrintJobEvent(req, event)) return;
      if (!ready) { changedWhileLoading = true; return; }
      writeSseRealtimeEnvelope(res, {
        channel: "dashboard", type: "summary.refresh",
        payload: { reason: "print_job", type: event.type, batchId: event.batchId },
      });
    });
    let keepAlive: ReturnType<typeof setInterval> | null = null;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      if (keepAlive) clearInterval(keepAlive);
      closeExpiry();
      offAudit();
      offPrintJob();
    };
    (typeof res.on === "function" ? res : req).on("close", cleanup);

    // Send initial payload
    const initial = await getDashboardSnapshot(req);
    if (closed) return;
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

    ready = true;
    if (changedWhileLoading) {
      writeSseRealtimeEnvelope(res, { channel: "dashboard", type: "summary.refresh", payload: { reason: "initial_race" } });
    }

    // Keepalive ping (prevents proxies killing connection)
    keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 25000);
  } catch (err) {
    console.error("dashboardEvents error:", err);
    if (res.headersSent) return res.end();
    return res.status(500).end();
  }
};

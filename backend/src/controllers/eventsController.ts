import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { onAuditLog } from "../services/auditService";
import { UserRole } from "@prisma/client";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import { getDashboardSnapshot } from "../services/dashboardSnapshotService";

function writeSse(res: Response, event: string, data: any) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

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
    writeSse(res, "stats", initial);

    const scopedLicenseeId = getEffectiveLicenseeId(req);
    const role = req.user.role;
    const linkedLicenseeIds =
      role === UserRole.MANUFACTURER || role === UserRole.MANUFACTURER_ADMIN || role === UserRole.MANUFACTURER_USER
        ? await resolveAccessibleLicenseeIdsForUser(req.user)
        : [];

    // Keepalive ping (prevents proxies killing connection)
    const keepAlive = setInterval(() => {
      res.write(": ping\n\n");
    }, 25000);

    // Listen for audit log emits (in-process)
    const off = onAuditLog(async (log) => {
      try {
        // Tenant filter
        if (role !== UserRole.SUPER_ADMIN && role !== UserRole.PLATFORM_SUPER_ADMIN) {
          if (linkedLicenseeIds.length > 0) {
            if (!log.licenseeId || !linkedLicenseeIds.includes(log.licenseeId)) return;
          } else {
            if (!scopedLicenseeId) return;
            if (log.licenseeId !== scopedLicenseeId) return;
          }
        } else {
          // super admin can optionally scope via ?licenseeId= (supported by getEffectiveLicenseeId)
          if (scopedLicenseeId && log.licenseeId !== scopedLicenseeId) return;
        }

        writeSse(res, "audit", log);

        // also send fresh stats
        const fresh = await getDashboardSnapshot(req);
        writeSse(res, "stats", fresh);
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

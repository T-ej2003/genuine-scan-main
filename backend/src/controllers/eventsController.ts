import { Response } from "express";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { getEffectiveLicenseeId } from "../middleware/tenantIsolation";
import { onAuditLog } from "../services/auditService";
import { UserRole } from "@prisma/client";
import { resolveAccessibleLicenseeIdsForUser } from "../services/manufacturerScopeService";
import { summarizeQrStatusCounts } from "../services/qrStatusMetrics";

function writeSse(res: Response, event: string, data: any) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

async function computeDashboard(req: AuthRequest) {
  if (!req.user) throw new Error("Not authenticated");

  const role = req.user.role;
  const userId = req.user.userId;
  const scopedLicenseeId = getEffectiveLicenseeId(req);

  const qrWhere: any = {};
  const batchWhere: any = {};

  const manufacturersWhere: any = {
    role: { in: [UserRole.MANUFACTURER, UserRole.MANUFACTURER_ADMIN, UserRole.MANUFACTURER_USER] },
    isActive: true,
  };

  if (
    role === UserRole.MANUFACTURER ||
    role === UserRole.MANUFACTURER_ADMIN ||
    role === UserRole.MANUFACTURER_USER
  ) {
    batchWhere.manufacturerId = userId;
    qrWhere.batch = { manufacturerId: userId };
    manufacturersWhere.id = userId;
  } else if (scopedLicenseeId) {
    qrWhere.licenseeId = scopedLicenseeId;
    batchWhere.licenseeId = scopedLicenseeId;
    manufacturersWhere.OR = [
      { licenseeId: scopedLicenseeId },
      { manufacturerLicenseeLinks: { some: { licenseeId: scopedLicenseeId } } },
    ];
  }

  const linkedLicenseeIds =
    role === UserRole.MANUFACTURER || role === UserRole.MANUFACTURER_ADMIN || role === UserRole.MANUFACTURER_USER
      ? await resolveAccessibleLicenseeIdsForUser(req.user)
      : [];

  const [totalQRCodes, totalBatches, manufacturers, activeLicensees, qrGrouped, qrTotal] =
    await Promise.all([
      prisma.qRCode.count({ where: qrWhere }),
      prisma.batch.count({ where: batchWhere }),
      prisma.user.count({ where: manufacturersWhere }),

      role === UserRole.SUPER_ADMIN || role === UserRole.PLATFORM_SUPER_ADMIN
        ? prisma.licensee.count({ where: { isActive: true } })
        : linkedLicenseeIds.length > 0
          ? prisma.licensee.count({ where: { id: { in: linkedLicenseeIds }, isActive: true } })
          : scopedLicenseeId
          ? prisma.licensee.count({ where: { id: scopedLicenseeId, isActive: true } })
          : 0,

      prisma.qRCode.groupBy({
        by: ["status"],
        where: qrWhere,
        _count: true,
      }),
      prisma.qRCode.count({ where: qrWhere }),
    ]);

  const byStatus = qrGrouped.reduce((acc, s) => {
    acc[s.status] = s._count;
    return acc;
  }, {} as Record<string, number>);

  return {
    totalQRCodes,
    activeLicensees,
    manufacturers,
    totalBatches,
    qr: { total: qrTotal, byStatus, ...summarizeQrStatusCounts(byStatus) },
  };
}

/**
 * SSE stream for dashboard updates.
 * Use EventSource in frontend:
 *   new EventSource(`${API}/api/events/dashboard?token=${token}`)
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
    const initial = await computeDashboard(req);
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
        const fresh = await computeDashboard(req);
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

import { UserRole } from "@prisma/client";
import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { getAttentionQueueSnapshot } from "../services/attentionQueueService";
import { readDailyScanCount } from "../rls-waves/session-c/c01/qrSystemRepository";
import { getDashboardSnapshot } from "../services/dashboardSnapshotService";
import { isManufacturerRole } from "../services/manufacturerScopeService";

export const getDashboardStats = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user?.role || !req.user?.userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    const snapshot = await getDashboardSnapshot(req);

    let scansToday: number | undefined;
    const requestId = String((req as AuthRequest & { requestId?: string }).requestId || "");
    if (req.user.role === UserRole.MANUFACTURER_ADMIN) {
      try {
        scansToday = await readDailyScanCount({
          capability: String(req.databaseSessionCapability || ""),
          requestId,
          licenseeId: (req.query?.licenseeId as string | undefined) || null,
        });
      } catch (error) {
        console.error("Dashboard daily scan count unavailable", { requestId, error });
      }
    }

    return res.json({
      success: true,
      data: {
        totalQRCodes: snapshot.totalQRCodes,
        activeLicensees: snapshot.activeLicensees,
        manufacturers: snapshot.manufacturers,
        totalBatches: snapshot.totalBatches,
        ...(isManufacturerRole(req.user.role) && { qrStats: { ...snapshot.qr, scansToday } }),
      },
    });
  } catch (err) {
    if (err instanceof Error && /access denied|no licensee association/i.test(err.message)) {
      return res.status(404).json({ success: false, error: "Dashboard not found" });
    }
    console.error("getDashboardStats error", err);
    return res.status(500).json({ success: false, error: "Failed to load dashboard stats" });
  }
};

export const getDashboardAttentionQueue = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user?.role || !req.user?.userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    const snapshot = await getAttentionQueueSnapshot(req);
    return res.json({ success: true, data: snapshot });
  } catch (err) {
    if (err instanceof Error && /access denied|no licensee association/i.test(err.message)) {
      return res.status(404).json({ success: false, error: "Dashboard not found" });
    }
    console.error("getDashboardAttentionQueue error", err);
    return res.status(500).json({ success: false, error: "Failed to load attention queue" });
  }
};

import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import { getAttentionQueueSnapshot } from "../services/attentionQueueService";
import { getDashboardSnapshot } from "../services/dashboardSnapshotService";

export const getDashboardStats = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user?.role || !req.user?.userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }
    const snapshot = await getDashboardSnapshot(req);

    return res.json({
      success: true,
      data: {
        totalQRCodes: snapshot.totalQRCodes,
        activeLicensees: snapshot.activeLicensees,
        manufacturers: snapshot.manufacturers,
        totalBatches: snapshot.totalBatches,
      },
    });
  } catch (err) {
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
    console.error("getDashboardAttentionQueue error", err);
    return res.status(500).json({ success: false, error: "Failed to load attention queue" });
  }
};

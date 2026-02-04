import { Response } from "express";
import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";
import { UserRole } from "@prisma/client";

export const getDashboardStats = async (req: AuthRequest, res: Response) => {
  try {
    const role = req.user?.role;
    const userId = req.user?.userId;
    const licenseeId = req.user?.licenseeId || null;

    if (!role || !userId) {
      return res.status(401).json({ success: false, error: "Not authenticated" });
    }

    // SUPER_ADMIN can optionally scope by ?licenseeId=
    const scopeLicenseeId =
      role === UserRole.SUPER_ADMIN ? ((req.query.licenseeId as string | undefined) || null) : licenseeId;

    const qrWhere = scopeLicenseeId ? { licenseeId: scopeLicenseeId } : {};
    const licenseeWhere = scopeLicenseeId ? { id: scopeLicenseeId } : {};

    // Manufacturers count:
    // - SUPER_ADMIN (no scope): all manufacturers
    // - SUPER_ADMIN (scoped): manufacturers inside that licensee
    // - LICENSEE_ADMIN: manufacturers in own licensee
    // - MANUFACTURER: manufacturers in own licensee (so dashboard is consistent)
    const mfgWhere: any = { role: UserRole.MANUFACTURER, isActive: true };
    if (scopeLicenseeId) mfgWhere.licenseeId = scopeLicenseeId;

    // Batches:
    const batchWhere: any = {};
    if (scopeLicenseeId) batchWhere.licenseeId = scopeLicenseeId;
    if (role === UserRole.MANUFACTURER) batchWhere.manufacturerId = userId;

    const [
      totalQRCodes,
      activeLicensees,
      manufacturers,
      totalBatches,
    ] = await Promise.all([
      prisma.qRCode.count({ where: qrWhere }),
      prisma.licensee.count({ where: { ...licenseeWhere, isActive: true } }),
      prisma.user.count({ where: mfgWhere }),
      prisma.batch.count({ where: batchWhere }),
    ]);

    return res.json({
      success: true,
      data: { totalQRCodes, activeLicensees, manufacturers, totalBatches },
    });
  } catch (err) {
    console.error("getDashboardStats error", err);
    return res.status(500).json({ success: false, error: "Failed to load dashboard stats" });
  }
};

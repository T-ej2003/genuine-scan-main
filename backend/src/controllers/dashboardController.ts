import { prisma } from "../config/database";

export const getDashboardStats = async (req, res) => {
  try {
    const totalQRCodes = await prisma.qRCode.count();
    const activeLicensees = await prisma.licensee.count({
      where: { active: true },
    });
    const manufacturers = await prisma.manufacturer.count();
    const totalBatches = await prisma.batch.count();

    return res.json({
      totalQRCodes,
      activeLicensees,
      manufacturers,
      totalBatches,
    });
  } catch (err) {
    console.error("dashboard stats error", err);
    return res.status(500).json({
      success: false,
      error: "Failed to load dashboard stats",
    });
  }
};


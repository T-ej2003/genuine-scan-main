import { Response } from "express";
import { AuthRequest } from "../middleware/auth";
import prisma from "../config/database";
import { Prisma, UserRole } from "@prisma/client";

export const getScanLogs = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.LICENSEE_ADMIN &&
      req.user.role !== UserRole.MANUFACTURER
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const prismaAny = prisma as any;
    if (!prismaAny.qrScanLog) {
      return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
    }

    const limit = Math.min(parseInt(String(req.query.limit ?? "100"), 10) || 100, 1000);
    const offset = parseInt(String(req.query.offset ?? "0"), 10) || 0;

    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN
        ? (req.query.licenseeId as string | undefined) || undefined
        : req.user.licenseeId || undefined;
    const batchId = (req.query.batchId as string | undefined) || undefined;
    const code = (req.query.code as string | undefined)?.trim() || undefined;

    const where: any = {};
    if (licenseeId) where.licenseeId = licenseeId;
    if (batchId) where.batchId = batchId;
    if (code) where.code = { contains: code, mode: "insensitive" };
    if (req.user.role === UserRole.MANUFACTURER) {
      where.batch = { manufacturerId: req.user.userId };
    }

    const [logs, total] = await Promise.all([
      prisma.qrScanLog.findMany({
        where,
        orderBy: { scannedAt: "desc" },
        take: limit,
        skip: offset,
        include: {
          licensee: { select: { id: true, name: true, prefix: true } },
          qrCode: { select: { id: true, code: true, status: true } },
        },
      }),
      prisma.qrScanLog.count({ where }),
    ]);

    return res.json({ success: true, data: { logs, total, limit, offset } });
  } catch (e) {
    console.error("getScanLogs error:", e);
    if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === "P2021") {
      return res.json({ success: true, data: { logs: [], total: 0, limit: 0, offset: 0 } });
    }
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

export const getBatchSummary = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });
    if (
      req.user.role !== UserRole.SUPER_ADMIN &&
      req.user.role !== UserRole.LICENSEE_ADMIN &&
      req.user.role !== UserRole.MANUFACTURER
    ) {
      return res.status(403).json({ success: false, error: "Access denied" });
    }

    const licenseeId =
      req.user.role === UserRole.SUPER_ADMIN
        ? (req.query.licenseeId as string | undefined) || undefined
        : req.user.licenseeId || undefined;
    const whereBatch: any = {};
    if (licenseeId) whereBatch.licenseeId = licenseeId;
    if (req.user.role === UserRole.MANUFACTURER) {
      whereBatch.manufacturerId = req.user.userId;
    }

    const batches = await prisma.batch.findMany({
      where: whereBatch,
      orderBy: { createdAt: "desc" },
      select: { id: true, name: true, licenseeId: true, startCode: true, endCode: true, totalCodes: true, createdAt: true },
    });

    if (batches.length === 0) {
      return res.json({ success: true, data: [] });
    }

    const batchIds = batches.map((b) => b.id);

    const grouped = await prisma.qRCode.groupBy({
      by: ["batchId", "status"],
      where: { batchId: { in: batchIds } },
      _count: { _all: true },
    });

    const map = new Map<string, Record<string, number>>();
    for (const g of grouped) {
      if (!g.batchId) continue;
      const current = map.get(g.batchId) || {};
      current[g.status] = g._count?._all || 0;
      map.set(g.batchId, current);
    }

    const data = batches.map((b) => ({
      ...b,
      counts: map.get(b.id) || {},
    }));

    return res.json({ success: true, data });
  } catch (e) {
    console.error("getBatchSummary error:", e);
    return res.status(500).json({ success: false, error: "Internal server error" });
  }
};

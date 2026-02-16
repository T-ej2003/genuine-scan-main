import { Request, Response } from "express";
import { UserRole } from "@prisma/client";
import { z } from "zod";

import prisma from "../config/database";
import { AuthRequest } from "../middleware/auth";

const routeTransitionSchema = z.object({
  routeFrom: z.string().trim().max(300).optional().nullable(),
  routeTo: z.string().trim().min(1).max(300),
  source: z.string().trim().max(80).optional().nullable(),
  transitionMs: z.number().int().min(0).max(120_000),
  verifyCodePresent: z.boolean().optional().default(false),
  verifyResult: z.string().trim().max(80).optional().nullable(),
  dropped: z.boolean().optional().default(false),
  deviceType: z.string().trim().max(40).optional().nullable(),
  networkType: z.string().trim().max(40).optional().nullable(),
  online: z.boolean().optional().default(true),
});

const toDate = (value: unknown) => {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const dt = new Date(raw);
  return Number.isFinite(dt.getTime()) ? dt : null;
};

export const captureRouteTransitionMetric = async (req: AuthRequest, res: Response) => {
  try {
    const parsed = routeTransitionSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        error: parsed.error.errors[0]?.message || "Invalid telemetry payload",
      });
    }

    const data = parsed.data;

    const row = await prisma.routeTransitionMetric.create({
      data: {
        userId: req.user?.userId || null,
        role: req.user?.role || null,
        licenseeId: req.user?.licenseeId || null,
        routeFrom: data.routeFrom || null,
        routeTo: data.routeTo,
        source: data.source || null,
        transitionMs: data.transitionMs,
        verifyCodePresent: data.verifyCodePresent,
        verifyResult: data.verifyResult || null,
        dropped: data.dropped,
        deviceType: data.deviceType || null,
        networkType: data.networkType || null,
        online: data.online,
      },
      select: { id: true },
    });

    return res.status(201).json({ success: true, data: row });
  } catch (error) {
    console.error("captureRouteTransitionMetric error:", error);
    return res.status(500).json({ success: false, error: "Failed to capture telemetry" });
  }
};

export const getRouteTransitionSummary = async (req: AuthRequest, res: Response) => {
  try {
    if (!req.user) return res.status(401).json({ success: false, error: "Not authenticated" });

    const from = toDate(req.query.from);
    const to = toDate(req.query.to);

    const where: any = {};
    if (from || to) {
      where.createdAt = {};
      if (from) where.createdAt.gte = from;
      if (to) where.createdAt.lte = to;
    }

    if (req.user.role !== UserRole.SUPER_ADMIN && req.user.role !== UserRole.PLATFORM_SUPER_ADMIN) {
      where.licenseeId = req.user.licenseeId || "__none__";
    } else {
      const licenseeId = String(req.query.licenseeId || "").trim();
      if (licenseeId) where.licenseeId = licenseeId;
    }

    const [byRoute, totals, verifySummary] = await Promise.all([
      prisma.routeTransitionMetric.groupBy({
        by: ["routeTo"],
        where,
        _avg: { transitionMs: true },
        _count: { _all: true },
        orderBy: { _count: { routeTo: "desc" } },
        take: 20,
      }),
      prisma.routeTransitionMetric.aggregate({
        where,
        _count: { _all: true },
        _avg: { transitionMs: true },
      }),
      prisma.routeTransitionMetric.aggregate({
        where: {
          ...where,
          routeTo: { startsWith: "/verify" },
        },
        _count: { _all: true, dropped: true },
        _avg: { transitionMs: true },
      }),
    ]);

    return res.json({
      success: true,
      data: {
        totals: {
          transitions: totals._count._all,
          avgTransitionMs: Number(totals._avg.transitionMs || 0),
        },
        verifyFunnel: {
          transitions: verifySummary._count._all,
          dropped: verifySummary._count.dropped,
          avgTransitionMs: Number(verifySummary._avg.transitionMs || 0),
        },
        routes: byRoute.map((row) => ({
          routeTo: row.routeTo,
          count: row._count._all,
          avgTransitionMs: Number(row._avg.transitionMs || 0),
        })),
      },
    });
  } catch (error) {
    console.error("getRouteTransitionSummary error:", error);
    return res.status(500).json({ success: false, error: "Failed to load telemetry summary" });
  }
};

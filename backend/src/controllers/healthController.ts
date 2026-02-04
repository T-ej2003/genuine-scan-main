import { Request, Response } from "express";
import prisma from "../config/database";

export const healthCheck = async (_req: Request, res: Response) => {
  const started = Date.now();
  try {
    await prisma.$queryRaw`SELECT 1`;
    return res.json({
      success: true,
      status: "ok",
      db: "ok",
      uptimeSec: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
      ms: Date.now() - started,
    });
  } catch (e: any) {
    return res.json({
      success: true,
      status: "degraded",
      db: "error",
      error: e?.message || "db error",
      uptimeSec: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
      ms: Date.now() - started,
    });
  }
};

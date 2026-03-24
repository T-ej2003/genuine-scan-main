import { Request, Response } from "express";
import prisma from "../config/database";
import { getLatencySummary } from "../observability/requestMetrics";
import { releaseMetadata } from "../observability/release";

const releasePayload = {
  name: releaseMetadata.name,
  version: releaseMetadata.version,
  gitSha: releaseMetadata.shortGitSha,
  environment: releaseMetadata.environment,
  release: releaseMetadata.release,
};

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
      release: releasePayload,
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
      release: releasePayload,
    });
  }
};

export const versionCheck = (_req: Request, res: Response) => {
  res.json({
    success: true,
    ...releasePayload,
    gitSha: releaseMetadata.gitSha,
  });
};

export const latencySummary = (_req: Request, res: Response) => {
  res.json({
    success: true,
    status: "ok",
    timestamp: new Date().toISOString(),
    release: releasePayload,
    latency: getLatencySummary(),
  });
};

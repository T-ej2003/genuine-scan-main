import { Request, Response } from "express";

import prisma from "../config/database";
import { getLatencySummary } from "../observability/requestMetrics";
import { releaseMetadata } from "../observability/release";
import { getObjectStorageHealth } from "../services/objectStorageService";
import { getRedisHealth } from "../services/redisService";

const releasePayloadInternal = {
  name: releaseMetadata.name,
  version: releaseMetadata.version,
  gitSha: releaseMetadata.shortGitSha,
  environment: releaseMetadata.environment,
  release: releaseMetadata.release,
};

const releasePayloadPublic = {
  environment: releaseMetadata.environment,
};

const getDatabaseHealth = async () => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return { configured: true, ready: true };
  } catch (error: any) {
    return {
      configured: true,
      ready: false,
      error: error?.message || "Database unreachable",
    };
  }
};

export const collectDependencyHealth = async () => {
  const [database, redis, objectStorage] = await Promise.all([
    getDatabaseHealth(),
    getRedisHealth(),
    getObjectStorageHealth(),
  ]);

  return { database, redis, objectStorage };
};

export const buildReadyPayload = async () => {
  const started = Date.now();
  const dependencies = await collectDependencyHealth();
  const strictProductionDependencies = process.env.NODE_ENV === "production";
  const ready =
    dependencies.database.ready &&
    (strictProductionDependencies
      ? dependencies.redis.configured && dependencies.redis.ready
      : !dependencies.redis.configured || dependencies.redis.ready) &&
    (strictProductionDependencies
      ? dependencies.objectStorage.configured && dependencies.objectStorage.ready
      : !dependencies.objectStorage.configured || dependencies.objectStorage.ready);

  return {
    success: ready,
    status: ready ? "ready" : "degraded",
    uptimeSec: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    ms: Date.now() - started,
    release: releasePayloadPublic,
    dependencies,
  };
};

export const healthCheck = async (_req: Request, res: Response) => {
  const payload = await buildReadyPayload();
  return res.json(payload);
};

export const liveHealthCheck = (_req: Request, res: Response) => {
  res.json({
    success: true,
    status: "live",
    uptimeSec: Math.round(process.uptime()),
    timestamp: new Date().toISOString(),
    release: releasePayloadPublic,
  });
};

export const readyHealthCheck = async (_req: Request, res: Response) => {
  const payload = await buildReadyPayload();
  return res.status(payload.success ? 200 : 503).json(payload);
};

export const internalReleaseMetadata = (_req: Request, res: Response) => {
  res.json({
    success: true,
    ...releasePayloadInternal,
    gitSha: releaseMetadata.gitSha,
  });
};

export const latencySummary = async (_req: Request, res: Response) => {
  const payload = await buildReadyPayload();
  res.json({
    ...payload,
    latency: getLatencySummary(),
  });
};

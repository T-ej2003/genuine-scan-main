import { createHash } from "crypto";
import type { Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";

import { getRedisClient, isRedisConfigured } from "../services/redisService";

type RequestResolver = (req: Request) => string | null | undefined;

type PublicLimiterOptions = {
  scope: string;
  windowMs: number;
  max: number;
  message: string;
  actorResolver?: RequestResolver;
  resourceResolver?: RequestResolver;
};

const normalizeValue = (value: unknown, max = 256) => String(value ?? "").trim().slice(0, max);
const shortHash = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 16);

const readFirstValue = (container: unknown, fieldNames: string[], max = 256) => {
  if (!container || typeof container !== "object") return "";
  for (const fieldName of fieldNames) {
    const raw = (container as Record<string, unknown>)[fieldName];
    const value = Array.isArray(raw) ? raw[0] : raw;
    const normalized = normalizeValue(value, max);
    if (normalized) return normalized;
  }
  return "";
};

const retryAfterSeconds = (req: Request) => {
  const limitedReq = req as Request & { rateLimit?: { resetTime?: Date } };
  const resetAt = limitedReq.rateLimit?.resetTime?.getTime?.() || Date.now() + 1000;
  return Math.max(1, Math.ceil((resetAt - Date.now()) / 1000));
};

const buildResourceKey = (req: Request, resolver?: RequestResolver) => {
  const resource = normalizeValue(resolver?.(req), 512);
  return resource ? `resource:${shortHash(resource.toLowerCase())}` : "resource:global";
};

export const buildPublicIpRateLimitKey = (req: Request, scope: string, resourceResolver?: RequestResolver) => {
  const ip = normalizeValue(req.ip || req.socket?.remoteAddress || "unknown", 256).toLowerCase();
  return `public:${scope}:ip:${shortHash(ip)}:${buildResourceKey(req, resourceResolver)}`;
};

export const buildPublicActorRateLimitKey = (
  req: Request,
  scope: string,
  actorResolver?: RequestResolver,
  resourceResolver?: RequestResolver
) => {
  const actorValue = normalizeValue(actorResolver?.(req), 512).toLowerCase();
  const fallbackIp = normalizeValue(req.ip || req.socket?.remoteAddress || "unknown", 256).toLowerCase();
  const actor = actorValue || `ip:${fallbackIp}`;
  return `public:${scope}:actor:${shortHash(actor)}:${buildResourceKey(req, resourceResolver)}`;
};

// Return a stable JSON error contract for public callers and surface a retry hint.
const createJson429Handler = (scope: string, message: string) => (req: Request, res: Response) => {
  const retryAfterSec = retryAfterSeconds(req);
  res.setHeader("Retry-After", String(retryAfterSec));
  return res.status(429).json({
    success: false,
    code: "RATE_LIMITED",
    error: message,
    scope,
    retryAfterSec,
  });
};

export const createPublicIpRateLimiter = ({ scope, windowMs, max, message, resourceResolver }: PublicLimiterOptions) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    store: isRedisConfigured()
      ? new RedisStore({
          sendCommand: (async (...args: string[]) => {
            const redis = await getRedisClient();
            if (!redis) throw new Error("Redis unavailable");
            const redisAny = redis as any;
            return redisAny.call(args[0], ...args.slice(1));
          }) as any,
        })
      : undefined,
    keyGenerator: (req) => buildPublicIpRateLimitKey(req, scope, resourceResolver),
    handler: createJson429Handler(scope, message),
  });

export const createPublicActorRateLimiter = ({
  scope,
  windowMs,
  max,
  message,
  actorResolver,
  resourceResolver,
}: PublicLimiterOptions) =>
  rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    store: isRedisConfigured()
      ? new RedisStore({
          sendCommand: (async (...args: string[]) => {
            const redis = await getRedisClient();
            if (!redis) throw new Error("Redis unavailable");
            const redisAny = redis as any;
            return redisAny.call(args[0], ...args.slice(1));
          }) as any,
        })
      : undefined,
    keyGenerator: (req) => buildPublicActorRateLimitKey(req, scope, actorResolver, resourceResolver),
    handler: createJson429Handler(scope, message),
  });

export const composeRequestResolvers =
  (...resolvers: RequestResolver[]): RequestResolver =>
  (req) => {
    for (const resolver of resolvers) {
      const value = normalizeValue(resolver(req), 512);
      if (value) return value;
    }
    return null;
  };

export const fromAuthorizationBearer: RequestResolver = (req) => {
  const header = normalizeValue(req.get("authorization"), 4096);
  if (!header.toLowerCase().startsWith("bearer ")) return null;
  return header.slice(7).trim();
};

export const fromUserAgent: RequestResolver = (req) => normalizeValue(req.get("user-agent"), 512);
export const fromBodyFields =
  (...fieldNames: string[]): RequestResolver =>
  (req) =>
    readFirstValue(req.body, fieldNames, 512);
export const fromQueryFields =
  (...fieldNames: string[]): RequestResolver =>
  (req) =>
    readFirstValue(req.query, fieldNames, 512);
export const fromParamFields =
  (...fieldNames: string[]): RequestResolver =>
  (req) =>
    readFirstValue(req.params, fieldNames, 512);
export const fromHeaderFields =
  (...fieldNames: string[]): RequestResolver =>
  (req) => {
    for (const fieldName of fieldNames) {
      const value = normalizeValue(req.get(fieldName), 512);
      if (value) return value;
    }
    return null;
  };

export const parsePositiveIntEnv = (key: string, fallback: number, min = 1, max = 100_000) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(raw)));
};

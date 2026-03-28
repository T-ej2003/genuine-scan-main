import { getRedisClient, isRedisConfigured } from "./redisService";

type RateHitResult = {
  blocked: boolean;
  retryAfterSec: number;
};

type Bucket = {
  count: number;
  resetAt: number;
};

const DEFAULT_WINDOW_MS = Number(process.env.INCIDENT_RATE_LIMIT_WINDOW_MS || "3600000");
const DEFAULT_MAX_PER_KEY = Number(process.env.INCIDENT_RATE_LIMIT_MAX_PER_KEY || "8");

const buckets = new Map<string, Bucket>();

const upsertBucket = (key: string, now: number): Bucket => {
  const existing = buckets.get(key);
  if (!existing || existing.resetAt <= now) {
    const fresh = { count: 0, resetAt: now + DEFAULT_WINDOW_MS };
    buckets.set(key, fresh);
    return fresh;
  }
  return existing;
};

const hitKey = (key: string): RateHitResult => {
  const now = Date.now();
  const bucket = upsertBucket(key, now);
  bucket.count += 1;
  const retryAfterSec = Math.max(1, Math.ceil((bucket.resetAt - now) / 1000));
  return {
    blocked: bucket.count > DEFAULT_MAX_PER_KEY,
    retryAfterSec,
  };
};

const makeKey = (prefix: string, value: string | null | undefined) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return null;
  return `${prefix}:${normalized}`;
};

const hitRedisKey = async (key: string): Promise<RateHitResult> => {
  const redis = await getRedisClient();
  if (!redis) return hitKey(key);

  const namespacedKey = `incident:${key}`;
  const count = await redis.incr(namespacedKey);
  let ttlMs = await redis.pttl(namespacedKey);
  if (ttlMs < 0) {
    await redis.pexpire(namespacedKey, DEFAULT_WINDOW_MS);
    ttlMs = DEFAULT_WINDOW_MS;
  }

  return {
    blocked: count > DEFAULT_MAX_PER_KEY,
    retryAfterSec: Math.max(1, Math.ceil(ttlMs / 1000)),
  };
};

export const enforceIncidentRateLimit = async (input: {
  ip?: string | null;
  qrCode?: string | null;
  deviceFp?: string | null;
}) => {
  const keys = [
    makeKey("ip", input.ip),
    makeKey("qr", input.qrCode),
    makeKey("dev", input.deviceFp),
    makeKey("mix", `${input.ip || ""}|${input.qrCode || ""}|${input.deviceFp || ""}`),
  ].filter(Boolean) as string[];

  if (keys.length === 0) {
    return { blocked: false, retryAfterSec: 0 };
  }

  let maxRetry = 0;
  for (const key of keys) {
    const result = isRedisConfigured() ? await hitRedisKey(key) : hitKey(key);
    if (result.retryAfterSec > maxRetry) maxRetry = result.retryAfterSec;
    if (result.blocked) {
      return { blocked: true, retryAfterSec: result.retryAfterSec };
    }
  }
  return { blocked: false, retryAfterSec: maxRetry };
};

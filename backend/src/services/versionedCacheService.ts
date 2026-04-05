import { getRedisClient, isRedisConfigured } from "./redisService";

type LocalCacheEntry = {
  expiresAt: number;
  raw: string;
};

const localCache = new Map<string, LocalCacheEntry>();
const localVersions = new Map<string, number>();

const cacheKeyFor = (namespace: string, version: number, scopeKey: string) =>
  `cache:${namespace}:v${version}:${scopeKey}`;

const versionKeyFor = (namespace: string) => `cache:${namespace}:version`;

const readLocal = <T>(key: string): T | null => {
  const entry = localCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    localCache.delete(key);
    return null;
  }
  try {
    return JSON.parse(entry.raw) as T;
  } catch {
    localCache.delete(key);
    return null;
  }
};

const writeLocal = (key: string, value: unknown, ttlSec: number) => {
  localCache.set(key, {
    expiresAt: Date.now() + Math.max(1, ttlSec) * 1000,
    raw: JSON.stringify(value),
  });
};

export const getCacheNamespaceVersion = async (namespace: string) => {
  if (!isRedisConfigured()) {
    return localVersions.get(namespace) || 0;
  }

  const redis = await getRedisClient();
  if (!redis) return localVersions.get(namespace) || 0;

  const raw = await redis.get(versionKeyFor(namespace));
  const parsed = Number.parseInt(String(raw || "0"), 10);
  return Number.isFinite(parsed) ? parsed : 0;
};

export const bumpCacheNamespaceVersion = async (namespace: string) => {
  if (!isRedisConfigured()) {
    const next = (localVersions.get(namespace) || 0) + 1;
    localVersions.set(namespace, next);
    return next;
  }

  const redis = await getRedisClient();
  if (!redis) {
    const next = (localVersions.get(namespace) || 0) + 1;
    localVersions.set(namespace, next);
    return next;
  }

  return redis.incr(versionKeyFor(namespace));
};

export const getOrComputeVersionedCache = async <T>(
  namespace: string,
  scopeKey: string,
  ttlSec: number,
  compute: () => Promise<T>
): Promise<T> => {
  const version = await getCacheNamespaceVersion(namespace);
  const cacheKey = cacheKeyFor(namespace, version, scopeKey);

  if (!isRedisConfigured()) {
    const localHit = readLocal<T>(cacheKey);
    if (localHit !== null) return localHit;

    const computed = await compute();
    writeLocal(cacheKey, computed, ttlSec);
    return computed;
  }

  const redis = await getRedisClient();
  if (!redis) {
    const localHit = readLocal<T>(cacheKey);
    if (localHit !== null) return localHit;
    const computed = await compute();
    writeLocal(cacheKey, computed, ttlSec);
    return computed;
  }

  const cached = await redis.get(cacheKey);
  if (cached) {
    try {
      return JSON.parse(cached) as T;
    } catch {
      await redis.del(cacheKey);
    }
  }

  const computed = await compute();
  await redis.set(cacheKey, JSON.stringify(computed), "EX", Math.max(1, ttlSec));
  return computed;
};

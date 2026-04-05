import { randomUUID } from "crypto";

import { getRedisClient, isRedisConfigured } from "./redisService";

const localLeases = new Map<string, { token: string; expiresAt: number }>();

const nowMs = () => Date.now();

const cleanupLocalLeases = () => {
  const now = nowMs();
  for (const [key, lease] of localLeases.entries()) {
    if (lease.expiresAt <= now) {
      localLeases.delete(key);
    }
  }
};

const acquireLocalLease = async (key: string, ttlMs: number) => {
  cleanupLocalLeases();
  const current = localLeases.get(key);
  if (current && current.expiresAt > nowMs()) return null;

  const token = randomUUID();
  localLeases.set(key, {
    token,
    expiresAt: nowMs() + ttlMs,
  });

  return async () => {
    const active = localLeases.get(key);
    if (active?.token === token) {
      localLeases.delete(key);
    }
  };
};

const acquireRedisLease = async (key: string, ttlMs: number) => {
  const redis = await getRedisClient();
  if (!redis) return acquireLocalLease(key, ttlMs);

  const namespacedKey = `lease:${key}`;
  const token = randomUUID();
  const result = await redis.set(namespacedKey, token, "PX", Math.max(1000, ttlMs), "NX");
  if (result !== "OK") return null;

  return async () => {
    const releaseScript = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      end
      return 0
    `;
    await redis.eval(releaseScript, 1, namespacedKey, token);
  };
};

export const withDistributedLease = async <T>(
  key: string,
  ttlMs: number,
  fn: () => Promise<T>
): Promise<{ acquired: boolean; result?: T }> => {
  const release = isRedisConfigured()
    ? await acquireRedisLease(key, ttlMs)
    : await acquireLocalLease(key, ttlMs);

  if (!release) {
    return { acquired: false };
  }

  try {
    const result = await fn();
    return { acquired: true, result };
  } finally {
    await release();
  }
};

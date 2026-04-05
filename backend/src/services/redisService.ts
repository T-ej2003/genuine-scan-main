import { randomUUID } from "crypto";

import Redis from "ioredis";

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const buildRedisUrl = () => {
  const direct = String(process.env.REDIS_URL || "").trim();
  if (direct) return direct;

  const host = String(process.env.REDIS_HOST || "").trim();
  if (!host) return "";

  const port = Number(process.env.REDIS_PORT || "6379");
  const password = String(process.env.REDIS_PASSWORD || "").trim();
  const db = Number(process.env.REDIS_DB || "0");
  const auth = password ? `:${encodeURIComponent(password)}@` : "";
  return `redis://${auth}${host}:${port}/${Number.isFinite(db) ? db : 0}`;
};

const redisUrl = buildRedisUrl();
const redisEnabled = Boolean(redisUrl);
const instanceId = String(process.env.INSTANCE_ID || "").trim() || randomUUID();

let client: Redis | null = null;
let publisher: Redis | null = null;
let subscriber: Redis | null = null;
let warnedUnavailable = false;
let subscriberInitialized = false;

const subscriberHandlers = new Map<string, Set<(payload: any) => void>>();

const buildClient = (connectionName: string) =>
  new Redis(redisUrl, {
    lazyConnect: true,
    maxRetriesPerRequest: 1,
    enableAutoPipelining: true,
    connectionName,
    tls: parseBool(process.env.REDIS_TLS) ? {} : undefined,
  });

const attachLogging = (redis: Redis, label: string) => {
  redis.on("error", (error) => {
    if (!warnedUnavailable) {
      warnedUnavailable = true;
      console.error(`[redis] ${label} error`, error);
    }
  });
};

const ensureClient = (kind: "client" | "publisher" | "subscriber") => {
  if (!redisEnabled) return null;

  if (kind === "client") {
    if (!client) {
      client = buildClient("mscqr-main");
      attachLogging(client, "client");
    }
    return client;
  }

  if (kind === "publisher") {
    if (!publisher) {
      publisher = buildClient("mscqr-pub");
      attachLogging(publisher, "publisher");
    }
    return publisher;
  }

  if (!subscriber) {
    subscriber = buildClient("mscqr-sub");
    attachLogging(subscriber, "subscriber");
  }
  return subscriber;
};

const ensureSubscriberInitialized = async () => {
  if (!redisEnabled || subscriberInitialized) return;
  const redis = ensureClient("subscriber");
  if (!redis) return;
  subscriberInitialized = true;
  redis.on("message", (channel, raw) => {
    const handlers = subscriberHandlers.get(channel);
    if (!handlers?.size) return;

    try {
      const payload = JSON.parse(raw);
      for (const handler of handlers) {
        handler(payload);
      }
    } catch (error) {
      console.error(`[redis] failed to handle message for ${channel}`, error);
    }
  });
};

export const isRedisConfigured = () => redisEnabled;
export const getRedisInstanceId = () => instanceId;

export const getRedisClient = async () => {
  const redis = ensureClient("client");
  if (!redis) return null;
  if (redis.status === "wait") await redis.connect();
  return redis;
};

export const getRedisPublisher = async () => {
  const redis = ensureClient("publisher");
  if (!redis) return null;
  if (redis.status === "wait") await redis.connect();
  return redis;
};

export const publishRedisJson = async (channel: string, payload: any) => {
  const redis = await getRedisPublisher();
  if (!redis) return false;
  await redis.publish(channel, JSON.stringify(payload));
  return true;
};

export const subscribeRedisJson = async (channel: string, handler: (payload: any) => void) => {
  const redis = ensureClient("subscriber");
  if (!redis) return () => undefined;

  await ensureSubscriberInitialized();
  if (redis.status === "wait") await redis.connect();

  const existing = subscriberHandlers.get(channel) || new Set<(payload: any) => void>();
  const hadHandlers = existing.size > 0;
  existing.add(handler);
  subscriberHandlers.set(channel, existing);
  if (!hadHandlers) {
    await redis.subscribe(channel);
  }

  return () => {
    const handlers = subscriberHandlers.get(channel);
    if (!handlers) return;
    handlers.delete(handler);
    if (handlers.size === 0) {
      subscriberHandlers.delete(channel);
      void redis.unsubscribe(channel).catch(() => undefined);
    }
  };
};

export const getRedisHealth = async () => {
  const redis = await getRedisClient();
  if (!redis) return { configured: false, ready: false };
  try {
    const pong = await redis.ping();
    return { configured: true, ready: pong === "PONG" };
  } catch {
    return { configured: true, ready: false };
  }
};

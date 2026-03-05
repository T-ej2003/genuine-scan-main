import { createHash } from "crypto";
import { Prisma } from "@prisma/client";

import prisma from "../config/database";
import { hashToken } from "../utils/security";

const parsePositiveIntEnv = (name: string, fallback: number, min = 30, max = 86_400) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const DEFAULT_TTL_SECONDS = parsePositiveIntEnv("IDEMPOTENCY_TTL_SECONDS", 600);

const parseBoolEnv = (name: string, fallback: boolean) => {
  const normalized = String(process.env[name] || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const STRICT_BY_DEFAULT = parseBoolEnv("IDEMPOTENCY_REQUIRED_BY_DEFAULT", true);

const stableStringify = (value: any): string => {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;

  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
};

const requestHash = (action: string, scope: string, payload: any) => {
  const canonical = `${action}|${scope}|${stableStringify(payload ?? null)}`;
  return createHash("sha256").update(canonical).digest("hex");
};

const keyHash = (action: string, scope: string, key: string) =>
  hashToken(`idem:${action}:${scope}:${key}`);

export const extractIdempotencyKey = (headers?: Record<string, unknown>, body?: Record<string, unknown>) => {
  const direct = String(headers?.["x-idempotency-key"] || "").trim();
  if (direct) return direct;

  const lower = String((headers as any)?.["X-Idempotency-Key"] || "").trim();
  if (lower) return lower;

  const bodyValue = String(body?.idempotencyKey || "").trim();
  return bodyValue || null;
};

export type IdempotencyBeginResult<T = any> = {
  replayed: boolean;
  keyHash: string | null;
  statusCode?: number;
  responsePayload?: T;
};

const loadExisting = async (hashedKey: string) =>
  prisma.actionIdempotencyKey.findUnique({
    where: { keyHash: hashedKey },
    select: {
      keyHash: true,
      requestHash: true,
      completedAt: true,
      statusCode: true,
      responsePayload: true,
      expiresAt: true,
    },
  });

const normalizeScope = (value?: string | null) => {
  const trimmed = String(value || "").trim();
  return trimmed || "global";
};

export const beginIdempotentAction = async <T = any>(params: {
  action: string;
  scope?: string | null;
  idempotencyKey?: string | null;
  requestPayload?: any;
  required?: boolean;
  ttlSeconds?: number;
}): Promise<IdempotencyBeginResult<T>> => {
  const action = String(params.action || "").trim();
  if (!action) throw new Error("IDEMPOTENCY_ACTION_REQUIRED");

  const scope = normalizeScope(params.scope);
  const required = params.required ?? STRICT_BY_DEFAULT;
  const providedKey = String(params.idempotencyKey || "").trim();

  if (!providedKey) {
    if (required) throw new Error("IDEMPOTENCY_KEY_REQUIRED");
    return { replayed: false, keyHash: null };
  }

  const hashedKey = keyHash(action, scope, providedKey);
  const expectedRequestHash = requestHash(action, scope, params.requestPayload ?? null);
  const now = new Date();

  const existing = await loadExisting(hashedKey);
  if (existing) {
    if (existing.expiresAt.getTime() < now.getTime()) {
      await prisma.actionIdempotencyKey.deleteMany({ where: { keyHash: hashedKey } });
    } else if (existing.requestHash && existing.requestHash !== expectedRequestHash) {
      throw new Error("IDEMPOTENCY_KEY_PAYLOAD_MISMATCH");
    } else if (!existing.completedAt) {
      throw new Error("IDEMPOTENCY_KEY_IN_PROGRESS");
    } else {
      return {
        replayed: true,
        keyHash: hashedKey,
        statusCode: existing.statusCode || 200,
        responsePayload: (existing.responsePayload as T) ?? ({} as T),
      };
    }
  }

  const ttlSeconds = Math.max(30, Math.min(86_400, Number(params.ttlSeconds || DEFAULT_TTL_SECONDS)));
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

  try {
    await prisma.actionIdempotencyKey.create({
      data: {
        keyHash: hashedKey,
        action,
        scope,
        requestHash: expectedRequestHash,
        expiresAt,
      },
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      const collision = await loadExisting(hashedKey);
      if (collision?.completedAt) {
        return {
          replayed: true,
          keyHash: hashedKey,
          statusCode: collision.statusCode || 200,
          responsePayload: (collision.responsePayload as T) ?? ({} as T),
        };
      }
      throw new Error("IDEMPOTENCY_KEY_IN_PROGRESS");
    }
    throw error;
  }

  return {
    replayed: false,
    keyHash: hashedKey,
  };
};

export const completeIdempotentAction = async (params: {
  keyHash?: string | null;
  statusCode: number;
  responsePayload: any;
}) => {
  const hashedKey = String(params.keyHash || "").trim();
  if (!hashedKey) return;

  await prisma.actionIdempotencyKey.updateMany({
    where: {
      keyHash: hashedKey,
      completedAt: null,
    },
    data: {
      statusCode: Math.max(100, Math.min(599, Math.floor(params.statusCode))),
      responsePayload: params.responsePayload ?? null,
      completedAt: new Date(),
    },
  });
};

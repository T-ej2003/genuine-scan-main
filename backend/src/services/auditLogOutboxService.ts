import { AuditLogOutboxStatus, Prisma } from "@prisma/client";

import prisma from "../config/database";
import { withDistributedLease } from "./distributedLeaseService";

const getStore = () => (prisma as any).auditLogOutbox;
const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};
const auditOutboxWorkerDisabled = () =>
  parseBool(process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS, false) ||
  !parseBool(process.env.RUN_AUDIT_OUTBOX_WORKER, true);
const isShutdownStarted = () => {
  const normalized = String(process.env.INTEGRATION_SHUTDOWN_STARTED || "").trim().toLowerCase();
  return stopping || ["1", "true", "yes", "on"].includes(normalized);
};

const parseIntEnv = (key: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

export const queueAuditLogOutbox = async (
  payload: Record<string, unknown>,
  error?: unknown,
  db?: Pick<Prisma.TransactionClient, "auditLogOutbox">
) => {
  const store = db?.auditLogOutbox || getStore();
  if (!store?.create) return null;

  try {
    const row = await store.create({
      data: {
        payload,
        status: AuditLogOutboxStatus.QUEUED,
        lastError: error instanceof Error ? error.message : error ? String(error) : null,
      },
    });
    return String(row.id || "");
  } catch (queueError) {
    if (db) throw queueError;
    console.warn("audit outbox enqueue skipped:", queueError);
    return null;
  }
};

export const flushAuditLogOutbox = async () => {
  if (isShutdownStarted()) return;
  const store = getStore();
  if (!store?.findMany || !store?.update) return;

  const batchSize = parseIntEnv("AUDIT_OUTBOX_BATCH_SIZE", 25, 1, 250);
  const now = new Date();
  const rows = await store.findMany({
    where: {
      status: { in: [AuditLogOutboxStatus.QUEUED, AuditLogOutboxStatus.FAILED] },
      nextAttemptAt: { lte: now },
    },
    orderBy: [{ createdAt: "asc" }],
    take: batchSize,
  });

  if (!rows.length) return;
  if (isShutdownStarted()) return;

  const { createAuditLog } = await import("./auditService");

  for (const row of rows) {
    if (isShutdownStarted()) return;
    try {
      const log = await createAuditLog((row.payload || {}) as any);
      await store.update({
        where: { id: row.id },
        data: {
          status: AuditLogOutboxStatus.SENT,
          flushedAuditLogId: String(log?.id || "") || null,
          attempts: { increment: 1 },
          lastError: null,
          nextAttemptAt: new Date(),
        },
      });
    } catch (error) {
      const attempts = Number(row.attempts || 0) + 1;
      const retryDelaySec = Math.min(300, Math.max(10, 2 ** attempts));
      await store.update({
        where: { id: row.id },
        data: {
          status: AuditLogOutboxStatus.FAILED,
          attempts,
          lastError: error instanceof Error ? error.message : String(error),
          nextAttemptAt: new Date(Date.now() + retryDelaySec * 1000),
        },
      });
    }
  }
};

let started = false;
let stopping = false;
let timer: NodeJS.Timeout | null = null;

export const startAuditLogOutboxWorker = () => {
  if (auditOutboxWorkerDisabled()) return;
  const store = getStore();
  if (started || !store?.findMany || !store?.update) return;

  started = true;
  stopping = false;
  const pollMs = parseIntEnv("AUDIT_OUTBOX_POLL_MS", 5000, 1000, 60000);
  timer = setInterval(() => {
    if (isShutdownStarted()) return;
    void withDistributedLease("audit-log-outbox-worker", Math.max(15_000, pollMs * 3), flushAuditLogOutbox).catch((error) => {
      console.warn("audit outbox flush failed:", error);
    });
  }, pollMs);
  timer.unref?.();
};

export const stopAuditLogOutboxWorker = () => {
  stopping = true;
  if (timer) clearInterval(timer);
  timer = null;
  started = false;
};

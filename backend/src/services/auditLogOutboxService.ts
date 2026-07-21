import { AuditLogOutboxStatus, Prisma } from "@prisma/client";
import { createHash, randomUUID } from "crypto";

import prisma from "../config/database";
import {
  B03AuditEnqueueInput,
  b03PayloadDigest,
  claimAuditLogOutboxSlice,
  consumeAuditLogOutbox,
  enqueueAuditLogOutbox,
  failAuditLogOutbox,
} from "../rls-waves/session-b/b03/repositoryFunctions";
import {
  b03WorkerBoundariesEnabled,
  withB03AuditWorkerContext,
} from "../rls-waves/session-b/b03/systemContext";
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
  db?: Pick<Prisma.TransactionClient, "auditLogOutbox"> & Partial<Pick<Prisma.TransactionClient, "$queryRaw">>,
  authority?: Omit<B03AuditEnqueueInput, "payload" | "payloadDigest" | "idempotencyKey" | "expiresAt" | "initialErrorCode">
) => {
  if (b03WorkerBoundariesEnabled()) {
    if (!db?.$queryRaw || !authority) {
      throw new Error("B03 audit enqueue requires an attributed transaction and durable authority");
    }
    const payloadDigest = b03PayloadDigest(payload);
    const idempotencyKey = createHash("sha256")
      .update(`AUDIT_LOG_RECOVERY:${authority.requestId}:${payloadDigest}`)
      .digest("hex");
    const row = await enqueueAuditLogOutbox(db as any, {
      ...authority,
      payload,
      payloadDigest,
      idempotencyKey,
      expiresAt: new Date(Date.now() + 86_400_000),
      initialErrorCode: error ? "AUDIT_PERSISTENCE_FAILED" : null,
    });
    return row.id;
  }

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

const flushAuditLogOutboxThroughB03Boundary = async () => {
  const batchSize = parseIntEnv("AUDIT_OUTBOX_BATCH_SIZE", 25, 1, 250);
  const claimRequestId = randomUUID();
  const claims = await withB03AuditWorkerContext(
    { jobId: `audit-outbox-claim:${claimRequestId}`, requestId: claimRequestId },
    (tx) => claimAuditLogOutboxSlice(tx, { attemptedAt: new Date(), batchSize })
  );

  for (const claim of claims) {
    if (isShutdownStarted()) return;
    const attemptedAt = new Date();
    const context = {
      jobId: claim.id,
      requestId: claim.requestId,
      organizationId: claim.organizationId,
      licenseeId: claim.licenseeId,
      manufacturerId: claim.manufacturerId,
      initiatingUserId: claim.initiatingUserId,
    };
    try {
      if (claim.expiresAt.getTime() <= attemptedAt.getTime()) {
        throw new Error("AUDIT_OUTBOX_EXPIRED");
      }
      await withB03AuditWorkerContext(context, (tx) => consumeAuditLogOutbox(tx, {
        jobId: claim.id,
        payloadDigest: claim.payloadDigest,
        attemptedAt,
      }));
    } catch (error) {
      const errorCode = error instanceof Error && /^[A-Z0-9_]{1,128}$/.test(error.message)
        ? error.message
        : "AUDIT_OUTBOX_DELIVERY_FAILED";
      await withB03AuditWorkerContext(context, (tx) => failAuditLogOutbox(tx, {
        jobId: claim.id,
        payloadDigest: claim.payloadDigest,
        attemptedAt,
        attempt: claim.attempt,
        errorCode,
      }));
    }
  }
};

export const flushAuditLogOutbox = async () => {
  if (isShutdownStarted()) return;
  if (b03WorkerBoundariesEnabled()) return flushAuditLogOutboxThroughB03Boundary();
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

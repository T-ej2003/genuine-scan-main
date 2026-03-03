import { createHmac } from "crypto";
import { Prisma } from "@prisma/client";

import prisma from "../config/database";
import { logger } from "../utils/logger";

const webhookUrl = () => String(process.env.SIEM_WEBHOOK_URL || "").trim();
const webhookSecret = () => String(process.env.SIEM_WEBHOOK_SECRET || "").trim();
const sinkMode = () => String(process.env.SIEM_SINK_MODE || "webhook").trim().toLowerCase();

const parseIntEnv = (key: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[key] || "").trim());
  if (!Number.isFinite(raw)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const computeSignature = (body: string) => {
  const secret = webhookSecret();
  if (!secret) return null;
  return createHmac("sha256", secret).update(body).digest("hex");
};

export const queueSecurityEvent = async (eventType: string, payload: Record<string, unknown>) => {
  if (!eventType) return;

  try {
    await prisma.securityEventOutbox.create({
      data: {
        eventType,
        payload: payload as Prisma.InputJsonValue,
      },
    });
  } catch (error) {
    logger.warn("Failed to enqueue SIEM event", {
      eventType,
      error: error instanceof Error ? error.message : String(error),
    });
  }
};

const sendToWebhook = async (row: { id: string; eventType: string; payload: any; createdAt: Date }) => {
  if (sinkMode() === "stdout") {
    logger.info("SIEM event", {
      id: row.id,
      eventType: row.eventType,
      createdAt: row.createdAt.toISOString(),
      payload: row.payload,
    });
    return;
  }

  const url = webhookUrl();
  if (!url) return;

  const body = JSON.stringify({
    id: row.id,
    eventType: row.eventType,
    createdAt: row.createdAt.toISOString(),
    payload: row.payload,
  });

  const signature = computeSignature(body);

  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(signature ? { "X-AQ-Signature": signature } : {}),
    },
    body,
  });

  if (!response.ok) {
    throw new Error(`SIEM webhook HTTP ${response.status}`);
  }
};

export const flushSecurityEventOutbox = async () => {
  const url = webhookUrl();
  if (!url && sinkMode() !== "stdout") return;

  const batchSize = parseIntEnv("SIEM_OUTBOX_BATCH_SIZE", 20, 1, 200);
  const now = new Date();
  const rows = await prisma.securityEventOutbox.findMany({
    where: {
      status: { in: ["QUEUED", "FAILED"] },
      nextAttemptAt: { lte: now },
    },
    orderBy: { createdAt: "asc" },
    take: batchSize,
  });

  for (const row of rows) {
    try {
      await sendToWebhook(row);
      await prisma.securityEventOutbox.update({
        where: { id: row.id },
        data: {
          status: "SENT",
          sentAt: new Date(),
          attempts: { increment: 1 },
          lastError: null,
          nextAttemptAt: new Date(),
        },
      });
    } catch (error) {
      const attempts = (row.attempts || 0) + 1;
      const retryDelaySec = Math.min(300, Math.max(5, 2 ** attempts));
      await prisma.securityEventOutbox.update({
        where: { id: row.id },
        data: {
          status: "FAILED",
          attempts,
          lastError: error instanceof Error ? error.message : String(error),
          nextAttemptAt: new Date(Date.now() + retryDelaySec * 1000),
        },
      });
    }
  }
};

let started = false;
let timer: NodeJS.Timeout | null = null;

export const startSecurityEventOutboxWorker = () => {
  if (started) return;

  const url = webhookUrl();
  if (!url && sinkMode() !== "stdout") {
    logger.info("SIEM outbox worker disabled (no webhook configured)");
    return;
  }

  started = true;
  const pollMs = parseIntEnv("SIEM_OUTBOX_POLL_MS", 5000, 1000, 60000);
  timer = setInterval(() => {
    void flushSecurityEventOutbox().catch((error) => {
      logger.warn("SIEM outbox flush failed", {
        error: error instanceof Error ? error.message : String(error),
      });
    });
  }, pollMs);

  timer.unref?.();
  logger.info("SIEM outbox worker started", { pollMs, mode: sinkMode() });
};

export const stopSecurityEventOutboxWorker = () => {
  if (timer) clearInterval(timer);
  timer = null;
  started = false;
};

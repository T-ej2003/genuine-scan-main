import type { Response } from "express";
import type { AuthRequest } from "../middleware/auth";

type RealtimeChannel = "dashboard" | "notifications" | "printer" | "printJob";

export const writeSseRealtimeEnvelope = <TPayload>(
  res: Response,
  input: {
    channel: RealtimeChannel;
    type: string;
    payload: TPayload;
    occurredAt?: string;
  }
) => {
  const envelope = {
    envelope: "MSCQR_SSE_V1" as const,
    channel: input.channel,
    type: input.type,
    occurredAt: input.occurredAt || new Date().toISOString(),
    payload: input.payload,
  };

  res.write("event: realtime\n");
  res.write(`data: ${JSON.stringify(envelope)}\n\n`);
};

export const closeSseAtTokenExpiry = (req: AuthRequest, res: Response, channel: RealtimeChannel) => {
  const expiresAt = req.sseTokenExpiresAtMs;
  if (!Number.isFinite(expiresAt) || !expiresAt) return () => undefined;
  const timer = setTimeout(() => {
    writeSseRealtimeEnvelope(res, { channel, type: "session.expired", payload: {} });
    res.end();
  }, Math.max(0, expiresAt - Date.now()));
  return () => clearTimeout(timer);
};

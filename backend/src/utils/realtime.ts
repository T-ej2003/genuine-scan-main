import type { Response } from "express";

type RealtimeChannel = "dashboard" | "notifications" | "printer";

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

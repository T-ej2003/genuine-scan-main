import { z } from "zod";

import { auditLogSchema, dashboardStatsSchema, qrStatsSchema } from "./dashboard";
import { dashboardNotificationArraySchema, printerConnectionStatusSchema } from "./printing";

export const realtimeChannelSchema = z.enum(["dashboard", "notifications", "printer"]);
export const realtimeEnvelopeSchema = z
  .object({
    envelope: z.literal("MSCQR_SSE_V1"),
    channel: realtimeChannelSchema,
    type: z.string().min(1),
    occurredAt: z.string(),
    payload: z.unknown(),
  })
  .passthrough();

export const dashboardSnapshotPayloadSchema = z
  .object({
    reason: z.string().optional(),
    summary: dashboardStatsSchema,
    qrStats: qrStatsSchema.nullable().optional(),
  })
  .passthrough();

export const dashboardAuditDeltaPayloadSchema = z
  .object({
    log: auditLogSchema,
  })
  .passthrough();

export const notificationSnapshotPayloadSchema = z
  .object({
    reason: z.string().optional(),
    notifications: dashboardNotificationArraySchema,
    unread: z.number(),
    total: z.number(),
    limit: z.number().optional(),
    offset: z.number().optional(),
    serverTime: z.string().optional(),
  })
  .passthrough();

export const notificationVersionPayloadSchema = z
  .object({
    reason: z.string().optional(),
    serverTime: z.string(),
  })
  .passthrough();

export const printerSnapshotPayloadSchema = z
  .object({
    reason: z.string().optional(),
    status: printerConnectionStatusSchema,
    serverTime: z.string().optional(),
  })
  .passthrough();

export const printerKeepalivePayloadSchema = z
  .object({
    serverTime: z.string(),
    signature: z.string(),
  })
  .passthrough();

export type RealtimeChannelDTO = z.infer<typeof realtimeChannelSchema>;
export type RealtimeEnvelopeDTO = z.infer<typeof realtimeEnvelopeSchema>;
export type DashboardSnapshotPayloadDTO = z.infer<typeof dashboardSnapshotPayloadSchema>;
export type DashboardAuditDeltaPayloadDTO = z.infer<typeof dashboardAuditDeltaPayloadSchema>;
export type NotificationSnapshotPayloadDTO = z.infer<typeof notificationSnapshotPayloadSchema>;
export type NotificationVersionPayloadDTO = z.infer<typeof notificationVersionPayloadSchema>;
export type PrinterSnapshotPayloadDTO = z.infer<typeof printerSnapshotPayloadSchema>;
export type PrinterKeepalivePayloadDTO = z.infer<typeof printerKeepalivePayloadSchema>;

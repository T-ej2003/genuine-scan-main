import { z } from "zod";

import { statusCountRecordSchema, userSummarySchema } from "./common";

export const qrStatsSchema = z
  .object({
    total: z.number().int().nonnegative().optional(),
    dormant: z.number().optional(),
    allocated: z.number().optional(),
    printed: z.number().optional(),
    scanned: z.number().optional(),
    scansToday: z.number().int().nonnegative().optional(),
    byStatus: statusCountRecordSchema.optional(),
    statusCounts: statusCountRecordSchema.optional(),
  })
  .passthrough();

export const dashboardStatsSchema = z
  .object({
    totalQRCodes: z.number().optional(),
    activeLicensees: z.number().optional(),
    manufacturers: z.number().optional(),
    totalBatches: z.number().optional(),
    qrStats: qrStatsSchema.optional(),
  })
  .passthrough();

export const auditLogSchema = z
  .object({
    id: z.string(),
    action: z.string().optional(),
    entityType: z.string().nullable().optional(),
    entityId: z.string().nullable().optional(),
    createdAt: z.string(),
    details: z.unknown().optional(),
    user: userSummarySchema.nullable().optional(),
    userId: z.string().nullable().optional(),
  })
  .passthrough();

export const auditLogArraySchema = z.array(auditLogSchema);

export type DashboardStatsDTO = z.infer<typeof dashboardStatsSchema>;
export type QrStatsDTO = z.infer<typeof qrStatsSchema>;
export type AuditLogDTO = z.infer<typeof auditLogSchema>;

import { z } from "zod";

import { licenseeSummarySchema, manufacturerSummarySchema, userSummarySchema } from "./common";

export const batchSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    licenseeId: z.string(),
    manufacturerId: z.string().nullable().optional(),
    batchKind: z.enum(["RECEIVED_PARENT", "MANUFACTURER_CHILD"]).optional(),
    parentBatchId: z.string().nullable().optional(),
    rootBatchId: z.string().nullable().optional(),
    startCode: z.string(),
    endCode: z.string(),
    totalCodes: z.number(),
    printedAt: z.string().nullable(),
    createdAt: z.string(),
    updatedAt: z.string().optional(),
    licensee: licenseeSummarySchema.pick({ id: true, name: true, prefix: true }).optional(),
    manufacturer: manufacturerSummarySchema.pick({ id: true, name: true, email: true }).optional(),
    _count: z.object({ qrCodes: z.number() }).optional(),
    availableCodes: z.number().optional(),
    unassignedRemainingCodes: z.number().optional(),
    assignedCodes: z.number().optional(),
    printableCodes: z.number().optional(),
    printedCodes: z.number().optional(),
    redeemedCodes: z.number().optional(),
    blockedCodes: z.number().optional(),
    remainingStartCode: z.string().nullable().optional(),
    remainingEndCode: z.string().nullable().optional(),
  })
  .passthrough();

export const batchArraySchema = z.array(batchSchema);

export const manufacturerOptionSchema = z
  .object({
    id: z.string(),
    name: z.string(),
    email: z.string(),
    isActive: z.boolean(),
  })
  .passthrough();

export const manufacturerOptionArraySchema = z.array(manufacturerOptionSchema);

export const batchTraceEventSchema = z
  .object({
    id: z.string(),
    eventType: z.enum(["COMMISSIONED", "ASSIGNED", "PRINTED", "REDEEMED", "BLOCKED"]).optional(),
    action: z.string().optional(),
    sourceAction: z.string().nullable().optional(),
    createdAt: z.string(),
    details: z.unknown().optional(),
    user: userSummarySchema.nullable().optional(),
    manufacturer: manufacturerSummarySchema.pick({ id: true, name: true, email: true }).nullable().optional(),
    qrCode: z
      .object({
        id: z.string(),
        code: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    userId: z.string().nullable().optional(),
  })
  .passthrough();

export const batchTraceEventArraySchema = z.array(batchTraceEventSchema);

export const batchAllocationMapSchema = z
  .object({
    sourceBatchId: z.string(),
    focusBatchId: z.string(),
    sourceBatch: z.unknown().nullable(),
    selectedBatch: z.unknown().nullable(),
    allocations: z.array(z.unknown()),
    totals: z.object({
      totalDistributedCodes: z.number(),
      sourceRemainingCodes: z.number(),
      pendingPrintableCodes: z.number(),
      printedCodes: z.number(),
    }),
  })
  .passthrough();

export type BatchDTO = z.infer<typeof batchSchema>;
export type ManufacturerDTO = z.infer<typeof manufacturerOptionSchema>;
export type BatchTraceEventDTO = z.infer<typeof batchTraceEventSchema>;
export type BatchAllocationMapDTO = z.infer<typeof batchAllocationMapSchema>;

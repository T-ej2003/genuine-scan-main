import { z } from "zod";

export const printOperationReasonSchema = z.object({
  reason: z.string().trim().min(8, "A clear reason is required.").max(500),
}).strict();

export const createReissueRequestSchema = z.object({
  reason: z.string().trim().min(8, "A clear reason is required.").max(500),
  quantity: z.number().int().positive().max(200000).optional(),
  affectedRangeStart: z.string().trim().max(128).optional(),
  affectedRangeEnd: z.string().trim().max(128).optional(),
}).strict();

export const listReissueRequestsQuerySchema = z.object({
  status: z.enum(["PENDING", "APPROVED", "REJECTED", "EXECUTED", "CANCELLED"]).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
}).strict();

export const reissueRequestDecisionSchema = z.object({
  decisionNote: z.string().trim().min(8, "A clear decision note is required.").max(500),
}).strict();

export const reissueRequestIdParamSchema = z.object({
  id: z.string().uuid("Invalid reissue request id"),
}).strict();

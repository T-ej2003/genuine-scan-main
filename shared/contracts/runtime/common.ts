import { z } from "zod";

export const nullableStringSchema = z.string().nullable().optional();

export const userSummarySchema = z
  .object({
    id: z.string(),
    name: z.string().nullable().optional(),
    email: z.string().nullable().optional(),
    role: z.string().nullable().optional(),
  })
  .passthrough();

export const licenseeSummarySchema = z
  .object({
    id: z.string(),
    name: z.string(),
    prefix: z.string(),
    brandName: nullableStringSchema,
    location: nullableStringSchema,
    website: nullableStringSchema,
    supportEmail: nullableStringSchema,
    supportPhone: nullableStringSchema,
  })
  .passthrough();

export const manufacturerSummarySchema = z
  .object({
    id: z.string(),
    name: z.string(),
    email: nullableStringSchema,
    location: nullableStringSchema,
    website: nullableStringSchema,
  })
  .passthrough();

export const statusCountRecordSchema = z.record(z.string(), z.number()).default({});

export const dateStringSchema = z.string();

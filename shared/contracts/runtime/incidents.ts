import { z } from "zod";

import { userSummarySchema } from "./common";

export const incidentSchema = z
  .object({
    id: z.string(),
    createdAt: z.string(),
    qrCodeValue: z.string(),
    incidentType: z.string(),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    status: z.string(),
    description: z.string(),
    consentToContact: z.boolean(),
    customerEmail: z.string().nullable().optional(),
    customerPhone: z.string().nullable().optional(),
    locationName: z.string().nullable().optional(),
    assignedToUserId: z.string().nullable().optional(),
    assignedToUser: userSummarySchema.nullable().optional(),
    handoff: z
      .object({
        currentStage: z.string().nullable().optional(),
        slaDueAt: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
    supportTicket: z
      .object({
        id: z.string(),
        referenceCode: z.string().nullable().optional(),
        status: z.string().nullable().optional(),
        slaDueAt: z.string().nullable().optional(),
      })
      .nullable()
      .optional(),
  })
  .passthrough();

export const incidentArraySchema = z.array(incidentSchema);

export const incidentDetailSchema = incidentSchema.extend({
  events: z.array(
    z
      .object({
        id: z.string(),
        createdAt: z.string(),
        actorType: z.string(),
        eventType: z.string(),
        eventPayload: z.unknown().optional(),
        actorUser: userSummarySchema.nullable().optional(),
      })
      .passthrough()
  ),
  evidence: z.array(
    z
      .object({
        id: z.string(),
        storageKey: z.string().nullable().optional(),
        fileType: z.string().nullable().optional(),
        createdAt: z.string(),
      })
      .passthrough()
  ),
  internalNotes: z.string().nullable().optional(),
  resolutionSummary: z.string().nullable().optional(),
  resolutionOutcome: z.string().nullable().optional(),
});

export type IncidentDTO = z.infer<typeof incidentSchema>;
export type IncidentDetailDTO = z.infer<typeof incidentDetailSchema>;

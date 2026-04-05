import { z } from "zod";

import { licenseeSummarySchema, userSummarySchema } from "./common";

export const supportTicketMessageSchema = z
  .object({
    id: z.string(),
    createdAt: z.string(),
    message: z.string(),
    isInternal: z.boolean().optional(),
    actorType: z.string().nullable().optional(),
    actorUser: userSummarySchema.nullable().optional(),
  })
  .passthrough();

export const supportTicketSchema = z
  .object({
    id: z.string(),
    referenceCode: z.string(),
    status: z.enum(["OPEN", "IN_PROGRESS", "WAITING_CUSTOMER", "RESOLVED", "CLOSED"]),
    priority: z.enum(["P1", "P2", "P3", "P4"]),
    subject: z.string(),
    createdAt: z.string(),
    updatedAt: z.string(),
    assignedToUserId: z.string().nullable().optional(),
    assignedToUser: userSummarySchema.nullable().optional(),
    incidentId: z.string(),
    incident: z
      .object({
        id: z.string(),
        qrCodeValue: z.string().optional(),
        status: z.string().optional(),
        severity: z.string().optional(),
        handoff: z
          .object({
            currentStage: z.string().nullable().optional(),
          })
          .nullable()
          .optional(),
      })
      .nullable()
      .optional(),
    sla: z
      .object({
        hasSla: z.boolean().optional(),
        dueAt: z.string().optional(),
        remainingMinutes: z.number().optional(),
        isBreached: z.boolean().optional(),
      })
      .nullable()
      .optional(),
  })
  .passthrough();

export const supportTicketArraySchema = z.array(supportTicketSchema);

export const supportTicketDetailSchema = supportTicketSchema.extend({
  messages: z.array(supportTicketMessageSchema),
});

export const supportIssueReportSchema = z
  .object({
    id: z.string(),
    title: z.string(),
    description: z.string().nullable().optional(),
    status: z.string(),
    responseMessage: z.string().nullable().optional(),
    respondedAt: z.string().nullable().optional(),
    respondedByUserId: z.string().nullable().optional(),
    sourcePath: z.string().nullable().optional(),
    pageUrl: z.string().nullable().optional(),
    autoDetected: z.boolean().optional(),
    screenshotPath: z.string().nullable().optional(),
    createdAt: z.string(),
    reporterUser: userSummarySchema.nullable().optional(),
    respondedByUser: userSummarySchema.nullable().optional(),
    licensee: licenseeSummarySchema.pick({ id: true, name: true, prefix: true }).nullable().optional(),
  })
  .passthrough();

export const supportIssueReportArraySchema = z.array(supportIssueReportSchema);

export const supportAssigneeSchema = z
  .object({
    id: z.string(),
    role: z.string().optional(),
    name: z.string().optional(),
    email: z.string().optional(),
  })
  .passthrough();

export const supportAssigneeArraySchema = z.array(supportAssigneeSchema);

export const supportTicketListResponseSchema = z
  .object({
    tickets: supportTicketArraySchema,
    total: z.number(),
  })
  .passthrough();

export const supportIssueReportListResponseSchema = z
  .object({
    reports: supportIssueReportArraySchema,
    total: z.number(),
  })
  .passthrough();

export type SupportTicket = z.infer<typeof supportTicketSchema>;
export type SupportTicketDetail = z.infer<typeof supportTicketDetailSchema>;
export type SupportTicketMessage = z.infer<typeof supportTicketMessageSchema>;
export type SupportIssueReport = z.infer<typeof supportIssueReportSchema>;
export type SupportAssignee = z.infer<typeof supportAssigneeSchema>;

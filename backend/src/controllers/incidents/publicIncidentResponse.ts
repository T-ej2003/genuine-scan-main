import { IncidentSeverity, IncidentStatus, SupportTicketStatus } from "@prisma/client";

import { ticketSlaSnapshot } from "../../services/supportWorkflowService";

type PublicIncident = {
  status: IncidentStatus;
  severity: IncidentSeverity;
};

type PublicIncidentSupportTicket = {
  referenceCode: string | null;
  status: SupportTicketStatus;
  slaDueAt: Date | null;
} | null;

type PublicIncidentTamperSummary = {
  summary: string;
  highestRisk: number;
  hasWarnings: boolean;
};

export const buildPublicIncidentReportResponse = (
  incident: PublicIncident,
  supportTicket: PublicIncidentSupportTicket,
  tamperSummary: PublicIncidentTamperSummary
) => ({
  reference: supportTicket?.referenceCode || null,
  supportTicketRef: supportTicket?.referenceCode || null,
  supportTicketStatus: supportTicket?.status || null,
  supportTicketSla: supportTicket ? ticketSlaSnapshot(supportTicket.slaDueAt) : null,
  status: incident.status,
  severity: incident.severity,
  tamperChecks: {
    summary: tamperSummary.summary,
    highestRisk: tamperSummary.highestRisk,
    hasWarnings: tamperSummary.hasWarnings,
  },
});

export interface IncidentDTO {
  id: string;
  createdAt: string;
  qrCodeValue: string;
  incidentType: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: string;
  description: string;
  consentToContact: boolean;
  customerEmail?: string | null;
  customerPhone?: string | null;
  locationName?: string | null;
  assignedToUserId?: string | null;
  assignedToUser?: { id: string; name?: string | null; email?: string | null } | null;
  handoff?: {
    currentStage?: string | null;
    slaDueAt?: string | null;
  } | null;
  supportTicket?: {
    id: string;
    referenceCode?: string | null;
    status?: string | null;
    slaDueAt?: string | null;
  } | null;
}

export interface IncidentDetailDTO extends IncidentDTO {
  events: Array<{
    id: string;
    createdAt: string;
    actorType: string;
    eventType: string;
    eventPayload?: unknown;
    actorUser?: { id: string; name?: string | null; email?: string | null } | null;
  }>;
  evidence: Array<{
    id: string;
    storageKey?: string | null;
    fileType?: string | null;
    createdAt: string;
  }>;
  internalNotes?: string | null;
  resolutionSummary?: string | null;
  resolutionOutcome?: string | null;
}

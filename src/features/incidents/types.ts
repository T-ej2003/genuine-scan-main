export type IncidentFiltersState = {
  status: string;
  severity: string;
  search: string;
  dateFrom: string;
  dateTo: string;
  licenseeId: string;
};

export type IncidentUpdatePayload = {
  status: string;
  assignedToUserId: string;
  severity: string;
  internalNotes: string;
  resolutionSummary: string;
  resolutionOutcome: string;
  tags: string;
};

export type IncidentRow = {
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
};

export type IncidentDetail = IncidentRow & {
  events: Array<{
    id: string;
    createdAt: string;
    actorType: string;
    eventType: string;
    eventPayload?: any;
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
};

export type IncidentEmailDeliveryInfo = {
  delivered: boolean;
  providerMessageId?: string | null;
  attemptedFrom?: string | null;
  usedFrom?: string | null;
  replyTo?: string | null;
  senderMode?: "actor" | "system";
  error?: string | null;
};

export const INCIDENT_STATUS_TONE: Record<string, string> = {
  NEW: "border-red-200 bg-red-50 text-red-700",
  TRIAGED: "border-amber-200 bg-amber-50 text-amber-700",
  INVESTIGATING: "border-cyan-200 bg-cyan-50 text-cyan-700",
  AWAITING_CUSTOMER: "border-slate-300 bg-slate-100 text-slate-700",
  AWAITING_LICENSEE: "border-slate-300 bg-slate-100 text-slate-700",
  MITIGATED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  RESOLVED: "border-emerald-200 bg-emerald-50 text-emerald-700",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
  REJECTED_SPAM: "border-slate-300 bg-slate-100 text-slate-700",
};

export const INCIDENT_SEVERITY_TONE: Record<string, string> = {
  LOW: "border-emerald-200 bg-emerald-50 text-emerald-700",
  MEDIUM: "border-amber-200 bg-amber-50 text-amber-700",
  HIGH: "border-orange-200 bg-orange-50 text-orange-700",
  CRITICAL: "border-red-200 bg-red-50 text-red-700",
};

export const toIncidentLabel = (value: string) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());

export const incidentPayloadValueToText = (value: unknown): string => {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map((v) => String(v)).join(", ");
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${toIncidentLabel(k)} ${String(v)}`)
      .join(", ");
  }
  return String(value);
};

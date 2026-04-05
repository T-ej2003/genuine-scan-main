import type {
  SupportAssignee as RuntimeSupportAssignee,
  SupportIssueReport as RuntimeSupportIssueReport,
  SupportTicket as RuntimeSupportTicket,
  SupportTicketDetail as RuntimeSupportTicketDetail,
  SupportTicketMessage as RuntimeSupportTicketMessage,
} from "../../../shared/contracts/runtime/support.ts";

export type SupportTicket = RuntimeSupportTicket;
export type SupportTicketDetail = RuntimeSupportTicketDetail;
export type SupportTicketMessage = RuntimeSupportTicketMessage;
export type SupportIssueReport = RuntimeSupportIssueReport;
export type SupportAssignee = RuntimeSupportAssignee;

export type SupportTicketStatus = SupportTicket["status"];
export type SupportTicketPriority = SupportTicket["priority"];

export type SupportQueueFilters = {
  status: "all" | SupportTicketStatus;
  priority: "all" | SupportTicketPriority;
  search: string;
};

export const SUPPORT_STATUSES: SupportTicketStatus[] = [
  "OPEN",
  "IN_PROGRESS",
  "WAITING_CUSTOMER",
  "RESOLVED",
  "CLOSED",
];

export const SUPPORT_PRIORITIES: SupportTicketPriority[] = ["P1", "P2", "P3", "P4"];

export const STATUS_TONE: Record<string, string> = {
  OPEN: "border-slate-300 bg-slate-100 text-slate-700",
  IN_PROGRESS: "border-cyan-200 bg-cyan-50 text-cyan-800",
  WAITING_CUSTOMER: "border-amber-200 bg-amber-50 text-amber-800",
  RESOLVED: "border-emerald-200 bg-emerald-50 text-emerald-800",
  CLOSED: "border-slate-300 bg-slate-100 text-slate-700",
};

export const PRIORITY_TONE: Record<string, string> = {
  P1: "border-red-200 bg-red-50 text-red-700",
  P2: "border-orange-200 bg-orange-50 text-orange-700",
  P3: "border-amber-200 bg-amber-50 text-amber-700",
  P4: "border-emerald-200 bg-emerald-50 text-emerald-700",
};

export const toLabel = (value?: string | null) =>
  String(value || "")
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

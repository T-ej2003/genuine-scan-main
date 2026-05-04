import type { VerificationClassification } from "@/features/verify/verify-model";

const SUPPORT_STATUS_LABELS: Record<string, string> = {
  OPEN: "Needs review",
  IN_PROGRESS: "In progress",
  WAITING_CUSTOMER: "Waiting for customer",
  RESOLVED: "Resolved",
  CLOSED: "Closed",
};

const INCIDENT_STATUS_LABELS: Record<string, string> = {
  NEW: "Needs review",
  TRIAGED: "Reviewed",
  INVESTIGATING: "Investigating",
  AWAITING_CUSTOMER: "Waiting for customer",
  AWAITING_LICENSEE: "Waiting for brand owner",
  MITIGATED: "Risk reduced",
  RESOLVED: "Resolved",
  CLOSED: "Closed",
  REJECTED_SPAM: "Spam",
};

const INCIDENT_SEVERITY_LABELS: Record<string, string> = {
  LOW: "Low",
  MEDIUM: "Medium",
  HIGH: "High",
  CRITICAL: "Critical",
};

const INCIDENT_STAGE_LABELS: Record<string, string> = {
  INTAKE: "New report",
  REVIEW: "Review",
  CONTAINMENT: "Containment",
  DOCUMENTATION: "Documentation",
  RESOLUTION: "Resolution",
};

const VERIFICATION_COPY: Record<
  VerificationClassification,
  {
    title: string;
    subtitle: string;
    badge: string;
  }
> = {
  FIRST_SCAN: {
    title: "MSCQR confirmed this label",
    subtitle: "This is the first recorded customer-facing check for this code.",
    badge: "Confirmed",
  },
  LEGIT_REPEAT: {
    title: "This garment is genuine",
    subtitle: "This code has been checked before and the latest scan pattern did not require review.",
    badge: "Recorded",
  },
  SUSPICIOUS_DUPLICATE: {
    title: "We could not fully verify this item",
    subtitle: "This check does not match the usual pattern for this code.",
    badge: "Review",
  },
  BLOCKED_BY_SECURITY: {
    title: "Do not rely on this code",
    subtitle: "MSCQR security controls stopped this code from being accepted.",
    badge: "Blocked",
  },
  NOT_READY_FOR_CUSTOMER_USE: {
    title: "Not ready for customer verification",
    subtitle: "MSCQR has not released this code for customer-facing verification yet.",
    badge: "Not ready",
  },
  NOT_FOUND: {
    title: "Code not found",
    subtitle: "MSCQR could not find a live record for this code.",
    badge: "Not found",
  },
};

const humanize = (value?: string | null) =>
  String(value || "")
    .trim()
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (character) => character.toUpperCase());

export const getSupportStatusLabel = (value?: string | null) =>
  SUPPORT_STATUS_LABELS[String(value || "").trim().toUpperCase()] || humanize(value) || "Unknown";

export const getIncidentStatusLabel = (value?: string | null) =>
  INCIDENT_STATUS_LABELS[String(value || "").trim().toUpperCase()] || humanize(value) || "Unknown";

export const getIncidentSeverityLabel = (value?: string | null) =>
  INCIDENT_SEVERITY_LABELS[String(value || "").trim().toUpperCase()] || humanize(value) || "Unknown";

export const getIncidentStageLabel = (value?: string | null) =>
  INCIDENT_STAGE_LABELS[String(value || "").trim().toUpperCase()] || humanize(value) || "Unknown";

export const getVerificationCopy = (value: VerificationClassification) => VERIFICATION_COPY[value];

export const getPrinterHelperLabel = () => "printer helper";

export const getPlainPrintStatusLabel = (value?: string | null) => {
  const normalized = String(value || "").trim().toUpperCase();
  if (normalized === "PENDING") return "Queued";
  if (normalized === "SENT") return "Sent to printer";
  if (normalized === "PRINT_CONFIRMED") return "Printed";
  if (normalized === "FAILED") return "Needs attention";
  if (normalized === "CANCELLED") return "Cancelled";
  return humanize(value) || "Status unknown";
};

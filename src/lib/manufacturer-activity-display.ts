import { sanitizePrinterUiError } from "@/lib/printer-user-facing";
import { maskEmail, supportReferenceLabel } from "@/lib/audit-display";

type AuditActorLike = {
  name?: string | null;
  email?: string | null;
};

export type ManufacturerActivityCategory = "printing" | "batches" | "users" | "printer_setup" | "issues" | "workspace";
export type ManufacturerActivityTone = "success" | "warning" | "danger" | "neutral" | "progress";

export type ManufacturerActivityDisplay = {
  title: string;
  description: string;
  category: ManufacturerActivityCategory;
  tone: ManufacturerActivityTone;
  visible: boolean;
};

export type ManufacturerPrintHistoryRow = {
  id: string;
  batchName: string;
  runLabel: string;
  requestedLabels: number;
  printedLabels: number;
  remainingLabels: number | null;
  printerName: string;
  actorLabel: string;
  statusLabel: string;
  statusTone: ManufacturerActivityTone;
  timestamp: string | null;
  issue: string | null;
};

const detailsObject = (value: unknown): Record<string, any> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return value as Record<string, any>;
};

const safeText = (value: unknown, fallback = "") => {
  const text = String(value ?? "").replace(/\s+/g, " ").trim();
  if (!text) return fallback;
  if (/token|secret|cookie|password|renderurl|authorization/i.test(text)) return fallback;
  if (/https?:\/\//i.test(text)) return fallback;
  return text.slice(0, 140);
};

const numberValue = (value: unknown, fallback = 0) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
};

const compactRef = (value: unknown, prefix = "Run") => {
  const raw = safeText(value);
  if (!raw) return "";
  if (raw.length <= 18 && !raw.includes("-")) return raw;
  return supportReferenceLabel(raw, prefix);
};

const labelCount = (value: unknown) => Number(value || 0).toLocaleString();

const actorLabel = (actor?: AuditActorLike | null) => {
  if (actor?.name && actor?.email) return `${safeText(actor.name)} • ${maskEmail(actor.email)}`;
  if (actor?.name) return safeText(actor.name, "Workspace user");
  if (actor?.email) return maskEmail(actor.email);
  return "MSCQR workspace";
};

const batchContext = (details: Record<string, any>) => {
  const batchName = safeText(details.batchName || details.batch?.name || details.name);
  return batchName ? ` Batch: ${batchName}.` : "";
};

const printerContext = (details: Record<string, any>) => {
  const printerName = safeText(details.printerName || details.printer?.name || details.selectedPrinterName);
  return printerName ? ` Printer: ${printerName}.` : "";
};

const quantityContext = (details: Record<string, any>) => {
  const count = details.quantity || details.count || details.issuedCount || details.printedCodes || details.itemCount;
  return count ? ` Labels: ${labelCount(count)}.` : "";
};

const printIssueContext = (details: Record<string, any>) => {
  const reason = safeText(details.reason || details.failureReason || details.error || details.compatibilityReason || details.trustReason);
  return reason ? ` ${sanitizePrinterUiError(reason, "The printer needs attention before printing continues.")}` : "";
};

export const getManufacturerActivityDisplay = (log: {
  action?: string | null;
  details?: unknown;
  user?: AuditActorLike | null;
}): ManufacturerActivityDisplay => {
  const action = String(log.action || "").trim().toUpperCase();
  const details = detailsObject(log.details);
  const printer = printerContext(details);
  const batch = batchContext(details);
  const quantity = quantityContext(details);

  switch (action) {
    case "LOCAL_AGENT_PRINT_ITEM_ACKED":
      return {
        title: "Print job received by printer connector",
        description: `The printer connector accepted a label from this workstation.${printer}${batch}`,
        category: "printing",
        tone: "progress",
        visible: true,
      };
    case "LOCAL_AGENT_PRINT_ITEM_CONFIRMED":
    case "NETWORK_DIRECT_PRINT_ITEM_CONFIRMED":
    case "NETWORK_IPP_PRINT_ITEM_CONFIRMED":
    case "DIRECT_PRINT_ITEM_CONFIRMED":
      return {
        title: "Label print confirmed",
        description: `A label was confirmed as printed by the printer workflow.${printer}${batch}`,
        category: "printing",
        tone: "success",
        visible: true,
      };
    case "DIRECT_PRINT_ITEM_ISSUED":
      return {
        title: "Label sent to printer workflow",
        description: `MSCQR prepared one label for controlled printer dispatch.${printer}${batch}`,
        category: "printing",
        tone: "progress",
        visible: true,
      };
    case "DIRECT_PRINT_TOKEN_ISSUED":
      return {
        title: "Print run prepared",
        description: `MSCQR prepared a secure print run for this workspace.${quantity}${batch}`,
        category: "printing",
        tone: "progress",
        visible: true,
      };
    case "PRINTED":
    case "CONFIRM_PRINT":
    case "PRINT_CONFIRMED":
      return {
        title: "Labels marked printed",
        description: `Print progress was confirmed for assigned labels.${quantity}${batch}`,
        category: "printing",
        tone: "success",
        visible: true,
      };
    case "PRINTER_CONNECTION_COMPAT_MODE_ONLINE":
      return {
        title: "Printer connected while setup was still being verified",
        description: `The printer was detected before secure verification was fully complete.${printer}`,
        category: "printer_setup",
        tone: "warning",
        visible: true,
      };
    case "PRINTER_CONNECTION_TRUSTED_ONLINE":
      return {
        title: "Printer connected and ready",
        description: `The printer connection was verified for controlled printing.${printer}`,
        category: "printer_setup",
        tone: "success",
        visible: true,
      };
    case "PRINTER_CONNECTION_UNTRUSTED_OR_OFFLINE":
      return {
        title: "Printer connection needs attention",
        description: `The printer could not be verified for printing.${printIssueContext(details)}`,
        category: "issues",
        tone: "danger",
        visible: true,
      };
    case "PRINTER_LOCAL_AGENT_RELINKED":
      return {
        title: "Printer connector relinked",
        description: `This workstation printer was matched to its saved printer profile.${printer}`,
        category: "printer_setup",
        tone: "success",
        visible: true,
      };
    case "AUTH_LOGIN_SUCCESS":
    case "AUTH_LOGIN_SUCCESS_RECENT_ADMIN_MFA":
      return {
        title: "User signed in",
        description: `${actorLabel(log.user)} signed in to the manufacturer workspace.`,
        category: "users",
        tone: "success",
        visible: true,
      };
    case "AUTH_LOGOUT":
      return {
        title: "User signed out",
        description: `${actorLabel(log.user)} signed out of the manufacturer workspace.`,
        category: "users",
        tone: "neutral",
        visible: true,
      };
    case "AUTH_LOGIN_FAIL":
    case "AUTH_LOGIN_LOCKED":
    case "AUTH_LOGIN_BLOCKED_RISK":
      return {
        title: "Sign-in attempt needs review",
        description: "A sign-in attempt was blocked or could not be completed.",
        category: "issues",
        tone: "warning",
        visible: true,
      };
    case "CREATE_BATCH":
    case "CREATE_PRODUCT_BATCH":
      return {
        title: "Batch created",
        description: `A label batch was added to the workspace.${quantity}${batch}`,
        category: "batches",
        tone: "success",
        visible: true,
      };
    case "ASSIGN_MANUFACTURER":
    case "ASSIGN_PRODUCT_BATCH_MANUFACTURER":
    case "ALLOCATE_QR_RANGE":
    case "ALLOCATE_QR_RANGE_LICENSEE":
      return {
        title: "Labels assigned for production",
        description: `Labels were assigned or updated for production.${quantity}${batch}`,
        category: "batches",
        tone: "progress",
        visible: true,
      };
    default:
      if (action.includes("PRINT") || action.includes("PRINTER")) {
        return {
          title: "Printing activity",
          description: `A printer or label update was recorded for this workspace.${printer}${batch}`,
          category: "printing",
          tone: action.includes("FAIL") || action.includes("ERROR") ? "warning" : "neutral",
          visible: true,
        };
      }
      if (action.includes("BATCH") || action.includes("QR") || action.includes("LABEL")) {
        return {
          title: "Batch activity",
          description: `A batch or label update was recorded for this workspace.${batch}${quantity}`,
          category: "batches",
          tone: "neutral",
          visible: true,
        };
      }
      if (action.includes("AUTH") || action.includes("LOGIN") || action.includes("USER")) {
        return {
          title: "User activity",
          description: "A user access update was recorded for this workspace.",
          category: "users",
          tone: "neutral",
          visible: true,
        };
      }
      return {
        title: "Workspace activity",
        description: "A workspace update was recorded. No action is needed unless this appears with a warning.",
        category: "workspace",
        tone: "neutral",
        visible: true,
      };
  }
};

export const getManufacturerActivityToneClass = (tone: ManufacturerActivityTone) => {
  switch (tone) {
    case "success":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "warning":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "danger":
      return "border-red-200 bg-red-50 text-red-700";
    case "progress":
      return "border-cyan-200 bg-cyan-50 text-cyan-700";
    default:
      return "border-slate-200 bg-slate-50 text-slate-700";
  }
};

export const buildManufacturerActivitySearchText = (
  log: { action?: string | null; details?: unknown; user?: AuditActorLike | null },
  display = getManufacturerActivityDisplay(log)
) => {
  const details = detailsObject(log.details);
  return [
    display.title,
    display.description,
    display.category,
    actorLabel(log.user),
    safeText(details.batchName || details.batch?.name || details.name),
    safeText(details.printerName || details.printer?.name || details.selectedPrinterName),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
};

export const buildManufacturerPrintHistoryRow = (job: Record<string, any>): ManufacturerPrintHistoryRow => {
  const session = detailsObject(job.session);
  const requestedLabels = numberValue(job.itemCount, numberValue(job.quantity));
  const printedLabels = numberValue(session.confirmedItems);
  const remainingLabels =
    typeof session.remainingToPrint === "number" ? numberValue(session.remainingToPrint) : Math.max(requestedLabels - printedLabels, 0);
  const status = String(job.status || "").toUpperCase();
  const pipelineState = String(job.pipelineState || "").toUpperCase();
  const issue = safeText(job.failureReason || job.confirmationFailureReason || session.failedReason);

  let statusLabel = "In progress";
  let statusTone: ManufacturerActivityTone = "progress";
  if (status === "CONFIRMED" || pipelineState === "PRINT_CONFIRMED") {
    statusLabel = remainingLabels > 0 ? "Partially completed" : "Completed";
    statusTone = remainingLabels > 0 ? "warning" : "success";
  } else if (status === "FAILED" || pipelineState === "FAILED") {
    statusLabel = printedLabels > 0 ? "Partially completed" : "Failed";
    statusTone = "danger";
  } else if (pipelineState === "NEEDS_OPERATOR_ACTION" || job.awaitingConfirmation) {
    statusLabel = "Recovery needed";
    statusTone = "warning";
  } else if (status === "CANCELLED") {
    statusLabel = "Cancelled";
    statusTone = "neutral";
  } else if (status === "SENT") {
    statusLabel = "Sent to printer";
    statusTone = "progress";
  } else if (status === "PENDING") {
    statusLabel = "Queued";
    statusTone = "progress";
  }

  const actor = job.createdBy || job.createdByUser || job.user || job.operator || null;

  return {
    id: String(job.id || job.jobNumber || "print-job"),
    batchName: safeText(job.batch?.name, "Unassigned batch"),
    runLabel: safeText(job.jobNumber, compactRef(job.id, "Run") || "Print run"),
    requestedLabels,
    printedLabels,
    remainingLabels: Number.isFinite(remainingLabels) ? remainingLabels : null,
    printerName: safeText(job.printer?.name, "Printer not recorded"),
    actorLabel: actor ? actorLabel(actor) : "Operator not included",
    statusLabel,
    statusTone,
    timestamp: safeText(job.completedAt || job.confirmedAt || job.sentAt || job.createdAt, "") || null,
    issue: issue ? sanitizePrinterUiError(issue, "This print run needs attention.") : null,
  };
};

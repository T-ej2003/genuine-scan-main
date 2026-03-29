import type { LocalPrinterAgentSnapshot, PrinterConnectionStatusLike } from "@/lib/printer-diagnostics";

type ManagedPrinterSummary = {
  name?: string | null;
  connectionType?: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY" | string | null;
};

const normalize = (value?: string | null) => String(value || "").trim();

const hasAny = (value: string, patterns: string[]) => patterns.some((pattern) => value.includes(pattern));

const toPlainPrinterSupportText = (raw?: string | null, fallback = "Printing needs review.") => {
  const original = normalize(raw);
  if (!original) return fallback;

  return original
    .replace(/workstation connector/gi, "printer helper")
    .replace(/printing connector on this workstation/gi, "printer helper on this computer")
    .replace(/printing connector/gi, "printer helper")
    .replace(/local print agent/gi, "printer helper")
    .replace(/workstation/gi, "this computer");
};

export const sanitizePrinterUiError = (raw?: string | null, fallback = "Printing is unavailable right now.") => {
  const original = normalize(raw);
  if (!original) return fallback;

  const value = original.toLowerCase();

  if (
    hasAny(value, [
      "unique constraint failed",
      "duplicate key",
      "already exists for this endpoint",
      "already exists for this printer uri",
      "p2002",
    ])
  ) {
    return "A saved printer profile already uses this connection. Open the existing setup to edit it or remove it first.";
  }
  if (hasAny(value, ["busy", "conflict", "please retry"])) {
    return "Another printing action is already using this batch. Please wait a moment and try again.";
  }
  if (hasAny(value, ["127.0.0.1", "localhost", "local print agent", "printer switch failed", "calibration failed"])) {
    return "The printer helper is not available on this computer right now.";
  }
  if (hasAny(value, ["mtls client certificate fingerprint header missing", "compatibility mode active"])) {
    return "Advanced secure printer verification is not set up yet. Printing can stay available while setup finishes.";
  }
  if (hasAny(value, ["mismatch", "not approved for this printer"]) && hasAny(value, ["fingerprint", "certificate", "mtls"])) {
    return "MSCQR and the printer helper are not using the same approved secure printer identity yet.";
  }
  if (hasAny(value, ["heartbeat", "trust", "attestation", "signature", "fingerprint", "certificate", "mtls"])) {
    return "MSCQR is still checking the secure printer connection. Refresh and try again in a moment.";
  }
  if (hasAny(value, ["gateway", "private-lan"]) && hasAny(value, ["offline", "credentials", "missing"])) {
    return "The site print link needs attention before this printer can be used.";
  }
  if (hasAny(value, ["application/pdf", "pdf is not advertised", "format unsupported"])) {
    return "This office printer does not support the required MSCQR print format.";
  }
  if (hasAny(value, ["ipp", "ipps"]) && hasAny(value, ["unreachable", "validation failed", "not reachable"])) {
    return "The saved office printer could not be reached. Check the printer connection and try again.";
  }
  if (hasAny(value, ["tcp", "socket", "host and port", "9100", "jetdirect", "network-direct"])) {
    return "The saved factory printer could not be reached. Check the printer or network connection and try again.";
  }
  if (hasAny(value, ["command language", "zpl", "tspl", "epl", "cpcl", "sbpl", "esc/pos", "esc_pos"])) {
    return "This printer profile needs a compatible setup before it can be used.";
  }
  if (hasAny(value, ["token", "payload", "print item", "issued", "agent_acked", "print session"])) {
    return "This print session changed while printing. Start a fresh print job and try again.";
  }
  if (hasAny(value, ["http 5", "internal server error", "server error"])) {
    return "Printing is temporarily unavailable. Please try again.";
  }
  if (value === "network error - is the backend running?") {
    return "Could not reach MSCQR. Please check the connection and try again.";
  }
  if (value === "request timed out") {
    return "The request took too long. Please try again.";
  }

  return fallback;
};

export const getPrinterProfileLabel = (printer?: ManagedPrinterSummary | null) => {
  if (!printer) return "printer";
  if (printer.connectionType === "NETWORK_DIRECT") return "saved label printer";
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? "saved site printer" : "saved office printer";
  }
  return "printer on this computer";
};

export const getPrinterDispatchLabel = (printer?: ManagedPrinterSummary | null) => {
  if (!printer) return "Printer on this computer";
  if (printer.connectionType === "NETWORK_DIRECT") return "Saved label printer";
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? "Saved site printer" : "Saved office printer";
  }
  return "Printer on this computer";
};

export const buildPrinterSupportSummary = (params: {
  localAgent: LocalPrinterAgentSnapshot;
  remoteStatus?: PrinterConnectionStatusLike | null;
  selectedPrinterName?: string | null;
  printerSummaryTitle: string;
  printerSummaryBody: string;
  managedPrinter?: ManagedPrinterSummary | null;
}) => {
  const lines = [
    "MSCQR printing support summary",
    `Generated: ${new Date().toISOString()}`,
    `Printer helper: ${params.localAgent.reachable ? "Online" : "Offline"}`,
    `Printer found on this computer: ${params.localAgent.connected ? "Yes" : "No"}`,
    `Selected printer: ${normalize(params.selectedPrinterName) || "Not selected"}`,
    `Current status: ${toPlainPrinterSupportText(params.printerSummaryTitle, "Printing needs review")}`,
    `What the user sees: ${toPlainPrinterSupportText(
      params.printerSummaryBody,
      "MSCQR is still checking the printer connection on this computer."
    )}`,
  ];

  if (params.managedPrinter?.name) {
    lines.push(`Saved printer: ${params.managedPrinter.name}`);
    lines.push(`Saved printer type: ${getPrinterDispatchLabel(params.managedPrinter)}`);
  }

  const remote = params.remoteStatus;
  if (remote?.lastHeartbeatAt) {
    lines.push(`Last cloud check: ${remote.lastHeartbeatAt}`);
  }

  return lines.join("\n");
};

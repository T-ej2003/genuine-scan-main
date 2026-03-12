import type { LocalPrinterAgentSnapshot, PrinterConnectionStatusLike } from "@/lib/printer-diagnostics";

type ManagedPrinterSummary = {
  name?: string | null;
  connectionType?: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY" | string | null;
};

const normalize = (value?: string | null) => String(value || "").trim();

const hasAny = (value: string, patterns: string[]) => patterns.some((pattern) => value.includes(pattern));

export const sanitizePrinterUiError = (raw?: string | null, fallback = "Printing is unavailable right now.") => {
  const original = normalize(raw);
  if (!original) return fallback;

  const value = original.toLowerCase();

  if (hasAny(value, ["busy", "conflict", "please retry"])) {
    return "Another printing action is already using this batch. Please wait a moment and try again.";
  }
  if (hasAny(value, ["127.0.0.1", "localhost", "local print agent", "printer switch failed", "calibration failed"])) {
    return "The workstation connector is not available on this device right now.";
  }
  if (hasAny(value, ["heartbeat", "trust", "attestation", "signature", "fingerprint", "certificate", "mtls"])) {
    return "The secure printer connection is not ready yet. Refresh and try again in a moment.";
  }
  if (hasAny(value, ["gateway", "private-lan"]) && hasAny(value, ["offline", "credentials", "missing"])) {
    return "The site print connector needs attention before this printer can be used.";
  }
  if (hasAny(value, ["application/pdf", "pdf is not advertised", "format unsupported"])) {
    return "This office printer does not support the required MSCQR print format.";
  }
  if (hasAny(value, ["ipp", "ipps"]) && hasAny(value, ["unreachable", "validation failed", "not reachable"])) {
    return "The saved office printer could not be reached. Check the printer setup and try again.";
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
  if (printer.connectionType === "NETWORK_DIRECT") return "factory label printer";
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? "private site printer" : "office printer";
  }
  return "workstation printer";
};

export const getPrinterDispatchLabel = (printer?: ManagedPrinterSummary | null) => {
  if (!printer) return "Workstation printing";
  if (printer.connectionType === "NETWORK_DIRECT") return "Factory label printer";
  if (printer.connectionType === "NETWORK_IPP") {
    return printer.deliveryMode === "SITE_GATEWAY" ? "Private site printer" : "Office / AirPrint printer";
  }
  return "Workstation printer";
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
    `Workstation connector: ${params.localAgent.reachable ? "Online" : "Offline"}`,
    `Printer detected on workstation: ${params.localAgent.connected ? "Yes" : "No"}`,
    `Selected printer: ${normalize(params.selectedPrinterName) || "Not selected"}`,
    `Current status: ${params.printerSummaryTitle}`,
    `What the user sees: ${params.printerSummaryBody}`,
  ];

  if (params.managedPrinter?.name) {
    lines.push(`Managed printer profile: ${params.managedPrinter.name}`);
    lines.push(`Managed printer type: ${getPrinterDispatchLabel(params.managedPrinter)}`);
  }

  const remote = params.remoteStatus;
  if (remote?.lastHeartbeatAt) {
    lines.push(`Last cloud check: ${remote.lastHeartbeatAt}`);
  }

  return lines.join("\n");
};

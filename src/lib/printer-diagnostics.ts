import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

export type PrinterInventoryRow = {
  printerId: string;
  printerName: string;
  model?: string | null;
  connection?: string | null;
  online?: boolean;
  isDefault?: boolean;
  protocols?: string[];
  languages?: string[];
  mediaSizes?: string[];
  dpi?: number | null;
  deviceUri?: string | null;
  portName?: string | null;
};

export type ManagedPrinterAutoDetectSuggestion = {
  routeType: "LOCAL_ONLY" | "NETWORK_DIRECT" | "NETWORK_IPP";
  readiness: "READY" | "NEEDS_DETAILS";
  summary: string;
  detail: string;
  host?: string | null;
  port?: number | null;
  resourcePath?: string | null;
  tlsEnabled?: boolean | null;
  printerUri?: string | null;
  commandLanguage?: "ZPL" | "TSPL" | "EPL" | "CPCL" | null;
};

export type PrinterConnectionStatusLike = {
  connected: boolean;
  trusted: boolean;
  compatibilityMode: boolean;
  degraded?: boolean;
  compatibilityReason?: string | null;
  eligibleForPrinting: boolean;
  connectionClass?: "TRUSTED" | "COMPATIBILITY" | "BLOCKED";
  stale: boolean;
  trustStatus?: string;
  trustReason?: string | null;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  printerName?: string | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  printers?: PrinterInventoryRow[];
  error?: string | null;
};

export type LocalPrinterAgentSnapshot = {
  reachable: boolean;
  connected: boolean;
  error?: string | null;
  checkedAt?: string | null;
};

export type PrinterDiagnosticState =
  | "trusted_ready"
  | "compatibility_ready"
  | "agent_unreachable"
  | "no_printers_detected"
  | "printer_offline"
  | "selection_required"
  | "heartbeat_stale"
  | "server_sync_pending"
  | "trust_blocked";

export type PrinterDiagnosticSummary = {
  state: PrinterDiagnosticState;
  badgeLabel: string;
  title: string;
  summary: string;
  detail: string;
  tone: "success" | "warning" | "neutral" | "danger";
  nextSteps: string[];
  selectedPrinter: PrinterInventoryRow | null;
};

export type NetworkDirectPrinterSummaryLike = {
  id?: string | null;
  name?: string | null;
  isActive?: boolean;
  isDefault?: boolean;
  connectionType?: "LOCAL_AGENT" | "NETWORK_DIRECT" | "NETWORK_IPP" | string | null;
  commandLanguage?: string | null;
  deliveryMode?: "DIRECT" | "SITE_GATEWAY" | string | null;
  registryStatus?: {
    state: "READY" | "ATTENTION" | "OFFLINE" | "BLOCKED";
    summary: string;
    detail?: string | null;
  } | null;
} | null;

const hasAny = (value: string, needles: string[]) => needles.some((needle) => value.includes(needle));
const toUpperList = (values: string[] | null | undefined) =>
  Array.isArray(values) ? values.map((value) => String(value || "").trim().toUpperCase()).filter(Boolean) : [];
const toCleanString = (value: unknown, max = 512) => String(value || "").trim().slice(0, max);
const SUPPORTED_NETWORK_DIRECT_LANGUAGES = ["ZPL", "TSPL", "EPL", "CPCL"] as const;

const normalizeResourcePath = (value?: string | null) => {
  const trimmed = toCleanString(value, 256);
  if (!trimmed || trimmed === "/") return "/ipp/print";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
};

const parseSocketEndpoint = (value?: string | null) => {
  const raw = toCleanString(value, 512);
  if (!/^socket:\/\//i.test(raw)) return null;
  try {
    const parsed = new URL(raw);
    if (!parsed.hostname) return null;
    return {
      host: parsed.hostname,
      port: Number(parsed.port || 9100) || 9100,
    };
  } catch {
    return null;
  }
};

const parseIppEndpoint = (value?: string | null) => {
  const raw = toCleanString(value, 512);
  if (!/^ipps?:\/\//i.test(raw)) return null;
  try {
    const parsed = new URL(raw.replace(/^ipp:\/\//i, "http://").replace(/^ipps:\/\//i, "https://"));
    const tlsEnabled = raw.toLowerCase().startsWith("ipps://") || parsed.protocol === "https:";
    const port = Number(parsed.port || 631) || 631;
    const resourcePath = normalizeResourcePath(parsed.pathname);
    const scheme = tlsEnabled ? "ipps" : "ipp";
    return {
      host: parsed.hostname,
      port,
      resourcePath,
      tlsEnabled,
      printerUri: `${scheme}://${parsed.hostname}:${port}${resourcePath}`,
    };
  } catch {
    return null;
  }
};

const parseWindowsRawEndpoint = (value?: string | null) => {
  const raw = toCleanString(value, 180);
  if (!raw) return null;
  if (/^ipps?:\/\//i.test(raw)) return null;
  const direct = raw.match(/^IP_([^_]+)$/i);
  if (direct) {
    return {
      host: direct[1],
      port: 9100,
    };
  }
  const embedded = raw.match(/^([^:]+):(\d{2,5})$/);
  if (embedded) {
    return {
      host: embedded[1],
      port: Number(embedded[2]) || 9100,
    };
  }
  return null;
};

const pickSupportedNetworkLanguage = (printer: PrinterInventoryRow) => {
  const languages = toUpperList(printer.languages);
  return (
    SUPPORTED_NETWORK_DIRECT_LANGUAGES.find((language) => languages.includes(language)) ||
    null
  );
};

export const normalizePrinterInventoryRows = (rows: unknown): PrinterInventoryRow[] => {
  if (!Array.isArray(rows)) return [];
  const result: PrinterInventoryRow[] = [];
  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const printerId = String((row as any).printerId || (row as any).id || "").trim();
    const printerName = String((row as any).printerName || (row as any).name || "").trim();
    if (!printerId || !printerName) continue;
    result.push({
      printerId,
      printerName,
      model: String((row as any).model || "").trim() || null,
      connection: String((row as any).connection || (row as any).transport || "").trim() || null,
      online: typeof (row as any).online === "boolean" ? Boolean((row as any).online) : true,
      isDefault: Boolean((row as any).isDefault),
      protocols: Array.isArray((row as any).protocols) ? (row as any).protocols : [],
      languages: Array.isArray((row as any).languages) ? (row as any).languages : [],
      mediaSizes: Array.isArray((row as any).mediaSizes) ? (row as any).mediaSizes : [],
      dpi: Number.isFinite(Number((row as any).dpi)) ? Number((row as any).dpi) : null,
      deviceUri: toCleanString((row as any).deviceUri, 512) || null,
      portName: toCleanString((row as any).portName, 180) || null,
    });
    if (result.length >= 40) break;
  }
  return result;
};

export const deriveManagedPrinterAutoDetect = (
  printer: PrinterInventoryRow
): ManagedPrinterAutoDetectSuggestion => {
  const protocols = toUpperList(printer.protocols);
  const connection = toCleanString(printer.connection, 80).toLowerCase();
  const deviceUri = toCleanString(printer.deviceUri, 512);
  const portName = toCleanString(printer.portName, 180);
  const supportedLanguage = pickSupportedNetworkLanguage(printer);

  const ippEndpoint = parseIppEndpoint(deviceUri) || parseIppEndpoint(portName);
  if (ippEndpoint) {
    return {
      routeType: "NETWORK_IPP",
      readiness: "READY",
      summary: "Detected as IPP/IPPS printer",
      detail: `MSCQR can prefill a managed IPP route for ${printer.printerName}.`,
      host: ippEndpoint.host,
      port: ippEndpoint.port,
      resourcePath: ippEndpoint.resourcePath,
      tlsEnabled: ippEndpoint.tlsEnabled,
      printerUri: ippEndpoint.printerUri,
      commandLanguage: null,
    };
  }

  const rawEndpoint = parseSocketEndpoint(deviceUri) || parseWindowsRawEndpoint(portName);
  if (rawEndpoint) {
    return {
      routeType: "NETWORK_DIRECT",
      readiness: supportedLanguage ? "READY" : "NEEDS_DETAILS",
      summary: supportedLanguage ? "Detected as raw TCP label printer" : "Detected as raw TCP network printer",
      detail: supportedLanguage
        ? `MSCQR can prefill a managed ${supportedLanguage} route for ${printer.printerName}.`
        : "The connector found a raw TCP endpoint, but you still need to confirm the printer language before saving.",
      host: rawEndpoint.host,
      port: rawEndpoint.port,
      commandLanguage: supportedLanguage,
    };
  }

  if (protocols.includes("IPP") || protocols.includes("IPPS") || connection === "ipp" || connection === "ipps" || connection === "bonjour") {
    return {
      routeType: "NETWORK_IPP",
      readiness: "NEEDS_DETAILS",
      summary: "Detected as AirPrint / IPP printer",
      detail:
        "The connector can see an IPP-capable printer, but MSCQR still needs a stable host or printer URI before it can save a managed route.",
      tlsEnabled: protocols.includes("IPPS") || connection === "ipps",
    };
  }

  if (
    supportedLanguage &&
    (protocols.includes("RAW-9100") || protocols.includes("TCP") || connection === "network")
  ) {
    return {
      routeType: "NETWORK_DIRECT",
      readiness: "NEEDS_DETAILS",
      summary: "Detected as network label printer",
      detail:
        "The connector can see a supported label printer language, but you still need to confirm the raw TCP host or port before saving a managed route.",
      commandLanguage: supportedLanguage,
    };
  }

  return {
    routeType: "LOCAL_ONLY",
    readiness: "NEEDS_DETAILS",
    summary: "Detected as workstation-managed printer",
    detail:
      "This printer is visible to the workstation connector, but it does not expose enough network details for a managed MSCQR route. Keep it on LOCAL_AGENT or enter a managed endpoint manually.",
    commandLanguage: supportedLanguage,
  };
};

export const getPrinterDiagnosticSummary = (params: {
  localAgent: LocalPrinterAgentSnapshot;
  remoteStatus?: PrinterConnectionStatusLike | null;
  printers?: PrinterInventoryRow[];
  selectedPrinterId?: string | null;
}): PrinterDiagnosticSummary => {
  const remote = params.remoteStatus || null;
  const printers = Array.isArray(params.printers) ? params.printers : [];
  const selectedPrinterId = String(
    params.selectedPrinterId || remote?.selectedPrinterId || remote?.printerId || printers.find((row) => row.isDefault)?.printerId || ""
  ).trim();
  const selectedPrinter =
    printers.find((row) => row.printerId === selectedPrinterId) ||
    printers.find((row) => row.isDefault) ||
    printers[0] ||
    null;

  if (remote?.connected && remote?.eligibleForPrinting && remote?.trusted) {
    return {
      state: "trusted_ready",
      badgeLabel: "Ready",
      title: "Printer ready",
      summary: `${remote.selectedPrinterName || remote.printerName || selectedPrinter?.printerName || "Selected printer"} is connected and ready to print.`,
      detail: "The workstation connector and MSCQR are both ready for this printer.",
      tone: "success",
      nextSteps: [
        "Continue to the batch workflow when you are ready to print.",
        "If output alignment changes, review the printer settings before the next run.",
      ],
      selectedPrinter,
    };
  }

  if (remote?.connected && remote?.eligibleForPrinting && remote?.compatibilityMode) {
    return {
      state: "compatibility_ready",
      badgeLabel: "Ready",
      title: "Printer ready",
      summary: `${remote.selectedPrinterName || remote.printerName || selectedPrinter?.printerName || "Selected printer"} is connected and can be used.`,
      detail: sanitizePrinterUiError(remote.compatibilityReason || remote.error || remote.trustReason, "The secure connection is still finishing setup."),
      tone: "warning",
      nextSteps: [
        "You can continue printing if this is the expected setup.",
        "If this state does not clear, ask your setup team to review the printer connection.",
      ],
      selectedPrinter,
    };
  }

  if (!params.localAgent.reachable) {
    return {
      state: "agent_unreachable",
      badgeLabel: "Connector offline",
      title: "Workstation connector is not available",
      summary: "MSCQR could not reach the printing connector on this workstation.",
      detail: sanitizePrinterUiError(params.localAgent.error, "The workstation connector is unavailable."),
      tone: "danger",
      nextSteps: [
        "Make sure the workstation connector is installed and running on this device.",
        "Refresh this page after the connector and printer are ready.",
      ],
      selectedPrinter,
    };
  }

  if (printers.length === 0) {
    return {
      state: "no_printers_detected",
      badgeLabel: "No printer",
      title: "No printer connection detected",
      summary: "MSCQR can reach the workstation connector, but no usable printer was detected.",
      detail: sanitizePrinterUiError(params.localAgent.error || remote?.error, "No printers were reported by the workstation connector."),
      tone: "neutral",
      nextSteps: [
        "Check the operating system printer list and driver installation.",
        "Reconnect or power on the printer, then refresh this page.",
      ],
      selectedPrinter,
    };
  }

  if (!selectedPrinterId && printers.length > 1) {
    return {
      state: "selection_required",
      badgeLabel: "Select printer",
      title: "Choose the active printer",
      summary: "Multiple printers are available and no active printer is selected yet.",
      detail: "Choose the printer you want MSCQR to use before starting a print job.",
      tone: "warning",
      nextSteps: [
        "Pick the target printer from this page or from the print dialog.",
        "Refresh status after selecting the correct printer.",
      ],
      selectedPrinter,
    };
  }

  if (selectedPrinter?.online === false) {
    return {
      state: "printer_offline",
      badgeLabel: "Printer offline",
      title: "Selected printer is offline",
      summary: `${selectedPrinter.printerName} is known to the local agent but is currently offline.`,
      detail: sanitizePrinterUiError(remote?.error || remote?.trustReason, "The printer is configured but is not ready for active jobs."),
      tone: "danger",
      nextSteps: [
        "Power on the printer and clear any paper, toner, label, or queue issue.",
        "Refresh this page after the printer returns online.",
      ],
      selectedPrinter,
    };
  }

  if (remote?.stale) {
    return {
      state: "heartbeat_stale",
      badgeLabel: "Check connection",
      title: "Printer status needs a refresh",
      summary: "A printer was detected, but MSCQR needs a fresh connection update before printing.",
      detail: sanitizePrinterUiError(remote.error || remote.trustReason, "MSCQR has not received a fresh printer update yet."),
      tone: "warning",
      nextSteps: [
        "Keep the workstation connector running on this device.",
        "Refresh this page and confirm the printer becomes ready again.",
      ],
      selectedPrinter,
    };
  }

  const remoteError = `${String(remote?.error || "")} ${String(remote?.trustReason || "")}`.toLowerCase();
  const remotePending =
    String(remote?.trustStatus || "").toUpperCase() === "UNREGISTERED" ||
    String(remote?.trustStatus || "").toUpperCase() === "PENDING" ||
    hasAny(remoteError, ["no printer registration", "no printer attestation yet", "missing signature identity"]);

  if (remotePending) {
    return {
      state: "server_sync_pending",
      badgeLabel: "Preparing",
      title: "Printer detected, finishing setup",
      summary: `${selectedPrinter?.printerName || remote?.selectedPrinterName || remote?.printerName || "Printer"} is visible on this device, but MSCQR is still finishing its setup.`,
      detail: sanitizePrinterUiError(remote?.error || remote?.trustReason, "MSCQR is still syncing this printer connection."),
      tone: "warning",
      nextSteps: [
        "Keep the workstation connector running and refresh this page.",
        "If this persists, contact your setup or support team.",
      ],
      selectedPrinter,
    };
  }

  return {
    state: "trust_blocked",
    badgeLabel: "Needs attention",
    title: "Printer connection needs attention",
    summary: `${selectedPrinter?.printerName || remote?.selectedPrinterName || remote?.printerName || "Selected printer"} is visible, but MSCQR cannot use it yet.`,
    detail: sanitizePrinterUiError(remote?.error || remote?.trustReason, "This printer connection needs support attention before printing."),
    tone: "danger",
    nextSteps: [
      "Review the printer connection and connector status before retrying.",
      "If needed, send a support summary to your support team.",
    ],
    selectedPrinter,
  };
};

export const shouldPreferNetworkDirectSummary = (params: {
  printers?: PrinterInventoryRow[];
  networkPrinter?: NetworkDirectPrinterSummaryLike;
}) => {
  const printers = Array.isArray(params.printers) ? params.printers : [];
  return Boolean(params.networkPrinter) && printers.length === 0;
};

export const selectPreferredManagedPrinter = <T extends NetworkDirectPrinterSummaryLike | null>(
  printers?: T[] | null
): Exclude<T, null> | null => {
  const activePrinters = (Array.isArray(printers) ? printers : []).filter(
    (printer): printer is Exclude<T, null> => {
      if (!printer) return false;
      return printer.connectionType !== "LOCAL_AGENT" && printer.isActive !== false;
    }
  );
  return (
    activePrinters.find((printer) => printer.isDefault) ||
    activePrinters.find((printer) => printer.registryStatus?.state === "READY") ||
    activePrinters[0] ||
    null
  );
};

export const getManagedPrinterDiagnosticSummary = (
  printer?: NetworkDirectPrinterSummaryLike | null
): PrinterDiagnosticSummary | null => {
  if (!printer) return null;

  const networkLabel =
    printer.connectionType === "NETWORK_IPP"
      ? printer.deliveryMode === "SITE_GATEWAY"
        ? "Private site printer"
        : "Office printer"
      : "Factory printer";
  const printerName = String(printer.name || networkLabel).trim() || networkLabel;
  const pseudoPrinter: PrinterInventoryRow = {
    printerId: String(printer.id || printerName).trim() || printerName,
    printerName,
    model: null,
    connection: String(printer.connectionType || "").trim() || null,
    online: printer.registryStatus?.state !== "OFFLINE",
    isDefault: Boolean(printer.isDefault),
    protocols: printer.connectionType === "NETWORK_IPP" ? [printer.deliveryMode === "SITE_GATEWAY" ? "ipps" : "ipp"] : [],
    languages: printer.connectionType === "NETWORK_IPP" ? ["PDF"] : [String(printer.commandLanguage || "AUTO")],
    mediaSizes: [],
    dpi: null,
  };

  if (printer.registryStatus?.state === "READY") {
    return {
      state: "compatibility_ready",
      badgeLabel: "Ready",
      title: `${networkLabel} ready`,
      summary: `${printerName} is registered and ready for controlled dispatch.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "This saved printer has already been checked and is ready."
      ),
      tone: "success",
      nextSteps: [
        "Open the batch workflow and choose this managed printer profile.",
        "If this route changes later, ask an admin to revalidate it before the next run.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  if (printer.registryStatus?.state === "ATTENTION") {
    return {
      state: "server_sync_pending",
      badgeLabel: "Needs validation",
      title: `${networkLabel} needs validation`,
      summary: `${printerName} is registered, but readiness still needs a live check.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Run a printer check to confirm this setup is ready."
      ),
      tone: "warning",
      nextSteps: [
        "Confirm the printer or site connector is online.",
        "Ask an admin to validate this saved printer route before printing.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  if (printer.registryStatus?.state === "BLOCKED") {
    return {
      state: "trust_blocked",
      badgeLabel: "Blocked",
      title: `${networkLabel} is blocked`,
      summary: `${printerName} cannot be used in its current configuration.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Review the saved printer route, then validate it again."
      ),
      tone: "danger",
      nextSteps: [
        "Update the managed printer profile.",
        "Validate it again after correcting the endpoint or language.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  if (printer.registryStatus?.state === "OFFLINE") {
    return {
      state: "printer_offline",
      badgeLabel: "Offline",
      title: `${networkLabel} is unreachable`,
      summary: `${printerName} is registered, but it is not reachable right now.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Bring the printer or site connector online, then run Check again."
      ),
      tone: "danger",
      nextSteps: [
        "Bring the printer or site connector online.",
        "Run Check again once the managed route is reachable.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  return {
    state: "server_sync_pending",
    badgeLabel: "Preparing",
    title: `${networkLabel} setup in progress`,
    summary: `${printerName} has been saved, but MSCQR still needs a live readiness check.`,
    detail: "Open the managed printer dialog and run Check to confirm the route end to end.",
    tone: "warning",
    nextSteps: [
      "Complete the profile details and run Check.",
      "Use the batch workflow once the managed route shows Ready.",
    ],
    selectedPrinter: pseudoPrinter,
  };
};

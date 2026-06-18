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
  windowsPortName?: string | null;
  windowsPortHost?: string | null;
  windowsPortNumber?: number | null;
  queueStatus?: string | null;
  queueHasErrors?: boolean;
  stuckJobCount?: number;
  retainedJobCount?: number;
  usbAvailable?: boolean;
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
  protocolVersion?: string | null;
  buildVersion?: string | null;
  connectorUpdateRequired?: boolean;
  printers?: PrinterInventoryRow[];
  error?: string | null;
  refreshPaused?: boolean;
  rateLimited?: boolean;
  notice?: string | null;
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
  | "trust_blocked"
  | "connector_update_required"
  | "blocked_with_alternative";

export type PrinterDiagnosticSummary = {
  state: PrinterDiagnosticState;
  badgeLabel: string;
  title: string;
  summary: string;
  detail: string;
  tone: "success" | "warning" | "neutral" | "danger";
  nextSteps: string[];
  selectedPrinter: PrinterInventoryRow | null;
  recommendedPrinter?: PrinterInventoryRow | null;
};

export type PrinterReadinessDisplay = {
  modeLabel: "Ready" | "Refreshing" | "Needs review" | "Check setup" | "Needs help";
  badgeLabel: "Ready" | "Refreshing" | "Needs check" | "Pending" | "Blocked";
  tone: "success" | "warning" | "neutral" | "danger";
  toneClass: string;
  title: string;
  summary: string;
  notice: string;
  blocksPrintStart: boolean;
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
const LABEL_PRINTER_TERMS = ["zdesigner", "zebra", "zt410", "zpl"];
const NON_LABEL_PRINTER_TERMS = [
  "canon",
  "airprint",
  "fax",
  "pdf",
  "onenote",
  "xps",
  "microsoft print to pdf",
  "print to pdf",
  "document writer",
];

const printerSearchText = (printer: PrinterInventoryRow) =>
  [
    printer.printerName,
    printer.model,
    printer.connection,
    printer.portName,
    printer.windowsPortName,
    printer.windowsPortHost,
    printer.queueStatus,
    ...(printer.languages || []),
    ...(printer.protocols || []),
    ...(printer.mediaSizes || []),
  ]
    .join(" ")
    .toLowerCase();

export const isPreferredLabelPrinter = (printer?: PrinterInventoryRow | null) =>
  Boolean(printer && hasAny(printerSearchText(printer), LABEL_PRINTER_TERMS));

export const isLowerPriorityPrinter = (printer?: PrinterInventoryRow | null) =>
  Boolean(printer && hasAny(printerSearchText(printer), NON_LABEL_PRINTER_TERMS));

const isUsbZebraPrinter = (printer?: PrinterInventoryRow | null) =>
  Boolean(
    printer &&
      isPreferredLabelPrinter(printer) &&
      (String(printer.connection || "").toLowerCase() === "usb" ||
        String(printer.portName || printer.windowsPortName || "").toUpperCase().startsWith("USB") ||
        printer.usbAvailable)
  );

export const findRecommendedUsbZebraAlternative = (
  printers: PrinterInventoryRow[],
  selectedPrinter?: PrinterInventoryRow | null
) => {
  if (!selectedPrinter || !isPreferredLabelPrinter(selectedPrinter)) return null;
  const selectedBlocked = selectedPrinter.online === false || selectedPrinter.queueHasErrors;
  if (!selectedBlocked) return null;
  return printers.find((printer) => printer.printerId !== selectedPrinter.printerId && printer.online !== false && isUsbZebraPrinter(printer)) || null;
};

export const getPrinterSelectionRank = (printer: PrinterInventoryRow) => {
  const text = printerSearchText(printer);
  let score = 0;
  if (printer.online === false) score -= 100;
  if (printer.isDefault) score += 2;
  for (const term of LABEL_PRINTER_TERMS) {
    if (text.includes(term)) score += 25;
  }
  for (const term of NON_LABEL_PRINTER_TERMS) {
    if (text.includes(term)) score -= 20;
  }
  if (toUpperList(printer.languages).includes("ZPL")) score += 30;
  return score;
};

export const chooseStablePrinterSelection = (
  printers: PrinterInventoryRow[],
  currentPrinterId?: string | null,
  remoteSelectedPrinterId?: string | null,
  remotePrinterId?: string | null
) => {
  const available = Array.isArray(printers) ? printers : [];
  const bestOnline =
    [...available]
      .filter((row) => row.online !== false)
      .sort((left, right) => getPrinterSelectionRank(right) - getPrinterSelectionRank(left))[0] || null;
  const current = available.find((row) => row.printerId === currentPrinterId);
  if (current && current.online !== false) {
    if (
      bestOnline &&
      bestOnline.printerId !== current.printerId &&
      isPreferredLabelPrinter(bestOnline) &&
      (isLowerPriorityPrinter(current) || getPrinterSelectionRank(bestOnline) - getPrinterSelectionRank(current) >= 35)
    ) {
      return bestOnline;
    }
    return current;
  }

  const remoteSelected = available.find((row) => row.printerId === remoteSelectedPrinterId);
  if (remoteSelected && remoteSelected.online !== false && !isLowerPriorityPrinter(remoteSelected)) return remoteSelected;

  const remotePrinter = available.find((row) => row.printerId === remotePrinterId);
  if (remotePrinter && remotePrinter.online !== false && !isLowerPriorityPrinter(remotePrinter)) return remotePrinter;

  return (
    bestOnline ||
    available.find((row) => row.printerId === remoteSelectedPrinterId) ||
    available[0] ||
    null
  );
};

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
      windowsPortName: toCleanString((row as any).windowsPortName, 180) || null,
      windowsPortHost: toCleanString((row as any).windowsPortHost, 180) || null,
      windowsPortNumber: Number.isFinite(Number((row as any).windowsPortNumber)) ? Number((row as any).windowsPortNumber) : null,
      queueStatus: toCleanString((row as any).queueStatus, 120) || null,
      queueHasErrors: Boolean((row as any).queueHasErrors),
      stuckJobCount: Number.isFinite(Number((row as any).stuckJobCount)) ? Number((row as any).stuckJobCount) : 0,
      retainedJobCount: Number.isFinite(Number((row as any).retainedJobCount)) ? Number((row as any).retainedJobCount) : 0,
      usbAvailable: Boolean((row as any).usbAvailable),
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
      summary: "Looks like a shared printer",
      detail: `MSCQR can fill in most of the shared printer details for ${printer.printerName}.`,
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
      summary: supportedLanguage ? "Looks like a factory label printer" : "Looks like a network printer",
      detail: supportedLanguage
        ? `MSCQR can fill in most of the factory label printer details for ${printer.printerName}.`
        : "MSCQR found the printer address, but you still need to confirm what label type this printer uses before you save it.",
      host: rawEndpoint.host,
      port: rawEndpoint.port,
      commandLanguage: supportedLanguage,
    };
  }

  if (protocols.includes("IPP") || protocols.includes("IPPS") || connection === "ipp" || connection === "ipps" || connection === "bonjour") {
    return {
      routeType: "NETWORK_IPP",
      readiness: "NEEDS_DETAILS",
      summary: "Looks like a shared printer",
      detail:
        "MSCQR can see a shared printer here, but it still needs a stable printer address before it can save this setup.",
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
      summary: "Looks like a factory label printer",
      detail:
        "MSCQR can see the label printer type, but it still needs the printer address before it can save this setup.",
      commandLanguage: supportedLanguage,
    };
  }

  return {
    routeType: "LOCAL_ONLY",
    readiness: "NEEDS_DETAILS",
    summary: "Use the printer already set up on this computer",
    detail:
      "MSCQR can see this printer on this computer, but it does not expose enough network details to save as a shared printer. Keep using it on this computer and return to batches when ready.",
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
  const explicitSelectedPrinter = printers.find((row) => row.printerId === params.selectedPrinterId) || null;
  const stableSelectedPrinter = chooseStablePrinterSelection(printers, params.selectedPrinterId, remote?.selectedPrinterId, remote?.printerId);
  const selectedPrinter =
    (explicitSelectedPrinter && (explicitSelectedPrinter.online === false || !isLowerPriorityPrinter(explicitSelectedPrinter))
      ? explicitSelectedPrinter
      : stableSelectedPrinter) ||
    printers.find((row) => row.isDefault) ||
    printers[0] ||
    null;
  const selectedPrinterId = String(selectedPrinter?.printerId || "").trim();
  const recommendedUsbPrinter = findRecommendedUsbZebraAlternative(printers, selectedPrinter);
  const selectedPortHost = selectedPrinter?.windowsPortHost || null;
  const selectedPortNumber = selectedPrinter?.windowsPortNumber || (selectedPortHost ? 9100 : null);

  if (remote?.connectorUpdateRequired) {
    const detected = remote.buildVersion || remote.agentVersion || "unknown";
    return {
      state: "connector_update_required",
      badgeLabel: "Update connector",
      title: "Connector update required",
      summary: "Printing is blocked until this workstation connector is updated.",
      detail: `Detected: ${detected}. Required: 2026.6.13 or newer with transport diagnostics.`,
      tone: "danger",
      nextSteps: [
        "Update MSCQR Connector on this workstation.",
        "Restart the connector, then re-check the printer connection.",
        "Print a setup test label before starting production labels.",
      ],
      selectedPrinter,
      recommendedPrinter: recommendedUsbPrinter,
    };
  }

  if (recommendedUsbPrinter) {
    const endpoint = selectedPortHost ? `${selectedPortHost}:${selectedPortNumber || 9100}` : "its saved Windows TCP/IP port";
    const stuckCount = Number(selectedPrinter?.stuckJobCount || 0);
    return {
      state: "blocked_with_alternative",
      badgeLabel: "Use USB Zebra",
      title: "Network Zebra queue is broken",
      summary: `Saved WiFi queue points to ${endpoint}, which is unreachable from this workstation.`,
      detail: `${recommendedUsbPrinter.printerName} is available on ${recommendedUsbPrinter.portName || recommendedUsbPrinter.windowsPortName || "USB"}.${stuckCount > 0 ? ` Windows queue has ${stuckCount} stuck MSCQR job${stuckCount === 1 ? "" : "s"}.` : ""}`,
      tone: "danger",
      nextSteps: [
        "Choose USB Zebra instead.",
        "Print a setup test label on the USB route.",
        "Update the WiFi printer IP before using the network queue again.",
      ],
      selectedPrinter,
      recommendedPrinter: recommendedUsbPrinter,
    };
  }

  if (selectedPrinter?.queueHasErrors) {
    const hostCopy = selectedPortHost ? ` Saved Zebra IP is stale or unreachable: ${selectedPortHost}:${selectedPortNumber || 9100}.` : "";
    const stuckCopy = Number(selectedPrinter.stuckJobCount || 0) > 0 ? " Windows queue has stuck jobs." : "";
    return {
      state: "printer_offline",
      badgeLabel: "Queue error",
      title: "Windows queue has an error",
      summary: `${selectedPrinter.printerName} is blocked by Windows queue status.`,
      detail: sanitizePrinterUiError(`${selectedPrinter.queueStatus || ""}${hostCopy}${stuckCopy}`, "Clear the Windows queue before printing."),
      tone: "danger",
      nextSteps: [
        "Clear stuck MSCQR print jobs from this printer queue.",
        "Use a healthy USB Zebra route if one is available.",
        "Update the saved WiFi printer IP before using this network queue again.",
      ],
      selectedPrinter,
      recommendedPrinter: null,
    };
  }

  if (remote?.connected && remote?.eligibleForPrinting) {
    const pendingSecureVerification =
      !remote.trusted ||
      remote.compatibilityMode ||
      String(remote.trustStatus || "").toUpperCase() === "UNREGISTERED" ||
      String(remote.trustStatus || "").toUpperCase() === "PENDING";
    const softNotice = remote.refreshPaused
      ? "Printer status refresh is temporarily paused. Printing can continue."
      : pendingSecureVerification
        ? "Secure printer verification is still finishing. Printing can continue."
        : "The printer helper and MSCQR are both ready for this printer.";

    return {
      state: remote.trusted && !remote.compatibilityMode ? "trusted_ready" : "compatibility_ready",
      badgeLabel: "Ready",
      title: "Printer ready",
      summary: `${selectedPrinter?.printerName || remote.selectedPrinterName || remote.printerName || "Selected printer"} is connected and ready to print.`,
      detail: softNotice,
      tone: "success",
      nextSteps: [
        "Continue to the batch workflow when you are ready to print.",
        "If output alignment changes, review the printer settings before the next run.",
      ],
      selectedPrinter,
    };
  }

  if (!params.localAgent.reachable) {
    return {
      state: "agent_unreachable",
      badgeLabel: "Helper offline",
      title: "Printer helper is not available",
      summary: "MSCQR could not reach the printer helper on this computer.",
      detail: sanitizePrinterUiError(params.localAgent.error, "The printer helper is unavailable."),
      tone: "danger",
      nextSteps: [
        "Make sure the printer helper is installed and running on this computer.",
        "Refresh this page after the helper and printer are ready.",
      ],
      selectedPrinter,
    };
  }

  if (printers.length === 0) {
    return {
      state: "no_printers_detected",
      badgeLabel: "No printer",
      title: "No printer connection detected",
      summary: "MSCQR can reach the printer helper, but no ready printer was found.",
      detail: sanitizePrinterUiError(params.localAgent.error || remote?.error, "No printers were reported by the printer helper."),
      tone: "neutral",
      nextSteps: [
        "Check the computer's printer list and driver setup.",
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
    const hostCopy = selectedPortHost ? ` Saved Zebra IP is stale or unreachable: ${selectedPortHost}:${selectedPortNumber || 9100}.` : "";
    const stuckCopy = Number(selectedPrinter.stuckJobCount || 0) > 0 ? " Windows queue has stuck jobs." : "";
    return {
      state: "printer_offline",
      badgeLabel: "Printer offline",
      title: "Selected printer is offline",
      summary: `${selectedPrinter.printerName} is known to the local agent but is currently offline.`,
      detail: sanitizePrinterUiError(
        `${remote?.error || remote?.trustReason || ""}${hostCopy}${stuckCopy}`,
        "The printer is configured but is not ready for active jobs."
      ),
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
        "Keep the printer helper running on this computer.",
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
        "Keep the printer helper running and refresh this page.",
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

export const buildPrinterReadinessDisplay = (params: {
  diagnostics: PrinterDiagnosticSummary;
  ready: boolean;
  refreshPaused?: boolean;
  rateLimited?: boolean;
  stale?: boolean;
  trusted?: boolean;
  compatibilityMode?: boolean;
  identityLabel?: string | null;
}): PrinterReadinessDisplay => {
  const transientRefresh = Boolean((params.refreshPaused || params.rateLimited) && params.ready && !params.stale);
  const blocksPrintStart = Boolean(params.stale || (!params.ready && params.diagnostics.tone === "danger"));
  const tone = transientRefresh ? "success" : params.diagnostics.tone;
  const modeLabel = transientRefresh
    ? "Refreshing"
    : params.ready
      ? "Ready"
      : params.diagnostics.tone === "warning"
        ? "Needs review"
        : params.diagnostics.tone === "neutral"
          ? "Check setup"
          : "Needs help";
  const badgeLabel = transientRefresh
    ? "Refreshing"
    : params.ready
      ? "Ready"
      : params.diagnostics.tone === "warning"
        ? "Needs check"
        : params.diagnostics.tone === "neutral"
          ? "Pending"
          : "Blocked";
  const identity = String(params.identityLabel || params.diagnostics.selectedPrinter?.printerName || "Selected printer").trim();
  const summary = transientRefresh
    ? `${identity} was ready at the last trusted check. Status refresh is temporarily paused.`
    : params.ready
      ? `${identity} is ready to print.`
      : params.diagnostics.summary;
  const notice = transientRefresh
    ? "Printer status refresh is temporarily paused. Printing can continue with the last ready status."
    : params.ready && (!params.trusted || params.compatibilityMode)
      ? "Secure printer verification is still finishing. Printing can continue."
      : "";

  const toneClass =
    tone === "success"
      ? "border-emerald-300 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
      : tone === "warning"
        ? "border-amber-300 bg-amber-50 text-amber-700 hover:bg-amber-100"
        : tone === "neutral"
          ? "border-slate-300 bg-slate-100 text-slate-700 hover:bg-slate-200"
          : "border-red-300 bg-red-50 text-red-700 hover:bg-red-100";

  return {
    modeLabel,
    badgeLabel,
    tone,
    toneClass,
    title: params.diagnostics.title,
    summary,
    notice,
    blocksPrintStart,
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
        ? "Saved site printer"
        : "Saved shared printer"
      : "Saved label printer";
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
      summary: `${printerName} is saved and ready to print.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "This saved printer has already been checked and is ready."
      ),
      tone: "success",
      nextSteps: [
        "Open batches and choose this saved printer when you are ready.",
        "If this printer changes later, ask an admin to check it again before the next run.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  if (printer.registryStatus?.state === "ATTENTION") {
    return {
      state: "server_sync_pending",
      badgeLabel: "Needs validation",
      title: `${networkLabel} needs validation`,
      summary: `${printerName} is saved, but it still needs a live check.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Run a printer check to confirm this setup is ready."
      ),
      tone: "warning",
      nextSteps: [
        "Confirm the printer or site link is online.",
        "Ask an admin to check this saved printer before printing.",
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
        "Update the saved printer details.",
        "Check it again after correcting the connection or printer language.",
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
        "Bring the printer or site link online.",
        "Run Check again once the saved printer is reachable.",
      ],
      selectedPrinter: pseudoPrinter,
    };
  }

  return {
    state: "server_sync_pending",
    badgeLabel: "Preparing",
    title: `${networkLabel} setup in progress`,
    summary: `${printerName} has been saved, but MSCQR still needs a live readiness check.`,
    detail: "Open the printer panel and run Check to confirm the connection end to end.",
    tone: "warning",
    nextSteps: [
      "Complete the profile details and run Check.",
      "Use the batch workflow once this saved printer shows Ready.",
    ],
    selectedPrinter: pseudoPrinter,
  };
};

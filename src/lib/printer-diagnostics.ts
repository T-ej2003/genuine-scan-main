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
};

export type PrinterConnectionStatusLike = {
  connected: boolean;
  trusted: boolean;
  compatibilityMode: boolean;
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

const hasAny = (value: string, needles: string[]) => needles.some((needle) => value.includes(needle));

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
    });
    if (result.length >= 40) break;
  }
  return result;
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
      badgeLabel: "Trusted",
      title: "Trusted printer ready",
      summary: `${remote.selectedPrinterName || remote.printerName || selectedPrinter?.printerName || "Selected printer"} is connected and ready for direct-print.`,
      detail: "The local agent is reporting a printer and the backend accepted the latest trust heartbeat.",
      tone: "success",
      nextSteps: [
        "Start the print job from the batch workflow.",
        "Keep the diagnostics page open if you want to monitor heartbeat freshness.",
      ],
      selectedPrinter,
    };
  }

  if (remote?.connected && remote?.eligibleForPrinting && remote?.compatibilityMode) {
    return {
      state: "compatibility_ready",
      badgeLabel: "Compatibility",
      title: "Printer ready in compatibility mode",
      summary: `${remote.selectedPrinterName || remote.printerName || selectedPrinter?.printerName || "Selected printer"} is connected, but advanced trust enrollment is not complete.`,
      detail: remote.compatibilityReason || remote.error || remote.trustReason || "Compatibility fallback is active.",
      tone: "warning",
      nextSteps: [
        "You can print for testing now.",
        "Enroll the printer identity and mTLS material before relying on this path for hardened production use.",
      ],
      selectedPrinter,
    };
  }

  if (!params.localAgent.reachable) {
    return {
      state: "agent_unreachable",
      badgeLabel: "Agent offline",
      title: "Local print agent is not reachable",
      summary: "The browser could not reach the workstation print agent at 127.0.0.1:17866.",
      detail: params.localAgent.error || "Local print agent is unavailable.",
      tone: "danger",
      nextSteps: [
        "Start or install the local print agent on this workstation.",
        "Confirm http://127.0.0.1:17866/status opens locally, then refresh diagnostics.",
      ],
      selectedPrinter,
    };
  }

  if (printers.length === 0) {
    return {
      state: "no_printers_detected",
      badgeLabel: "No printer",
      title: "No printer connection detected",
      summary: "The local print agent is running, but it did not detect any attached printer.",
      detail: params.localAgent.error || remote?.error || "No printers were returned by the local agent.",
      tone: "neutral",
      nextSteps: [
        "Check the operating system printer list and driver installation.",
        "Reconnect the USB or network printer, then refresh diagnostics.",
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
      detail: "Select the printer you want the local agent to use, then refresh server status.",
      tone: "warning",
      nextSteps: [
        "Pick the target printer from the diagnostics or batch dialog.",
        "Apply the selection and refresh the connection state.",
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
      detail: remote?.error || remote?.trustReason || "The printer is attached in configuration but not online for active jobs.",
      tone: "danger",
      nextSteps: [
        "Power on the printer and clear any paper, toner, label, or queue issue.",
        "Refresh diagnostics after the printer returns online.",
      ],
      selectedPrinter,
    };
  }

  if (remote?.stale) {
    return {
      state: "heartbeat_stale",
      badgeLabel: "Heartbeat stale",
      title: "Printer heartbeat is stale",
      summary: "A printer was detected, but the backend heartbeat is too old to trust.",
      detail: remote.error || remote.trustReason || "The server has not received a fresh attestation within the allowed window.",
      tone: "warning",
      nextSteps: [
        "Keep the print agent running so it can send a fresh heartbeat.",
        "Refresh diagnostics and confirm the heartbeat age resets.",
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
      badgeLabel: "Sync pending",
      title: "Printer detected locally, waiting for server readiness",
      summary: `${selectedPrinter?.printerName || remote?.selectedPrinterName || remote?.printerName || "Printer"} is visible locally, but server registration or attestation is still pending.`,
      detail: remote?.error || remote?.trustReason || "The backend has not accepted a complete identity heartbeat yet.",
      tone: "warning",
      nextSteps: [
        "Keep the local agent open and refresh diagnostics.",
        "If this persists, verify the agent is sending heartbeat identity fields and selected printer metadata.",
      ],
      selectedPrinter,
    };
  }

  return {
    state: "trust_blocked",
    badgeLabel: "Trust blocked",
    title: "Printer trust or heartbeat validation is blocked",
    summary: `${selectedPrinter?.printerName || remote?.selectedPrinterName || remote?.printerName || "Selected printer"} is visible, but the backend rejected the connection for direct-print.`,
    detail: remote?.error || remote?.trustReason || "Heartbeat validation failed.",
    tone: "danger",
    nextSteps: [
      "Check whether the agent is sending public key, signature, and certificate fingerprint material.",
      "Refresh diagnostics after the local agent identity is corrected.",
    ],
    selectedPrinter,
  };
};

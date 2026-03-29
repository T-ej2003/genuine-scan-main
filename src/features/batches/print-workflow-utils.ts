import { getPrinterDispatchLabel, sanitizePrinterUiError } from "@/lib/printer-user-facing";

import type {
  LocalPrinterRow,
  PrinterConnectionStatus,
  PrinterNoticeTone,
  PrinterSelectionNotice,
  RegisteredPrinterRow,
} from "./types";

export const PRINTER_FAILURE_AUTO_REPORT_COOLDOWN_MS = 3 * 60 * 1000;

export const formatDispatchModeLabel = (mode?: string | null) => {
  if (mode === "NETWORK_DIRECT") return "Factory label printer";
  if (mode === "NETWORK_IPP") return "Office printer";
  if (mode === "LOCAL_AGENT") return "Printer on this computer";
  return "Printer";
};

const normalizePrintProgressPhase = (phase?: string | null) => String(phase || "").trim().toLowerCase();

export const isCompletedPrintProgressPhase = (phase?: string | null) => {
  const normalized = normalizePrintProgressPhase(phase);
  return (
    normalized === "completed" ||
    normalized === "print job completed" ||
    normalized === "print session completed"
  );
};

export const isTerminalPrintProgressPhase = (phase?: string | null) => {
  const normalized = normalizePrintProgressPhase(phase);
  return (
    isCompletedPrintProgressPhase(normalized) ||
    normalized === "print job failed" ||
    normalized === "print job cancelled"
  );
};

export const buildManagedNetworkPrinterNotice = (
  printer: RegisteredPrinterRow | null
): PrinterSelectionNotice => {
  if (!printer) {
    return {
      title: "Select a saved printer",
      summary: "Choose a saved printer profile before starting this print job.",
      detail: "Save and check a printer in Printer Setup before you start this print run.",
      tone: "neutral",
    };
  }

  const state = printer.registryStatus?.state || "ATTENTION";
  const profileLabel = getPrinterDispatchLabel(printer);

  if (state === "READY") {
    return {
      title: `${profileLabel} printer ready`,
      summary: `${printer.name} is validated and ready for server-side dispatch.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        printer.connectionType === "NETWORK_IPP"
          ? "This shared printer is ready for standards-based printing."
          : "This factory label printer is ready for controlled dispatch."
      ),
      tone: "success",
    };
  }

  if (state === "OFFLINE") {
    return {
      title: "Network printer offline",
      summary: `${printer.name} is saved, but it is not reachable right now.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Bring the printer or site print link online and run the check again before printing."
      ),
      tone: "danger",
    };
  }

  if (state === "BLOCKED") {
    return {
      title: "Network printer blocked",
      summary: `${printer.name} cannot be used in its current configuration.`,
      detail: sanitizePrinterUiError(
        printer.registryStatus?.detail,
        "Update the saved setup and run the check again before printing."
      ),
      tone: "danger",
    };
  }

  return {
    title: "Network printer needs validation",
    summary: `${printer.name} is registered, but readiness has not been confirmed yet.`,
    detail: sanitizePrinterUiError(
      printer.registryStatus?.detail,
      "Open Printer Setup and run a check before printing."
    ),
    tone: "warning",
  };
};

export const normalizePrinterRows = (rows: unknown): LocalPrinterRow[] => {
  if (!Array.isArray(rows)) return [];
  const result: LocalPrinterRow[] = [];

  for (const row of rows) {
    if (!row || typeof row !== "object") continue;
    const printerId = String((row as { printerId?: unknown; id?: unknown }).printerId || (row as { id?: unknown }).id || "").trim();
    const printerName = String((row as { printerName?: unknown; name?: unknown }).printerName || (row as { name?: unknown }).name || "").trim();
    if (!printerId || !printerName) continue;

    result.push({
      printerId,
      printerName,
      model: String((row as { model?: unknown }).model || "").trim() || null,
      connection: String((row as { connection?: unknown; transport?: unknown }).connection || (row as { transport?: unknown }).transport || "").trim() || null,
      online: Boolean((row as { online?: unknown }).online ?? true),
      isDefault: Boolean((row as { isDefault?: unknown }).isDefault),
      protocols: Array.isArray((row as { protocols?: unknown }).protocols) ? ((row as { protocols: string[] }).protocols) : [],
      languages: Array.isArray((row as { languages?: unknown }).languages) ? ((row as { languages: string[] }).languages) : [],
      mediaSizes: Array.isArray((row as { mediaSizes?: unknown }).mediaSizes) ? ((row as { mediaSizes: string[] }).mediaSizes) : [],
      dpi: Number.isFinite(Number((row as { dpi?: unknown }).dpi)) ? Number((row as { dpi?: unknown }).dpi) : null,
    });

    if (result.length >= 40) break;
  }

  return result;
};

export const defaultPrinterStatus: PrinterConnectionStatus = {
  connected: false,
  trusted: false,
  compatibilityMode: false,
  compatibilityReason: null,
  eligibleForPrinting: false,
  connectionClass: "BLOCKED",
  stale: true,
  requiredForPrinting: true,
  trustStatus: "UNREGISTERED",
  trustReason: "No trusted printer registration",
  lastHeartbeatAt: null,
  ageSeconds: null,
  registrationId: null,
  agentId: null,
  deviceFingerprint: null,
  mtlsFingerprint: null,
  printerName: null,
  printerId: null,
  selectedPrinterId: null,
  selectedPrinterName: null,
  deviceName: null,
  agentVersion: null,
  capabilitySummary: null,
  printers: [],
  calibrationProfile: null,
  error: "No trusted printer heartbeat yet",
};

export const printerNoticeTone = (tone: PrinterNoticeTone) => tone;

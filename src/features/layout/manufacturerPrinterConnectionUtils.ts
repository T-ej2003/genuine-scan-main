import type { PrinterConnectionStatusDTO } from "../../../shared/contracts/runtime/printing.ts";

export const PRINTER_FAILURE_REPORT_COOLDOWN_MS = 3 * 60 * 1000;
export const PRINTER_BACKGROUND_REFRESH_MS = 30_000;
export const DISABLE_E2E_PRINTER_AGENT_POLLING =
  import.meta.env.VITE_E2E_DISABLE_PRINTER_AGENT_POLLING === "true";
export const PRINTER_DIALOG_SESSION_STORAGE_VERSION = "v1";
export const PRINTER_ONBOARDING_STORAGE_VERSION = "v1";

export const defaultPrinterStatus: PrinterConnectionStatusDTO = {
  connected: false,
  trusted: false,
  compatibilityMode: false,
  degraded: false,
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

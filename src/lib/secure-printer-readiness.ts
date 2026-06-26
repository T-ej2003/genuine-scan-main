import { sanitizePrinterUiError } from "@/lib/printer-user-facing";

type PrinterStatusLike = {
  connected?: boolean | null;
  eligibleForPrinting?: boolean | null;
  trusted?: boolean | null;
  compatibilityMode?: boolean | null;
  stale?: boolean | null;
  connectionClass?: string | null;
  securePrinterSession?: boolean | null;
  freshHelperHeartbeat?: boolean | null;
  helperConnection?: boolean | null;
  eligiblePrinter?: boolean | null;
  trustStatus?: string | null;
  trustReason?: string | null;
  error?: string | null;
  selectedPrinterName?: string | null;
  printerName?: string | null;
  selectedPrinterId?: string | null;
  printerId?: string | null;
  agentVersion?: string | null;
  buildVersion?: string | null;
  persistentSessionRequired?: boolean | null;
  persistentSessionCapable?: boolean | null;
  persistentSessionMinimumBuildVersion?: string | null;
  persistentSessionUpdateRequired?: boolean | null;
  persistentSessionDisconnected?: boolean | null;
};

export type SecurePrintReadiness = {
  ready: boolean;
  reasonCode:
    | "READY"
    | "VERIFICATION_EXPIRED"
    | "HELPER_OFFLINE"
    | "CONNECTOR_UPDATE_REQUIRED"
    | "SECURE_SESSION_MISSING"
    | "PRINTER_NOT_ELIGIBLE";
  badgeLabel: "Ready" | "Needs check" | "Blocked";
  tone: "success" | "warning" | "danger";
  summary: string;
  detail: string;
  recoveryAction: "none" | "refresh_printer_helper";
  canRetry: boolean;
};

const hasMtlsMissingReason = (status?: PrinterStatusLike | null) =>
  `${status?.trustReason || ""} ${status?.error || ""}`.toLowerCase().includes("mtls client certificate fingerprint header missing");

const printerLabel = (status?: PrinterStatusLike | null) =>
  String(status?.selectedPrinterName || status?.printerName || status?.selectedPrinterId || status?.printerId || "Selected printer").trim();

export const isSecurePrintReady = (status?: PrinterStatusLike | null) =>
  Boolean(
    status?.connected &&
      status?.eligibleForPrinting &&
      status?.trusted &&
	      status?.securePrinterSession !== false &&
	      status?.freshHelperHeartbeat !== false &&
	      status?.helperConnection !== false &&
	      status?.eligiblePrinter !== false &&
	      status?.persistentSessionDisconnected !== true &&
	      !status?.compatibilityMode &&
	      !status?.stale &&
      String(status?.connectionClass || "TRUSTED").toUpperCase() === "TRUSTED"
  );

export const buildSecurePrintReadiness = (status?: PrinterStatusLike | null): SecurePrintReadiness => {
  if (isSecurePrintReady(status)) {
    return {
      ready: true,
      reasonCode: "READY",
      badgeLabel: "Ready",
      tone: "success",
      summary: `${printerLabel(status)} is ready to print.`,
      detail: "The printer helper has a fresh trusted session.",
      recoveryAction: "none",
      canRetry: false,
    };
  }

  if (status?.persistentSessionUpdateRequired) {
    const minimum = String(status.persistentSessionMinimumBuildVersion || "2026.6.25").trim();
    const detected = String(status.buildVersion || status.agentVersion || "unknown").trim();
    return {
      ready: false,
      reasonCode: "CONNECTOR_UPDATE_REQUIRED",
      badgeLabel: "Blocked",
      tone: "danger",
      summary: "MSCQR Connector update required.",
      detail: `Update MSCQR Connector to use persistent print session mode. Required ${minimum}; detected ${detected}.`,
      recoveryAction: "refresh_printer_helper",
      canRetry: true,
    };
  }

  if (!status?.connected) {
    if (status?.persistentSessionRequired && status?.persistentSessionCapable && status?.persistentSessionDisconnected !== false) {
      return {
        ready: false,
        reasonCode: "SECURE_SESSION_MISSING",
        badgeLabel: "Blocked",
        tone: "danger",
        summary: "Persistent session is not connected.",
        detail: "Helper installed and printer detected are not enough for production printing. Keep MSCQR Connector 2026.6.25 running until Cloud trust and the persistent session are connected.",
        recoveryAction: "refresh_printer_helper",
        canRetry: true,
      };
    }
    const expired = Boolean(status?.stale || hasMtlsMissingReason(status));
    return {
      ready: false,
      reasonCode: expired ? "VERIFICATION_EXPIRED" : "HELPER_OFFLINE",
      badgeLabel: expired ? "Needs check" : "Blocked",
      tone: expired ? "warning" : "danger",
      summary: "Printer verification expired. Refresh printer helper before printing.",
      detail: sanitizePrinterUiError(
        status?.trustReason || status?.error,
        "Ensure MSCQR Connector 2026.6.25 is running, refresh printer helper status, and restart the connector if this does not recover."
      ),
      recoveryAction: "refresh_printer_helper",
      canRetry: true,
    };
  }

  if (status?.stale || !status?.trusted || status?.compatibilityMode || hasMtlsMissingReason(status)) {
    return {
      ready: false,
      reasonCode: status?.stale ? "VERIFICATION_EXPIRED" : "SECURE_SESSION_MISSING",
      badgeLabel: "Needs check",
      tone: "warning",
      summary: "Printer verification expired. Refresh printer helper before printing.",
      detail: sanitizePrinterUiError(
        status?.trustReason || status?.error,
        "The printer is visible, but MSCQR needs a fresh trusted helper session before printing."
      ),
      recoveryAction: "refresh_printer_helper",
      canRetry: true,
    };
  }

  return {
    ready: false,
    reasonCode: "PRINTER_NOT_ELIGIBLE",
    badgeLabel: "Blocked",
    tone: "danger",
    summary: "Printer is not eligible for secure printing.",
    detail: sanitizePrinterUiError(status?.trustReason || status?.error, "Refresh printer helper status before retrying."),
    recoveryAction: "refresh_printer_helper",
    canRetry: true,
  };
};

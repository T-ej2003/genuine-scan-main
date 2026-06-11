import { chooseStablePrinterSelection, type PrinterInventoryRow } from "@/lib/printer-diagnostics";

export type LocalPrinterStatusPayload = {
  connected?: boolean;
  printerName?: string | null;
  printerId?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  protocolVersion?: string | null;
  buildVersion?: string | null;
  transportDiagnosticsVersion?: string | null;
  capabilities?: Record<string, unknown> | null;
  error?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  publicKeyPem?: string | null;
  clientCertFingerprint?: string | null;
  heartbeatNonce?: string | null;
  heartbeatIssuedAt?: string | null;
  heartbeatSignature?: string | null;
  capabilitySummary?: Record<string, unknown> | null;
  calibrationProfile?: Record<string, unknown> | null;
};

export const resolvePreferredLocalPrinter = (
  localPrinters: PrinterInventoryRow[],
  localData?: LocalPrinterStatusPayload | null
) =>
  chooseStablePrinterSelection(
    localPrinters,
    localData?.selectedPrinterId || localData?.printerId || null,
    localData?.selectedPrinterId || null,
    localData?.printerId || null
  );

export const buildHeartbeatPayloadFromLocalStatus = (
  localData: LocalPrinterStatusPayload | null | undefined,
  localPrinters: PrinterInventoryRow[]
) => {
  const heartbeatSelectedId = String(localData?.selectedPrinterId || localData?.printerId || "").trim();
  const heartbeatPreferredPrinter = resolvePreferredLocalPrinter(localPrinters, localData) || null;
  const signedHeartbeatPrinter =
    heartbeatPreferredPrinter?.printerId === heartbeatSelectedId ? heartbeatPreferredPrinter : null;

  return {
    connected: Boolean(localData?.connected),
    printerName: signedHeartbeatPrinter?.printerName || localData?.printerName || undefined,
    printerId: signedHeartbeatPrinter?.printerId || localData?.printerId || undefined,
    selectedPrinterId: signedHeartbeatPrinter?.printerId || localData?.selectedPrinterId || undefined,
    selectedPrinterName: signedHeartbeatPrinter?.printerName || localData?.selectedPrinterName || undefined,
    deviceName: localData?.deviceName || undefined,
    agentVersion: localData?.agentVersion || undefined,
    protocolVersion: localData?.protocolVersion || undefined,
    buildVersion: localData?.buildVersion || undefined,
    transportDiagnosticsVersion: localData?.transportDiagnosticsVersion || undefined,
    capabilities: localData?.capabilities || undefined,
    error: localData?.error || undefined,
    agentId: localData?.agentId || undefined,
    deviceFingerprint: localData?.deviceFingerprint || undefined,
    publicKeyPem: localData?.publicKeyPem || undefined,
    clientCertFingerprint: localData?.clientCertFingerprint || undefined,
    heartbeatNonce: localData?.heartbeatNonce || undefined,
    heartbeatIssuedAt: localData?.heartbeatIssuedAt || undefined,
    heartbeatSignature: localData?.heartbeatSignature || undefined,
    capabilitySummary: localData?.capabilitySummary || undefined,
    printers: localPrinters,
    calibrationProfile: localData?.calibrationProfile || undefined,
  };
};

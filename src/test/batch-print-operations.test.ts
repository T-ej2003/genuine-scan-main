import { beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { createPrintJob } from "@/features/batches/batch-print-operations";

vi.mock("@/lib/api-client", () => ({
  default: {
    selectLocalPrinter: vi.fn(),
    getLocalPrintAgentStatus: vi.fn(),
    reportPrinterHeartbeat: vi.fn(),
    getPrinterConnectionStatus: vi.fn(),
    configureLocalPrintAgentBackend: vi.fn(),
    wakeLocalPrintAgent: vi.fn(),
    createPrintJob: vi.fn(),
    getPrintJobStatus: vi.fn(),
  },
}));

const setter = () => vi.fn();

const productionReadyPrinterStatus = {
  connected: true,
  trusted: true,
  eligibleForPrinting: true,
  securePrinterSession: true,
  freshHelperHeartbeat: true,
  helperConnection: true,
  eligiblePrinter: true,
  compatibilityMode: false,
  stale: false,
  connectionClass: "TRUSTED",
  trustStatus: "TRUSTED",
  registrationId: "registration-trusted-1",
  selectedPrinterId: "usb-zebra",
  printerId: "usb-zebra",
  selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
  printerName: "ZDesigner ZT410-300dpi ZPL",
  agentVersion: "2026.6.25",
  buildVersion: "2026.6.25",
  persistentSessionRequired: true,
  persistentSessionCapable: true,
  persistentSessionUpdateRequired: false,
  persistentSessionDisconnected: false,
  capabilities: {
    supportsPersistentPrintSession: true,
  },
  printers: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
};

describe("batch print operations", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.selectLocalPrinter).mockResolvedValue({ success: true, data: {} } as any);
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        selectedPrinterId: "usb-zebra",
        printerId: "usb-zebra",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
        agentVersion: "2026.6.25",
        buildVersion: "2026.6.25",
        capabilities: { supportsPersistentPrintSession: true },
        websocket: {
          mode: "websocket",
          supported: true,
          connected: true,
          sessionId: "session-live-1",
          registrationId: "registration-trusted-1",
          selectedPrinterId: "usb-zebra",
          lastConnectedAt: new Date().toISOString(),
          lastHeartbeatAt: new Date().toISOString(),
          lastDisconnectedAt: null,
          lastError: null,
          lastRejectReasonCode: null,
        },
        printers: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
      },
    } as any);
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({
      success: true,
      data: productionReadyPrinterStatus,
    } as any);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: productionReadyPrinterStatus,
    } as any);
    vi.mocked(apiClient.configureLocalPrintAgentBackend).mockResolvedValue({ success: true, data: {} } as any);
    vi.mocked(apiClient.wakeLocalPrintAgent).mockResolvedValue({ success: true, data: { accepted: true } } as any);
    vi.mocked(apiClient.createPrintJob).mockResolvedValue({
      success: true,
      data: {
        printJobId: "job-live",
        tokenCount: 10,
        mode: "LOCAL_AGENT",
        pipelineState: "QUEUED",
        printer: { name: "ZDesigner ZT410-300dpi ZPL" },
      },
    } as any);
  });

  it("hands local-agent jobs to the realtime modal without waking REST claim polling", async () => {
    const setPrintJobId = setter();
    const setPrintProgressPhase = setter();
    const setPrintProgressNotice = setter();

    await createPrintJob({
      toast: vi.fn(),
      printBatch: { id: "batch-1", name: "Batch 1" } as any,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: {
        id: "printer-profile-1",
        name: "ZDesigner ZT410-300dpi ZPL",
        connectionType: "LOCAL_AGENT",
        nativePrinterId: "usb-zebra",
        isActive: true,
      } as any,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }] as any,
      printerStatus: productionReadyPrinterStatus as any,
      activeLocalPrinterId: "usb-zebra",
      selectedPrinterCanPrint: true,
      setPrinterStatus: setter(),
      buildCalibrationPayload: () => ({}),
      autoReportPrinterFailure: vi.fn(),
      onBatchesChanged: vi.fn(),
      loadRecentPrintJobs: vi.fn(),
      setPrintJobId,
      printJobId: "",
      directRemainingToPrint: null,
      setPrintProgressOpen: setter(),
      setPrintProgressPhase,
      setPrintProgressTotal: setter(),
      setPrintProgressPrinted: setter(),
      setPrintProgressRemaining: setter(),
      setPrintProgressCurrentCode: setter(),
      setPrintProgressError: setter(),
      setPrintProgressNotice,
      setPrintProgressPrinterName: setter(),
      setPrintProgressDispatchMode: setter(),
      setDirectRemainingToPrint: setter(),
    });

    expect(setPrintJobId).toHaveBeenCalledWith("job-live");
    expect(apiClient.wakeLocalPrintAgent).not.toHaveBeenCalled();
    expect(setPrintProgressPhase).toHaveBeenLastCalledWith("Waiting for connector progress");
    expect(setPrintProgressNotice).toHaveBeenCalledWith("Waiting for backend-confirmed printer progress.");
    expect(apiClient.getPrintJobStatus).not.toHaveBeenCalled();
  });

  it("does not hand off or wake REST polling when the persistent session is disconnected", async () => {
    const disconnectedStatus = {
      ...productionReadyPrinterStatus,
      connected: false,
      trusted: false,
      eligibleForPrinting: false,
      securePrinterSession: false,
      freshHelperHeartbeat: true,
      helperConnection: false,
      connectionClass: "BLOCKED",
      persistentSessionDisconnected: true,
      error: "Persistent printer session is disconnected.",
    };
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValueOnce({
      success: true,
      data: disconnectedStatus,
    } as any);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({
      success: true,
      data: disconnectedStatus,
    } as any);
    const setPrintJobId = setter();
    const toast = vi.fn();

    await createPrintJob({
      toast,
      printBatch: { id: "batch-1", name: "Batch 1" } as any,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: {
        id: "printer-profile-1",
        name: "ZDesigner ZT410-300dpi ZPL",
        connectionType: "LOCAL_AGENT",
        nativePrinterId: "usb-zebra",
        isActive: true,
      } as any,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }] as any,
      printerStatus: disconnectedStatus as any,
      activeLocalPrinterId: "usb-zebra",
      selectedPrinterCanPrint: true,
      setPrinterStatus: setter(),
      buildCalibrationPayload: () => ({}),
      autoReportPrinterFailure: vi.fn(),
      onBatchesChanged: vi.fn(),
      loadRecentPrintJobs: vi.fn(),
      setPrintJobId,
      printJobId: "",
      directRemainingToPrint: null,
      setPrintProgressOpen: setter(),
      setPrintProgressPhase: setter(),
      setPrintProgressTotal: setter(),
      setPrintProgressPrinted: setter(),
      setPrintProgressRemaining: setter(),
      setPrintProgressCurrentCode: setter(),
      setPrintProgressError: setter(),
      setPrintProgressNotice: setter(),
      setPrintProgressPrinterName: setter(),
      setPrintProgressDispatchMode: setter(),
      setDirectRemainingToPrint: setter(),
    });

    expect(setPrintJobId).not.toHaveBeenCalled();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(apiClient.wakeLocalPrintAgent).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Printer session disconnected",
      })
    );
  });

  it("blocks old connector versions without auto-report spam", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({
      success: true,
      data: {
        connected: false,
        eligibleForPrinting: false,
        persistentSessionRequired: true,
        persistentSessionCapable: false,
        persistentSessionUpdateRequired: true,
        persistentSessionMinimumBuildVersion: "2026.6.25",
        buildVersion: "2026.6.16",
      },
    } as any);
    const setPrintProgressPhase = setter();
    const setPrintProgressNotice = setter();
    const autoReportPrinterFailure = vi.fn();
    const toast = vi.fn();

    await createPrintJob({
      toast,
      printBatch: { id: "batch-1", name: "Batch 1" } as any,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: {
        id: "printer-profile-1",
        name: "ZDesigner ZT410-300dpi ZPL",
        connectionType: "LOCAL_AGENT",
        nativePrinterId: "usb-zebra",
        isActive: true,
      } as any,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }] as any,
      printerStatus: productionReadyPrinterStatus as any,
      activeLocalPrinterId: "usb-zebra",
      selectedPrinterCanPrint: true,
      setPrinterStatus: setter(),
      buildCalibrationPayload: () => ({}),
      autoReportPrinterFailure,
      onBatchesChanged: vi.fn(),
      loadRecentPrintJobs: vi.fn(),
      setPrintJobId: setter(),
      printJobId: "",
      directRemainingToPrint: null,
      setPrintProgressOpen: setter(),
      setPrintProgressPhase,
      setPrintProgressTotal: setter(),
      setPrintProgressPrinted: setter(),
      setPrintProgressRemaining: setter(),
      setPrintProgressCurrentCode: setter(),
      setPrintProgressError: setter(),
      setPrintProgressNotice,
      setPrintProgressPrinterName: setter(),
      setPrintProgressDispatchMode: setter(),
      setDirectRemainingToPrint: setter(),
    });

    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(apiClient.wakeLocalPrintAgent).not.toHaveBeenCalled();
    expect(autoReportPrinterFailure).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Connector update required",
      })
    );
    expect(setPrintProgressPhase).not.toHaveBeenCalledWith("Waiting for printer helper");
    expect(setPrintProgressNotice).not.toHaveBeenCalledWith("Connector wake failed. Safe fallback polling remains active.");
  });
});

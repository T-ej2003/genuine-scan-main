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
        printers: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
      },
    } as any);
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "usb-zebra",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      },
    } as any);
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "usb-zebra",
        selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
      },
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

  it("hands local-agent jobs to the modal poller without operation-level status polling", async () => {
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
      printerStatus: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "usb-zebra",
        printerId: "usb-zebra",
      } as any,
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
    expect(apiClient.wakeLocalPrintAgent).toHaveBeenCalledWith("user_print_job_created");
    expect(setPrintProgressPhase).toHaveBeenLastCalledWith("Waiting for connector to claim job");
    expect(setPrintProgressNotice).toHaveBeenCalledWith("Connector wake sent. Waiting for backend-confirmed printer progress.");
    expect(apiClient.getPrintJobStatus).not.toHaveBeenCalled();
  });

  it("keeps fallback status visible when local connector wake fails", async () => {
    vi.mocked(apiClient.wakeLocalPrintAgent).mockResolvedValueOnce({ success: false, error: "Local print agent is unavailable" } as any);
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
      printerStatus: {
        connected: true,
        eligibleForPrinting: true,
        selectedPrinterId: "usb-zebra",
        printerId: "usb-zebra",
      } as any,
      activeLocalPrinterId: "usb-zebra",
      selectedPrinterCanPrint: true,
      setPrinterStatus: setter(),
      buildCalibrationPayload: () => ({}),
      autoReportPrinterFailure: vi.fn(),
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

    expect(setPrintProgressPhase).toHaveBeenLastCalledWith("Waiting for printer helper");
    expect(setPrintProgressNotice).toHaveBeenCalledWith("Connector wake failed. Safe fallback polling remains active.");
  });
});

import { beforeEach, describe, expect, it, vi } from "vitest";

import apiClient from "@/lib/api-client";
import { createPrintJob } from "@/features/batches/batch-print-operations";
import { defaultPrinterStatus } from "@/features/batches/print-workflow-utils";
import type { BatchRow, LocalPrinterRow, RegisteredPrinterRow } from "@/features/batches/types";

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

const testBatch: BatchRow = {
  id: "batch-1", name: "Batch 1", licenseeId: "licensee-1", startCode: "A", endCode: "Z",
  totalCodes: 10, printedAt: null, createdAt: "2026-10-28T00:00:00.000Z",
};
const testProfile: RegisteredPrinterRow = {
  id: "printer-profile-1", name: "ZDesigner ZT410-300dpi ZPL", connectionType: "LOCAL_AGENT",
  commandLanguage: "ZPL", nativePrinterId: "usb-zebra", isActive: true,
};
const testPrinters: LocalPrinterRow[] = [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }];

const productionReadyPrinterStatus = {
  ...defaultPrinterStatus,
  connected: true,
  trusted: true,
  eligibleForPrinting: true,
  securePrinterSession: true,
  freshHelperHeartbeat: true,
  helperConnection: true,
  eligiblePrinter: true,
  compatibilityMode: false,
  stale: false,
  connectionClass: "TRUSTED" as const,
  trustStatus: "TRUSTED",
  requiredForPrinting: true,
  lastHeartbeatAt: "2026-10-28T12:00:00.000Z",
  ageSeconds: 0,
  registrationId: "registration-trusted-1",
  selectedPrinterId: "usb-zebra",
  printerId: "usb-zebra",
  selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
  printerName: "ZDesigner ZT410-300dpi ZPL",
  agentVersion: "2026.6.26",
  buildVersion: "2026.6.26",
  persistentSessionRequired: true,
  persistentSessionCapable: true,
  persistentSessionUpdateRequired: false,
  persistentSessionDisconnected: false,
  capabilities: {
    supportsPersistentPrintSession: true,
  },
  printers: [{ printerId: "usb-zebra", printerName: "ZDesigner ZT410-300dpi ZPL", online: true }],
};

const localAgentStatus: NonNullable<Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>["data"]> = {
  connected: true, printerName: testPrinters[0].printerName, printerId: "usb-zebra",
  selectedPrinterId: "usb-zebra", selectedPrinterName: testPrinters[0].printerName,
  deviceName: null, agentVersion: "2026.6.26", protocolVersion: null,
  buildVersion: "2026.6.26", transportDiagnosticsVersion: null,
  capabilities: { supportsPersistentPrintSession: true }, error: null,
  agentId: null, deviceFingerprint: null, publicKeyPem: null,
  clientCertFingerprint: null, heartbeatNonce: null, heartbeatIssuedAt: null,
  heartbeatSignature: null, compatibilityMode: false, capabilitySummary: null,
  websocket: { mode: "websocket", supported: true, connected: true,
    sessionId: "session-live-1", registrationId: "registration-trusted-1", selectedPrinterId: "usb-zebra",
    lastConnectedAt: "2026-10-28T12:00:00.000Z", lastHeartbeatAt: "2026-10-28T12:00:00.000Z",
    lastDisconnectedAt: null, lastError: null, lastRejectReasonCode: null },
  printers: testPrinters, calibrationProfile: null,
};

const operationContext = (
  overrides: Partial<Parameters<typeof createPrintJob>[0]> = {}
): Parameters<typeof createPrintJob>[0] => ({
  toast: vi.fn(), printBatch: testBatch, printQuantity: "1", getAvailableInventory: () => 10,
  selectedPrinterProfile: testProfile, selectedPrinterId: "usb-zebra", detectedPrinters: testPrinters,
  printerStatus: productionReadyPrinterStatus, activeLocalPrinterId: "usb-zebra", selectedPrinterCanPrint: true,
  setPrinterStatus: setter(), buildCalibrationPayload: () => ({}), autoReportPrinterFailure: vi.fn(),
  loadRecentPrintJobs: async () => undefined, setPrintJobId: setter(), printJobId: "",
  directRemainingToPrint: null, setPrintProgressOpen: setter(), setPrintProgressPhase: setter(),
  setPrintProgressTotal: setter(), setPrintProgressPrinted: setter(), setPrintProgressRemaining: setter(),
  setPrintProgressCurrentCode: setter(), setPrintProgressError: setter(),
  setPrintProgressPrinterName: setter(), setPrintProgressDispatchMode: setter(),
  setDirectRemainingToPrint: setter(), ...overrides,
});

describe("batch print operations", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(apiClient.selectLocalPrinter).mockResolvedValue({ success: true, data: {} });
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({
      success: true,
      data: localAgentStatus,
    });
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValue({
      success: true,
      data: productionReadyPrinterStatus,
    });
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true,
      data: productionReadyPrinterStatus,
    });
    vi.mocked(apiClient.configureLocalPrintAgentBackend).mockResolvedValue({ success: true, data: {} });
    vi.mocked(apiClient.wakeLocalPrintAgent).mockResolvedValue({ success: true, data: { accepted: true } });
    vi.mocked(apiClient.createPrintJob).mockResolvedValue({
      success: true,
      data: {
        printJobId: "job-live",
        tokenCount: 10,
        mode: "LOCAL_AGENT",
        pipelineState: "QUEUED",
        printer: { name: "ZDesigner ZT410-300dpi ZPL" },
      },
    });
  });

  it("does not replace connector-originated attestation with a browser REST heartbeat during submission", async () => {
    await createPrintJob(operationContext());
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
    expect(apiClient.getPrinterConnectionStatus).toHaveBeenCalledWith({ force: true, minIntervalMs: 0 });
    expect(apiClient.createPrintJob).toHaveBeenCalledTimes(1);
  });

  it("does not create a job when a forced status check returns rate-limited cached readiness", async () => {
    const toast = vi.fn();
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({
      success: true, code: "RATE_LIMITED", degraded: true,
      data: { ...productionReadyPrinterStatus, rateLimited: true, refreshPaused: true },
    });
    await createPrintJob(operationContext({ toast }));
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Printer verification unavailable" }));
  });

  it("rejects a mismatched or unverified selection before changing the local queue", async () => {
    const toast = vi.fn();
    await createPrintJob(operationContext({ selectedPrinterCanPrint: false,
      selectedPrinterId: "another-queue", activeLocalPrinterId: "another-queue", toast }));
    expect(apiClient.selectLocalPrinter).not.toHaveBeenCalled();
    expect(apiClient.createPrintJob).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Printer verification required" }));
  });

  it("hands local-agent jobs to the realtime modal without waking REST claim polling", async () => {
    const setPrintJobId = setter();
    const setPrintProgressPhase = setter();
    const setPrintProgressNotice = setter();

    await createPrintJob({
      toast: vi.fn(),
      printBatch: testBatch,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: testProfile,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: testPrinters,
      printerStatus: productionReadyPrinterStatus,
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

  it("marks unsafe payload creation failures as failed before print", async () => {
    vi.mocked(apiClient.createPrintJob).mockResolvedValueOnce({
      success: false,
      errorCode: "print_payload_invalid",
      message: "Generated ZPL looks unsafe for this Zebra profile.",
      error: "unsafe_zpl_payload",
    });
    const setPrintProgressPhase = setter();
    const setPrintProgressError = setter();

    await createPrintJob({
      toast: vi.fn(),
      printBatch: testBatch,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: testProfile,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: testPrinters,
      printerStatus: productionReadyPrinterStatus,
      activeLocalPrinterId: "usb-zebra",
      selectedPrinterCanPrint: true,
      setPrinterStatus: setter(),
      buildCalibrationPayload: () => ({}),
      autoReportPrinterFailure: vi.fn().mockResolvedValue(true),
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
      setPrintProgressError,
      setPrintProgressNotice: setter(),
      setPrintProgressPrinterName: setter(),
      setPrintProgressDispatchMode: setter(),
      setDirectRemainingToPrint: setter(),
    });

    expect(setPrintProgressPhase).toHaveBeenLastCalledWith("Failed before print");
    expect(setPrintProgressError).toHaveBeenCalledWith(
      "The print payload was blocked before reaching the printer. No labels were printed. Use diagnostic test label or contact admin."
    );
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
      connectionClass: "BLOCKED" as const,
      persistentSessionDisconnected: true,
      error: "Persistent printer session is disconnected.",
    };
    vi.mocked(apiClient.reportPrinterHeartbeat).mockResolvedValueOnce({
      success: true,
      data: disconnectedStatus,
    });
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({
      success: true,
      data: disconnectedStatus,
    });
    const setPrintJobId = setter();
    const toast = vi.fn();

    await createPrintJob({
      toast,
      printBatch: testBatch,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: testProfile,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: testPrinters,
      printerStatus: disconnectedStatus,
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
    const outdatedStatus = {
      ...productionReadyPrinterStatus,
      connected: false,
      trusted: false,
      eligibleForPrinting: false,
      connectionClass: "BLOCKED" as const,
      persistentSessionRequired: true,
      persistentSessionCapable: false,
      persistentSessionUpdateRequired: true,
      persistentSessionMinimumBuildVersion: "2026.6.26",
      buildVersion: "2026.6.16",
    };
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValueOnce({
      success: true,
      data: outdatedStatus,
    });
    const setPrintProgressPhase = setter();
    const setPrintProgressNotice = setter();
    const autoReportPrinterFailure = vi.fn();
    const toast = vi.fn();

    await createPrintJob({
      toast,
      printBatch: testBatch,
      printQuantity: "10",
      getAvailableInventory: () => 10,
      selectedPrinterProfile: testProfile,
      selectedPrinterId: "usb-zebra",
      detectedPrinters: testPrinters,
      printerStatus: productionReadyPrinterStatus,
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

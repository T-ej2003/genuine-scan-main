import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { loadManufacturerPrinterRuntimeSnapshot, refreshManufacturerPrinterRuntimeSnapshot } from "@/features/printing/hooks";
import { defaultPrinterStatus } from "@/features/batches/print-workflow-utils";

vi.mock("@/lib/api-client", () => ({ default: {
  getPrinterConnectionStatus: vi.fn(), getLocalPrintAgentStatus: vi.fn(), listRegisteredPrinters: vi.fn(),
} }));

describe("start print run runtime verification", () => {
  const localStatus: NonNullable<Awaited<ReturnType<typeof apiClient.getLocalPrintAgentStatus>>["data"]> = {
    connected: true, printerName: null, printerId: null, selectedPrinterId: null,
    selectedPrinterName: null, deviceName: null, agentVersion: null, protocolVersion: null,
    buildVersion: null, transportDiagnosticsVersion: null, capabilities: null,
    error: null, agentId: null, deviceFingerprint: null, publicKeyPem: null,
    clientCertFingerprint: null, heartbeatNonce: null, heartbeatIssuedAt: null,
    heartbeatSignature: null, compatibilityMode: false, websocket: null,
    capabilitySummary: null, printers: [], calibrationProfile: null,
  };
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-28T12:00:00Z"));
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true, data: localStatus });
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue({ success: true, data: [] });
  });
  afterEach(() => { vi.useRealTimers(); vi.clearAllMocks(); });

  it.each([429, 401, 500])("does not describe a %i verification failure as a disconnected helper", async (status) => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status, error: "verification unavailable" });
    const result = await loadManufacturerPrinterRuntimeSnapshot(true, { force: true });
    expect(result.localAgent.connected).toBe(true);
    expect(result.remoteStatus.eligibleForPrinting).toBe(false);
    expect(result.remoteStatus.trustReason).not.toBe("No trusted printer registration");
  });

  it("rejects cached success marked rate limited during a forced dialogue refresh", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: true, code: "RATE_LIMITED", degraded: true,
      data: { ...defaultPrinterStatus, connected: true, trusted: true, eligibleForPrinting: true,
        connectionClass: "TRUSTED", trustStatus: "TRUSTED", stale: false, rateLimited: true,
        requiredForPrinting: true, lastHeartbeatAt: null, ageSeconds: 0 },
    });
    const result = await refreshManufacturerPrinterRuntimeSnapshot();
    expect(result.remoteStatus.eligibleForPrinting).toBe(false);
    expect(result.remoteStatus.trustReason).toMatch(/verification is unavailable/i);
  });
});

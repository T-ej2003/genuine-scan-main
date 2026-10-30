import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { loadManufacturerPrinterRuntimeSnapshot, refreshManufacturerPrinterRuntimeSnapshot } from "@/features/printing/hooks";
import { defaultPrinterStatus } from "@/features/batches/print-workflow-utils";

vi.mock("@/lib/api-client", () => ({ default: {
  getPrinterConnectionStatus: vi.fn(), getLocalPrintAgentStatus: vi.fn(), listRegisteredPrinters: vi.fn(),
  reportPrinterHeartbeat: vi.fn(),
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

  it("blocks expired verification until a connector-originated renewal is visible from the server", async () => {
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue({ success: true, data: {
      ...localStatus, printerId: "queue-1", selectedPrinterId: "queue-1", agentId: "agent-1",
      deviceFingerprint: "device-1", heartbeatNonce: "nonce-123456789", heartbeatIssuedAt: new Date().toISOString(),
      heartbeatSignature: "signed-connector-heartbeat",
    } });
    const expiredStatus = {
      ...defaultPrinterStatus, connected: true, trusted: true, eligibleForPrinting: false, stale: false,
      connectionClass: "TRUSTED", trustStatus: "TRUSTED", trustReason: "Printer attestation expired",
      selectedPrinterId: "queue-1", printerId: "queue-1", persistentSessionDisconnected: false,
      signedAttestation: { required: true, present: true, signatureValid: true, fresh: false },
      requiredForPrinting: true, lastHeartbeatAt: null, ageSeconds: 0,
    } as const;
    vi.mocked(apiClient.getPrinterConnectionStatus)
      .mockResolvedValueOnce({ success: true, data: expiredStatus })
      .mockResolvedValueOnce({ success: true, data: {
        ...expiredStatus, eligibleForPrinting: true, trustReason: null,
        signedAttestation: { ...expiredStatus.signedAttestation, fresh: true },
      } });
    const before = await refreshManufacturerPrinterRuntimeSnapshot();
    expect(before.localAgent.connected).toBe(true);
    expect(before.remoteStatus.eligibleForPrinting).toBe(false);
    const after = await refreshManufacturerPrinterRuntimeSnapshot();
    expect(after.remoteStatus.eligibleForPrinting).toBe(true);
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
  });

  it("keeps printing blocked when connector renewal is unavailable", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: false, status: 503, error: "verification unavailable",
    });
    const result = await refreshManufacturerPrinterRuntimeSnapshot();
    expect(result.remoteStatus.eligibleForPrinting).toBe(false);
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
  });
});

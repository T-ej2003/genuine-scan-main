import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import apiClient from "@/lib/api-client";
import { loadManufacturerPrinterRuntimeSnapshot } from "@/features/printing/hooks";
import { defaultPrinterStatus } from "@/features/batches/print-workflow-utils";
import { buildSecurePrintReadiness } from "@/lib/secure-printer-readiness";
import { queryClient } from "@/lib/query-client";

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
  afterEach(() => { queryClient.clear(); vi.useRealTimers(); vi.clearAllMocks(); });

  const trustedStatus = {
    ...defaultPrinterStatus,
    connected: true, trusted: true, eligibleForPrinting: true,
    securePrinterSession: true, freshHelperHeartbeat: true, helperConnection: true, eligiblePrinter: true,
    connectionClass: "TRUSTED" as const, trustStatus: "TRUSTED", stale: false,
    lastHeartbeatAt: "2026-10-28T11:59:55Z", ageSeconds: 5,
    registrationId: "registration-1", selectedPrinterId: "queue-1", printerId: "queue-1",
    selectedPrinterName: "Factory printer", printers: [{ printerId: "queue-1", printerName: "Factory printer", online: true, isDefault: true, protocols: [], languages: [], mediaSizes: [], dpi: null }],
  };

  it("retains verified identity through HTTP 503 without retaining print readiness or heartbeat freshness", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status: 503, error: "Status unavailable" });
    const previous = {
      localAgent: { reachable: true, connected: true, error: null, checkedAt: "2026-10-28T11:59:55Z" },
      remoteStatus: trustedStatus, detectedPrinters: trustedStatus.printers,
      registeredPrinters: [], preferredPrinterId: "queue-1",
    };
    const result = await loadManufacturerPrinterRuntimeSnapshot(true, { previous });
    expect(result.remoteStatus.registrationId).toBe("registration-1");
    expect(result.remoteStatus.selectedPrinterId).toBe("queue-1");
    expect(result.remoteStatus.lastHeartbeatAt).toBe("2026-10-28T11:59:55Z");
    expect(result.remoteStatus.ageSeconds).toBeNull();
    expect(result.remoteStatus.trustStatus).toBe("UNAVAILABLE");
    expect(result.remoteStatus.connected).toBe(false);
    expect(buildSecurePrintReadiness(result.remoteStatus).ready).toBe(false);
    expect(buildSecurePrintReadiness(result.remoteStatus).reasonCode).toBe("VERIFICATION_UNAVAILABLE");
  });

  it("fails closed when a status request rejects or returns malformed data", async () => {
    const previous = {
      localAgent: { reachable: true, connected: true, error: null, checkedAt: "2026-10-28T11:59:55Z" },
      remoteStatus: trustedStatus, detectedPrinters: trustedStatus.printers,
      registeredPrinters: [], preferredPrinterId: "queue-1",
    };
    vi.mocked(apiClient.getPrinterConnectionStatus)
      .mockRejectedValueOnce(new Error("network failure"))
      .mockResolvedValueOnce({ success: true, data: { connected: true } as never });
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const snapshot = await loadManufacturerPrinterRuntimeSnapshot(true, { previous });
      expect(snapshot.remoteStatus.registrationId).toBe("registration-1");
      expect(snapshot.remoteStatus.trustStatus).toBe("UNAVAILABLE");
      expect(buildSecurePrintReadiness(snapshot.remoteStatus).ready).toBe(false);
    }
  });

  it("does not retain another session's registration after authorization is rejected", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({ success: false, status: 403, error: "Forbidden" });
    const snapshot = await loadManufacturerPrinterRuntimeSnapshot(true, { previous: {
      localAgent: { reachable: true, connected: true, error: null, checkedAt: null },
      remoteStatus: trustedStatus, detectedPrinters: trustedStatus.printers,
      registeredPrinters: [{ id: "registration-1", name: "Factory printer", connectionType: "LOCAL_AGENT", isActive: true }],
      preferredPrinterId: "queue-1",
    } });
    expect(snapshot.remoteStatus.registrationId).toBeNull();
    expect(snapshot.registeredPrinters).toEqual([]);
    expect(buildSecurePrintReadiness(snapshot.remoteStatus).ready).toBe(false);
  });

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
    const result = await loadManufacturerPrinterRuntimeSnapshot(true, { force: true });
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
    const before = await loadManufacturerPrinterRuntimeSnapshot(true, { force: true });
    expect(before.localAgent.connected).toBe(true);
    expect(before.remoteStatus.eligibleForPrinting).toBe(false);
    const after = await loadManufacturerPrinterRuntimeSnapshot(true, { force: true });
    expect(after.remoteStatus.eligibleForPrinting).toBe(true);
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
  });

  it("keeps printing blocked when connector renewal is unavailable", async () => {
    vi.mocked(apiClient.getPrinterConnectionStatus).mockResolvedValue({
      success: false, status: 503, error: "verification unavailable",
    });
    const result = await loadManufacturerPrinterRuntimeSnapshot(true, { force: true });
    expect(result.remoteStatus.eligibleForPrinting).toBe(false);
    expect(apiClient.reportPrinterHeartbeat).not.toHaveBeenCalled();
  });
});

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api-client", () => ({ default: {
  getLocalPrintAgentStatus: vi.fn(), listRegisteredPrinters: vi.fn(),
  getConnectorUpgradePairing: vi.fn(), connectorUpgradeChallenge: vi.fn(),
  connectorUpgradeProof: vi.fn(), connectorMaintenance: vi.fn(),
  connectorMaintenanceEvidence: vi.fn(), completeConnectorUpgradePairing: vi.fn(),
  connectorPostInstallEvidence: vi.fn(),
  connectorUpgradeReleaseStatus: vi.fn(),
} }));

import apiClient from "@/lib/api-client";
import { authorizeInstallerUpgrade } from "@/features/connector/authorizeInstallerUpgrade";

const id = "a832a54d-d741-4f51-8c9d-e01e031c53d3";
const printerId = "4170c54b-2173-4867-b95a-7006b9aa60f5";
const challengeId = "7211b2fe-b043-4292-8ee3-9895ef81a49b";
const token = "a".repeat(64);
const binding = { agentId: "agent-1", deviceFingerprint: "device-1", sourceVersion: "2026.11.19.1",
  targetVersion: "2026.11.20.1", installerSha256: "b".repeat(64), stateSha256: "c".repeat(64) };
const ok = (data: unknown = {}) => ({ success: true, data });

describe("automatic connector upgrade handoff", () => {
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

  it("binds fresh proof and maintenance evidence to the private installer pairing, then releases only after post-install proof", async () => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue(ok({ ...binding, buildVersion: binding.sourceVersion }) as any);
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue(ok([{ id: printerId, agentId: binding.agentId,
      deviceFingerprint: binding.deviceFingerprint }]) as any);
    vi.mocked(apiClient.getConnectorUpgradePairing).mockResolvedValue(ok({ binding }) as any);
    vi.mocked(apiClient.connectorUpgradeChallenge).mockResolvedValue(ok({ challenge: { challengeId, attemptId: id,
      manufacturerId: "manufacturer", tenantId: null, printerId, registrationId: "registration" } }) as any);
    vi.mocked(apiClient.connectorUpgradeProof).mockResolvedValue(ok() as any);
    let authorizationResponses = 0;
    vi.mocked(apiClient.connectorMaintenance).mockImplementation(async (_printer, input: any) => {
      if (input.action === "authorize" && authorizationResponses++ === 0) return { success: false, unknownOutcome: true } as any;
      return ok(input.action === "request" ? { requestId: id } : input.action === "authorize" ? { token } : { state: "ACTIVE" }) as any;
    });
    vi.mocked(apiClient.connectorMaintenanceEvidence).mockResolvedValue({ success: true, evidence: { statement: "preinstall", signature: "signed" } } as any);
    vi.mocked(apiClient.completeConnectorUpgradePairing).mockResolvedValue(ok() as any);
    vi.mocked(apiClient.connectorPostInstallEvidence).mockResolvedValue({ success: true, evidence: { statement: "postinstall", signature: "signed" } } as any);
    vi.stubGlobal("fetch", vi.fn(async (url: string) => ({ ok: true, json: async () => ({ success: true,
      ...(url.endsWith("device-proof") ? { signature: "device-proof" } : {}),
      ...(url.endsWith("checkpoint-evidence") ? { evidence: { statement: "checkpoint", signature: "signed" } } : {}),
      ...(url.endsWith("postinstall-proof") ? { proof: { statement: "runtime", signature: "signed" } } : {}),
    }) })));
    const completion = authorizeInstallerUpgrade(id);
    await vi.waitFor(() => expect(apiClient.completeConnectorUpgradePairing).toHaveBeenCalledWith(printerId, id, token));
    await vi.advanceTimersByTimeAsync(2000);
    await completion;
    expect(apiClient.connectorUpgradeProof).toHaveBeenCalledWith(printerId, challengeId, "device-proof");
    expect(apiClient.connectorMaintenanceEvidence).toHaveBeenCalledWith(printerId,
      expect.objectContaining({ binding: expect.objectContaining({ attemptId: id, fenceRequestId: id }) }));
    expect(apiClient.connectorMaintenance).toHaveBeenCalledWith(printerId,
      { action: "release", evidence: { statement: "postinstall", signature: "signed" } });
    expect(authorizationResponses).toBe(2);
    vi.unstubAllGlobals();
  });
});

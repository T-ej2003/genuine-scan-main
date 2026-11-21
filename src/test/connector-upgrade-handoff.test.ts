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
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); vi.clearAllMocks(); });

  it.each([[false, false], [true, false], [false, true], [true, true]])(
    "binds proof to the pairing, including a stopped connector: lost=%s offline=%s", async (lostReleaseResponse, offline) => {
    vi.useFakeTimers();
    vi.mocked(apiClient.getLocalPrintAgentStatus).mockResolvedValue(ok({ ...binding, buildVersion: binding.sourceVersion,
      upgradeMode: offline ? "OFFLINE_EXISTING_INSTALL" : null }) as any);
    vi.mocked(apiClient.listRegisteredPrinters).mockResolvedValue(ok([{ id: printerId, agentId: binding.agentId,
      deviceFingerprint: binding.deviceFingerprint }]) as any);
    const calls: string[] = [];
    vi.mocked(apiClient.getConnectorUpgradePairing).mockImplementation(async () => {
      calls.push("pairing");
      return ok({ binding }) as any;
    });
    vi.mocked(apiClient.connectorUpgradeChallenge).mockResolvedValue(ok({ challenge: { challengeId, attemptId: id,
      manufacturerId: "manufacturer", tenantId: null, printerId, registrationId: "registration" } }) as any);
    vi.mocked(apiClient.connectorUpgradeProof).mockResolvedValue(ok() as any);
    let authorizationResponses = 0;
    vi.mocked(apiClient.connectorMaintenance).mockImplementation(async (_printer, input: any) => {
      if (input.action === "request") calls.push("fence");
      if (input.action === "authorize" && authorizationResponses++ === 0) throw new Error("authorization response lost");
      if (input.action === "release" && lostReleaseResponse) throw new Error("release response lost");
      return ok(input.action === "request" ? { requestId: id } : input.action === "authorize" ? { token } :
        { authorized: true, dispatchFenced: false }) as any;
    });
    vi.mocked(apiClient.connectorMaintenanceEvidence).mockResolvedValue({ success: true, evidence: { statement: "preinstall", signature: "signed" } } as any);
    vi.mocked(apiClient.completeConnectorUpgradePairing).mockRejectedValueOnce(new Error("pairing response lost"))
      .mockResolvedValue(ok() as any);
    vi.mocked(apiClient.connectorPostInstallEvidence).mockResolvedValue({ success: true, evidence: { statement: "postinstall", signature: "signed" } } as any);
    vi.mocked(apiClient.connectorUpgradeReleaseStatus).mockResolvedValue(ok({ released: true, dispatchFenced: false }) as any);
    let postInstallAttempts = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: string) => {
      if (url.endsWith("postinstall-proof") && postInstallAttempts++ < (lostReleaseResponse ? 130 : 0))
        throw new Error("replacement connector is still starting");
      return { ok: true, json: async () => ({ success: true,
      ...(url.endsWith("device-proof") ? { signature: "device-proof" } : {}),
      ...(url.endsWith("checkpoint-evidence") ? { evidence: { statement: "checkpoint", signature: "signed" } } : {}),
      ...(url.endsWith("postinstall-proof") ? { proof: { statement: "runtime", signature: "signed" } } : {}),
    }) }; }));
    const completion = authorizeInstallerUpgrade(id);
    await vi.waitFor(() => expect(apiClient.completeConnectorUpgradePairing).toHaveBeenCalledWith(printerId, id, token));
    expect(authorizeInstallerUpgrade(id)).toBe(completion);
    await vi.advanceTimersByTimeAsync((lostReleaseResponse ? 131 : 1) * 2000);
    await completion;
    expect(apiClient.connectorUpgradeProof).toHaveBeenCalledWith(printerId, challengeId, "device-proof");
    expect(apiClient.connectorMaintenanceEvidence).toHaveBeenCalledWith(printerId,
      expect.objectContaining({ binding: expect.objectContaining({ attemptId: id, fenceRequestId: id }) }));
    expect(apiClient.connectorMaintenance).toHaveBeenCalledWith(printerId,
      { action: "release", evidence: { statement: "postinstall", signature: "signed" } });
    expect(apiClient.connectorUpgradeReleaseStatus).toHaveBeenCalledTimes(lostReleaseResponse ? 1 : 0);
    expect(apiClient.completeConnectorUpgradePairing).toHaveBeenCalledTimes(2);
    expect(authorizationResponses).toBe(2);
    expect(calls.slice(0, 2)).toEqual(offline ? ["fence", "pairing"] : ["pairing", "fence"]);
    vi.unstubAllGlobals();
  });
});

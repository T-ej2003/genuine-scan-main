import apiClient from "@/lib/api-client";

const localBase = String(import.meta.env.VITE_PRINT_AGENT_URL || "http://127.0.0.1:17866").replace(/\/+$/, "");

const localPost = async (path: string, body: unknown) => {
  const response = await fetch(`${localBase}${path}`, {
    method: "POST", mode: "cors", cache: "no-store",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok || result?.success !== true) throw new Error("The installed connector could not authorize this upgrade.");
  return result;
};

export async function authorizeInstallerUpgrade(pairingId: string, signal?: AbortSignal) {
  const local = await apiClient.getLocalPrintAgentStatus();
  const roster = await apiClient.listRegisteredPrinters(true);
  if (!local.success || !local.data || !roster.success || !Array.isArray(roster.data))
    throw new Error("Sign in on the printer computer and keep the existing connector running.");
  const status = local.data as { agentId?: string | null; deviceFingerprint?: string | null; buildVersion?: string | null };
  const matches = (roster.data as Array<{ id?: string; agentId?: string; deviceFingerprint?: string }>).filter(printer =>
    printer.agentId === status.agentId && printer.deviceFingerprint === status.deviceFingerprint);
  if (matches.length !== 1 || !matches[0].id) throw new Error("The registered connector and printer could not be matched uniquely.");
  const printerId = matches[0].id;
  const paired = await apiClient.getConnectorUpgradePairing(printerId, pairingId);
  if (!paired.success || !paired.data?.binding) throw new Error("The installer pairing is unavailable.");
  const candidate = paired.data.binding;
  if (candidate.agentId !== status.agentId || candidate.deviceFingerprint !== status.deviceFingerprint ||
      candidate.sourceVersion !== status.buildVersion || !candidate.targetVersion)
    throw new Error("The installed connector differs from the signed installer.");
  const challengeResponse = await apiClient.connectorUpgradeChallenge(printerId, candidate.targetVersion,
    candidate.attemptId || undefined);
  if (!challengeResponse.success || !challengeResponse.data?.challenge) throw new Error("Device verification is unavailable.");
  const challenge = challengeResponse.data.challenge;
  const challengeId = String(challenge.challengeId || "");
  const proof = await localPost("/maintenance/device-proof", challenge);
  const verified = await apiClient.connectorUpgradeProof(printerId, challengeId, String(proof.signature || ""));
  if (!verified.success) throw new Error("Device identity could not be verified.");
  const requested = await apiClient.connectorMaintenance(printerId, { action: "request" });
  const fenceRequestId = String(requested.data?.requestId || "");
  if (!requested.success || !fenceRequestId) throw new Error("Backend printing isolation could not be established.");
  await localPost("/maintenance/fence", {});
  const checkpoint = await localPost("/maintenance/checkpoint-evidence", challenge);
  const binding: Record<string, string | null> = { ...candidate, ...Object.fromEntries(
    ["attemptId", "manufacturerId", "tenantId", "printerId", "registrationId"].map(key => [key, challenge[key] ?? null])),
    fenceRequestId };
  const evidence = await apiClient.connectorMaintenanceEvidence(printerId, {
    challengeId, checkpoint: checkpoint.evidence, binding,
  });
  const signedEvidence = (evidence as any).evidence;
  if (!evidence.success || !signedEvidence)
    throw new Error("Printing state could not be independently verified. Printing remains isolated.");
  let token = "";
  for (let retry = 0; retry < 3 && !token; retry += 1) {
    const authorized = await apiClient.connectorMaintenance(printerId, { action: "authorize", evidence: signedEvidence }).catch(() => null);
    if (authorized?.success) token = String(authorized.data?.token || "");
  }
  if (!/^[a-f0-9]{64}$/.test(token))
    throw new Error("Upgrade authorization could not be issued. Printing remains isolated.");
  let delivered = false;
  for (let retry = 0; retry < 3 && !delivered; retry += 1)
    delivered = Boolean((await apiClient.completeConnectorUpgradePairing(printerId, pairingId, token).catch(() => null))?.success);
  if (!delivered) throw new Error("The installer could not receive authorization. Printing remains isolated.");
  for (let index = 0; index < 120; index += 1) {
    if (signal?.aborted) return;
    await new Promise(resolve => window.setTimeout(resolve, 2000));
    let postInstall;
    try { postInstall = await localPost("/maintenance/postinstall-proof", { attemptId: binding["attemptId"] }); }
    catch { continue; }
    const verifiedPostInstall = await apiClient.connectorPostInstallEvidence(printerId, { token, proof: postInstall.proof });
    const releaseEvidence = (verifiedPostInstall as any).evidence;
    if (!verifiedPostInstall.success || !releaseEvidence)
      throw new Error("Post-install verification failed. The connector remains installed with printing paused.");
    const released = await apiClient.connectorMaintenance(printerId, { action: "release", evidence: releaseEvidence }).catch(() => null);
    if (!released?.success || released.data?.authorized !== true || released.data?.dispatchFenced !== false) {
      const receipt = await apiClient.connectorUpgradeReleaseStatus(token, binding);
      if (!receipt.success || receipt.data?.released !== true || receipt.data?.dispatchFenced !== false)
        throw new Error("Backend safety checks did not release printing. Uncertain attempts remain protected.");
    }
    return;
  }
  throw new Error("The upgraded connector did not reconnect in time. Printing remains paused for safe recovery.");
}

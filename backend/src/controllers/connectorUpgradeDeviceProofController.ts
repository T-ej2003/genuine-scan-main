import { Response } from "express";
import { randomUUID } from "crypto";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter, readUpgradeDeviceBinding } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { getConnectorReleaseManifest } from "../services/connectorReleaseService";
import { getRedisClient } from "../services/redisService";
import { createUpgradeDeviceChallenge, upgradeAttemptKey, upgradeChallengeSchema, upgradeProofKey, verifyUpgradeDeviceChallenge } from "../services/connectorUpgradeDeviceProof";

const challengeKey = (id: string) => `connector-upgrade:challenge:${id}`;
const version = z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/);
const newer = (target: string, source: string) => {
  const a = target.split(".").map(Number), b = source.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return false;
};

export const trustedBinding = async (req: AuthRequest) => {
  if (!req.user) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
  const printerId = z.string().uuid().parse(req.params.id);
  const result = await readUpgradeDeviceBinding({ capability: String(req.databaseSessionCapability || ""),
    requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
    printerId });
  const trusted = z.object({ agentId: z.string().min(3), deviceFingerprint: z.string().min(8),
    manufacturerId: z.string(), tenantId: z.string().nullable(), printerId: z.string().uuid(),
    registrationId: z.string().uuid(), publicKeyPem: z.string().min(1), sourceVersion: version }).parse(result);
  if (trusted.manufacturerId !== req.user.userId || trusted.printerId !== printerId)
    throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
  const { publicKeyPem, sourceVersion, ...binding } = trusted;
  return { publicKeyPem, sourceVersion, binding };
};

export const issueConnectorUpgradeChallenge = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const { targetVersion, attemptId } = z.object({ targetVersion: version, attemptId: z.string().uuid().optional() }).strict().parse(req.body);
    const { binding, sourceVersion } = await trustedBinding(req);
    const release = getConnectorReleaseManifest().releases.find(item => item.version === targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade")
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const redis = await getRedisClient();
    if (!redis) throw new Error("CONNECTOR_UPGRADE_CHALLENGE_STORE_UNAVAILABLE");
    const id = attemptId || randomUUID();
    let immutable = { ...binding, sourceVersion, targetVersion };
    if (attemptId) {
      const raw = await redis.get(upgradeAttemptKey(id));
      if (!raw) throw new Error("CONNECTOR_UPGRADE_ATTEMPT_NOT_FOUND");
      const previous = JSON.parse(raw);
      if (Object.entries(binding).some(([key, value]) => previous[key] !== value) ||
          previous.targetVersion !== targetVersion || ![previous.sourceVersion, targetVersion].includes(sourceVersion) ||
          !previous.fenceRequestId || !newer(targetVersion, previous.sourceVersion))
        throw new Error("CONNECTOR_UPGRADE_ATTEMPT_MISMATCH");
      immutable = { ...binding, sourceVersion: previous.sourceVersion, targetVersion };
      const status = await administerPrintingPrinter({ capability: String(req.databaseSessionCapability || ""),
        requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
        operation: "MAINTENANCE_STATUS", printerId: binding.printerId, payload: {} });
      if (status.state !== "DISPATCH_FENCED" || status.requestId !== previous.fenceRequestId)
        throw new Error("CONNECTOR_UPGRADE_FENCE_MISMATCH");
    } else if (!newer(targetVersion, sourceVersion) ||
      await redis.set(upgradeAttemptKey(id), JSON.stringify(immutable), "PX", 86_400_000, "NX") !== "OK")
      throw new Error("CONNECTOR_UPGRADE_ATTEMPT_CONFLICT");
    const challenge = createUpgradeDeviceChallenge({ ...immutable, currentVersion: sourceVersion, attemptId: id });
    if (await redis.set(challengeKey(challenge.challengeId), JSON.stringify(challenge), "PX", 120_000, "NX") !== "OK")
      throw new Error("CONNECTOR_UPGRADE_CHALLENGE_STORE_UNAVAILABLE");
    return res.json({ success: true, data: { challenge } });
  } catch {
    return res.status(409).json({ success: false, error: "Connector upgrade device challenge is unavailable." });
  }
};

export const verifyConnectorUpgradeProof = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const { challengeId, signature } = z.object({ challengeId: z.string().uuid(),
      signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/) }).strict().parse(req.body);
    const { binding, publicKeyPem, sourceVersion } = await trustedBinding(req);
    const redis = await getRedisClient();
    if (!redis) throw new Error("CONNECTOR_UPGRADE_CHALLENGE_STORE_UNAVAILABLE");
    const raw = await redis.eval('local v=redis.call("GET",KEYS[1]); if v then redis.call("DEL",KEYS[1]); end; return v', 1, challengeKey(challengeId));
    if (typeof raw !== "string") throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const challenge = upgradeChallengeSchema.parse(JSON.parse(raw));
    if (challenge.challengeId !== challengeId) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const attempt = await redis.get(upgradeAttemptKey(challenge.attemptId));
    const original = attempt && JSON.parse(attempt);
    if (!original || Object.entries(binding).some(([key, value]) => original[key] !== value) ||
        original.sourceVersion !== challenge.sourceVersion || original.targetVersion !== challenge.targetVersion ||
        challenge.currentVersion !== sourceVersion || ![original.sourceVersion, original.targetVersion].includes(sourceVersion))
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const release = getConnectorReleaseManifest().releases.find(item => item.version === challenge.targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade" ||
        !newer(challenge.targetVersion, original.sourceVersion))
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const proof = verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem,
      binding: { ...binding, attemptId: challenge.attemptId, sourceVersion: original.sourceVersion,
        currentVersion: sourceVersion, targetVersion: challenge.targetVersion } });
    if (await redis.set(upgradeProofKey(challengeId), JSON.stringify({ challenge, proofSha256: proof.proofSha256, publicKeyPem }),
      "PX", Math.max(1, Date.parse(challenge.expiresAt) - Date.now()), "NX") !== "OK")
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    return res.json({ success: true, attemptId: challenge.attemptId, challengeId, proofSha256: proof.proofSha256 });
  } catch {
    return res.status(403).json({ success: false, error: "Connector upgrade device proof was rejected." });
  }
};

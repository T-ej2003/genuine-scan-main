import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { getConnectorReleaseManifest } from "../services/connectorReleaseService";
import { getRedisClient } from "../services/redisService";
import { createUpgradeDeviceChallenge, upgradeChallengeSchema, verifyUpgradeDeviceChallenge } from "../services/connectorUpgradeDeviceProof";

const challengeKey = (id: string) => `connector-upgrade:challenge:${id}`;
const proofKey = (id: string) => `connector-upgrade:proof:${id}`;
const version = z.string().regex(/^\d+\.\d+\.\d+(?:\.\d+)?$/);
const newer = (target: string, source: string) => {
  const a = target.split(".").map(Number), b = source.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i += 1) {
    if ((a[i] || 0) !== (b[i] || 0)) return (a[i] || 0) > (b[i] || 0);
  }
  return false;
};

const trustedBinding = async (req: AuthRequest) => {
  if (!req.user) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
  const printerId = z.string().uuid().parse(req.params.id);
  const result = await administerPrintingPrinter({ capability: String(req.databaseSessionCapability || ""),
    requestId: String((req as AuthRequest & { requestId?: string }).requestId || ""),
    operation: "MAINTENANCE_DEVICE_BINDING", printerId });
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
    const { targetVersion } = z.object({ targetVersion: version }).strict().parse(req.body);
    const { binding, sourceVersion } = await trustedBinding(req);
    const release = getConnectorReleaseManifest().releases.find(item => item.version === targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade" ||
        !newer(targetVersion, sourceVersion))
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const challenge = createUpgradeDeviceChallenge({ ...binding, sourceVersion, targetVersion });
    const redis = await getRedisClient();
    if (!redis || await redis.set(challengeKey(challenge.attemptId), JSON.stringify(challenge), "PX", 120_000, "NX") !== "OK")
      throw new Error("CONNECTOR_UPGRADE_CHALLENGE_STORE_UNAVAILABLE");
    return res.json({ success: true, challenge });
  } catch {
    return res.status(409).json({ success: false, error: "Connector upgrade device challenge is unavailable." });
  }
};

export const verifyConnectorUpgradeProof = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const { attemptId, signature } = z.object({ attemptId: z.string().uuid(),
      signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/) }).strict().parse(req.body);
    const { binding, publicKeyPem, sourceVersion } = await trustedBinding(req);
    const redis = await getRedisClient();
    if (!redis) throw new Error("CONNECTOR_UPGRADE_CHALLENGE_STORE_UNAVAILABLE");
    const raw = await redis.eval('local v=redis.call("GET",KEYS[1]); if v then redis.call("DEL",KEYS[1]); end; return v', 1, challengeKey(attemptId));
    if (typeof raw !== "string") throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const challenge = upgradeChallengeSchema.parse(JSON.parse(raw));
    if (challenge.attemptId !== attemptId) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const release = getConnectorReleaseManifest().releases.find(item => item.version === challenge.targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade" ||
        !newer(challenge.targetVersion, sourceVersion))
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const proof = verifyUpgradeDeviceChallenge({ challenge, signature, publicKeyPem,
      binding: { ...binding, sourceVersion, targetVersion: challenge.targetVersion } });
    if (await redis.set(proofKey(attemptId), JSON.stringify({ challenge, proofSha256: proof.proofSha256 }), "PX", 120_000, "NX") !== "OK")
      throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    return res.json({ success: true, attemptId, proofSha256: proof.proofSha256 });
  } catch {
    return res.status(403).json({ success: false, error: "Connector upgrade device proof was rejected." });
  }
};

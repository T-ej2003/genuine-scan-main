import { createHash, randomBytes } from "crypto";
import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { issueConnectorIsolationEvidence, verifyConnectorIsolationEvidence } from "../services/connectorMaintenanceEvidence";
import { upgradeAttemptKey, upgradeChallengeSchema, upgradeHandoffKey, upgradeProofKey } from "../services/connectorUpgradeDeviceProof";
import { verifyMaintenanceCheckpoint } from "../services/connectorUpgradeDeviceProof";
import { trustedBinding } from "./connectorUpgradeDeviceProofController";
import { getConnectorReleaseManifest } from "../services/connectorReleaseService";
import { getRedisClient } from "../services/redisService";
import { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";
import { openCookieToken, sealCookieToken } from "../services/auth/cookieTokenProtectionService";

const printingCapability = (req: AuthRequest) => String(req.databaseSessionCapability || "").trim();
const printingRequestId = (req: AuthRequest) => String((req as AuthRequest & { requestId?: string }).requestId || "").trim();
const maintenanceBinding = z.record(z.string(), z.string().max(256).nullable());

export const issueVerifiedConnectorMaintenanceEvidence = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = z.object({ challengeId: z.string().uuid(),
      checkpoint: z.object({ statement: z.string().max(900_000), signature: z.string().max(200) }).strict(),
      binding: maintenanceBinding }).strict().parse(req.body);
    const { binding: trusted, publicKeyPem, sourceVersion } = await trustedBinding(req);
    const redis = await getRedisClient();
    if (!redis) throw new Error("CONNECTOR_UPGRADE_PROOF_STORE_UNAVAILABLE");
    const raw = await redis.get(upgradeProofKey(input.challengeId));
    if (!raw) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const proof = JSON.parse(raw);
    const challenge = upgradeChallengeSchema.parse(proof.challenge);
    const checkpoint = verifyMaintenanceCheckpoint(input.checkpoint, challenge, publicKeyPem);
    const attemptRaw = await redis.get(upgradeAttemptKey(challenge.attemptId));
    if (!attemptRaw) throw new Error("CONNECTOR_UPGRADE_ATTEMPT_NOT_FOUND");
    const attempt = JSON.parse(attemptRaw);
    const release = getConnectorReleaseManifest().releases.find(item => item.version === challenge.targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade" ||
        !release.platforms.windows?.sha256 ||
        Object.entries(trusted).some(([key, value]) => challenge[key as keyof typeof challenge] !== value || input.binding[key] !== value) ||
        Object.entries(attempt).some(([key, value]) => key !== "fenceRequestId" && input.binding[key] !== value) ||
        challenge.currentVersion !== sourceVersion || attempt.sourceVersion !== challenge.sourceVersion ||
        attempt.targetVersion !== challenge.targetVersion ||
        input.binding.attemptId !== challenge.attemptId || input.binding.sourceVersion !== challenge.sourceVersion ||
        input.binding.targetVersion !== challenge.targetVersion ||
        input.binding.installerSha256 !== release.platforms.windows.sha256 ||
        input.binding.publicKeySha256 !== createHash("sha256").update(publicKeyPem).digest("hex") ||
        input.binding.protocolVersion !== LOCAL_AGENT_DIRECT_PROTOCOL_VERSION ||
        (attempt.fenceRequestId && input.binding.fenceRequestId !== attempt.fenceRequestId))
      throw new Error("CONNECTOR_UPGRADE_BINDING_INVALID");
    const snapshot = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
      operation: "MAINTENANCE_INVENTORY", printerId: trusted.printerId, payload: {} });
    if (snapshot.state !== "DISPATCH_FENCED" || snapshot.requestId !== input.binding.fenceRequestId ||
        !/^[a-f0-9]{64}$/.test(String(proof.proofSha256 || "")) ||
        !/^[a-f0-9]{64}$/.test(String(snapshot.workDigest || "")) ||
        !Array.isArray(snapshot.inventory?.items) || snapshot.inventory.items.length !== 0 ||
        checkpoint.journal.count !== 0 ||
        Object.keys(snapshot.inventory?.diagnostics || {}).length !== 0 ||
        (snapshot.inventory?.localDiagnostics || []).length !== 0)
      throw new Error("MAINTENANCE_RECONCILIATION_REQUIRED");
    const now = Date.now();
    const evidence = issueConnectorIsolationEvidence({ purpose: "mscqr-legacy-connector-isolation-v1",
      binding: input.binding, challengeId: challenge.challengeId, deviceProofSha256: proof.proofSha256,
      workDigest: snapshot.workDigest, verifiedAt: new Date(now).toISOString(),
      expiresAt: new Date(Math.min(now + 120_000, Date.parse(challenge.expiresAt))).toISOString(),
      isolationEvidence: [
        { kind: "dispatch-isolation", sha256: createHash("sha256").update(input.checkpoint.statement).digest("hex"), reference: challenge.challengeId },
        { kind: "connector-work-inventory", sha256: checkpoint.journal.sha256, reference: challenge.challengeId },
      ], reconciliations: [] });
    return res.json({ success: true, evidence });
  } catch {
    return res.status(409).json({ success: false, error: "Verified connector maintenance evidence is unavailable." });
  }
};

export const requestConnectorMaintenance = async (req: AuthRequest, res: Response) => {
  try {
    const input = z.discriminatedUnion("action", [
      z.object({ action: z.literal("request") }).strict(),
      z.object({ action: z.literal("inventory") }).strict(),
      z.object({ action: z.enum(["authorize","release"]), evidence: z.object({ statement: z.string().max(100000), signature: z.string().max(200) }).strict() }).strict(),
      z.object({ action: z.enum(["consume", "verify"]), token: z.string().regex(/^[a-f0-9]{64}$/), binding: maintenanceBinding }).strict(),
    ]).parse(req.body || {});
    let token: string | undefined;
    let payload: Record<string, unknown> = {};
    if (input.action === "authorize") {
      token = randomBytes(32).toString("hex");
      payload = { evidence: verifyConnectorIsolationEvidence(input.evidence),
        tokenHash: createHash("sha256").update(token).digest("hex") };
      if ((payload.evidence as any).binding?.protocolVersion !== LOCAL_AGENT_DIRECT_PROTOCOL_VERSION) throw new Error("MAINTENANCE_PROTOCOL_UNSUPPORTED");
      const evidence = payload.evidence as any;
      const binding = evidence.binding;
      const redis = await getRedisClient();
      if (!redis || typeof binding?.attemptId !== "string" || typeof evidence.challengeId !== "string" ||
          !/^[a-f0-9]{64}$/.test(String(evidence.deviceProofSha256 || ""))) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
      const attemptRaw = await redis.get(upgradeAttemptKey(binding.attemptId));
      if (!attemptRaw || Object.entries(JSON.parse(attemptRaw)).some(([key, value]) => key !== "fenceRequestId" && binding[key] !== value))
        throw new Error("CONNECTOR_UPGRADE_ATTEMPT_MISMATCH");
      // The database gate serializes AUTHORIZE and rejects a second live token.
      // Keep the short-lived proof retryable until that transaction commits.
      const raw = await redis.get(upgradeProofKey(evidence.challengeId));
      if (typeof raw !== "string") throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
      const stored = JSON.parse(raw);
      const challenge = upgradeChallengeSchema.parse(stored.challenge);
      if (Date.parse(challenge.expiresAt) <= Date.now() ||
          challenge.challengeId !== evidence.challengeId || challenge.attemptId !== binding.attemptId ||
          stored.proofSha256 !== evidence.deviceProofSha256 ||
          ["agentId", "deviceFingerprint", "manufacturerId", "tenantId", "printerId", "registrationId",
            "sourceVersion", "targetVersion"].some(key => challenge[key as keyof typeof challenge] !== binding[key]))
        throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
      if (await redis.set(upgradeAttemptKey(binding.attemptId),
        JSON.stringify({ ...JSON.parse(attemptRaw), fenceRequestId: binding.fenceRequestId }), "PX", 86_400_000) !== "OK")
        throw new Error("CONNECTOR_UPGRADE_ATTEMPT_STORE_UNAVAILABLE");
    } else if (input.action === "release") {
      payload = { evidence: verifyConnectorIsolationEvidence(input.evidence,"mscqr-upgrade-verification-v1") };
    } else if (input.action === "consume" || input.action === "verify") {
      payload = { binding: input.binding, tokenHash: createHash("sha256").update(input.token).digest("hex") };
    }
    if (token && input.action === "authorize") {
      const redis = await getRedisClient();
      const evidence = payload.evidence as any;
      const ttl = Math.min(900_000, Date.parse(evidence.expiresAt) - Date.now());
      if (!redis || ttl <= 0 || await redis.set(upgradeHandoffKey(String(payload.tokenHash)),
        JSON.stringify({ capability: sealCookieToken(printingCapability(req), "auth.database-session"),
          binding: evidence.binding, printerId: String(req.params.id) }), "PX", ttl, "NX") !== "OK")
        throw new Error("CONNECTOR_UPGRADE_HANDOFF_UNAVAILABLE");
    }
    const data = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
      operation: ({ request: "MAINTENANCE_REQUEST", inventory: "MAINTENANCE_INVENTORY", authorize: "MAINTENANCE_AUTHORIZE",
        consume: "MAINTENANCE_CONSUME", verify: "MAINTENANCE_VERIFY", release: "MAINTENANCE_RELEASE" } as const)[input.action], printerId: String(req.params.id), payload });
    res.setHeader("Cache-Control", "no-store");
    return res.json({ success: true, data: { ...data, ...(token ? { token } : {}) } });
  } catch (error: any) {
    if (error instanceof z.ZodError && error.issues.some(issue => issue.code === 'too_big' && issue.path.join('.') === 'evidence.statement')) {
      return res.status(400).json({success:false,code:'MAINTENANCE_EVIDENCE_TOO_LARGE',error:'Signed maintenance evidence exceeds 100,000 characters. Keep dispatch fenced; partial evidence cannot authorize an upgrade.'});
    }
    if (error instanceof z.ZodError) return res.status(400).json({ success: false, error: "Invalid maintenance request." });
    if (/MAINTENANCE_WORKSET_TOO_LARGE/.test(String(error?.message))) {
      return res.status(409).json({success:false,code:'MAINTENANCE_WORKSET_TOO_LARGE',error:'Unresolved maintenance work exceeds the supported bounded inventory. Keep dispatch fenced and reconcile accepted work through authenticated confirmation. Do not reset uncertain work or submit partial inventories; contact MSCQR support for governed continuation.'});
    }
    const denied = /DENIED|CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID|CONNECTOR_UPGRADE_ATTEMPT_MISMATCH|permission|NO_DATA|query returned no rows|No .*found/i.test(String(error?.message));
    return res.status(denied ? 403 : 409).json({ success: false,
      error: denied ? "Connector maintenance is not authorized." : "Connector maintenance could not be established." });
  }
};

export const redeemConnectorMaintenanceHandoff = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = z.object({ action: z.enum(["consume", "verify"]), token: z.string().regex(/^[a-f0-9]{64}$/),
      binding: maintenanceBinding }).strict().parse(req.body);
    const tokenHash = createHash("sha256").update(input.token).digest("hex");
    const redis = await getRedisClient();
    const raw = redis && await redis.get(upgradeHandoffKey(tokenHash));
    if (!raw) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    const stored = JSON.parse(raw);
    const binding = stored.binding as Record<string, string>;
    if (!binding || Object.keys(binding).length !== Object.keys(input.binding).length ||
        Object.entries(binding).some(([key, value]) => input.binding[key] !== value) ||
        stored.printerId !== binding.printerId) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    const capability = openCookieToken(String(stored.capability), "auth.database-session");
    if (!capability) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    const data = await administerPrintingPrinter({ capability, requestId: printingRequestId(req),
      operation: input.action === "consume" ? "MAINTENANCE_CONSUME" : "MAINTENANCE_VERIFY",
      printerId: stored.printerId, payload: { binding, tokenHash } });
    if (data?.authorized !== true || data?.dispatchFenced !== true ||
        Object.keys(data.binding || {}).length !== Object.keys(binding).length ||
        Object.entries(binding).some(([key, value]) => data.binding[key] !== value))
      throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    return res.json({ success: true, data });
  } catch {
    return res.status(403).json({ success: false, error: "Connector maintenance handoff was rejected." });
  }
};


import { createHash, randomBytes, timingSafeEqual } from "crypto";
import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter, protectUpgradeUnknownAttempts, redeemPrintingUpgradeHandoff } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { issueConnectorIsolationEvidence, verifyConnectorIsolationEvidence } from "../services/connectorMaintenanceEvidence";
import { MAX_MAINTENANCE_CHECKPOINT_CHARS, upgradeAttemptKey, upgradeAuthorizationKey, upgradeChallengeSchema, upgradeHandoffKey, upgradePairingKey, upgradePairingResultKey, upgradeProofKey, verifyPostInstallStatement } from "../services/connectorUpgradeDeviceProof";
import { verifyMaintenanceCheckpoint } from "../services/connectorUpgradeDeviceProof";
import { trustedBinding } from "./connectorUpgradeDeviceProofController";
import { getConnectorReleaseManifest } from "../services/connectorReleaseService";
import { getRedisClient } from "../services/redisService";
import { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";
import { openCookieToken, sealCookieToken } from "../services/auth/cookieTokenProtectionService";

const printingCapability = (req: AuthRequest) => String(req.databaseSessionCapability || "").trim();
const printingRequestId = (req: AuthRequest) => String((req as AuthRequest & { requestId?: string }).requestId || "").trim();
const maintenanceBinding = z.record(z.string(), z.string().max(256).nullable());
const pairingSchema = z.object({ pairingId: z.string().uuid(), secret: z.string().regex(/^[a-f0-9]{64}$/) });
const pairingLifetimeMs = 15 * 60_000;

export const createConnectorUpgradePairing = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = pairingSchema.extend({ binding: maintenanceBinding }).strict().parse(req.body);
    if (!["agentId", "deviceFingerprint", "sourceVersion", "targetVersion", "installerSha256", "stateSha256"]
      .every(key => typeof input.binding[key] === "string" && input.binding[key])) throw new Error("INVALID_PAIRING");
    const redis = await getRedisClient();
    if (!redis || await redis.set(upgradePairingKey(input.pairingId), JSON.stringify({
      secretHash: createHash("sha256").update(input.secret).digest("hex"), binding: input.binding,
    }), "PX", pairingLifetimeMs, "NX") !== "OK") throw new Error("PAIRING_UNAVAILABLE");
    return res.json({ success: true, pairingId: input.pairingId });
  } catch {
    return res.status(409).json({ success: false, error: "Connector upgrade pairing is unavailable." });
  }
};

export const pollConnectorUpgradePairing = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = pairingSchema.strict().parse(req.body);
    const redis = await getRedisClient();
    const raw = redis && await redis.get(upgradePairingKey(input.pairingId));
    if (!raw) throw new Error("PAIRING_INVALID");
    const stored = JSON.parse(raw);
    const supplied = createHash("sha256").update(input.secret).digest();
    if (typeof stored.secretHash !== "string" || !/^[a-f0-9]{64}$/.test(stored.secretHash) ||
      !timingSafeEqual(supplied, Buffer.from(stored.secretHash, "hex"))) throw new Error("PAIRING_INVALID");
    const result = await redis.get(upgradePairingResultKey(input.pairingId));
    if (!result) return res.status(202).json({ success: false, pending: true });
    const value = JSON.parse(result);
    const token = openCookieToken(String(value.sealedToken), "connector-upgrade.authorization");
    if (!token || !/^[a-f0-9]{64}$/.test(token)) throw new Error("PAIRING_INVALID");
    return res.json({ success: true, token, binding: value.binding });
  } catch {
    return res.status(403).json({ success: false, error: "Connector upgrade pairing was rejected." });
  }
};

export const readConnectorUpgradePairing = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const pairingId = z.string().uuid().parse(req.params.pairingId);
    const { binding } = await trustedBinding(req);
    const redis = await getRedisClient();
    const raw = redis && await redis.get(upgradePairingKey(pairingId));
    if (!raw) throw new Error("PAIRING_INVALID");
    const candidate = maintenanceBinding.parse(JSON.parse(raw).binding);
    if (candidate.agentId !== binding.agentId || candidate.deviceFingerprint !== binding.deviceFingerprint ||
        (candidate.registrationId && candidate.registrationId !== binding.registrationId) ||
        (candidate.printerId && candidate.printerId !== binding.printerId)) throw new Error("PAIRING_INVALID");
    return res.json({ success: true, data: { binding: candidate } });
  } catch {
    return res.status(403).json({ success: false, error: "Connector upgrade pairing was rejected." });
  }
};

export const completeConnectorUpgradePairing = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = z.object({ pairingId: z.string().uuid(), token: z.string().regex(/^[a-f0-9]{64}$/) }).strict().parse(req.body);
    if (!req.user) throw new Error("PAIRING_INVALID");
    const printerId = z.string().uuid().parse(req.params.id);
    const redis = await getRedisClient();
    if (!redis) throw new Error("PAIRING_INVALID");
    const [pairingRaw, handoffRaw] = await Promise.all([
      redis.get(upgradePairingKey(input.pairingId)),
      redis.get(upgradeHandoffKey(createHash("sha256").update(input.token).digest("hex"))),
    ]);
    if (!pairingRaw || !handoffRaw) throw new Error("PAIRING_INVALID");
    const candidate = maintenanceBinding.parse(JSON.parse(pairingRaw).binding);
    const handoff = JSON.parse(handoffRaw);
    const bound = maintenanceBinding.parse(handoff.binding);
    const attemptRaw = bound.attemptId && await redis.get(upgradeAttemptKey(bound.attemptId));
    const attempt = attemptRaw && JSON.parse(attemptRaw);
    if (handoff.printerId !== printerId || bound.printerId !== printerId ||
        bound.manufacturerId !== req.user.userId || !attempt ||
        Object.entries(attempt).some(([key, value]) => key !== "fenceRequestId" && bound[key] !== value) ||
        Object.entries(candidate).some(([key, value]) => bound[key] !== value)) throw new Error("PAIRING_INVALID");
    const key = upgradePairingResultKey(input.pairingId);
    const value = JSON.stringify({ sealedToken: sealCookieToken(input.token, "connector-upgrade.authorization"), binding: bound });
    if (await redis.set(key, value, "PX", pairingLifetimeMs, "NX") !== "OK") {
      const previous = await redis.get(key);
      const existing = previous && JSON.parse(previous);
      if (!existing || openCookieToken(String(existing.sealedToken), "connector-upgrade.authorization") !== input.token ||
          JSON.stringify(existing.binding) !== JSON.stringify(bound)) throw new Error("PAIRING_CONFLICT");
    }
    return res.json({ success: true });
  } catch {
    return res.status(403).json({ success: false, error: "Connector upgrade pairing was rejected." });
  }
};

export const issueVerifiedConnectorMaintenanceEvidence = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = z.object({ challengeId: z.string().uuid(),
      checkpoint: z.object({ statement: z.string().max(MAX_MAINTENANCE_CHECKPOINT_CHARS), signature: z.string().max(200) }).strict(),
      binding: maintenanceBinding }).strict().parse(req.body);
    if (!req.user) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const redis = await getRedisClient();
    if (!redis) throw new Error("CONNECTOR_UPGRADE_PROOF_STORE_UNAVAILABLE");
    const raw = await redis.get(upgradeProofKey(input.challengeId));
    if (!raw) throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
    const proof = JSON.parse(raw);
    const challenge = upgradeChallengeSchema.parse(proof.challenge);
    const checkpoint = verifyMaintenanceCheckpoint(input.checkpoint, challenge, String(proof.publicKeyPem || ""));
    const attemptRaw = await redis.get(upgradeAttemptKey(challenge.attemptId));
    if (!attemptRaw) throw new Error("CONNECTOR_UPGRADE_ATTEMPT_NOT_FOUND");
    const attempt = JSON.parse(attemptRaw);
    const release = getConnectorReleaseManifest().releases.find(item => item.version === challenge.targetVersion);
    if (!release?.productionSignedAvailable || release.platforms.windows?.installationScope !== "certified-upgrade" ||
        !release.platforms.windows?.sha256 ||
        challenge.manufacturerId !== req.user.userId || challenge.printerId !== req.params.id ||
        ["agentId", "deviceFingerprint", "manufacturerId", "tenantId", "printerId", "registrationId"]
          .some(key => input.binding[key] !== challenge[key as keyof typeof challenge]) ||
        Object.entries(attempt).some(([key, value]) => key !== "fenceRequestId" && input.binding[key] !== value) ||
        attempt.sourceVersion !== challenge.sourceVersion ||
        attempt.targetVersion !== challenge.targetVersion ||
        input.binding.attemptId !== challenge.attemptId || input.binding.sourceVersion !== challenge.sourceVersion ||
        input.binding.targetVersion !== challenge.targetVersion ||
        input.binding.installerSha256 !== release.platforms.windows.sha256 ||
        input.binding.publicKeySha256 !== createHash("sha256").update(String(proof.publicKeyPem || "")).digest("hex") ||
        input.binding.protocolVersion !== LOCAL_AGENT_DIRECT_PROTOCOL_VERSION ||
        (attempt.fenceRequestId && input.binding.fenceRequestId !== attempt.fenceRequestId))
      throw new Error("CONNECTOR_UPGRADE_BINDING_INVALID");
    let snapshot = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
      operation: "MAINTENANCE_INVENTORY", printerId: challenge.printerId, payload: {} });
    if (snapshot.state !== "DISPATCH_FENCED" || snapshot.requestId !== input.binding.fenceRequestId ||
        !/^[a-f0-9]{64}$/.test(String(proof.proofSha256 || "")) ||
        !/^[a-f0-9]{64}$/.test(String(snapshot.workDigest || "")) ||
        !Array.isArray(snapshot.inventory?.items) ||
        Object.keys(snapshot.inventory?.diagnostics || {}).length !== 0 ||
        (snapshot.inventory?.localDiagnostics || []).length !== 0)
      throw new Error("MAINTENANCE_RECONCILIATION_REQUIRED");
    let protectedItemIds: string[] = [];
    if (checkpoint.journal.count > 0) {
      const fenceRequestId = input.binding.fenceRequestId;
      if (typeof fenceRequestId !== "string") throw new Error("MAINTENANCE_RECONCILIATION_REQUIRED");
      const protectedResult = await protectUpgradeUnknownAttempts({ capability: printingCapability(req),
        requestId: printingRequestId(req), printerId: challenge.printerId,
        fenceRequestId, journalSha256: checkpoint.journal.sha256,
        entries: checkpoint.journal.entries });
      if (!Array.isArray(protectedResult.protectedItemIds) ||
          protectedResult.protectedItemIds.length !== protectedResult.protected ||
          protectedResult.protected + protectedResult.settled + protectedResult.historicalReissues +
            protectedResult.supersededUnsubmitted + protectedResult.gatewayJournalEntries !== checkpoint.journal.count)
        throw new Error("MAINTENANCE_RECONCILIATION_REQUIRED");
      protectedItemIds = protectedResult.protectedItemIds;
      snapshot = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
        operation: "MAINTENANCE_INVENTORY", printerId: challenge.printerId, payload: {} });
    }
    const protectedSet = new Set(protectedItemIds);
    const entriesByItemAndHash = new Map<string, (typeof checkpoint.journal.entries)[number]>(
      checkpoint.journal.entries.map(entry => [`${entry.printItemId}:${entry.sha256}`, entry]));
    const journalByItem = new Map<string, (typeof checkpoint.journal.entries)[number] | undefined>(snapshot.inventory.items.map((item: any) => [item.id,
      entriesByItemAndHash.get(`${item.id}:${item.dispatchMetadata?.upgradeNoReplay?.entrySha256}`)]));
    if (snapshot.state !== "DISPATCH_FENCED" || snapshot.requestId !== input.binding.fenceRequestId ||
        journalByItem.size !== protectedSet.size || snapshot.inventory.items.length !== journalByItem.size ||
        snapshot.inventory.items.some((item: any) => {
          const entry = journalByItem.get(item.id);
          const marker = item.dispatchMetadata?.upgradeNoReplay;
          return !entry || item.state !== "FROZEN" || item.pipelineState !== "NEEDS_OPERATOR_ACTION" ||
            marker?.journalSha256 !== checkpoint.journal.sha256 || marker.entrySha256 !== entry.sha256 ||
            marker.attemptId !== entry.attemptId;
        })) throw new Error("MAINTENANCE_RECONCILIATION_REQUIRED");
    const reconciliations = snapshot.inventory.items.map((item: any) => ({ itemId: item.id,
      outcome: "PROTECTED_UNKNOWN", reference: journalByItem.get(item.id)!.sha256 }));
    const now = Date.now();
    const evidence = issueConnectorIsolationEvidence({ purpose: "mscqr-legacy-connector-isolation-v1",
      binding: input.binding, challengeId: challenge.challengeId, deviceProofSha256: proof.proofSha256,
      workDigest: snapshot.workDigest, verifiedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 900_000).toISOString(),
      isolationEvidence: [
        { kind: "dispatch-isolation", sha256: createHash("sha256").update(input.checkpoint.statement).digest("hex"), reference: challenge.challengeId },
        { kind: "connector-work-inventory", sha256: checkpoint.journal.sha256, reference: challenge.challengeId },
      ], reconciliations });
    return res.json({ success: true, evidence });
  } catch {
    return res.status(409).json({ success: false, error: "Verified connector maintenance evidence is unavailable." });
  }
};

export const issueVerifiedPostInstallEvidence = async (req: AuthRequest, res: Response) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const input = z.object({ token: z.string().regex(/^[a-f0-9]{64}$/),
      proof: z.object({ statement: z.string().max(4096), signature: z.string().max(200) }).strict() }).strict().parse(req.body);
    const { binding: trusted, publicKeyPem, sourceVersion } = await trustedBinding(req);
    const tokenHash = createHash("sha256").update(input.token).digest("hex");
    const redis = await getRedisClient();
    const raw = redis && await redis.get(upgradeHandoffKey(tokenHash));
    if (!raw) throw new Error("POSTINSTALL_UNAVAILABLE");
    const handoff = JSON.parse(raw);
    const binding = maintenanceBinding.parse(handoff.binding);
    const proof = verifyPostInstallStatement(input.proof, publicKeyPem);
    if (handoff.printerId !== req.params.id || binding.manufacturerId !== req.user?.userId ||
        binding.printerId !== req.params.id || sourceVersion !== binding.targetVersion ||
        proof.attemptId !== binding.attemptId || proof.version !== binding.targetVersion ||
        proof.sha256 !== binding.targetSha256 || proof.agentId !== binding.agentId ||
        proof.deviceFingerprint !== binding.deviceFingerprint || proof.registrationId !== binding.registrationId ||
        Object.entries(trusted).some(([key, value]) => binding[key] !== value)) throw new Error("POSTINSTALL_UNAVAILABLE");
    const snapshot = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
      operation: "MAINTENANCE_INVENTORY", printerId: String(req.params.id), payload: {} });
    if (snapshot.state !== "DISPATCH_FENCED" || snapshot.requestId !== binding.fenceRequestId ||
        !/^[a-f0-9]{64}$/.test(String(snapshot.workDigest || "")) ||
        !Array.isArray(snapshot.inventory?.items) ||
        Object.keys(snapshot.inventory?.diagnostics || {}).length > 0 ||
        (snapshot.inventory?.localDiagnostics || []).length > 0 ||
        snapshot.inventory.items.some((item: any) => item.state !== "FROZEN" ||
          item.pipelineState !== "NEEDS_OPERATOR_ACTION" ||
          item.dispatchMetadata?.upgradeNoReplay?.journalSha256 !== proof.journalSha256))
      throw new Error("POSTINSTALL_RECONCILIATION_REQUIRED");
    const now = Date.now();
    const evidence = issueConnectorIsolationEvidence({ purpose: "mscqr-upgrade-verification-v1", binding,
      tokenHash, workDigest: snapshot.workDigest, verifiedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 120_000).toISOString(),
      runtime: { version: proof.version, sha256: proof.sha256, agentId: proof.agentId,
        deviceFingerprint: proof.deviceFingerprint, processCount: 1,
        verificationSha256: createHash("sha256").update(input.proof.statement).digest("hex") },
      isolationEvidence: [
        { kind: "dispatch-isolation", sha256: createHash("sha256").update(input.proof.statement).digest("hex"), reference: proof.attemptId },
        { kind: "connector-work-inventory", sha256: proof.journalSha256, reference: proof.attemptId },
      ], reconciliations: snapshot.inventory.items.map((item: any) => ({ itemId: item.id,
        outcome: "PROTECTED_UNKNOWN", reference: item.dispatchMetadata.upgradeNoReplay.entrySha256 })) });
    return res.json({ success: true, evidence });
  } catch {
    return res.status(409).json({ success: false, error: "Verified post-install recovery is unavailable; printing remains fenced." });
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
      payload = { evidence: verifyConnectorIsolationEvidence(input.evidence) };
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
      const ttl = Math.min(900_000, Date.parse(evidence.expiresAt) - Date.now());
      if (ttl <= 0) throw new Error("CONNECTOR_UPGRADE_HANDOFF_UNAVAILABLE");
      const authorizationKey = upgradeAuthorizationKey(evidence.evidenceSha256);
      let authorization = await redis.get(authorizationKey);
      if (!authorization) {
        const candidate = JSON.stringify({ token: sealCookieToken(randomBytes(32).toString("hex"), "connector-upgrade.authorization"),
          binding, printerId: String(req.params.id) });
        if (await redis.set(authorizationKey, candidate, "PX", ttl, "NX") === "OK") authorization = candidate;
        else authorization = await redis.get(authorizationKey);
      }
      if (!authorization) throw new Error("CONNECTOR_UPGRADE_HANDOFF_UNAVAILABLE");
      const authorizationRecord = JSON.parse(authorization);
      token = openCookieToken(String(authorizationRecord.token), "connector-upgrade.authorization") || undefined;
      if (!token || !/^[a-f0-9]{64}$/.test(token) || authorizationRecord.printerId !== req.params.id ||
          JSON.stringify(authorizationRecord.binding) !== JSON.stringify(binding)) throw new Error("CONNECTOR_UPGRADE_HANDOFF_UNAVAILABLE");
      payload.tokenHash = createHash("sha256").update(token).digest("hex");
      const handoff = JSON.stringify({ binding, printerId: authorizationRecord.printerId });
      const handoffKey = upgradeHandoffKey(String(payload.tokenHash));
      if (await redis.set(handoffKey, handoff, "PX", ttl, "NX") !== "OK" && await redis.get(handoffKey) !== handoff)
        throw new Error("CONNECTOR_UPGRADE_HANDOFF_UNAVAILABLE");
    } else if (input.action === "release") {
      payload = { evidence: verifyConnectorIsolationEvidence(input.evidence,"mscqr-upgrade-verification-v1") };
      const verified = payload.evidence as { tokenHash?: string; binding?: Record<string, string | null> };
      const redis = await getRedisClient();
      const raw = verified.tokenHash && redis && await redis.get(upgradeHandoffKey(verified.tokenHash));
      if (!raw || JSON.stringify(JSON.parse(raw).binding) !== JSON.stringify(verified.binding) ||
          JSON.parse(raw).printerId !== req.params.id) throw new Error("POSTINSTALL_RELEASE_EXPIRED");
    } else if (input.action === "consume" || input.action === "verify") {
      payload = { binding: input.binding, tokenHash: createHash("sha256").update(input.token).digest("hex") };
    }
    const data = await administerPrintingPrinter({ capability: printingCapability(req), requestId: printingRequestId(req),
      operation: ({ request: "MAINTENANCE_REQUEST", inventory: "MAINTENANCE_INVENTORY", authorize: "MAINTENANCE_AUTHORIZE",
        consume: "MAINTENANCE_CONSUME", verify: "MAINTENANCE_VERIFY", release: "MAINTENANCE_RELEASE" } as const)[input.action], printerId: String(req.params.id), payload });
    if (input.action === "release") {
      const released = payload.evidence as { tokenHash?: string; binding?: Record<string, string> };
      if (data?.authorized !== true || data?.dispatchFenced !== false ||
          !/^[a-f0-9]{64}$/.test(String(released.tokenHash || ""))) throw new Error("POSTINSTALL_RELEASE_UNVERIFIED");
    }
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
    const input = z.object({ action: z.enum(["consume", "verify", "revoke", "release-status"]), token: z.string().regex(/^[a-f0-9]{64}$/),
      binding: maintenanceBinding }).strict().parse(req.body);
    const tokenHash = createHash("sha256").update(input.token).digest("hex");
    if (input.action === "release-status") {
      const released = await redeemPrintingUpgradeHandoff({ operation: "RELEASE_STATUS", tokenHash, binding: input.binding });
      if (released?.released !== true || released?.dispatchFenced !== false ||
          Object.keys(released.binding || {}).length !== Object.keys(input.binding).length ||
          Object.entries(released.binding || {}).some(([key, value]) => input.binding[key] !== value))
        throw new Error("POSTINSTALL_RELEASE_NOT_CONFIRMED");
      return res.json({ success: true, data: released });
    }
    const redis = await getRedisClient();
    const raw = redis && await redis.get(upgradeHandoffKey(tokenHash));
    if (!raw) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    const stored = JSON.parse(raw);
    const binding = stored.binding as Record<string, string>;
    if (!binding || Object.keys(binding).length !== Object.keys(input.binding).length ||
        Object.entries(binding).some(([key, value]) => input.binding[key] !== value) ||
        stored.printerId !== binding.printerId) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    const data = await redeemPrintingUpgradeHandoff({ operation: input.action.toUpperCase() as "CONSUME" | "VERIFY" | "REVOKE",
      tokenHash, binding: input.binding });
    if (input.action === "revoke") {
      if (data?.revoked !== true || data?.dispatchFenced !== true) throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
      return res.json({ success: true, data: { revoked: true, dispatchFenced: true } });
    }
    if (data?.authorized !== true || data?.dispatchFenced !== true ||
        Object.keys(data.binding || {}).length !== Object.keys(binding).length ||
        Object.entries(binding).some(([key, value]) => data.binding[key] !== value))
      throw new Error("CONNECTOR_UPGRADE_HANDOFF_INVALID");
    return res.json({ success: true, data });
  } catch {
    return res.status(403).json({ success: false, error: "Connector maintenance handoff was rejected." });
  }
};


import { createHash, randomBytes } from "crypto";
import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { verifyConnectorIsolationEvidence } from "../services/connectorMaintenanceEvidence";
import { upgradeAttemptKey, upgradeChallengeSchema, upgradeProofKey } from "../services/connectorUpgradeDeviceProof";
import { getRedisClient } from "../services/redisService";
import { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";

const printingCapability = (req: AuthRequest) => String(req.databaseSessionCapability || "").trim();
const printingRequestId = (req: AuthRequest) => String((req as AuthRequest & { requestId?: string }).requestId || "").trim();

export const requestConnectorMaintenance = async (req: AuthRequest, res: Response) => {
  try {
    const input = z.discriminatedUnion("action", [
      z.object({ action: z.literal("request") }).strict(),
      z.object({ action: z.literal("inventory") }).strict(),
      z.object({ action: z.enum(["authorize","release"]), evidence: z.object({ statement: z.string().max(100000), signature: z.string().max(200) }).strict() }).strict(),
      z.object({ action: z.enum(["consume", "verify"]), token: z.string().regex(/^[a-f0-9]{64}$/), binding: z.record(z.string(), z.string().max(256)) }).strict(),
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
      const raw = await redis.eval('local v=redis.call("GET",KEYS[1]); if v then redis.call("DEL",KEYS[1]); end; return v',
        1, upgradeProofKey(evidence.challengeId));
      if (typeof raw !== "string") throw new Error("CONNECTOR_UPGRADE_DEVICE_PROOF_INVALID");
      const stored = JSON.parse(raw);
      const challenge = upgradeChallengeSchema.parse(stored.challenge);
      if (challenge.challengeId !== evidence.challengeId || challenge.attemptId !== binding.attemptId ||
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


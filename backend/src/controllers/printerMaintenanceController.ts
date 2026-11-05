import { createHash, randomBytes } from "crypto";
import { Response } from "express";
import { z } from "zod";
import { AuthRequest } from "../middleware/auth";
import { administerPrintingPrinter } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { verifyConnectorIsolationEvidence } from "../services/connectorMaintenanceEvidence";
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
    if (error instanceof z.ZodError) return res.status(400).json({ success: false, error: "Invalid maintenance request." });
    const denied = /DENIED|permission|NO_DATA|query returned no rows|No .*found/i.test(String(error?.message));
    return res.status(denied ? 403 : 409).json({ success: false,
      error: denied ? "Connector maintenance is not authorized." : "Connector maintenance could not be established." });
  }
};


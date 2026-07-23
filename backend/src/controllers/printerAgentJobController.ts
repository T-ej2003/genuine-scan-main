import { createHash, randomUUID } from "crypto";
import { Request, Response } from "express";

import { buildApprovedPrintPayload, buildPrintPayloadDiagnostics } from "../services/printPayloadService";
import { LOCAL_AGENT_BUSY_RETRY_MS, LOCAL_AGENT_NO_WORK_RETRY_MS } from "../services/localAgentClaimService";
import { LOCAL_AGENT_DIRECT_PROTOCOL_VERSION } from "../services/localAgentProtocol";
import { buildLocalAgentClaimRuntimeBlock } from "../services/localAgentProductionRuntimeGate";
import {
  buildLocalAgentValidationErrorPayload,
  claimSchema,
  confirmSchema,
  failSchema,
  getLocalAgentRequestId,
  localAgentAckSchema,
  validateLocalAgentAckDispatchPhase,
} from "../services/localAgentAckProtocolService";
import { verifyLocalAgentRequest } from "../services/localAgentRequestAuthService";
import { publishPrintJobViewEvent } from "../services/printJobRealtimeService";
import { recordConnectorEvent } from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { claimLocalAgentPrinterTestJob } from "../services/printerTestLabelService";

export const localAgentErrorResponse = (res: Response, error: any) =>
  res.status(error?.statusCode || 500).json({
    success: false,
    error: error?.message || "Internal server error",
    ...(error?.errorCode ? { code: error.errorCode, errorCode: error.errorCode } : {}),
    ...(error?.serverTime ? { serverTime: error.serverTime } : {}),
    ...(error?.timestampSkewSeconds != null ? { timestampSkewSeconds: error.timestampSkewSeconds } : {}),
  });

const requestId = (req: Request) => {
  const value = String(getLocalAgentRequestId(req) || "").trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)
    ? value
    : randomUUID();
};

const evidenceHash = (signature: string) => createHash("sha256").update(signature).digest("hex");

const connectorEvent = async (
  req: Request,
  data: any,
  registration: any,
  operation: "CLAIM" | "ACK" | "CONFIRM" | "FAIL"
) =>
  recordConnectorEvent({
    registrationId: registration.id,
    agentId: data.agentId,
    deviceFingerprint: data.deviceFingerprint,
    nonce: data.nonce,
    issuedAt: data.issuedAt,
    requestId: requestId(req),
    operation,
    jobId: data.printJobId || "",
    itemId: data.printItemId || null,
    printerId: String(data.selectedPrinterId || data.printerId || "").trim(),
    payloadHash: String(data.payloadHash || evidenceHash(data.signature)).trim(),
    deviceJobRef: String(data.deviceJobRef || "").trim() || null,
    details: {
      bytesWritten: data.bytesWritten || null,
      markDispatched: data.markDispatched !== false,
      dispatchMetadata: data.dispatchMetadata || null,
      agentMetadata: data.agentMetadata || null,
      reason: data.reason || null,
    },
  });

const publish = (result: any, type: string, reason: string) => {
  if (!result?.printJobId) return;
  void publishPrintJobViewEvent({
    printJobId: result.printJobId,
    manufacturerId: result.manufacturerId || null,
    licenseeId: result.licenseeId || null,
    batchId: result.batchId || null,
    type,
    reason,
  });
};

export const claimLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = claimSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent claim payload" });
    }
    const registration = await verifyLocalAgentRequest(parsed.data, "claim", undefined, { skipReadiness: true });
    const runtimeBlock = buildLocalAgentClaimRuntimeBlock(parsed.data, registration);
    if (runtimeBlock) return res.status(runtimeBlock.status).json(runtimeBlock.payload);

    const resolvedPrinterId = String(registration.resolvedPrinterId || "").trim();
    if (resolvedPrinterId) {
      const testClaim = await claimLocalAgentPrinterTestJob({
        printerIds: [resolvedPrinterId],
        connectorBoundary: {
          registrationId: registration.id,
          agentId: parsed.data.agentId,
          deviceFingerprint: parsed.data.deviceFingerprint,
          nonce: parsed.data.nonce,
          issuedAt: parsed.data.issuedAt,
          requestId: requestId(req),
        },
      });
      if (testClaim) {
        return res.json({
          success: true,
          retryAfterMs: LOCAL_AGENT_BUSY_RETRY_MS,
          protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
          data: { ...testClaim, protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION },
        });
      }
    }

    const claimed = await connectorEvent(req, parsed.data, registration, "CLAIM");
    if (!claimed?.available) {
      return res.json({ success: true, data: null, retryAfterMs: LOCAL_AGENT_NO_WORK_RETRY_MS });
    }
    const payload = buildApprovedPrintPayload({
      printer: claimed.printer,
      qr: claimed.qrCode,
      manufacturerId: claimed.manufacturerId,
      printJobId: claimed.printJobId,
      printItemId: claimed.printItemId,
      jobNumber: claimed.jobNumber,
      reprintOfJobId: claimed.reprintOfJobId,
      serialContext: {
        sequence: claimed.issueSequence,
        issuedAt: claimed.issuedAt,
        batch: claimed.batch,
        licensee: claimed.batch?.licensee,
        manufacturer: claimed.manufacturer,
        printer: claimed.printer,
      },
    });
    console.info("local_agent_claim", {
      event: "work_returned",
      registrationId: registration.id,
      printJobId: claimed.printJobId,
      printItemId: claimed.printItemId,
      payloadDiagnostics: buildPrintPayloadDiagnostics({
        payloadType: payload.payloadType,
        labelLanguage: payload.commandLanguage,
        payloadContent: payload.payloadContent,
      }),
    });
    return res.json({
      success: true,
      retryAfterMs: LOCAL_AGENT_BUSY_RETRY_MS,
      protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
      data: {
        protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
        printJobId: claimed.printJobId,
        printSessionId: claimed.printSessionId,
        printItemId: claimed.printItemId,
        code: claimed.code,
        ...payload,
        printer: {
          id: claimed.printer.id,
          name: claimed.printer.name,
          nativePrinterId: claimed.printer.nativePrinterId,
          selectedPrinterId: String(parsed.data.selectedPrinterId || parsed.data.printerId || "").trim(),
          dpi: Number(claimed.printer.capabilitySummary?.dpi || claimed.printer.calibrationProfile?.dpi || 0) || null,
          languages: Array.isArray(claimed.printer.capabilitySummary?.languages)
            ? claimed.printer.capabilitySummary.languages.map((value: unknown) => String(value || "").trim())
            : [],
        },
        calibrationProfile: claimed.printer.calibrationProfile || null,
        jobNumber: claimed.jobNumber,
      },
    });
  } catch (error: any) {
    console.error("claimLocalAgentPrintJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

export const ackLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = localAgentAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      const payload = buildLocalAgentValidationErrorPayload({
        req,
        body: req.body || {},
        errorCode: "invalid_local_agent_ack_payload",
        message: "Invalid local agent ACK payload.",
        issues: parsed.error.issues,
      });
      return res.status(400).json(payload);
    }
    const dispatchPhase = validateLocalAgentAckDispatchPhase(parsed.data);
    if (!dispatchPhase.ok) {
      return res.status(400).json(buildLocalAgentValidationErrorPayload({
        req,
        body: req.body || {},
        errorCode: "invalid_local_agent_ack_payload",
        message: "Invalid local agent ACK payload.",
        issues: dispatchPhase.issues,
      }));
    }
    const registration = await verifyLocalAgentRequest(parsed.data, "ack", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });
    const result = await connectorEvent(req, parsed.data, registration, "ACK");
    publish(result, "local_agent.ack", "local_agent_rest_ack");
    return res.json({ success: true, data: { ...result, acknowledged: true, deviceJobRef: parsed.data.deviceJobRef || null } });
  } catch (error: any) {
    console.error("ackLocalAgentPrintJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

export const confirmLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = confirmSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent confirm payload" });
    }
    const registration = await verifyLocalAgentRequest(parsed.data, "confirm", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });
    const result = await connectorEvent(req, parsed.data, registration, "CONFIRM");
    publish(result, "local_agent.confirm", "local_agent_rest_confirm");
    return res.json({ success: true, data: { ...result, jobConfirmed: Number(result.remainingToPrint || 0) === 0 } });
  } catch (error: any) {
    console.error("confirmLocalAgentPrintJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

export const failLocalAgentPrintJob = async (req: Request, res: Response) => {
  try {
    const parsed = failSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent failure payload" });
    }
    const registration = await verifyLocalAgentRequest(parsed.data, "fail", {
      printJobId: parsed.data.printJobId,
      printItemId: parsed.data.printItemId,
    });
    const result = await connectorEvent(req, parsed.data, registration, "FAIL");
    publish(result, "local_agent.fail", "local_agent_rest_fail");
    return res.json({ success: true, data: { ...result, reason: parsed.data.reason } });
  } catch (error: any) {
    console.error("failLocalAgentPrintJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

import { randomUUID } from "crypto";
import { Request, Response } from "express";

import {
  localAgentTestAckSchema,
  localAgentTestFailSchema,
} from "../services/localAgentAckProtocolService";
import {
  acknowledgeGatewayPrinterTestJob,
  acknowledgeLocalAgentPrinterTestJob,
  confirmGatewayPrinterTestJob,
  confirmLocalAgentPrinterTestJob as confirmLocalAgentPrinterTestJobState,
  failGatewayPrinterTestJob,
  failLocalAgentPrinterTestJob as failLocalAgentPrinterTestJobState,
} from "../services/printerTestLabelService";
import { verifyLocalAgentRequest } from "../services/localAgentRequestAuthService";
import { localAgentErrorResponse } from "./printerAgentJobController";

const connectorBoundary = (req: Request, parsed: any, registration: any) => ({
  registrationId: String(registration.id),
  agentId: parsed.agentId,
  deviceFingerprint: parsed.deviceFingerprint,
  nonce: parsed.nonce,
  issuedAt: parsed.issuedAt,
  requestId: String((req as Request & { requestId?: string }).requestId || randomUUID()),
});

export const ackLocalAgentPrinterTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = localAgentTestAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent test ACK payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "ack");
    const acknowledged =
      (await acknowledgeLocalAgentPrinterTestJob({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        metadata: {
          payloadHash: String(parsed.data.payloadHash || "").trim() || null,
          bytesWritten: parsed.data.bytesWritten || null,
          deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
          payloadType: String(parsed.data.payloadType || "").trim() || null,
          agentMetadata: parsed.data.agentMetadata || null,
        },
        connectorBoundary: connectorBoundary(req, parsed.data, registration),
      })) ||
      acknowledgeGatewayPrinterTestJob({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        metadata: {
          payloadHash: String(parsed.data.payloadHash || "").trim() || null,
          bytesWritten: parsed.data.bytesWritten || null,
          deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
          payloadType: String(parsed.data.payloadType || "").trim() || null,
          agentMetadata: parsed.data.agentMetadata || null,
        },
      });
    if (!acknowledged) return res.status(404).json({ success: false, error: "Printer test job not found." });
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, acknowledged: true } });
  } catch (error: any) {
    console.error("ackLocalAgentPrinterTestJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

export const confirmLocalAgentPrinterTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = localAgentTestAckSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent test confirm payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "confirm");
    const confirmed =
      (await confirmLocalAgentPrinterTestJobState({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        payloadType: parsed.data.payloadType as any,
        deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
        confirmationMode: "LOCAL_QUEUE",
        metadata: {
          payloadHash: String(parsed.data.payloadHash || "").trim() || null,
          bytesWritten: parsed.data.bytesWritten || null,
          agentMetadata: parsed.data.agentMetadata || null,
        },
        connectorBoundary: connectorBoundary(req, parsed.data, registration),
      })) ||
      confirmGatewayPrinterTestJob({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        payloadType: parsed.data.payloadType as any,
        deviceJobRef: String(parsed.data.deviceJobRef || "").trim() || null,
        confirmationMode: "LOCAL_QUEUE",
        metadata: {
          payloadHash: String(parsed.data.payloadHash || "").trim() || null,
          bytesWritten: parsed.data.bytesWritten || null,
          agentMetadata: parsed.data.agentMetadata || null,
        },
      });
    if (!confirmed) return res.status(404).json({ success: false, error: "Printer test job not found." });
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, confirmed: true } });
  } catch (error: any) {
    console.error("confirmLocalAgentPrinterTestJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

export const failLocalAgentPrinterTestJob = async (req: Request, res: Response) => {
  try {
    const parsed = localAgentTestFailSchema.safeParse(req.body || {});
    if (!parsed.success) {
      return res.status(400).json({ success: false, error: parsed.error.errors[0]?.message || "Invalid local agent test failure payload" });
    }

    const registration = await verifyLocalAgentRequest(parsed.data, "fail");
    const failed =
      (await failLocalAgentPrinterTestJobState({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        reason: parsed.data.reason,
        connectorBoundary: connectorBoundary(req, parsed.data, registration),
      })) ||
      failGatewayPrinterTestJob({
        printerId: parsed.data.printerId,
        testJobId: parsed.data.testJobId,
        reason: parsed.data.reason,
      });
    if (!failed) return res.status(404).json({ success: false, error: "Printer test job not found." });
    return res.json({ success: true, data: { testJobId: parsed.data.testJobId, failed: true } });
  } catch (error: any) {
    console.error("failLocalAgentPrinterTestJob error:", error);
    return localAgentErrorResponse(res, error);
  }
};

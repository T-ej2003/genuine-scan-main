import { randomUUID } from "node:crypto";

import { PrintDispatchMode, PrinterConnectionType } from "@prisma/client";
import { Request, Response } from "express";

import {
  recordGatewayPrintingEvent,
  resolvePrintingConnectorIdentity,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import { buildApprovedPrintContext, buildApprovedPrintPayload } from "../services/printPayloadService";
import { hashGatewaySecret } from "../services/printerRegistryService";
import {
  acknowledgeGatewayPrinterTestJob,
  claimGatewayPrinterTestJob,
  confirmGatewayPrinterTestJob,
  failGatewayPrinterTestJob,
} from "../services/printerTestLabelService";

const credentials = (req: Request) => ({
  gatewayId: String(req.get("x-printer-gateway-id") || req.body?.gatewayId || "").trim(),
  gatewaySecretHash: hashGatewaySecret(String(req.get("x-printer-gateway-secret") || req.body?.gatewaySecret || "").trim()),
});
const modeFor = (connectionType: PrinterConnectionType) =>
  connectionType === PrinterConnectionType.NETWORK_IPP
    ? PrintDispatchMode.NETWORK_IPP
    : PrintDispatchMode.NETWORK_DIRECT;

const gateway = async (req: Request, operation: "VERIFY" | "HEARTBEAT" = "VERIFY") => {
  const auth = credentials(req);
  if (!auth.gatewayId || !String(req.get("x-printer-gateway-secret") || req.body?.gatewaySecret || "").trim()) return null;
  const identity = await resolvePrintingConnectorIdentity({
    kind: "SITE_GATEWAY",
    gatewayId: auth.gatewayId,
    gatewaySecretHash: auth.gatewaySecretHash,
    operation,
  }).catch(() => null);
  return identity ? { ...auth, printer: identity.printer } : null;
};

const bodyDetails = (req: Request) => ({
  payloadHash: req.body?.payloadHash || null,
  bytesWritten: req.body?.bytesWritten || null,
  deviceJobRef: req.body?.deviceJobRef || null,
  ippJobId: req.body?.ippJobId || null,
  reason: req.body?.reason || null,
  gatewayMetadata: req.body?.gatewayMetadata || null,
});

const claim = async (req: Request, res: Response, connectionType: PrinterConnectionType) => {
  const auth = await gateway(req);
  if (!auth || auth.printer.connectionType !== connectionType) {
    return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
  }
  const result = await recordGatewayPrintingEvent({
    ...auth,
    requestId: randomUUID(),
    operation: "CLAIM",
    mode: modeFor(connectionType),
  });
  if (!result.available) return res.json({ success: true, data: null });
  const item = result.item;
  const qr = {
    id: item.qrCodeId,
    code: item.code,
    displayCode: item.displayCode,
    batchId: item.batchId,
    licenseeId: item.licenseeId,
    tokenNonce: item.tokenNonce,
    tokenIssuedAt: item.tokenIssuedAt ? new Date(item.tokenIssuedAt) : null,
    tokenExpiresAt: item.tokenExpiresAt ? new Date(item.tokenExpiresAt) : null,
    tokenHash: item.tokenHash,
    replayEpoch: item.replayEpoch,
  };
  const payload = connectionType === PrinterConnectionType.NETWORK_DIRECT
    ? buildApprovedPrintPayload({
        printer: result.printer,
        qr,
        manufacturerId: result.job.manufacturerId,
        printJobId: result.job.id,
        printItemId: item.id,
        jobNumber: result.job.jobNumber,
        reprintOfJobId: result.job.reprintOfJobId,
      })
    : buildApprovedPrintContext({
        qr,
        manufacturerId: result.job.manufacturerId,
        reprintOfJobId: result.job.reprintOfJobId,
      });
  return res.json({ success: true, data: { ...result, payload } });
};

const event = async (
  req: Request,
  res: Response,
  connectionType: PrinterConnectionType,
  operation: "ACK" | "CONFIRM" | "FAIL"
) => {
  const auth = await gateway(req);
  if (!auth || auth.printer.connectionType !== connectionType) {
    return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
  }
  const result = await recordGatewayPrintingEvent({
    ...auth,
    requestId: randomUUID(),
    operation,
    mode: modeFor(connectionType),
    jobId: String(req.body?.printJobId || ""),
    itemId: String(req.body?.printItemId || ""),
    details: bodyDetails(req),
  });
  return res.json({ success: true, data: result });
};

export const gatewayHeartbeat = async (req: Request, res: Response) => {
  const auth = await gateway(req, "HEARTBEAT");
  if (!auth) return res.status(401).json({ success: false, error: "Invalid gateway credentials" });
  return res.json({ success: true, data: {
    gatewayId: auth.gatewayId,
    printerId: auth.printer.id,
    connectionType: auth.printer.connectionType,
    deliveryMode: auth.printer.deliveryMode,
    status: "ONLINE",
  } });
};

export const claimGatewayIppJob = (req: Request, res: Response) => claim(req, res, PrinterConnectionType.NETWORK_IPP);
export const claimGatewayDirectJob = (req: Request, res: Response) => claim(req, res, PrinterConnectionType.NETWORK_DIRECT);
export const ackGatewayIppJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_IPP, "ACK");
export const confirmGatewayIppJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_IPP, "CONFIRM");
export const failGatewayIppJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_IPP, "FAIL");
export const ackGatewayDirectJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_DIRECT, "ACK");
export const confirmGatewayDirectJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_DIRECT, "CONFIRM");
export const failGatewayDirectJob = (req: Request, res: Response) => event(req, res, PrinterConnectionType.NETWORK_DIRECT, "FAIL");

const testGateway = async (req: Request) => {
  const auth = await gateway(req);
  if (!auth) throw Object.assign(new Error("Invalid gateway credentials"), { statusCode: 401 });
  return auth;
};
export const claimGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const auth = await testGateway(req);
    return res.json({ success: true, data: claimGatewayPrinterTestJob({
      printerId: auth.printer.id,
      connectionType: auth.printer.connectionType,
    }) });
  } catch (error: any) {
    return res.status(error.statusCode || 400).json({ success: false, error: error.message });
  }
};
export const ackGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const auth = await testGateway(req);
    return res.json({ success: true, data: acknowledgeGatewayPrinterTestJob({
      printerId: auth.printer.id,
      testJobId: String(req.body?.testJobId || ""),
      metadata: bodyDetails(req),
    }) });
  } catch (error: any) {
    return res.status(error.statusCode || 400).json({ success: false, error: error.message });
  }
};
export const confirmGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const auth = await testGateway(req);
    return res.json({ success: true, data: confirmGatewayPrinterTestJob({
      printerId: auth.printer.id,
      testJobId: String(req.body?.testJobId || ""),
      metadata: bodyDetails(req),
    }) });
  } catch (error: any) {
    return res.status(error.statusCode || 400).json({ success: false, error: error.message });
  }
};
export const failGatewayTestJob = async (req: Request, res: Response) => {
  try {
    const auth = await testGateway(req);
    return res.json({ success: true, data: failGatewayPrinterTestJob({
      printerId: auth.printer.id,
      testJobId: String(req.body?.testJobId || ""),
      reason: String(req.body?.reason || "gateway_test_failed"),
    }) });
  } catch (error: any) {
    return res.status(error.statusCode || 400).json({ success: false, error: error.message });
  }
};

import { PrinterTrustStatus } from "@prisma/client";

import prisma from "../config/database";
import {
  buildPrinterAgentActionPayload,
  getPrinterAgentIssuedAtSkewSeconds,
  isPrinterAgentIssuedAtFresh,
  verifyPrinterAgentPayloadSignature,
} from "./printerAgentSigningService";
import type { LocalAgentRequestPayload } from "./localAgentAckProtocolService";
import { getPrinterConnectionStatusForUser } from "./printerConnectionService";

export const verifyLocalAgentRequest = async (
  parsed: LocalAgentRequestPayload,
  action: "claim" | "ack" | "confirm" | "fail",
  identifiers?: { printJobId?: string | null; printItemId?: string | null }
) => {
  if (!isPrinterAgentIssuedAtFresh(parsed.issuedAt)) {
    const timestampSkewSeconds = getPrinterAgentIssuedAtSkewSeconds(parsed.issuedAt);
    throw Object.assign(new Error("Agent request timestamp expired."), {
      statusCode: 401,
      errorCode: "agent_timestamp_expired",
      serverTime: new Date().toISOString(),
      timestampSkewSeconds: timestampSkewSeconds == null ? null : Math.round(timestampSkewSeconds),
    });
  }

  const registration = await prisma.printerRegistration.findFirst({
    where: {
      agentId: parsed.agentId,
      deviceFingerprint: parsed.deviceFingerprint,
      revokedAt: null,
    },
    orderBy: [{ lastSeenAt: "desc" }, { updatedAt: "desc" }],
  });

  if (!registration || registration.trustStatus === PrinterTrustStatus.REVOKED) {
    throw Object.assign(new Error("Printer registration not trusted."), { statusCode: 401 });
  }

  if (!String(registration.publicKeyPem || "").includes("BEGIN")) {
    throw Object.assign(new Error("Printer registration public key is not enrolled."), { statusCode: 401 });
  }

  const payload = buildPrinterAgentActionPayload({
    action,
    agentId: parsed.agentId,
    deviceFingerprint: parsed.deviceFingerprint,
    printerId: parsed.printerId,
    printJobId: identifiers?.printJobId || null,
    printItemId: identifiers?.printItemId || null,
    nonce: parsed.nonce,
    issuedAt: parsed.issuedAt,
  });

  const signatureValid = verifyPrinterAgentPayloadSignature({
    publicKeyPem: registration.publicKeyPem,
    payload,
    signature: parsed.signature,
  });

  if (!signatureValid) {
    throw Object.assign(new Error("Printer agent signature verification failed."), { statusCode: 401 });
  }

  const printerStatus = await getPrinterConnectionStatusForUser(registration.userId);
  const activePrinterId = String(printerStatus.selectedPrinterId || printerStatus.printerId || "").trim();
  const requestedPrinterId = String(parsed.printerId || "").trim();
  const readyForThisConnector =
    printerStatus.eligibleForPrinting === true &&
    printerStatus.trusted === true &&
    printerStatus.compatibilityMode !== true &&
    printerStatus.stale !== true &&
    printerStatus.registrationId === registration.id &&
    printerStatus.agentId === registration.agentId &&
    printerStatus.deviceFingerprint === registration.deviceFingerprint &&
    (!requestedPrinterId || activePrinterId === requestedPrinterId);

  if (!readyForThisConnector) {
    throw Object.assign(new Error("Printer verification expired. Refresh printer helper before printing."), {
      statusCode: 409,
      errorCode: "PRINTER_ATTESTATION_STALE",
      printerStatus,
    });
  }

  return registration;
};

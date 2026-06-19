import { PrinterTrustStatus } from "@prisma/client";
import { createHash } from "crypto";

import prisma from "../config/database";
import {
  buildPrinterAgentActionPayload,
  getPrinterAgentIssuedAtSkewSeconds,
  isPrinterAgentIssuedAtFresh,
  verifyPrinterAgentPayloadSignature,
} from "./printerAgentSigningService";
import type { LocalAgentRequestPayload } from "./localAgentAckProtocolService";
import { getPrinterConnectionStatusForUser } from "./printerConnectionService";

const sha256Short = (value: string | null | undefined) =>
  String(value || "").trim() ? createHash("sha256").update(String(value || "").trim()).digest("hex").slice(0, 16) : null;

const logLocalAgentTrust = (event: string, payload: Record<string, unknown>) => {
  console.info("local_agent_trust", { event, ...payload });
};

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
    logLocalAgentTrust("registration_rejected", {
      action,
      registrationFound: Boolean(registration),
      agentIdHash: sha256Short(parsed.agentId),
      deviceFingerprintHash: sha256Short(parsed.deviceFingerprint),
      printerIdHash: sha256Short(parsed.printerId),
      trusted: false,
      active: false,
      approved: false,
      rejectReason: registration?.trustStatus === PrinterTrustStatus.REVOKED ? "registration_revoked" : "registration_missing",
    });
    throw Object.assign(new Error("Printer registration not trusted."), { statusCode: 401 });
  }

  if (!String(registration.publicKeyPem || "").includes("BEGIN")) {
    logLocalAgentTrust("registration_rejected", {
      action,
      registrationFound: true,
      registrationId: registration.id,
      agentIdHash: sha256Short(parsed.agentId),
      deviceFingerprintHash: sha256Short(parsed.deviceFingerprint),
      publicKeyFingerprint: sha256Short(registration.publicKeyPem),
      trusted: false,
      active: true,
      approved: false,
      rejectReason: "public_key_not_enrolled",
    });
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
    logLocalAgentTrust("signature_rejected", {
      action,
      registrationFound: true,
      registrationId: registration.id,
      agentIdHash: sha256Short(parsed.agentId),
      deviceFingerprintHash: sha256Short(parsed.deviceFingerprint),
      publicKeyFingerprint: sha256Short(registration.publicKeyPem),
      selectedPrinterHash: sha256Short(parsed.printerId),
      claimSignatureVerified: false,
      rejectReason: "bad_signature",
    });
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
    logLocalAgentTrust("readiness_rejected", {
      action,
      registrationFound: true,
      registrationId: registration.id,
      agentIdHash: sha256Short(parsed.agentId),
      deviceFingerprintHash: sha256Short(parsed.deviceFingerprint),
      publicKeyFingerprint: sha256Short(registration.publicKeyPem),
      heartbeatAgeSeconds: printerStatus.ageSeconds ?? null,
      trusted: printerStatus.trusted === true,
      active: printerStatus.connected === true,
      approved: Boolean(registration.approvedAt || registration.trustStatus === PrinterTrustStatus.TRUSTED),
      selectedPrinterMatch: !requestedPrinterId || activePrinterId === requestedPrinterId,
      claimSignatureVerified: true,
      rejectReason: "trusted_readiness_mismatch",
      trustStatus: printerStatus.trustStatus || null,
      missingFields: printerStatus.missingFields || [],
    });
    throw Object.assign(new Error("Printer verification expired. Refresh printer helper before printing."), {
      statusCode: 409,
      errorCode: "PRINTER_ATTESTATION_STALE",
      printerStatus,
    });
  }

  logLocalAgentTrust("request_trusted", {
    action,
    registrationFound: true,
    registrationId: registration.id,
    agentIdHash: sha256Short(parsed.agentId),
    deviceFingerprintHash: sha256Short(parsed.deviceFingerprint),
    publicKeyFingerprint: sha256Short(registration.publicKeyPem),
    heartbeatAgeSeconds: printerStatus.ageSeconds ?? null,
    trusted: true,
    active: true,
    approved: Boolean(registration.approvedAt || registration.trustStatus === PrinterTrustStatus.TRUSTED),
    selectedPrinterMatch: true,
    claimSignatureVerified: true,
    rejectReason: null,
  });

  return registration;
};

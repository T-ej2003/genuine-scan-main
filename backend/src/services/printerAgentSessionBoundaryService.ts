import { createHash, randomUUID } from "crypto";
import { PrintPayloadType } from "@prisma/client";

import {
  recordConnectorEvent,
  resolvePrintingConnectorIdentity,
} from "../rls-waves/session-c/c02/printingLifecycleRepository";
import {
  sessionClientMessageSchema,
  sessionHelloSchema,
  PRINT_AGENT_REQUIRE_MTLS,
  type SessionClientMessage,
  type SessionHello,
  type TrustedPrinterAgentSession,
} from "./printerAgentSessionService";
import {
  buildPrinterAgentSessionPayload,
  isPrinterAgentIssuedAtFresh,
  verifyPrinterAgentPayloadSignature,
} from "./printerAgentSigningService";
import {
  isLocalAgentPersistentSessionCapable,
  LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
} from "./localAgentProtocol";
import { buildApprovedPrintPayload } from "./printPayloadService";
import { publishPrintJobViewEvent } from "./printJobRealtimeService";
import {
  acknowledgeLocalAgentPrinterTestJob,
  claimLocalAgentPrinterTestJob,
  confirmLocalAgentPrinterTestJob,
  failLocalAgentPrinterTestJob,
} from "./printerTestLabelService";

export { sessionClientMessageSchema, sessionHelloSchema };
export type { TrustedPrinterAgentSession };

type SessionState = {
  session: TrustedPrinterAgentSession;
  lastMessageSeq: number;
  chunks: Map<string, { jobId: string; itemId: string; licenseeId: string; batchId: string; payloadHash: string | null; acknowledged: boolean; terminal?: "CONFIRM" | "FAIL" }>;
};

const sessions = new Map<string, SessionState>();
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const nonce = (value: string) => hash(value).slice(0, 32);

const verifyMessage = (
  session: TrustedPrinterAgentSession,
  message: SessionHello | SessionClientMessage
) => {
  if (message.type !== "hello" && message.sessionId !== session.id) {
    throw Object.assign(new Error("Printer session identity mismatch."), {
      statusCode: 403, errorCode: "session_identity_mismatch",
    });
  }
  if (!isPrinterAgentIssuedAtFresh(message.issuedAt)) {
    throw Object.assign(new Error("Agent session message timestamp expired."), {
      statusCode: 401,
      errorCode: "agent_timestamp_expired",
    });
  }
  const payload = buildPrinterAgentSessionPayload({
    messageType: message.type,
    registrationId: message.type === "hello" ? message.registrationId || null : session.registrationId,
    agentId: session.agentId,
    deviceFingerprint: session.deviceFingerprint,
    selectedPrinterId: message.type === "hello" ? message.selectedPrinterId : session.selectedPrinterId,
    connectorVersion: session.connectorVersion,
    sessionId: "sessionId" in message ? message.sessionId : null,
    chunkId: "chunkId" in message ? message.chunkId : null,
    printJobId: "printJobId" in message ? message.printJobId : null,
    printItemId: "printItemId" in message ? message.printItemId : null,
    testJobId: "testJobId" in message ? message.testJobId : null,
    messageSeq: "messageSeq" in message ? message.messageSeq : null,
    nonce: message.nonce,
    issuedAt: message.issuedAt,
  });
  if (!verifyPrinterAgentPayloadSignature({
    publicKeyPem: session.publicKeyPem,
    payload,
    signature: message.signature,
  })) {
    throw Object.assign(new Error("Printer agent session signature verification failed."), {
      statusCode: 401,
      errorCode: "bad_session_signature",
    });
  }
};

export const logPrinterSessionResolverOutcome = (
  event: "printer_session_rejected" | "printer_session_connected" | "printer_session_resolved",
  summary: Record<string, unknown>
) => console.info(event, summary);

export const openTrustedPrinterAgentSession = async (
  hello: SessionHello,
  options: { mtlsFingerprintHeader?: string | null } = {}
): Promise<TrustedPrinterAgentSession> => {
  if (!isLocalAgentPersistentSessionCapable(hello.connectorVersion)
      || (hello.printerHealth as any)?.capabilities?.supportsPersistentPrintSession !== true) {
    throw Object.assign(new Error("Connector update required for persistent printing."), {
      statusCode: 426,
      errorCode: "persistent_session_connector_update_required",
      minimumConnectorVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
    });
  }
  const identity = await resolvePrintingConnectorIdentity({
    kind: "LOCAL_AGENT",
    agentId: hello.agentId,
    deviceFingerprint: hello.deviceFingerprint,
    printerSelector: hello.selectedPrinterId,
  }) as any;
  const registration = identity.registration;
  const printer = identity.printer;
  if (!registration?.id || !printer?.id || !registration.publicKeyPem) {
    throw Object.assign(new Error("Printer registration not trusted."), {
      statusCode: 403,
      errorCode: "registration_not_trusted",
    });
  }
  if ((hello.registrationId && hello.registrationId !== registration.id)
      || hello.agentId !== registration.agentId
      || hello.deviceFingerprint !== registration.deviceFingerprint) {
    throw Object.assign(new Error("Printer registration identity mismatch."), {
      statusCode: 403,
      errorCode: "registration_identity_mismatch",
    });
  }
  if (PRINT_AGENT_REQUIRE_MTLS) {
    const fingerprint = options.mtlsFingerprintHeader?.trim();
    if (!fingerprint || fingerprint.length > 256
        || (registration.certFingerprint && registration.certFingerprint !== fingerprint)) {
      throw Object.assign(new Error("Trusted printer mTLS identity required."), {
        statusCode: 403,
        errorCode: "mtls_required",
      });
    }
  }
  const session: TrustedPrinterAgentSession = {
    id: randomUUID(),
    connectionId: randomUUID(),
    registrationId: registration.id,
    printerId: printer.id,
    // Keep the authenticated wire selector stable; printerId is the resolved DB identity.
    selectedPrinterId: hello.selectedPrinterId,
    selectedPrinterName: hello.selectedPrinterName || printer.name || null,
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    connectorVersion: hello.connectorVersion || null,
    publicKeyPem: registration.publicKeyPem,
    publicKeyFingerprint: hash(registration.publicKeyPem),
    manufacturerId: registration.userId,
  };
  verifyMessage(session, hello);
  sessions.set(session.id, { session, lastMessageSeq: 0, chunks: new Map() });
  return session;
};

export const closeTrustedPrinterAgentSession = async (sessionId: string, reason: string) => {
  sessions.delete(sessionId);
  console.info("printer_session_disconnected", { agentSessionId: sessionId, reason: reason.slice(0, 120) });
};

const active = (session: TrustedPrinterAgentSession) => {
  const state = sessions.get(session.id);
  if (!state) {
    throw Object.assign(new Error("Printer agent session is no longer active."), {
      statusCode: 401,
      errorCode: "session_not_active",
    });
  }
  return state;
};

export const recordTrustedSessionHeartbeat = async (
  session: TrustedPrinterAgentSession,
  message: SessionClientMessage
) => {
  const state = active(session);
  verifyMessage(session, message);
  if (message.messageSeq <= state.lastMessageSeq) {
    throw Object.assign(new Error("Printer session message replayed."), {
      statusCode: 409,
      errorCode: "message_replay",
    });
  }
  state.lastMessageSeq = message.messageSeq;
  await resolvePrintingConnectorIdentity({
    kind: "LOCAL_AGENT",
    agentId: session.agentId,
    deviceFingerprint: session.deviceFingerprint,
    printerSelector: session.printerId,
    operation: "HEARTBEAT",
  });
};

export const buildNextPrintChunkForSession = async (
  session: TrustedPrinterAgentSession
) => {
  const state = active(session);
  const test = await claimLocalAgentPrinterTestJob({
    printerIds: [session.printerId],
    connectorBoundary: {
      registrationId: session.registrationId,
      agentId: session.agentId,
      deviceFingerprint: session.deviceFingerprint,
      nonce: nonce(randomUUID()),
      issuedAt: new Date(),
      requestId: randomUUID(),
    },
  });
  if (test) return { type: "test_label" as const, sessionId: session.id, ...test };

  const claimed = await recordConnectorEvent({
    registrationId: session.registrationId,
    agentId: session.agentId,
    deviceFingerprint: session.deviceFingerprint,
    nonce: nonce(randomUUID()),
    issuedAt: new Date(),
    requestId: randomUUID(),
    operation: "CLAIM",
    jobId: randomUUID(),
    printerId: session.printerId,
    details: { sessionId: session.id, deliveryMode: "PERSISTENT_SESSION" },
  }) as any;
  if (!claimed?.available) return null;

  const chunkId = randomUUID();
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
  state.chunks.set(chunkId, {
    jobId: claimed.printJobId,
    itemId: claimed.printItemId,
    licenseeId: claimed.batch.licenseeId,
    batchId: claimed.batch.id,
    payloadHash: payload.payloadHash,
    acknowledged: false,
  });
  return {
    type: "print_chunk" as const,
    sessionId: session.id,
    chunkId,
    idempotencyKey: hash(`${claimed.printJobId}:${claimed.printItemId}`),
    printJobId: claimed.printJobId,
    printSessionId: claimed.printSessionId,
    range: {
      startSequence: claimed.issueSequence,
      endSequence: claimed.issueSequence,
      startCode: claimed.code,
      endCode: claimed.code,
      count: 1,
    },
    printer: {
      id: claimed.printer.id,
      name: claimed.printer.name,
      nativePrinterId: claimed.printer.nativePrinterId,
      selectedPrinterId: session.selectedPrinterId,
      languages: claimed.printer.capabilitySummary?.languages || [],
    },
    calibrationProfile: claimed.printer.calibrationProfile || null,
    labels: [{
      printItemId: claimed.printItemId,
      issueSequence: claimed.issueSequence,
      code: claimed.code,
      payloadType: payload.payloadType,
      payloadContent: payload.payloadContent,
      payloadHash: payload.payloadHash,
      previewLabel: payload.previewLabel,
      commandLanguage: payload.commandLanguage,
      scanUrl: payload.scanUrl,
    }],
  };
};

export const handleTrustedSessionProgressMessage = async (
  session: TrustedPrinterAgentSession,
  message: SessionClientMessage
) => {
  if (message.type === "heartbeat") {
    await recordTrustedSessionHeartbeat(session, message);
    return { ok: true as const };
  }
  const state = active(session);
  verifyMessage(session, message);
  if (message.messageSeq <= state.lastMessageSeq) {
    throw Object.assign(new Error("Printer session message replayed."), {
      statusCode: 409,
      errorCode: "message_replay",
    });
  }
  state.lastMessageSeq = message.messageSeq;

  if (message.type.startsWith("test_")) {
    const connectorBoundary = {
      registrationId: session.registrationId,
      agentId: session.agentId,
      deviceFingerprint: session.deviceFingerprint,
      nonce: nonce(message.nonce),
      issuedAt: message.issuedAt,
      requestId: randomUUID(),
    };
    const input = {
      printerId: session.printerId,
      testJobId: String(message.testJobId || ""),
      metadata: { messageSeq: message.messageSeq, deviceJobRef: message.deviceJobRef || null },
      connectorBoundary,
    };
    if (message.type === "test_ack") await acknowledgeLocalAgentPrinterTestJob(input);
    else if (message.type === "test_confirmed") await confirmLocalAgentPrinterTestJob({
      ...input,
      payloadType: (message.payloadType || PrintPayloadType.ZPL) as PrintPayloadType,
      deviceJobRef: message.deviceJobRef || null,
      confirmationMode: "LOCAL_QUEUE",
    });
    else await failLocalAgentPrinterTestJob({
      printerId: session.printerId,
      testJobId: input.testJobId,
      reason: message.error || "Connector reported test-label failure.",
      connectorBoundary,
    });
    return { ok: true as const };
  }

  const chunk = state.chunks.get(String(message.chunkId || ""));
  if (!chunk || (message.printItemId && message.printItemId !== chunk.itemId)
      || (message.printJobId && message.printJobId !== chunk.jobId)
      || (message.payloadHash && message.payloadHash !== chunk.payloadHash)) {
    throw Object.assign(new Error("Print item does not belong to this connector chunk."), {
      statusCode: 403,
      errorCode: "chunk_item_mismatch",
    });
  }
  const terminal = ["chunk_confirmed", "label_confirmed"].includes(message.type) ? "CONFIRM"
    : ["chunk_failed", "label_failed"].includes(message.type) ? "FAIL" : null;
  if (chunk.terminal) {
    if (terminal === chunk.terminal) return { ok: true as const };
    throw Object.assign(new Error("Connector receipt conflicts with terminal state."), {
      statusCode: 409, errorCode: "terminal_receipt_conflict",
    });
  }
  const call = (operation: "ACK" | "CONFIRM" | "FAIL") => recordConnectorEvent({
    registrationId: session.registrationId,
    agentId: session.agentId,
    deviceFingerprint: session.deviceFingerprint,
    nonce: nonce(message.nonce),
    issuedAt: message.issuedAt,
    requestId: randomUUID(),
    operation,
    jobId: chunk.jobId,
    itemId: chunk.itemId,
    printerId: session.printerId,
    payloadHash: message.payloadHash || chunk.payloadHash,
    deviceJobRef: message.deviceJobRef || null,
    details: {
      sessionId: session.id,
      chunkId: message.chunkId,
      messageSeq: message.messageSeq,
      bytesWritten: message.bytesWritten || null,
      reason: message.error || null,
    },
  });
  if (["chunk_ack","chunk_spooled","label_spooled"].includes(message.type)) {
    await call("ACK");
    chunk.acknowledged = true;
  } else if (["chunk_confirmed","label_confirmed"].includes(message.type)) {
    if (!chunk.acknowledged) {
      throw Object.assign(new Error("A signed print acknowledgement is required before confirmation."), {
        statusCode: 409, errorCode: "print_ack_required",
      });
    }
    await call("CONFIRM");
    chunk.terminal = "CONFIRM";
  } else {
    await call("FAIL");
    chunk.terminal = "FAIL";
  }
  // Retain only a bounded receipt window; evicted identities fail closed.
  const completed = [...state.chunks].filter(([, receipt]) => receipt.terminal);
  for (const [id] of completed.slice(0, Math.max(0, completed.length - 128))) state.chunks.delete(id);
  await publishPrintJobViewEvent({
    printJobId: chunk.jobId,
    manufacturerId: session.manufacturerId,
    licenseeId: chunk.licenseeId,
    batchId: chunk.batchId,
    type: message.type,
    reason: "printer_session_progress",
  });
  return { ok: true as const };
};

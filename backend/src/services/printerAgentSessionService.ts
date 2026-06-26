import { createHash, randomUUID } from "crypto";
import {
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintPayloadType,
  PrinterTrustStatus,
} from "@prisma/client";
import { z } from "zod";

import prisma from "../config/database";
import { buildApprovedPrintPayload } from "./printPayloadService";
import { acknowledgePrintItemDispatch, buildPrintConfirmationDeadline, confirmPrintItemDispatch, resolvePrinterConfirmationMode } from "./printConfirmationService";
import { getPrinterAgentIssuedAtSkewSeconds, isPrinterAgentIssuedAtFresh, buildPrinterAgentSessionPayload, verifyPrinterAgentPayloadSignature } from "./printerAgentSigningService";
import { publishPrintJobViewEvent } from "./printJobRealtimeService";
import { publishPrinterConnectionStatusForUser } from "./printerConnectionService";
import { markBatchPrintAcknowledged } from "./batchStateMachineService";
import {
  CONNECTOR_PERSISTENT_SESSION_UPDATE_REQUIRED_MESSAGE,
  LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
  isLocalAgentPersistentSessionCapable,
} from "./localAgentProtocol";
import {
  acknowledgeLocalAgentPrinterTestJob,
  claimLocalAgentPrinterTestJob,
  confirmLocalAgentPrinterTestJob,
  failLocalAgentPrinterTestJob,
} from "./printerTestLabelService";

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");
const sha256Short = (value: unknown) => {
  const normalized = String(value || "").trim();
  return normalized ? sha256Hex(normalized).slice(0, 16) : null;
};
const toCleanString = (value: unknown, max = 500) => String(value || "").trim().slice(0, max);
const toJsonArray = (value: unknown): string[] => Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean) : [];
const toJsonRecord = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;

const parsePositiveIntEnv = (name: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const parseBoolEnv = (name: string, fallback: boolean) => {
  const normalized = String(process.env[name] || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

export const PRINT_AGENT_SESSION_CHUNK_SIZE = parsePositiveIntEnv("PRINT_AGENT_SESSION_CHUNK_SIZE", 50, 1, 100);
const PRINT_AGENT_SESSION_EXPIRY_SECONDS = parsePositiveIntEnv("PRINT_AGENT_SESSION_EXPIRY_SECONDS", 12 * 60 * 60, 60, 24 * 60 * 60);
const PRINT_AGENT_REQUIRE_MTLS = parseBoolEnv("PRINT_AGENT_REQUIRE_MTLS", false);

export const sessionHelloSchema = z.object({
  type: z.literal("hello"),
  registrationId: z.string().trim().uuid().optional().nullable(),
  agentId: z.string().trim().min(3).max(180),
  deviceFingerprint: z.string().trim().min(8).max(256),
  selectedPrinterId: z.string().trim().min(1).max(180),
  selectedPrinterName: z.string().trim().max(180).optional().nullable(),
  connectorVersion: z.string().trim().max(80).optional().nullable(),
  nonce: z.string().trim().min(8).max(180),
  issuedAt: z.string().trim().min(10).max(80),
  signature: z.string().trim().min(16).max(4096),
  printerHealth: z.record(z.any()).optional().nullable(),
}).strict();

export const sessionClientMessageSchema = z.object({
  type: z.enum([
    "heartbeat",
    "chunk_ack",
    "chunk_spooled",
    "chunk_confirmed",
    "chunk_failed",
    "label_spooled",
    "label_confirmed",
    "label_failed",
    "test_ack",
    "test_confirmed",
    "test_failed",
  ]),
  sessionId: z.string().trim().uuid(),
  chunkId: z.string().trim().uuid().optional().nullable(),
  printJobId: z.string().trim().uuid().optional().nullable(),
  printItemId: z.string().trim().uuid().optional().nullable(),
  testJobId: z.string().trim().max(160).optional().nullable(),
  messageSeq: z.coerce.number().int().min(1).max(2_000_000_000),
  nonce: z.string().trim().min(8).max(180),
  issuedAt: z.string().trim().min(10).max(80),
  signature: z.string().trim().min(16).max(4096),
  deviceJobRef: z.string().trim().max(240).optional().nullable(),
  payloadHash: z.string().trim().max(256).optional().nullable(),
  bytesWritten: z.coerce.number().int().min(1).max(50_000_000).optional().nullable(),
  printPath: z.string().trim().max(120).optional().nullable(),
  labelLanguage: z.string().trim().max(80).optional().nullable(),
  payloadType: z.string().trim().max(80).optional().nullable(),
  error: z.string().trim().max(1000).optional().nullable(),
  printerHealth: z.record(z.any()).optional().nullable(),
}).strict();

export type SessionHello = z.infer<typeof sessionHelloSchema>;
export type SessionClientMessage = z.infer<typeof sessionClientMessageSchema>;

export type TrustedPrinterAgentSession = {
  id: string;
  connectionId: string;
  registrationId: string;
  printerId: string;
  selectedPrinterId: string;
  selectedPrinterName: string | null;
  agentId: string;
  deviceFingerprint: string;
  connectorVersion: string | null;
  publicKeyPem: string;
  publicKeyFingerprint: string;
  manufacturerId: string;
};

type PrinterSessionRegistrationCandidate = {
  id: string;
  userId: string;
  agentId: string;
  deviceFingerprint: string;
  publicKeyPem: string;
  certFingerprint: string | null;
  trustStatus: PrinterTrustStatus;
  approvedAt: Date | null;
  revokedAt: Date | null;
  lastSeenAt: Date | null;
  updatedAt: Date;
};

type PrinterSessionResolverSummary = {
  reasonCode: string;
  requestPath?: string | null;
  agentIdHash: string | null;
  deviceFingerprintHash: string | null;
  registrationCandidateCount: number;
  trustedCandidateCount: number;
  revokedCandidateCount: number;
  selectedRegistrationIdHashOrShortId: string | null;
  selectedTrustStatus: string | null;
  signatureVerified: boolean;
  selectedPrinterIdPresent: boolean;
  selectedPrinterMatch: boolean;
  buildVersion: string | null;
  supportsPersistentPrintSession: boolean;
  connectorVersionAccepted: boolean;
  httpStatus: number;
};

type TrustedPrinterAgentRegistrationResolution = {
  registration: PrinterSessionRegistrationCandidate;
  printer: {
    id: string;
    name: string;
    nativePrinterId: string | null;
    connectionType: string;
    profile?: { id: string } | null;
  };
  publicKeyFingerprint: string;
  summary: PrinterSessionResolverSummary;
};

const resolveCapabilities = (hello: SessionHello) => {
  const health = toJsonRecord(hello.printerHealth);
  const capabilities = toJsonRecord(health?.capabilities);
  return {
    supportsPersistentPrintSession: capabilities?.supportsPersistentPrintSession === true,
  };
};

const buildSessionResolverSummary = (params: {
  reasonCode: string;
  hello: SessionHello;
  candidates: PrinterSessionRegistrationCandidate[];
  selected?: PrinterSessionRegistrationCandidate | null;
  signatureVerified?: boolean;
  selectedPrinterMatch?: boolean;
  httpStatus?: number;
}) => {
  const capabilities = resolveCapabilities(params.hello);
  return {
    reasonCode: params.reasonCode,
    agentIdHash: sha256Short(params.hello.agentId),
    deviceFingerprintHash: sha256Short(params.hello.deviceFingerprint),
    registrationCandidateCount: params.candidates.length,
    trustedCandidateCount: params.candidates.filter(
      (candidate) =>
        candidate.trustStatus === PrinterTrustStatus.TRUSTED &&
        !candidate.revokedAt &&
        String(candidate.publicKeyPem || "").includes("BEGIN")
    ).length,
    revokedCandidateCount: params.candidates.filter(
      (candidate) => candidate.trustStatus === PrinterTrustStatus.REVOKED || Boolean(candidate.revokedAt)
    ).length,
    selectedRegistrationIdHashOrShortId: params.selected ? sha256Short(params.selected.id) : null,
    selectedTrustStatus: params.selected?.trustStatus || null,
    signatureVerified: params.signatureVerified === true,
    selectedPrinterIdPresent: Boolean(toCleanString(params.hello.selectedPrinterId, 180)),
    selectedPrinterMatch: params.selectedPrinterMatch === true,
    buildVersion: toCleanString(params.hello.connectorVersion, 80) || null,
    supportsPersistentPrintSession: capabilities.supportsPersistentPrintSession,
    connectorVersionAccepted: isLocalAgentPersistentSessionCapable(params.hello.connectorVersion),
    httpStatus: params.httpStatus || 403,
  } satisfies PrinterSessionResolverSummary;
};

const sessionResolverError = (message: string, summary: PrinterSessionResolverSummary, extra: Record<string, unknown> = {}) =>
  Object.assign(new Error(message), {
    statusCode: summary.httpStatus,
    errorCode: summary.reasonCode,
    resolverSummary: summary,
    ...extra,
  });

export const logPrinterSessionResolverOutcome = (
  event: "printer_session_rejected" | "printer_session_connected" | "printer_session_resolved",
  summary: PrinterSessionResolverSummary & Record<string, unknown>
) => {
  console.info(event, summary);
};

const verifySessionSignature = (params: {
  publicKeyPem: string;
  type: SessionHello["type"] | SessionClientMessage["type"];
  registrationId?: string | null;
  agentId: string;
  deviceFingerprint: string;
  selectedPrinterId: string;
  connectorVersion?: string | null;
  sessionId?: string | null;
  chunkId?: string | null;
  printJobId?: string | null;
  printItemId?: string | null;
  testJobId?: string | null;
  messageSeq?: number | null;
  nonce: string;
  issuedAt: string;
  signature: string;
}) => {
  if (!isPrinterAgentIssuedAtFresh(params.issuedAt)) {
    const skewSeconds = getPrinterAgentIssuedAtSkewSeconds(params.issuedAt);
    throw Object.assign(new Error("Agent session message timestamp expired."), {
      statusCode: 401,
      errorCode: "agent_timestamp_expired",
      timestampSkewSeconds: skewSeconds == null ? null : Math.round(skewSeconds),
      serverTime: new Date().toISOString(),
    });
  }
  const payload = buildPrinterAgentSessionPayload({
    messageType: params.type,
    registrationId: params.registrationId || null,
    agentId: params.agentId,
    deviceFingerprint: params.deviceFingerprint,
    selectedPrinterId: params.selectedPrinterId,
    connectorVersion: params.connectorVersion || null,
    sessionId: params.sessionId || null,
    chunkId: params.chunkId || null,
    printJobId: params.printJobId || null,
    printItemId: params.printItemId || null,
    testJobId: params.testJobId || null,
    messageSeq: params.messageSeq || null,
    nonce: params.nonce,
    issuedAt: params.issuedAt,
  });
  if (!verifyPrinterAgentPayloadSignature({ publicKeyPem: params.publicKeyPem, payload, signature: params.signature })) {
    throw Object.assign(new Error("Printer agent session signature verification failed."), {
      statusCode: 401,
      errorCode: "bad_session_signature",
    });
  }
};

export const openTrustedPrinterAgentSession = async (
  hello: SessionHello,
  options: { mtlsFingerprintHeader?: string | null } = {}
): Promise<TrustedPrinterAgentSession> => {
  const resolved = await resolveTrustedPrinterAgentRegistrationForSession(hello, options);
  const { registration, printer, publicKeyFingerprint } = resolved;

  const now = new Date();
  const connectionId = randomUUID();
  const superseded = await prisma.printerAgentSession.updateMany({
    where: {
      registrationId: registration.id,
      selectedPrinterId: printer.nativePrinterId || hello.selectedPrinterId,
      connectionState: "CONNECTED",
      revokedAt: null,
    },
    data: {
      connectionState: "SUPERSEDED",
      disconnectedAt: now,
      closeReason: "superseded_by_new_persistent_session",
    },
  });
  const session = await prisma.printerAgentSession.create({
    data: {
      connectionId,
      registrationId: registration.id,
      printerProfileId: printer.profile?.id || null,
      agentId: registration.agentId,
      deviceFingerprint: registration.deviceFingerprint,
      publicKeyFingerprint,
      selectedPrinterId: printer.nativePrinterId || hello.selectedPrinterId,
      selectedPrinterName: hello.selectedPrinterName || printer.name,
      connectorVersion: hello.connectorVersion || null,
      printerHealth: hello.printerHealth || undefined,
      trustMode: PRINT_AGENT_REQUIRE_MTLS ? "STRICT_MTLS" : "SIGNED_ATTESTATION",
      connectedAt: now,
      lastSeenAt: now,
      lastSignedHeartbeatAt: now,
      expiresAt: new Date(now.getTime() + PRINT_AGENT_SESSION_EXPIRY_SECONDS * 1000),
      metadata: {
        mtlsFingerprint: toCleanString(options.mtlsFingerprintHeader, 256) || null,
      },
    },
  });

  logPrinterSessionResolverOutcome("printer_session_connected", {
    ...resolved.summary,
    reasonCode: "session_connected",
    httpStatus: 101,
    agentSessionId: session.id,
    sessionId: session.id,
    connectionId,
    registrationIdHashOrShortId: sha256Short(registration.id),
    selectedPrinterIdHashOrSafeName: sha256Short(printer.nativePrinterId || hello.selectedPrinterId),
    supersededSessionCount: superseded.count,
    trustMode: PRINT_AGENT_REQUIRE_MTLS ? "STRICT_MTLS" : "SIGNED_ATTESTATION",
  });
  void publishPrinterConnectionStatusForUser(registration.userId).catch(() => undefined);

  return {
    id: session.id,
    connectionId,
    registrationId: registration.id,
    printerId: printer.id,
    selectedPrinterId: printer.nativePrinterId || hello.selectedPrinterId,
    selectedPrinterName: hello.selectedPrinterName || printer.name,
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    connectorVersion: hello.connectorVersion || null,
    publicKeyPem: registration.publicKeyPem,
    publicKeyFingerprint,
    manufacturerId: registration.userId,
  };
};

export const resolveTrustedPrinterAgentRegistrationForSession = async (
  hello: SessionHello,
  options: { mtlsFingerprintHeader?: string | null } = {}
): Promise<TrustedPrinterAgentRegistrationResolution> => {
  const capabilities = resolveCapabilities(hello);
  const emptyCandidates: PrinterSessionRegistrationCandidate[] = [];
  if (!isLocalAgentPersistentSessionCapable(hello.connectorVersion)) {
    const summary = buildSessionResolverSummary({
      reasonCode: "persistent_session_connector_update_required",
      hello,
      candidates: emptyCandidates,
      httpStatus: 426,
    });
    throw sessionResolverError(CONNECTOR_PERSISTENT_SESSION_UPDATE_REQUIRED_MESSAGE, summary, {
      minimumConnectorVersion: LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION,
    });
  }
  if (!capabilities.supportsPersistentPrintSession) {
    const summary = buildSessionResolverSummary({
      reasonCode: "persistent_session_capability_required",
      hello,
      candidates: emptyCandidates,
      httpStatus: 403,
    });
    throw sessionResolverError("Connector must advertise persistent print session support.", summary);
  }

  const candidates = await prisma.printerRegistration.findMany({
    where: {
      OR: [
        {
          agentId: hello.agentId,
          deviceFingerprint: hello.deviceFingerprint,
        },
        ...(hello.registrationId ? [{ id: hello.registrationId }] : []),
      ],
    },
    orderBy: [{ lastSeenAt: "desc" }, { updatedAt: "desc" }],
  }) as PrinterSessionRegistrationCandidate[];

  let lastSummary = buildSessionResolverSummary({
    reasonCode: "registration_not_trusted",
    hello,
    candidates,
  });
  let sawSignatureFailure = false;
  let sawPrinterMismatch = false;
  let sawTrustedCandidate = false;

  for (const candidate of candidates) {
    const selectedBase = buildSessionResolverSummary({
      reasonCode: "registration_not_trusted",
      hello,
      candidates,
      selected: candidate,
    });

    if (
      candidate.agentId !== hello.agentId ||
      candidate.deviceFingerprint !== hello.deviceFingerprint ||
      candidate.trustStatus === PrinterTrustStatus.REVOKED ||
      candidate.revokedAt
    ) {
      lastSummary = selectedBase;
      continue;
    }

    if (candidate.trustStatus !== PrinterTrustStatus.TRUSTED || !candidate.approvedAt) {
      lastSummary = { ...selectedBase, reasonCode: "registration_not_approved" };
      continue;
    }
    sawTrustedCandidate = true;

    if (!String(candidate.publicKeyPem || "").includes("BEGIN")) {
      lastSummary = { ...selectedBase, reasonCode: "public_key_not_enrolled" };
      continue;
    }

    const publicKeyFingerprint = sha256Hex(candidate.publicKeyPem);
    if (!publicKeyFingerprint) {
      lastSummary = { ...selectedBase, reasonCode: "public_key_fingerprint_missing" };
      continue;
    }

    if (PRINT_AGENT_REQUIRE_MTLS) {
      const headerFingerprint = toCleanString(options.mtlsFingerprintHeader, 256);
      if (!headerFingerprint || (candidate.certFingerprint && candidate.certFingerprint !== headerFingerprint)) {
        lastSummary = { ...selectedBase, reasonCode: "mtls_required" };
        continue;
      }
    }

    try {
      verifySessionSignature({
        publicKeyPem: candidate.publicKeyPem,
        type: "hello",
        registrationId: hello.registrationId || null,
        agentId: hello.agentId,
        deviceFingerprint: hello.deviceFingerprint,
        selectedPrinterId: hello.selectedPrinterId,
        connectorVersion: hello.connectorVersion || null,
        nonce: hello.nonce,
        issuedAt: hello.issuedAt,
        signature: hello.signature,
      });
    } catch (error: any) {
      sawSignatureFailure = true;
      lastSummary = {
        ...selectedBase,
        reasonCode: error?.errorCode || "bad_session_signature",
        signatureVerified: false,
        httpStatus: Number(error?.statusCode || 403),
      };
      continue;
    }

    const printer = await prisma.printer.findFirst({
      where: {
        printerRegistrationId: candidate.id,
        isActive: true,
        OR: [{ nativePrinterId: hello.selectedPrinterId }, { id: hello.selectedPrinterId }],
      },
      include: { profile: true },
      orderBy: [{ isDefault: "desc" }, { updatedAt: "desc" }],
    });
    if (!printer) {
      sawPrinterMismatch = true;
      lastSummary = {
        ...selectedBase,
        reasonCode: "selected_printer_mismatch",
        signatureVerified: true,
        selectedPrinterMatch: false,
        httpStatus: 403,
      };
      continue;
    }
    if (printer.connectionType !== "LOCAL_AGENT") {
      lastSummary = {
        ...selectedBase,
        reasonCode: "printer_transport_mismatch",
        signatureVerified: true,
        selectedPrinterMatch: true,
        httpStatus: 403,
      };
      continue;
    }

    return {
      registration: candidate,
      printer,
      publicKeyFingerprint,
      summary: {
        ...selectedBase,
        reasonCode: "session_resolved",
        signatureVerified: true,
        selectedPrinterMatch: true,
        httpStatus: 101,
      },
    };
  }

  const reasonCode = sawPrinterMismatch
    ? "selected_printer_mismatch"
    : sawSignatureFailure
      ? "bad_session_signature"
      : sawTrustedCandidate
        ? lastSummary.reasonCode
        : "registration_not_trusted";
  const summary = {
    ...lastSummary,
    reasonCode,
    httpStatus: reasonCode === "agent_timestamp_expired" ? 403 : 403,
  };
  throw sessionResolverError(
    reasonCode === "selected_printer_mismatch"
      ? "Selected printer is not registered for this connector."
      : reasonCode === "bad_session_signature"
        ? "Printer agent session signature verification failed."
        : "Printer registration not trusted.",
    summary
  );
};

export const closeTrustedPrinterAgentSession = async (sessionId: string, reason: string) => {
  await prisma.printerAgentSession.updateMany({
    where: { id: sessionId, connectionState: "CONNECTED" },
    data: {
      connectionState: "DISCONNECTED",
      disconnectedAt: new Date(),
      closeReason: reason.slice(0, 500),
    },
  });
  console.info("printer_session_disconnected", {
    agentSessionId: sessionId,
    reason: reason.slice(0, 120),
  });
  const session = await prisma.printerAgentSession.findUnique({
    where: { id: sessionId },
    select: { registration: { select: { userId: true } } },
  });
  if (session?.registration?.userId) {
    void publishPrinterConnectionStatusForUser(session.registration.userId).catch(() => undefined);
  }
};

const loadActiveSession = async (session: TrustedPrinterAgentSession) => {
  const row = await prisma.printerAgentSession.findUnique({ where: { id: session.id } });
  if (!row || row.connectionState !== "CONNECTED" || row.revokedAt) {
    throw Object.assign(new Error("Printer agent session is no longer active."), { statusCode: 401, errorCode: "session_not_active" });
  }
  const registration = await prisma.printerRegistration.findUnique({ where: { id: session.registrationId } });
  if (!registration || registration.revokedAt || registration.trustStatus === PrinterTrustStatus.REVOKED) {
    throw Object.assign(new Error("Printer registration revoked."), { statusCode: 401, errorCode: "registration_revoked" });
  }
  return row;
};

export const verifyTrustedSessionMessage = async (
  session: TrustedPrinterAgentSession,
  message: SessionClientMessage
) => {
  await loadActiveSession(session);
  verifySessionSignature({
    publicKeyPem: session.publicKeyPem,
    type: message.type,
    registrationId: session.registrationId,
    agentId: session.agentId,
    deviceFingerprint: session.deviceFingerprint,
    selectedPrinterId: session.selectedPrinterId,
    connectorVersion: session.connectorVersion,
    sessionId: session.id,
    chunkId: message.chunkId || null,
    printJobId: message.printJobId || null,
    printItemId: message.printItemId || null,
    testJobId: message.testJobId || null,
    messageSeq: message.messageSeq,
    nonce: message.nonce,
    issuedAt: message.issuedAt,
    signature: message.signature,
  });
};

export const recordTrustedSessionHeartbeat = async (
  session: TrustedPrinterAgentSession,
  message: SessionClientMessage
) => {
  await verifyTrustedSessionMessage(session, message);
  await prisma.printerAgentSession.update({
    where: { id: session.id },
    data: {
      lastSeenAt: new Date(),
      lastSignedHeartbeatAt: new Date(),
      printerHealth: message.printerHealth || undefined,
    },
  });
  console.debug("printer_session_heartbeat", {
    agentSessionId: session.id,
    registrationId: session.registrationId,
    agentId: session.agentId,
    selectedPrinterId: session.selectedPrinterId,
  });
  void publishPrinterConnectionStatusForUser(session.manufacturerId).catch(() => undefined);
};

const reserveChunkItems = async (params: {
  printSessionId: string;
  printJobId: string;
  registrationId: string;
  printerId: string;
  agentSessionId: string;
  actorUserId: string;
  chunkSize: number;
}) => {
  const now = new Date();
  const confirmationDeadlineAt = buildPrintConfirmationDeadline(now);
  return prisma.$transaction(async (tx) => {
    const existing = await tx.printJobChunk.findFirst({
      where: {
        printSessionId: params.printSessionId,
        registrationId: params.registrationId,
        status: { in: ["CREATED", "ASSIGNED"] },
      },
      orderBy: [{ createdAt: "asc" }],
    });
    if (existing) return existing;

    const session = await tx.printSession.findUnique({
      where: { id: params.printSessionId },
      select: { issuedItems: true },
    });
    const rows = await tx.printItem.findMany({
      where: { printSessionId: params.printSessionId, state: PrintItemState.RESERVED },
      orderBy: [{ code: "asc" }],
      take: params.chunkSize,
      include: {
        qrCode: {
          select: {
            id: true,
            code: true,
            displayCode: true,
            batchId: true,
            licenseeId: true,
            tokenNonce: true,
            tokenIssuedAt: true,
            tokenExpiresAt: true,
            tokenHash: true,
            replayEpoch: true,
            status: true,
          },
        },
      },
    });
    if (!rows.length) return null;

    const baseSequence = Number(session?.issuedItems || 0);
    for (let index = 0; index < rows.length; index += 1) {
      const item = rows[index];
      const issueSequence = baseSequence + index + 1;
      await tx.printItem.updateMany({
        where: { id: item.id, state: PrintItemState.RESERVED },
        data: {
          state: PrintItemState.ISSUED,
          pipelineState: PrintPipelineState.SENT_TO_PRINTER,
          issuedAt: now,
          confirmationDeadlineAt,
          issueSequence,
        },
      });
      await tx.printItemEvent.create({
        data: {
          printItemId: item.id,
          eventType: PrintItemEventType.ISSUED,
          previousState: PrintItemState.RESERVED,
          nextState: PrintItemState.ISSUED,
          actorUserId: params.actorUserId,
          details: {
            dispatchMode: PrintDispatchMode.LOCAL_AGENT,
            pipelineState: PrintPipelineState.SENT_TO_PRINTER,
            confirmationDeadlineAt: confirmationDeadlineAt.toISOString(),
            deliveryMode: "PERSISTENT_SESSION_CHUNK",
          },
        },
      });
    }

    await tx.printSession.update({
      where: { id: params.printSessionId },
      data: { issuedItems: { increment: rows.length } },
    });

    return tx.printJobChunk.create({
      data: {
        printJobId: params.printJobId,
        printSessionId: params.printSessionId,
        registrationId: params.registrationId,
        printerId: params.printerId,
        agentSessionId: params.agentSessionId,
        idempotencyKey: sha256Hex(`${params.printJobId}:${params.printSessionId}:${baseSequence + 1}:${baseSequence + rows.length}`),
        status: "ASSIGNED",
        startSequence: baseSequence + 1,
        endSequence: baseSequence + rows.length,
        itemCount: rows.length,
        itemIds: rows.map((row) => row.id),
        rangeStartCode: rows[0]?.code || null,
        rangeEndCode: rows[rows.length - 1]?.code || null,
        assignedAt: now,
        metadata: {
          chunkSize: params.chunkSize,
        },
      },
    });
  });
};

export const buildNextPrintChunkForSession = async (
  session: TrustedPrinterAgentSession,
  chunkSize = PRINT_AGENT_SESSION_CHUNK_SIZE
) => {
  const activeSession = await loadActiveSession(session);
  const testClaim = await claimLocalAgentPrinterTestJob({ printerIds: [session.printerId] });
  if (testClaim) {
    return {
      type: "test_label" as const,
      sessionId: activeSession.id,
      registrationId: session.registrationId,
      selectedPrinterId: session.selectedPrinterId,
      selectedPrinterName: session.selectedPrinterName,
      ...testClaim,
    };
  }

  const job = await prisma.printJob.findFirst({
    where: {
      manufacturerId: session.manufacturerId,
      printerId: session.printerId,
      printMode: PrintDispatchMode.LOCAL_AGENT,
      status: { in: [PrintJobStatus.PENDING, PrintJobStatus.SENT] },
      printSession: { is: { status: "ACTIVE" } },
    },
    include: {
      batch: {
        select: {
          id: true,
          name: true,
          licenseeId: true,
          metadata: true,
          licensee: { select: { id: true, name: true, prefix: true, location: true, metadata: true } },
        },
      },
      manufacturer: { select: { id: true, name: true, location: true, metadata: true } },
      printer: { include: { profile: true } },
      printSession: true,
    },
    orderBy: [{ createdAt: "asc" }],
  });
  if (!job?.printSession || !job.printer) return null;

  if (resolvePrinterConfirmationMode(job.printer) !== "LOCAL_QUEUE") {
    return null;
  }

  const inFlightChunk = await prisma.printJobChunk.findFirst({
    where: {
      printSessionId: job.printSession.id,
      registrationId: session.registrationId,
      status: { in: ["SENT", "ACKED", "SPOOLED"] },
    },
    orderBy: [{ sentAt: "asc" }, { createdAt: "asc" }],
    select: { id: true },
  });
  if (inFlightChunk) return null;

  if (job.status === PrintJobStatus.PENDING) {
    await prisma.printJob.update({
      where: { id: job.id },
      data: {
        status: PrintJobStatus.SENT,
        pipelineState: PrintPipelineState.SENT_TO_PRINTER,
        sentAt: new Date(),
      },
    });
    await markBatchPrintAcknowledged({
      batchId: job.batchId,
      printJobId: job.id,
      actorUserId: job.manufacturerId,
    });
  }

  const chunk = await reserveChunkItems({
    printSessionId: job.printSession.id,
    printJobId: job.id,
    registrationId: session.registrationId,
    printerId: session.printerId,
    agentSessionId: session.id,
    actorUserId: job.manufacturerId,
    chunkSize,
  });
  if (!chunk) return null;

  const itemIds = toJsonArray(chunk.itemIds);
  const items = await prisma.printItem.findMany({
    where: { id: { in: itemIds }, printSessionId: job.printSession.id },
    orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
    include: {
      qrCode: {
        select: {
          id: true,
          code: true,
          displayCode: true,
          batchId: true,
          licenseeId: true,
          tokenNonce: true,
          tokenIssuedAt: true,
          tokenExpiresAt: true,
          tokenHash: true,
          replayEpoch: true,
          status: true,
        },
      },
    },
  });

  const labels = [];
  for (const item of items) {
    if (item.qrCode.status !== "ACTIVATED") continue;
    const payload = buildApprovedPrintPayload({
      printer: {
        id: job.printer.id,
        name: job.printer.name,
        connectionType: job.printer.connectionType,
        commandLanguage: job.printer.commandLanguage,
        nativePrinterId: job.printer.nativePrinterId,
        ipAddress: job.printer.ipAddress,
        port: job.printer.port,
        calibrationProfile: toJsonRecord(job.printer.calibrationProfile),
        capabilitySummary: toJsonRecord(job.printer.capabilitySummary),
        metadata: toJsonRecord(job.printer.metadata),
      },
      qr: item.qrCode,
      manufacturerId: job.manufacturerId,
      printJobId: job.id,
      printItemId: item.id,
      jobNumber: job.jobNumber,
      reprintOfJobId: job.reprintOfJobId,
      serialContext: {
        sequence: item.issueSequence,
        issuedAt: item.issuedAt,
        batch: job.batch || null,
        licensee: job.batch?.licensee || null,
        manufacturer: job.manufacturer || null,
        printer: job.printer || null,
      },
    });
    labels.push({
      printItemId: item.id,
      issueSequence: item.issueSequence,
      code: item.code,
      payloadType: payload.payloadType,
      payloadContent: payload.payloadContent,
      payloadHash: payload.payloadHash,
      previewLabel: payload.previewLabel,
      commandLanguage: payload.commandLanguage,
      scanUrl: payload.scanUrl,
    });
  }

  await prisma.printJobChunk.update({
    where: { id: chunk.id },
    data: {
      status: "SENT",
      sentAt: new Date(),
    },
  });
  await prisma.printerAgentSession.update({
    where: { id: session.id },
    data: {
      activePrintJobId: job.id,
      lastSeenAt: new Date(),
    },
  });

  void publishPrintJobViewEvent({
    printJobId: job.id,
    manufacturerId: job.manufacturerId,
    licenseeId: job.batch.licenseeId || null,
    batchId: job.batchId,
    type: "chunk.sent",
    reason: "printer_session_chunk_sent",
  });
  console.info("printer_session_work_sent", {
    agentSessionId: session.id,
    registrationId: session.registrationId,
    printJobId: job.id,
    printSessionId: job.printSession.id,
    chunkId: chunk.id,
    startSequence: chunk.startSequence,
    endSequence: chunk.endSequence,
    itemCount: labels.length,
  });

  return {
    type: "print_chunk" as const,
    sessionId: activeSession.id,
    chunkId: chunk.id,
    idempotencyKey: chunk.idempotencyKey,
    printJobId: job.id,
    printSessionId: job.printSession.id,
    range: {
      startSequence: chunk.startSequence,
      endSequence: chunk.endSequence,
      startCode: chunk.rangeStartCode,
      endCode: chunk.rangeEndCode,
      count: labels.length,
    },
    printer: {
      id: job.printer.id,
      name: job.printer.name,
      nativePrinterId: job.printer.nativePrinterId,
      selectedPrinterId: session.selectedPrinterId,
      languages: Array.isArray((job.printer.capabilitySummary as Record<string, unknown> | null)?.languages)
        ? (((job.printer.capabilitySummary as Record<string, unknown>).languages as unknown[]) || []).map((value) => String(value || "").trim())
        : [],
    },
    calibrationProfile: (job.printer.calibrationProfile as Record<string, unknown> | null) || null,
    labels,
  };
};

const loadChunkJob = async (chunkId: string, session: TrustedPrinterAgentSession) => {
  const chunk = await prisma.printJobChunk.findFirst({
    where: {
      id: chunkId,
      registrationId: session.registrationId,
    },
    include: {
      printJob: {
        include: {
          batch: { select: { id: true, licenseeId: true } },
          printer: true,
          printSession: true,
        },
      },
    },
  });
  if (!chunk?.printJob?.printSession || !chunk.printJob.printer) {
    throw Object.assign(new Error("Print chunk not found for this session."), { statusCode: 404, errorCode: "chunk_not_found" });
  }
  if (chunk.printJob.printerId !== session.printerId || chunk.printJob.manufacturerId !== session.manufacturerId) {
    throw Object.assign(new Error("Print chunk does not belong to this connector."), { statusCode: 403, errorCode: "chunk_scope_mismatch" });
  }
  return chunk;
};

export const handleTrustedSessionProgressMessage = async (
  session: TrustedPrinterAgentSession,
  message: SessionClientMessage
) => {
  await verifyTrustedSessionMessage(session, message);
  const now = new Date();
  await prisma.printerAgentSession.update({
    where: { id: session.id },
    data: {
      lastSeenAt: now,
      lastSignedHeartbeatAt: message.type === "heartbeat" ? now : undefined,
      printerHealth: message.printerHealth || undefined,
    },
  });
  if (message.type === "heartbeat") return { ok: true as const };

  if (message.type === "test_ack" || message.type === "test_confirmed" || message.type === "test_failed") {
    const testJobId = toCleanString(message.testJobId, 160);
    if (!testJobId) {
      throw Object.assign(new Error("Test-label progress message is missing test job id."), {
        statusCode: 400,
        errorCode: "test_job_id_missing",
      });
    }
    const testMetadata = {
      printerRegistrationId: session.registrationId,
      agentSessionId: session.id,
      messageSeq: message.messageSeq,
      printPath: toCleanString(message.printPath, 120) || null,
      labelLanguage: toCleanString(message.labelLanguage, 80) || null,
      payloadType: toCleanString(message.payloadType, 80) || null,
      payloadHash: toCleanString(message.payloadHash, 256) || null,
      bytesWritten: message.bytesWritten || null,
      deviceJobRef: toCleanString(message.deviceJobRef, 240) || null,
    };
    if (message.type === "test_ack") {
      await acknowledgeLocalAgentPrinterTestJob({
        printerId: session.printerId,
        testJobId,
        metadata: testMetadata,
      });
    } else if (message.type === "test_confirmed") {
      await confirmLocalAgentPrinterTestJob({
        printerId: session.printerId,
        testJobId,
        payloadType: (toCleanString(message.payloadType, 80) || PrintPayloadType.ZPL) as PrintPayloadType,
        deviceJobRef: toCleanString(message.deviceJobRef, 240) || null,
        confirmationMode: "LOCAL_QUEUE",
        metadata: testMetadata,
      });
    } else {
      await failLocalAgentPrinterTestJob({
        printerId: session.printerId,
        testJobId,
        reason: toCleanString(message.error, 1000) || "Connector reported test-label failure.",
      });
    }
    return { ok: true as const };
  }

  if (!message.chunkId) throw Object.assign(new Error("Chunk progress message is missing chunk id."), { statusCode: 400 });

  const chunk = await loadChunkJob(message.chunkId, session);
  const itemIds = new Set(toJsonArray(chunk.itemIds));
  const printItemId = toCleanString(message.printItemId, 80);
  if (printItemId && !itemIds.has(printItemId)) {
    throw Object.assign(new Error("Print item does not belong to this chunk."), { statusCode: 403, errorCode: "chunk_item_mismatch" });
  }

  const job = chunk.printJob;
  if (!job.printer || !job.printSession) {
    throw Object.assign(new Error("Print chunk has no active printer/session relation."), {
      statusCode: 404,
      errorCode: "chunk_job_relation_missing",
    });
  }
  const confirmationMode = resolvePrinterConfirmationMode(job.printer);
  const payloadHash = toCleanString(message.payloadHash, 256) || null;
  const deviceJobRef = toCleanString(message.deviceJobRef, 240) || null;
  const bytesWritten = message.bytesWritten || null;
  const dispatchMetadata = {
    printerRegistrationId: session.registrationId,
    agentSessionId: session.id,
    chunkId: chunk.id,
    messageSeq: message.messageSeq,
    printPath: toCleanString(message.printPath, 120) || null,
    labelLanguage: toCleanString(message.labelLanguage, 80) || null,
  };

  if (message.type === "chunk_ack") {
    await prisma.printJobChunk.updateMany({
      where: { id: chunk.id, status: { in: ["SENT", "ASSIGNED", "CREATED"] } },
      data: { status: "ACKED", acknowledgedAt: now, lastMessageSeq: message.messageSeq },
    });
    console.info("printer_session_chunk_ack", {
      agentSessionId: session.id,
      registrationId: session.registrationId,
      printJobId: job.id,
      chunkId: chunk.id,
      messageSeq: message.messageSeq,
    });
  } else if (message.type === "chunk_spooled") {
    await prisma.printJobChunk.update({
      where: { id: chunk.id },
      data: { status: "SPOOLED", acknowledgedAt: chunk.acknowledgedAt || now, lastMessageSeq: message.messageSeq },
    });
  } else if (message.type === "chunk_confirmed") {
    await prisma.printJobChunk.update({
      where: { id: chunk.id },
      data: { status: "CONFIRMED", confirmedAt: now, confirmedCount: chunk.itemCount, lastMessageSeq: message.messageSeq },
    });
    console.info("printer_session_chunk_confirm", {
      agentSessionId: session.id,
      registrationId: session.registrationId,
      printJobId: job.id,
      chunkId: chunk.id,
      confirmedCount: chunk.itemCount,
      messageSeq: message.messageSeq,
    });
  } else if (message.type === "chunk_failed") {
    await prisma.printJobChunk.update({
      where: { id: chunk.id },
      data: { status: "FAILED", failedAt: now, failureReason: toCleanString(message.error, 1000) || "Connector reported chunk failure.", lastMessageSeq: message.messageSeq },
    });
  } else if (message.type === "label_spooled" && printItemId) {
    const beforeItem = await prisma.printItem.findUnique({
      where: { id: printItemId },
      select: { state: true, dispatchedAt: true },
    });
    const alreadySpooled = Boolean(beforeItem?.dispatchedAt) || beforeItem?.state === PrintItemState.AGENT_ACKED || beforeItem?.state === PrintItemState.PRINT_CONFIRMED;
    await acknowledgePrintItemDispatch({
      printItemId,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: job.payloadType || null,
      payloadHash,
      bytesWritten,
      deviceJobRef,
      dispatchMetadata,
      confirmationMode,
      markDispatched: true,
    });
    await prisma.printJobChunk.update({
      where: { id: chunk.id },
      data: {
        status: "SPOOLED",
        ...(alreadySpooled ? {} : { acknowledgedCount: { increment: 1 } }),
        acknowledgedAt: chunk.acknowledgedAt || now,
        lastMessageSeq: message.messageSeq,
      },
    });
  } else if (message.type === "label_confirmed" && printItemId) {
    const beforeItem = await prisma.printItem.findUnique({
      where: { id: printItemId },
      select: { state: true, printConfirmedAt: true },
    });
    const alreadyConfirmed = beforeItem?.state === PrintItemState.PRINT_CONFIRMED || Boolean(beforeItem?.printConfirmedAt);
    const finalized = await confirmPrintItemDispatch({
      printSessionId: job.printSession.id,
      printJobId: job.id,
      batchId: job.batchId,
      printItemId,
      actorUserId: job.manufacturerId,
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: job.payloadType || null,
      payloadHash,
      bytesWritten,
      deviceJobRef,
      dispatchMetadata,
      confirmationMode,
      confirmationEvidence: {
        ...dispatchMetadata,
        queueConfirmed: true,
      },
    });
    const updated = alreadyConfirmed
      ? await prisma.printJobChunk.update({
          where: { id: chunk.id },
          data: { lastMessageSeq: message.messageSeq },
        })
      : await prisma.printJobChunk.update({
          where: { id: chunk.id },
          data: { confirmedCount: { increment: 1 }, lastMessageSeq: message.messageSeq },
        });
    if (updated.confirmedCount >= updated.itemCount) {
      await prisma.printJobChunk.update({
        where: { id: chunk.id },
        data: { status: "CONFIRMED", confirmedAt: now },
      });
    }
    if (finalized.jobConfirmed) {
      await prisma.printerAgentSession.updateMany({
        where: { id: session.id, activePrintJobId: job.id },
        data: { activePrintJobId: null },
      });
      console.info("printer_session_job_completed", {
        agentSessionId: session.id,
        registrationId: session.registrationId,
        printJobId: job.id,
        printSessionId: job.printSession.id,
      });
    }
  } else if (message.type === "label_failed" && printItemId) {
    await prisma.printItem.updateMany({
      where: { id: printItemId, state: { in: [PrintItemState.ISSUED, PrintItemState.AGENT_ACKED] } },
      data: {
        state: PrintItemState.FAILED,
        pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION,
        failedAt: now,
        failureReason: toCleanString(message.error, 1000) || "Connector reported label failure.",
      },
    });
    await prisma.printJobChunk.update({
      where: { id: chunk.id },
      data: { status: "FAILED", failedCount: { increment: 1 }, failedAt: now, failureReason: toCleanString(message.error, 1000) || "Connector reported label failure.", lastMessageSeq: message.messageSeq },
    });
    await prisma.printJob.update({
      where: { id: job.id },
      data: {
        status: PrintJobStatus.PARTIALLY_COMPLETED,
        pipelineState: PrintPipelineState.NEEDS_OPERATOR_ACTION,
        failureReason: toCleanString(message.error, 1000) || "Connector reported label failure.",
      },
    });
  }

  void publishPrintJobViewEvent({
    printJobId: job.id,
    manufacturerId: job.manufacturerId,
    licenseeId: job.batch.licenseeId || null,
    batchId: job.batchId,
    type: message.type,
    reason: "printer_session_progress",
  });

  return { ok: true as const };
};

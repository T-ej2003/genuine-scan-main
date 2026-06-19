import { createHash, createPublicKey, verify as cryptoVerify } from "crypto";
import { Prisma, PrinterTrustStatus, UserRole } from "@prisma/client";
import type {
  LocalPrinterDTO as PrinterInventoryDevice,
  PrinterCapabilitySummaryDTO as PrinterCapabilitySummary,
  PrinterConnectionStatusDTO as PrinterConnectionStatus,
} from "../../../shared/contracts/printing.d.ts";

import prisma from "../config/database";
import { hashIp, hashToken, normalizeUserAgent, randomOpaqueToken } from "../utils/security";
import {
  CONNECTOR_UPDATE_REQUIRED_MESSAGE,
  getMissingTransportDiagnosticsCapabilities,
  isLocalAgentTransportDiagnosticsCurrent,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} from "./localAgentProtocol";
import { getRedisInstanceId, publishRedisJson, subscribeRedisJson } from "./redisService";
import { bumpCacheNamespaceVersion } from "./versionedCacheService";

export type { PrinterCapabilitySummary, PrinterConnectionStatus, PrinterInventoryDevice };

type PrinterRegistrationWithLatest = {
  id: string;
  userId: string;
  deviceFingerprint: string;
  agentId: string;
  publicKeyPem: string;
  certFingerprint: string | null;
  trustStatus: PrinterTrustStatus;
  trustReason: string | null;
  approvedAt: Date | null;
  revokedAt: Date | null;
  lastSeenAt: Date | null;
  updatedAt: Date;
  attestations: Array<{
    id: string;
    attestedAt: Date;
    expiresAt: Date;
    signatureValid: boolean;
    trustValid: boolean;
    rejectionReason: string | null;
    mtlsFingerprint: string | null;
    metadata: any;
    createdAt: Date;
  }>;
};

export type PrinterConnectionRealtimeEvent = {
  userId: string;
  status: PrinterConnectionStatus;
  changedAt: string;
};

const listeners = new Set<(event: PrinterConnectionRealtimeEvent) => void>();
const PRINTER_CONNECTION_EVENT_CHANNEL = "mscqr:realtime:printer-connection";
let printerConnectionChannelReady = false;

const parsePositiveIntEnv = (name: string, fallback: number, min = 5, max = 3600) => {
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

const HEARTBEAT_TTL_SECONDS = parsePositiveIntEnv("PRINT_AGENT_HEARTBEAT_TTL_SECONDS", 35);
const HEARTBEAT_TTL_MS = HEARTBEAT_TTL_SECONDS * 1000;
const MAX_SIGNATURE_SKEW_SECONDS = parsePositiveIntEnv("PRINT_AGENT_MAX_SIGNATURE_SKEW_SECONDS", 120, 10, 900);

const REQUIRE_SIGNATURE = parseBoolEnv("PRINT_AGENT_REQUIRE_SIGNATURE", true);
const REQUIRE_MTLS = parseBoolEnv("PRINT_AGENT_REQUIRE_MTLS", false);
const ALLOW_COMPATIBILITY_MODE = parseBoolEnv("PRINT_AGENT_ALLOW_COMPATIBILITY_MODE", true);
const LEGACY_HEARTBEAT_SUBJECTS = ["manufacturer-browser-heartbeat"];
const TRUST_MODE: "STRICT_MTLS" | "SIGNED_ATTESTATION" = REQUIRE_MTLS ? "STRICT_MTLS" : "SIGNED_ATTESTATION";

const buildReadinessFields = (status: {
  registrationId?: string | null;
  stale?: boolean | null;
  connected?: boolean | null;
  eligibleForPrinting?: boolean | null;
  trusted?: boolean | null;
  compatibilityMode?: boolean | null;
  selectedPrinterId?: string | null;
  printerId?: string | null;
}) => {
  const freshHelperHeartbeat = Boolean(status.registrationId && !status.stale);
  const helperConnection = Boolean(status.connected);
  const eligiblePrinter = Boolean(status.eligibleForPrinting);
  const securePrinterSession = Boolean(status.trusted && !status.compatibilityMode && freshHelperHeartbeat && helperConnection);
  const missingFields = new Set<string>();
  if (!status.registrationId) missingFields.add("printerRegistration");
  if (!freshHelperHeartbeat) missingFields.add("freshHelperHeartbeat");
  if (!helperConnection) missingFields.add("helperConnection");
  if (!eligiblePrinter) missingFields.add("eligiblePrinter");
  if (!securePrinterSession) missingFields.add("securePrinterSession");
  if (!status.selectedPrinterId && !status.printerId) missingFields.add("selectedPrinter");
  return {
    trustMode: TRUST_MODE,
    securePrinterSession,
    freshHelperHeartbeat,
    helperConnection,
    eligiblePrinter,
    missingFields: Array.from(missingFields),
    recoveryAction: missingFields.size > 0 ? "refresh_printer_status" : null,
  };
};

const normalizePem = (value: string) => String(value || "").replace(/\\n/g, "\n").trim();
const looksLikePem = (value: string) => normalizePem(value).includes("BEGIN");
const toCleanString = (value: unknown, max = 500) => String(value || "").trim().slice(0, max);
const toCleanStringArray = (value: unknown, maxItems = 24, maxLen = 120): string[] => {
  if (!Array.isArray(value)) return [];
  const unique = new Set<string>();
  for (const item of value) {
    const normalized = toCleanString(item, maxLen);
    if (!normalized) continue;
    unique.add(normalized);
    if (unique.size >= maxItems) break;
  }
  return Array.from(unique);
};
const toFiniteIntArray = (value: unknown, maxItems = 12): number[] => {
  if (!Array.isArray(value)) return [];
  const unique = new Set<number>();
  for (const item of value) {
    const parsed = Number.parseInt(String(item || "").trim(), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) continue;
    unique.add(parsed);
    if (unique.size >= maxItems) break;
  }
  return Array.from(unique).sort((a, b) => a - b);
};

const stableStringify = (value: any): string => {
  if (value === null || value === undefined) return "null";
  if (typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableStringify(item)).join(",")}]`;

  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
};

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const decodeBase64Url = (value: string): Buffer => {
  const normalized = String(value || "").trim();
  if (!normalized) throw new Error("Empty signature");

  const padded = normalized.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (padded.length % 4)) % 4;
  return Buffer.from(`${padded}${"=".repeat(padLength)}`, "base64");
};

const buildHeartbeatSignedPayload = (input: {
  userId: string;
  agentId: string;
  deviceFingerprint: string;
  printerId: string;
  connected: boolean;
  heartbeatNonce: string;
  heartbeatIssuedAt: string;
}) => {
  return [
    "v1",
    input.userId,
    input.agentId,
    input.deviceFingerprint,
    input.printerId,
    input.connected ? "1" : "0",
    input.heartbeatNonce,
    input.heartbeatIssuedAt,
  ].join("|");
};

const buildHeartbeatSignedPayloadCandidates = (input: {
  userId: string;
  agentId: string;
  deviceFingerprint: string;
  printerId: string;
  connected: boolean;
  heartbeatNonce: string;
  heartbeatIssuedAt: string;
}) => {
  const candidates = new Set<string>();
  candidates.add(buildHeartbeatSignedPayload(input));
  for (const legacyUserId of LEGACY_HEARTBEAT_SUBJECTS) {
    candidates.add(
      buildHeartbeatSignedPayload({
        ...input,
        userId: legacyUserId,
      })
    );
  }
  return Array.from(candidates);
};

const verifyAgentSignature = (params: {
  publicKeyPem: string;
  signature: string;
  signedPayload: string;
}) => {
  const key = createPublicKey(normalizePem(params.publicKeyPem));
  const signature = decodeBase64Url(params.signature);
  const payload = Buffer.from(params.signedPayload, "utf8");

  try {
    if (cryptoVerify("sha256", payload, key, signature)) return true;
  } catch {
    // fall through to curve-native verify mode
  }

  try {
    return cryptoVerify(null, payload, key, signature);
  } catch {
    return false;
  }
};

const verifyAgentSignatureAcrossPayloads = (params: {
  publicKeyPem: string;
  signature: string;
  signedPayloads: string[];
}) => {
  for (const signedPayload of params.signedPayloads) {
    if (
      verifyAgentSignature({
        publicKeyPem: params.publicKeyPem,
        signature: params.signature,
        signedPayload,
      })
    ) {
      return signedPayload;
    }
  }
  return null;
};

const normalizeCapabilitySummary = (source: any): PrinterCapabilitySummary | null => {
  if (!source || typeof source !== "object") return null;
  const transports = toCleanStringArray(source.transports || source.paths || source.connections, 12, 80);
  const protocols = toCleanStringArray(source.protocols, 24, 80);
  const languages = toCleanStringArray(source.languages || source.labelLanguages, 24, 80);
  const dpiOptions = toFiniteIntArray(source.dpiOptions || source.dpi || source.dpis, 12);
  const mediaSizes = toCleanStringArray(source.mediaSizes || source.media || source.paperSizes, 24, 80);

  return {
    transports,
    protocols,
    languages,
    supportsRaster: Boolean(source.supportsRaster || source.rasterFallback || source.imageFallback),
    supportsPdf: Boolean(source.supportsPdf || source.pdf),
    dpiOptions,
    mediaSizes,
  };
};

const normalizePrinterInventory = (value: unknown): PrinterInventoryDevice[] => {
  if (!Array.isArray(value)) return [];
  const rows: PrinterInventoryDevice[] = [];
  for (const raw of value) {
    if (!raw || typeof raw !== "object") continue;
    const printerId = toCleanString((raw as any).printerId || (raw as any).id, 180);
    const printerName = toCleanString((raw as any).printerName || (raw as any).name, 180);
    if (!printerId || !printerName) continue;
    rows.push({
      printerId,
      printerName,
      model: toCleanString((raw as any).model, 180) || null,
      connection: toCleanString((raw as any).connection || (raw as any).transport, 80) || null,
      online: Boolean((raw as any).online ?? true),
      isDefault: Boolean((raw as any).isDefault),
      protocols: toCleanStringArray((raw as any).protocols, 12, 60),
      languages: toCleanStringArray((raw as any).languages, 12, 60),
      mediaSizes: toCleanStringArray((raw as any).mediaSizes, 12, 60),
      dpi: Number.isFinite(Number((raw as any).dpi)) ? Number((raw as any).dpi) : null,
      deviceUri: toCleanString((raw as any).deviceUri, 512) || null,
      portName: toCleanString((raw as any).portName, 180) || null,
      windowsPortName: toCleanString((raw as any).windowsPortName, 180) || null,
      windowsPortHost: toCleanString((raw as any).windowsPortHost, 180) || null,
      windowsPortNumber: Number.isFinite(Number((raw as any).windowsPortNumber))
        ? Number((raw as any).windowsPortNumber)
        : null,
      queueStatus: toCleanString((raw as any).queueStatus, 120) || null,
      queueHasErrors: Boolean((raw as any).queueHasErrors),
      stuckJobCount: Number.isFinite(Number((raw as any).stuckJobCount)) ? Number((raw as any).stuckJobCount) : 0,
      retainedJobCount: Number.isFinite(Number((raw as any).retainedJobCount)) ? Number((raw as any).retainedJobCount) : 0,
      usbAvailable: Boolean((raw as any).usbAvailable),
    });
    if (rows.length >= 40) break;
  }
  return rows;
};

const normalizeStatusPayload = (metadata: any) => {
  const source = metadata && typeof metadata === "object" ? metadata : {};
  const capabilities = source.capabilities && typeof source.capabilities === "object"
    ? (source.capabilities as Record<string, unknown>)
    : null;
  return {
    connected: Boolean(source.connected),
    printerName: toCleanString(source.printerName, 180) || null,
    printerId: toCleanString(source.printerId, 180) || null,
    deviceName: toCleanString(source.deviceName, 180) || null,
    agentVersion: toCleanString(source.agentVersion, 80) || null,
    protocolVersion: toCleanString(source.protocolVersion, 80) || null,
    buildVersion: toCleanString(source.buildVersion, 80) || null,
    transportDiagnosticsVersion: toCleanString(source.transportDiagnosticsVersion, 80) || null,
    capabilities,
    error: toCleanString(source.error, 500) || null,
    heartbeatIssuedAt: toCleanString(source.heartbeatIssuedAt, 80) || null,
    selectedPrinterId: toCleanString(source.selectedPrinterId, 180) || null,
    selectedPrinterName: toCleanString(source.selectedPrinterName, 180) || null,
    capabilitySummary: normalizeCapabilitySummary(source.capabilitySummary || source.capabilities),
    printers: normalizePrinterInventory(source.printers),
    calibrationProfile:
      source.calibrationProfile && typeof source.calibrationProfile === "object"
        ? (source.calibrationProfile as Record<string, any>)
        : null,
  };
};

const buildStatus = (registration: PrinterRegistrationWithLatest | null | undefined): PrinterConnectionStatus => {
  if (!registration) {
    const readiness = buildReadinessFields({
      registrationId: null,
      stale: true,
      connected: false,
      eligibleForPrinting: false,
      trusted: false,
      compatibilityMode: false,
      selectedPrinterId: null,
      printerId: null,
    });
    return {
      connected: false,
      trusted: false,
      compatibilityMode: false,
      compatibilityReason: null,
      eligibleForPrinting: false,
      connectionClass: "BLOCKED",
      ...readiness,
      signedAttestation: {
        required: REQUIRE_SIGNATURE,
        present: false,
        signatureValid: false,
        fresh: false,
        issuedAt: null,
      },
      stale: true,
      requiredForPrinting: true,
      trustStatus: "UNREGISTERED",
      trustReason: "No trusted printer registration",
      lastHeartbeatAt: null,
      ageSeconds: null,
      registrationId: null,
      agentId: null,
      deviceFingerprint: null,
      mtlsFingerprint: null,
      printerName: null,
      printerId: null,
      deviceName: null,
      agentVersion: null,
      protocolVersion: null,
      buildVersion: null,
      connectorUpdateRequired: false,
      selectedPrinterId: null,
      selectedPrinterName: null,
      capabilitySummary: null,
      printers: [],
      calibrationProfile: null,
      error: "No printer registration",
    };
  }

  const latestAttestation = registration.attestations[0] || null;
  const payload = normalizeStatusPayload(latestAttestation?.metadata || {});
  const missingCapabilities = getMissingTransportDiagnosticsCapabilities(payload.capabilities);
  const connectorUpdateRequired = Boolean(
    payload.connected &&
      !isLocalAgentTransportDiagnosticsCurrent({
        protocolVersion: payload.protocolVersion,
        buildVersion: payload.buildVersion,
        transportDiagnosticsVersion: payload.transportDiagnosticsVersion,
        capabilities: payload.capabilities,
      })
  );
  const nowMs = Date.now();
  const attestedMs = latestAttestation?.attestedAt ? new Date(latestAttestation.attestedAt).getTime() : NaN;
  const ageMs = Number.isFinite(attestedMs) ? Math.max(0, nowMs - attestedMs) : null;
  const stale = ageMs == null ? true : ageMs > HEARTBEAT_TTL_MS;

  const trustedRegistration = registration.trustStatus === PrinterTrustStatus.TRUSTED && !registration.revokedAt;
  const trustedAttestation = Boolean(latestAttestation?.trustValid && latestAttestation?.signatureValid);
  const trusted = trustedRegistration && trustedAttestation && !stale && !connectorUpdateRequired;
  const compatibilityReason =
    latestAttestation?.rejectionReason || registration.trustReason || payload.error || "Compatibility mode fallback";
  const compatibilityMode = Boolean(
      ALLOW_COMPATIBILITY_MODE &&
      payload.connected &&
      !connectorUpdateRequired &&
      !trusted &&
      !stale &&
      registration.trustStatus !== PrinterTrustStatus.REVOKED
  );
  const connected = payload.connected && (trusted || compatibilityMode);
  const eligibleForPrinting = trusted;

  const trustReason = trusted
    ? null
    : registration.revokedAt
      ? "Printer registration revoked"
      : connectorUpdateRequired
        ? CONNECTOR_UPDATE_REQUIRED_MESSAGE
      : latestAttestation?.rejectionReason || registration.trustReason || null;

  const error = trusted
    ? null
    : connected && compatibilityMode
      ? `Compatibility mode active: ${compatibilityReason}`
      : connectorUpdateRequired
        ? `${CONNECTOR_UPDATE_REQUIRED_MESSAGE} Expected protocol ${LOCAL_AGENT_DIRECT_PROTOCOL_VERSION}, build ${LOCAL_AGENT_MIN_VERSION_HINT}, and transport diagnostics ${LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION}.`
      : payload.error ||
        (stale
          ? "Printer attestation stale"
          : !latestAttestation
            ? "No printer attestation yet"
            : !latestAttestation.signatureValid
              ? "Invalid printer heartbeat signature"
              : !latestAttestation.trustValid
                ? latestAttestation.rejectionReason || "Printer trust validation failed"
                : trustReason);
  const connectionClass: "TRUSTED" | "COMPATIBILITY" | "BLOCKED" = trusted
    ? "TRUSTED"
    : connected && compatibilityMode
      ? "COMPATIBILITY"
      : "BLOCKED";
  const selectedPrinterId = payload.selectedPrinterId || payload.printerId || null;
  const readiness = buildReadinessFields({
    registrationId: registration.id,
    stale,
    connected,
    eligibleForPrinting,
    trusted,
    compatibilityMode,
    selectedPrinterId,
    printerId: payload.printerId,
  });
  const signedAttestation = {
    required: REQUIRE_SIGNATURE,
    present: Boolean(latestAttestation),
    signatureValid: Boolean(latestAttestation?.signatureValid),
    fresh: Boolean(latestAttestation?.signatureValid && !stale && !connectorUpdateRequired),
    issuedAt: payload.heartbeatIssuedAt,
  };

  return {
    connected,
    trusted,
    compatibilityMode,
    compatibilityReason: compatibilityMode ? compatibilityReason : null,
    eligibleForPrinting,
    connectionClass,
    ...readiness,
    signedAttestation,
    stale,
    requiredForPrinting: true,
    trustStatus: registration.trustStatus,
    trustReason,
    lastHeartbeatAt: latestAttestation?.attestedAt ? latestAttestation.attestedAt.toISOString() : null,
    ageSeconds: ageMs == null ? null : Math.floor(ageMs / 1000),
    registrationId: registration.id,
    agentId: registration.agentId || null,
    deviceFingerprint: registration.deviceFingerprint || null,
    mtlsFingerprint: latestAttestation?.mtlsFingerprint || null,
    printerName: payload.printerName,
    printerId: payload.printerId,
    deviceName: payload.deviceName,
    agentVersion: payload.agentVersion,
    protocolVersion: payload.protocolVersion,
    buildVersion: payload.buildVersion,
    transportDiagnosticsVersion: payload.transportDiagnosticsVersion,
    capabilities: payload.capabilities,
    missingCapabilities,
    connectorUpdateRequired,
    selectedPrinterId,
    selectedPrinterName: payload.selectedPrinterName || payload.printerName || null,
    capabilitySummary: payload.capabilitySummary,
    printers: payload.printers,
    calibrationProfile: payload.calibrationProfile,
    error,
  };
};

const loadLatestRegistrationForUser = async (userId: string): Promise<PrinterRegistrationWithLatest | null> => {
  return prisma.printerRegistration.findFirst({
    where: { userId },
    orderBy: [{ lastSeenAt: "desc" }, { updatedAt: "desc" }],
    include: {
      attestations: {
        orderBy: [{ createdAt: "desc" }],
        take: 1,
      },
    },
  }) as Promise<PrinterRegistrationWithLatest | null>;
};

const notifyConnectionListeners = (event: PrinterConnectionRealtimeEvent) => {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch {
      // ignore listener failures
    }
  }
};

const emitConnectionEvent = (event: PrinterConnectionRealtimeEvent) => {
  notifyConnectionListeners(event);
  void publishRedisJson(PRINTER_CONNECTION_EVENT_CHANNEL, {
    origin: getRedisInstanceId(),
    event,
  }).catch(() => undefined);
};

const statusChanged = (a: PrinterConnectionStatus, b: PrinterConnectionStatus) => {
  return (
    a.connected !== b.connected ||
    a.trusted !== b.trusted ||
    a.compatibilityMode !== b.compatibilityMode ||
    String(a.connectionClass || "") !== String(b.connectionClass || "") ||
    a.stale !== b.stale ||
    String(a.error || "") !== String(b.error || "") ||
    String(a.printerName || "") !== String(b.printerName || "") ||
    String(a.printerId || "") !== String(b.printerId || "") ||
    String(a.deviceName || "") !== String(b.deviceName || "") ||
    String(a.agentVersion || "") !== String(b.agentVersion || "") ||
    String((a as any).protocolVersion || "") !== String((b as any).protocolVersion || "") ||
    String((a as any).buildVersion || "") !== String((b as any).buildVersion || "") ||
    String((a as any).transportDiagnosticsVersion || "") !== String((b as any).transportDiagnosticsVersion || "") ||
    Boolean((a as any).connectorUpdateRequired) !== Boolean((b as any).connectorUpdateRequired) ||
    String(a.selectedPrinterId || "") !== String(b.selectedPrinterId || "") ||
    String(a.selectedPrinterName || "") !== String(b.selectedPrinterName || "")
  );
};

export const onPrinterConnectionEvent = (listener: (event: PrinterConnectionRealtimeEvent) => void) => {
  if (!printerConnectionChannelReady) {
    printerConnectionChannelReady = true;
    void subscribeRedisJson(PRINTER_CONNECTION_EVENT_CHANNEL, (payload) => {
      if (!payload || payload.origin === getRedisInstanceId()) return;
      if (payload.event) notifyConnectionListeners(payload.event as PrinterConnectionRealtimeEvent);
    });
  }
  listeners.add(listener);
  return () => listeners.delete(listener);
};

export const getPrinterConnectionStatusForUser = async (userId: string): Promise<PrinterConnectionStatus> => {
  const registration = await loadLatestRegistrationForUser(userId);
  return buildStatus(registration);
};

export const isPrinterConnectedForUser = async (userId: string): Promise<boolean> => {
  const status = await getPrinterConnectionStatusForUser(userId);
  return status.connected;
};

export const upsertPrinterConnectionHeartbeat = async (input: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  orgId?: string | null;
  connected: boolean;
  printerName?: string | null;
  printerId?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  protocolVersion?: string | null;
  buildVersion?: string | null;
  transportDiagnosticsVersion?: string | null;
  capabilities?: any;
  error?: string | null;
  sourceIp?: string | null;
  userAgent?: string | null;
  agentId?: string | null;
  deviceFingerprint?: string | null;
  publicKeyPem?: string | null;
  clientCertFingerprint?: string | null;
  mtlsFingerprintHeader?: string | null;
  heartbeatNonce?: string | null;
  heartbeatIssuedAt?: string | null;
  heartbeatSignature?: string | null;
  selectedPrinterId?: string | null;
  selectedPrinterName?: string | null;
  capabilitySummary?: any;
  printers?: any[];
  calibrationProfile?: any;
}) => {
  const previousStatus = await getPrinterConnectionStatusForUser(input.userId);

  const now = new Date();
  const rawAgentId = toCleanString(input.agentId, 180);
  const rawDeviceFingerprint = toCleanString(input.deviceFingerprint, 256);
  const fallbackAgentId = `compat-agent-${sha256Hex(`user:${input.userId}`).slice(0, 16)}`;
  const fallbackDeviceFingerprintSeed = [
    input.userId,
    rawAgentId || fallbackAgentId,
    toCleanString(input.printerId, 180),
    toCleanString(input.deviceName, 180),
    toCleanString(input.printerName, 180),
  ].join("|");
  const fallbackDeviceFingerprint = `compat-${sha256Hex(fallbackDeviceFingerprintSeed).slice(0, 48)}`;
  const agentId = rawAgentId || fallbackAgentId;
  const deviceFingerprint = rawDeviceFingerprint || fallbackDeviceFingerprint;
  const publicKeyPem = String(input.publicKeyPem || "").trim();
  const clientCertFingerprint = String(input.clientCertFingerprint || "").trim();
  const mtlsFingerprintHeader = String(input.mtlsFingerprintHeader || "").trim();
  const heartbeatNonce = String(input.heartbeatNonce || "").trim() || randomOpaqueToken(12);
  const heartbeatIssuedAt = String(input.heartbeatIssuedAt || "").trim();
  const heartbeatSignature = String(input.heartbeatSignature || "").trim();
  const incomingPublicKeyPem = looksLikePem(publicKeyPem) ? normalizePem(publicKeyPem) : "";

  const metadata = {
    connected: Boolean(input.connected),
    printerName: String(input.printerName || "").trim() || null,
    printerId: String(input.printerId || "").trim() || null,
    deviceName: String(input.deviceName || "").trim() || null,
    agentVersion: String(input.agentVersion || "").trim() || null,
    protocolVersion: String(input.protocolVersion || "").trim() || null,
    buildVersion: String(input.buildVersion || "").trim() || null,
    transportDiagnosticsVersion: String(input.transportDiagnosticsVersion || "").trim() || null,
    capabilities: input.capabilities && typeof input.capabilities === "object" ? input.capabilities : null,
    error: String(input.error || "").trim() || null,
    heartbeatIssuedAt,
    selectedPrinterId: toCleanString(input.selectedPrinterId, 180) || null,
    selectedPrinterName: toCleanString(input.selectedPrinterName, 180) || null,
    capabilitySummary: normalizeCapabilitySummary(input.capabilitySummary),
    printers: normalizePrinterInventory(input.printers),
    calibrationProfile:
      input.calibrationProfile && typeof input.calibrationProfile === "object"
        ? (input.calibrationProfile as Record<string, any>)
        : null,
  };

  const sourceIpHash = hashIp(input.sourceIp || null);
  const normalizedUa = normalizeUserAgent(input.userAgent || null);
  const userAgentHash = normalizedUa ? hashToken(`ua:${normalizedUa}`) : null;
  const heartbeatIssuedAtMs = heartbeatIssuedAt ? new Date(heartbeatIssuedAt).getTime() : NaN;
  const heartbeatIssuedAtValid = Number.isFinite(heartbeatIssuedAtMs);
  const heartbeatSkewSeconds = heartbeatIssuedAtValid ? Math.abs(Date.now() - heartbeatIssuedAtMs) / 1000 : NaN;
  const signedPayloadCandidates = heartbeatIssuedAt
    ? buildHeartbeatSignedPayloadCandidates({
        userId: input.userId,
        agentId,
        deviceFingerprint,
        printerId: metadata.printerId || "unknown-printer",
        connected: Boolean(input.connected),
        heartbeatNonce,
        heartbeatIssuedAt,
      })
    : [];

  let registration =
    deviceFingerprint
      ? await prisma.printerRegistration.findUnique({
          where: {
            userId_deviceFingerprint: {
              userId: input.userId,
              deviceFingerprint,
            },
          },
        })
      : null;
  const existingUserRegistration = !registration
    ? await prisma.printerRegistration.findFirst({
        where: {
          userId: input.userId,
          revokedAt: null,
        },
        orderBy: [{ lastSeenAt: "desc" }, { updatedAt: "desc" }],
      })
    : null;

  let signatureValid = false;
  let trustValid = false;
  let rejectionReason: string | null = null;
  let verifiedHeartbeatPayload: string | null = null;

  if (!registration && existingUserRegistration) {
    const replacementPublicKeyChanged =
      Boolean(incomingPublicKeyPem) &&
      incomingPublicKeyPem !== normalizePem(String(existingUserRegistration.publicKeyPem || ""));
    const replacementSignedPayload =
      replacementPublicKeyChanged && heartbeatSignature && heartbeatIssuedAtValid && heartbeatSkewSeconds <= MAX_SIGNATURE_SKEW_SECONDS
        ? verifyAgentSignatureAcrossPayloads({
            publicKeyPem: incomingPublicKeyPem,
            signature: heartbeatSignature,
            signedPayloads: signedPayloadCandidates,
          })
        : null;
    if (replacementSignedPayload && deviceFingerprint && agentId) {
      verifiedHeartbeatPayload = replacementSignedPayload;
      registration = await prisma.printerRegistration.create({
        data: {
          userId: input.userId,
          orgId: input.orgId || null,
          licenseeId: input.licenseeId || null,
          deviceFingerprint,
          agentId,
          publicKeyPem: incomingPublicKeyPem,
          certFingerprint: clientCertFingerprint || mtlsFingerprintHeader || null,
          trustStatus: PrinterTrustStatus.PENDING,
          trustReason: "Awaiting first successful cryptographic attestation",
        },
      });
      console.info("printer_agent_heartbeat_registration", {
        event: "replacement_registration_created",
        registrationFound: false,
        previousRegistrationId: existingUserRegistration.id,
        newRegistrationId: registration.id,
        agentIdHash: sha256Hex(agentId).slice(0, 16),
        deviceFingerprintHash: sha256Hex(deviceFingerprint).slice(0, 16),
        publicKeyFingerprint: sha256Hex(incomingPublicKeyPem).slice(0, 16),
        licenseeScopePresent: Boolean(input.licenseeId),
        orgScopePresent: Boolean(input.orgId),
        rejectReason: null,
      });
    } else {
      rejectionReason = "Printer device fingerprint mismatch";
    }
  }

  if (!registration && !existingUserRegistration && deviceFingerprint && agentId) {
    registration = await prisma.printerRegistration.create({
      data: {
        userId: input.userId,
        orgId: input.orgId || null,
        licenseeId: input.licenseeId || null,
        deviceFingerprint,
        agentId,
        publicKeyPem: publicKeyPem || `compat:${agentId}`,
        certFingerprint: clientCertFingerprint || mtlsFingerprintHeader || null,
        trustStatus: PrinterTrustStatus.PENDING,
        trustReason: publicKeyPem
          ? "Awaiting first successful cryptographic attestation"
          : "Compatibility registration pending cryptographic enrollment",
      },
    });
  }

  if (!registration) {
    rejectionReason = "Missing printer registration identity";
  }

  if (registration?.agentId && agentId && registration.agentId !== agentId) {
    rejectionReason = "Printer agent identity mismatch";
  }

  if (
    registration &&
    publicKeyPem &&
    !String(registration.publicKeyPem || "").startsWith("compat:") &&
    incomingPublicKeyPem !== normalizePem(registration.publicKeyPem)
  ) {
    rejectionReason = "Printer public key mismatch";
  }

  let resolvedPublicKeyPem = normalizePem(String(registration?.publicKeyPem || ""));
  const canRotateTrustedKey =
    Boolean(registration) &&
    Boolean(incomingPublicKeyPem) &&
    signedPayloadCandidates.length > 0 &&
    Boolean(heartbeatSignature) &&
    registration?.trustStatus !== PrinterTrustStatus.REVOKED &&
    incomingPublicKeyPem !== normalizePem(String(registration?.publicKeyPem || "")) &&
    heartbeatIssuedAtValid &&
    heartbeatSkewSeconds <= MAX_SIGNATURE_SKEW_SECONDS &&
    Boolean(
      (verifiedHeartbeatPayload = verifyAgentSignatureAcrossPayloads({
        publicKeyPem: incomingPublicKeyPem,
        signature: heartbeatSignature,
        signedPayloads: signedPayloadCandidates,
      }))
    );

  if (canRotateTrustedKey) {
    resolvedPublicKeyPem = incomingPublicKeyPem;
    rejectionReason = null;
  } else if (
    registration &&
    publicKeyPem &&
    !String(registration.publicKeyPem || "").startsWith("compat:") &&
    incomingPublicKeyPem &&
    incomingPublicKeyPem !== normalizePem(registration.publicKeyPem)
  ) {
    rejectionReason = "Printer public key mismatch";
  } else if (!resolvedPublicKeyPem && incomingPublicKeyPem) {
    resolvedPublicKeyPem = incomingPublicKeyPem;
  }

  if (!input.connected) {
    trustValid = false;
  } else {
    const requiresIdentity = REQUIRE_SIGNATURE;
    if (requiresIdentity && (!registration || signedPayloadCandidates.length === 0 || !heartbeatSignature)) {
      rejectionReason = rejectionReason || "Missing signature identity fields";
    }

    if (requiresIdentity && registration && signedPayloadCandidates.length > 0 && heartbeatSignature) {
      if (!looksLikePem(resolvedPublicKeyPem)) {
        rejectionReason = rejectionReason || "Printer public key is not enrolled";
      }
      if (!heartbeatIssuedAtValid) {
        rejectionReason = "Invalid heartbeatIssuedAt";
      } else {
        if (heartbeatSkewSeconds > MAX_SIGNATURE_SKEW_SECONDS) {
          rejectionReason = `Heartbeat signature timestamp skew exceeded (${Math.round(heartbeatSkewSeconds)}s)`;
        }
      }

      if (!rejectionReason) {
        const matchingPayload =
          verifiedHeartbeatPayload ||
          verifyAgentSignatureAcrossPayloads({
            publicKeyPem: resolvedPublicKeyPem,
            signature: heartbeatSignature,
            signedPayloads: signedPayloadCandidates,
          });
        verifiedHeartbeatPayload = matchingPayload;
        signatureValid = Boolean(matchingPayload);
        if (!signatureValid) {
          rejectionReason = "Heartbeat signature verification failed";
        }
      }
    } else if (!requiresIdentity) {
      signatureValid = true;
    }

    let mtlsValid = true;
    if (REQUIRE_MTLS) {
      if (!mtlsFingerprintHeader) {
        mtlsValid = false;
        rejectionReason = rejectionReason || "mTLS client certificate fingerprint header missing";
      } else if (clientCertFingerprint && mtlsFingerprintHeader !== clientCertFingerprint) {
        mtlsValid = false;
        rejectionReason = rejectionReason || "mTLS certificate fingerprint mismatch";
      } else if (registration?.certFingerprint && mtlsFingerprintHeader !== registration.certFingerprint) {
        mtlsValid = false;
        rejectionReason = rejectionReason || "mTLS fingerprint is not approved for this printer";
      }
    }

    trustValid = Boolean(signatureValid && mtlsValid && registration && registration.trustStatus !== PrinterTrustStatus.REVOKED);
  }

  if (registration) {
    let nextTrustStatus = registration.trustStatus;
    if (trustValid) {
      nextTrustStatus = PrinterTrustStatus.TRUSTED;
    } else if (input.connected && registration.trustStatus !== PrinterTrustStatus.REVOKED) {
      nextTrustStatus = PrinterTrustStatus.FAILED;
    }

    registration = await prisma.printerRegistration.update({
      where: { id: registration.id },
      data: {
        orgId: input.orgId || registration.orgId,
        licenseeId: input.licenseeId || registration.licenseeId,
        agentId: agentId || registration.agentId,
        publicKeyPem:
          looksLikePem(resolvedPublicKeyPem) &&
          (
            String(registration.publicKeyPem || "").startsWith("compat:") ||
            !registration.publicKeyPem ||
            normalizePem(String(registration.publicKeyPem || "")) !== resolvedPublicKeyPem
          )
            ? resolvedPublicKeyPem
            : registration.publicKeyPem,
        certFingerprint: registration.certFingerprint || clientCertFingerprint || mtlsFingerprintHeader || null,
        trustStatus: nextTrustStatus,
        trustReason: trustValid ? null : rejectionReason,
        approvedAt: trustValid ? registration.approvedAt || now : registration.approvedAt,
        lastSeenAt: now,
      },
    });

    if (trustValid && existingUserRegistration && existingUserRegistration.id !== registration.id) {
      await prisma.printerRegistration.updateMany({
        where: {
          userId: input.userId,
          revokedAt: null,
          id: { not: registration.id },
        },
        data: {
          trustStatus: PrinterTrustStatus.REVOKED,
          trustReason: "Replaced by a newer signed connector registration",
          revokedAt: now,
        },
      });
    }

    console.info("printer_agent_heartbeat_registration", {
      event: "heartbeat_attested",
      registrationFound: true,
      registrationId: registration.id,
      agentIdHash: sha256Hex(agentId || registration.agentId).slice(0, 16),
      deviceFingerprintHash: sha256Hex(deviceFingerprint || registration.deviceFingerprint).slice(0, 16),
      publicKeyFingerprint: looksLikePem(resolvedPublicKeyPem) ? sha256Hex(resolvedPublicKeyPem).slice(0, 16) : null,
      licenseeScopePresent: Boolean(input.licenseeId || registration.licenseeId),
      orgScopePresent: Boolean(input.orgId || registration.orgId),
      heartbeatAgeSeconds: heartbeatIssuedAtValid ? Math.round(heartbeatSkewSeconds) : null,
      trusted: trustValid,
      trustStatus: registration.trustStatus,
      selectedPrinterIdPresent: Boolean(metadata.selectedPrinterId || metadata.printerId),
      heartbeatSignatureVerified: signatureValid,
      rejectReason: rejectionReason,
      replacementRegistration: Boolean(existingUserRegistration && existingUserRegistration.id !== registration.id),
    });

    const hashSource = verifiedHeartbeatPayload || signedPayloadCandidates[0] || stableStringify(metadata);
    await prisma.printerAttestation.create({
      data: {
        printerRegistrationId: registration.id,
        signedPayloadHash: sha256Hex(hashSource),
        heartbeatNonce,
        attestedAt: now,
        expiresAt: new Date(now.getTime() + HEARTBEAT_TTL_MS),
        sourceIpHash,
        userAgentHash,
        mtlsFingerprint: mtlsFingerprintHeader || clientCertFingerprint || null,
        signatureValid,
        trustValid: Boolean(trustValid && input.connected),
        rejectionReason,
        metadata: metadata as unknown as Prisma.InputJsonValue,
      },
    });
  }

  const nextStatus = await getPrinterConnectionStatusForUser(input.userId);
  const changed = statusChanged(previousStatus, nextStatus);

  if (changed) {
    void bumpCacheNamespaceVersion("printer-status").catch(() => undefined);
    emitConnectionEvent({
      userId: input.userId,
      status: nextStatus,
      changedAt: new Date().toISOString(),
    });
  }

  return {
    changed,
    previousConnected: previousStatus.connected,
    status: nextStatus,
  };
};

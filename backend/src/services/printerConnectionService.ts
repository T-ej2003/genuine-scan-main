import { createHash, createPublicKey, verify as cryptoVerify } from "crypto";
import { Prisma, PrinterTrustStatus, UserRole } from "@prisma/client";
import type {
  LocalPrinterDTO as PrinterInventoryDevice,
  PrinterCapabilitySummaryDTO as PrinterCapabilitySummary,
  PrinterConnectionStatusDTO as PrinterConnectionStatus,
} from "../../../shared/contracts/printing.d.ts";

import prisma from "../config/database";
import { hashIp, hashToken, normalizeUserAgent, randomOpaqueToken } from "../utils/security";

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
const REQUIRE_MTLS = parseBoolEnv("PRINT_AGENT_REQUIRE_MTLS", true);
const ALLOW_COMPATIBILITY_MODE = parseBoolEnv("PRINT_AGENT_ALLOW_COMPATIBILITY_MODE", true);

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
    });
    if (rows.length >= 40) break;
  }
  return rows;
};

const normalizeStatusPayload = (metadata: any) => {
  const source = metadata && typeof metadata === "object" ? metadata : {};
  return {
    connected: Boolean(source.connected),
    printerName: toCleanString(source.printerName, 180) || null,
    printerId: toCleanString(source.printerId, 180) || null,
    deviceName: toCleanString(source.deviceName, 180) || null,
    agentVersion: toCleanString(source.agentVersion, 80) || null,
    error: toCleanString(source.error, 500) || null,
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
    return {
      connected: false,
      trusted: false,
      compatibilityMode: false,
      compatibilityReason: null,
      eligibleForPrinting: false,
      connectionClass: "BLOCKED",
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
  const nowMs = Date.now();
  const attestedMs = latestAttestation?.attestedAt ? new Date(latestAttestation.attestedAt).getTime() : NaN;
  const ageMs = Number.isFinite(attestedMs) ? Math.max(0, nowMs - attestedMs) : null;
  const stale = ageMs == null ? true : ageMs > HEARTBEAT_TTL_MS;

  const trustedRegistration = registration.trustStatus === PrinterTrustStatus.TRUSTED && !registration.revokedAt;
  const trustedAttestation = Boolean(latestAttestation?.trustValid && latestAttestation?.signatureValid);
  const trusted = trustedRegistration && trustedAttestation && !stale;
  const compatibilityReason =
    latestAttestation?.rejectionReason || registration.trustReason || payload.error || "Compatibility mode fallback";
  const compatibilityMode = Boolean(
    ALLOW_COMPATIBILITY_MODE &&
      payload.connected &&
      !trusted &&
      !stale &&
      registration.trustStatus !== PrinterTrustStatus.REVOKED
  );
  const connected = payload.connected && (trusted || compatibilityMode);
  const eligibleForPrinting = connected;

  const trustReason = trusted
    ? null
    : registration.revokedAt
      ? "Printer registration revoked"
      : latestAttestation?.rejectionReason || registration.trustReason || null;

  const error = trusted
    ? null
    : connected && compatibilityMode
      ? `Compatibility mode active: ${compatibilityReason}`
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

  return {
    connected,
    trusted,
    compatibilityMode,
    compatibilityReason: compatibilityMode ? compatibilityReason : null,
    eligibleForPrinting,
    connectionClass,
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
    selectedPrinterId: payload.selectedPrinterId || payload.printerId || null,
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

const emitConnectionEvent = (event: PrinterConnectionRealtimeEvent) => {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch {
      // ignore listener failures
    }
  }
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
    String(a.selectedPrinterId || "") !== String(b.selectedPrinterId || "") ||
    String(a.selectedPrinterName || "") !== String(b.selectedPrinterName || "")
  );
};

export const onPrinterConnectionEvent = (listener: (event: PrinterConnectionRealtimeEvent) => void) => {
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

  const metadata = {
    connected: Boolean(input.connected),
    printerName: String(input.printerName || "").trim() || null,
    printerId: String(input.printerId || "").trim() || null,
    deviceName: String(input.deviceName || "").trim() || null,
    agentVersion: String(input.agentVersion || "").trim() || null,
    error: String(input.error || "").trim() || null,
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

  let signatureValid = false;
  let trustValid = false;
  let rejectionReason: string | null = null;

  if (!registration && deviceFingerprint && agentId) {
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

  if (
    registration &&
    publicKeyPem &&
    !String(registration.publicKeyPem || "").startsWith("compat:") &&
    normalizePem(publicKeyPem) !== normalizePem(registration.publicKeyPem)
  ) {
    rejectionReason = "Printer public key mismatch";
  }

  const signedPayload =
    registration && heartbeatIssuedAt
      ? buildHeartbeatSignedPayload({
          userId: input.userId,
          agentId: agentId || registration.agentId,
          deviceFingerprint: deviceFingerprint || registration.deviceFingerprint,
          printerId: metadata.printerId || "unknown-printer",
          connected: Boolean(input.connected),
          heartbeatNonce,
          heartbeatIssuedAt,
        })
      : null;

  if (!input.connected) {
    trustValid = false;
  } else {
    const requiresIdentity = REQUIRE_SIGNATURE;
    if (requiresIdentity && (!registration || !signedPayload || !heartbeatSignature)) {
      rejectionReason = rejectionReason || "Missing signature identity fields";
    }

    if (requiresIdentity && registration && signedPayload && heartbeatSignature) {
      if (!looksLikePem(registration.publicKeyPem)) {
        rejectionReason = rejectionReason || "Printer public key is not enrolled";
      }
      const issuedAtMs = new Date(heartbeatIssuedAt).getTime();
      if (!Number.isFinite(issuedAtMs)) {
        rejectionReason = "Invalid heartbeatIssuedAt";
      } else {
        const skewSeconds = Math.abs(Date.now() - issuedAtMs) / 1000;
        if (skewSeconds > MAX_SIGNATURE_SKEW_SECONDS) {
          rejectionReason = `Heartbeat signature timestamp skew exceeded (${Math.round(skewSeconds)}s)`;
        }
      }

      if (!rejectionReason) {
        signatureValid = verifyAgentSignature({
          publicKeyPem: registration.publicKeyPem,
          signature: heartbeatSignature,
          signedPayload,
        });
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
          publicKeyPem && (String(registration.publicKeyPem || "").startsWith("compat:") || !registration.publicKeyPem)
            ? publicKeyPem
            : registration.publicKeyPem,
        certFingerprint: registration.certFingerprint || clientCertFingerprint || mtlsFingerprintHeader || null,
        trustStatus: nextTrustStatus,
        trustReason: trustValid ? null : rejectionReason,
        approvedAt: trustValid ? registration.approvedAt || now : registration.approvedAt,
        lastSeenAt: now,
      },
    });

    const hashSource = signedPayload || stableStringify(metadata);
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

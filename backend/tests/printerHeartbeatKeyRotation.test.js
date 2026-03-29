const assert = require("assert");
const path = require("path");
const { generateKeyPairSync } = require("crypto");
const { PrinterTrustStatus, UserRole } = require("@prisma/client");

process.env.PRINT_AGENT_REQUIRE_SIGNATURE = "true";
process.env.PRINT_AGENT_REQUIRE_MTLS = "false";
process.env.PRINT_AGENT_ALLOW_COMPATIBILITY_MODE = "true";

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

const oldKeyPair = generateKeyPairSync("ed25519");
const newKeyPair = generateKeyPairSync("ed25519");
const now = new Date();

let latestAttestation = {
  id: "attestation-1",
  attestedAt: now,
  expiresAt: new Date(now.getTime() + 30 * 60_000),
  signatureValid: true,
  trustValid: true,
  rejectionReason: null,
  mtlsFingerprint: null,
  metadata: {
    connected: true,
    printerName: "Zebra ZD421",
    printerId: "zebra-zd421",
    deviceName: "Factory Mac",
    agentVersion: "1.0.0",
    selectedPrinterId: "zebra-zd421",
    selectedPrinterName: "Zebra ZD421",
    printers: [],
  },
  createdAt: new Date("2026-03-29T06:55:00.000Z"),
};

let registration = {
  id: "registration-1",
  userId: "manufacturer-1",
  orgId: "org-1",
  licenseeId: "licensee-1",
  deviceFingerprint: "device-rotating-key",
  agentId: "agent-rotating-key",
  publicKeyPem: oldKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
  certFingerprint: null,
  trustStatus: PrinterTrustStatus.FAILED,
  trustReason: "Printer public key mismatch",
  approvedAt: null,
  revokedAt: null,
  lastSeenAt: now,
  updatedAt: now,
};

const buildStatusRegistration = () => ({
  ...registration,
  attestations: [latestAttestation],
});

mockModule("config/database.js", {
  __esModule: true,
  default: {
    printerRegistration: {
      findFirst: async ({ where }) => {
        if (where?.userId) return buildStatusRegistration();
        return null;
      },
      findUnique: async () => registration,
      create: async ({ data }) => {
        registration = {
          id: "registration-created",
          userId: data.userId,
          orgId: data.orgId,
          licenseeId: data.licenseeId,
          deviceFingerprint: data.deviceFingerprint,
          agentId: data.agentId,
          publicKeyPem: data.publicKeyPem,
          certFingerprint: data.certFingerprint,
          trustStatus: data.trustStatus,
          trustReason: data.trustReason,
          approvedAt: null,
          revokedAt: null,
          lastSeenAt: null,
          updatedAt: new Date(),
        };
        return registration;
      },
      update: async ({ data }) => {
        registration = {
          ...registration,
          ...data,
          updatedAt: new Date(),
        };
        return registration;
      },
    },
    printerAttestation: {
      create: async ({ data }) => {
        latestAttestation = {
          id: "attestation-2",
          attestedAt: data.attestedAt,
          expiresAt: data.expiresAt,
          signatureValid: data.signatureValid,
          trustValid: data.trustValid,
          rejectionReason: data.rejectionReason,
          mtlsFingerprint: data.mtlsFingerprint,
          metadata: data.metadata,
          createdAt: data.attestedAt,
        };
        return latestAttestation;
      },
    },
  },
});

const { buildPrinterAgentHeartbeatPayload, signPrinterAgentPayload } = require("../dist/services/printerAgentSigningService");
const { upsertPrinterConnectionHeartbeat } = require("../dist/services/printerConnectionService");

(async () => {
  const heartbeatIssuedAt = new Date().toISOString();
  const heartbeatPayload = buildPrinterAgentHeartbeatPayload({
    userId: "manufacturer-browser-heartbeat",
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    printerId: "zebra-zd421",
    connected: true,
    heartbeatNonce: "rotation-nonce-1",
    heartbeatIssuedAt,
  });
  const rotatedPublicKeyPem = newKeyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
  const heartbeatSignature = signPrinterAgentPayload(
    newKeyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    heartbeatPayload
  );

  const result = await upsertPrinterConnectionHeartbeat({
    userId: "manufacturer-1",
    role: UserRole.MANUFACTURER,
    licenseeId: "licensee-1",
    orgId: "org-1",
    connected: true,
    printerName: "Zebra ZD421",
    printerId: "zebra-zd421",
    selectedPrinterId: "zebra-zd421",
    selectedPrinterName: "Zebra ZD421",
    deviceName: "Factory Mac",
    agentVersion: "2.0.0",
    sourceIp: "198.51.100.10",
    userAgent: "Mozilla/5.0",
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    publicKeyPem: rotatedPublicKeyPem,
    heartbeatNonce: "rotation-nonce-1",
    heartbeatIssuedAt,
    heartbeatSignature,
    printers: [],
  });

  assert.strictEqual(
    registration.publicKeyPem.trim(),
    rotatedPublicKeyPem.trim(),
    "heartbeat should promote the rotated local-agent key after a valid signed attestation"
  );
  assert.strictEqual(result.status.trusted, true, "rotated local-agent key should restore a trusted connection");
  assert.strictEqual(result.status.connectionClass, "TRUSTED", "restored heartbeat should exit compatibility mode");
  assert.strictEqual(result.status.compatibilityMode, false, "trusted key rotation should not remain in compatibility mode");

  console.log("printer heartbeat key rotation tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

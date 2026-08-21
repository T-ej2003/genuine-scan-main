const assert = require("assert");
const path = require("path");
const { generateKeyPairSync } = require("crypto");
const { PrinterTrustStatus, UserRole } = require("@prisma/client");
const { closeRedisConnections } = require("../dist/services/redisService");

process.env.PRINT_AGENT_REQUIRE_SIGNATURE = "true";
process.env.PRINT_AGENT_REQUIRE_MTLS = "false";
process.env.PRINT_AGENT_ALLOW_COMPATIBILITY_MODE = "true";
process.env.PRINT_AGENT_MTLS_TRUSTED_PROXY_IPS = "";
process.env.PRINT_AGENT_SESSION_MODE = "rest";

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

const keyPair = generateKeyPairSync("ed25519");
const publicKeyPem = keyPair.publicKey.export({ type: "spki", format: "pem" }).toString();
const privateKeyPem = keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const now = new Date();

let registration;
let latestAttestation;

const resetState = () => {
  registration = {
    id: "registration-launch-1",
    userId: "manufacturer-1",
    orgId: "org-1",
    licenseeId: "licensee-1",
    deviceFingerprint: "device-launch",
    agentId: "agent-launch",
    publicKeyPem,
    certFingerprint: null,
    trustStatus: PrinterTrustStatus.PENDING,
    trustReason: "Awaiting first successful cryptographic attestation",
    approvedAt: null,
    revokedAt: null,
    lastSeenAt: now,
    updatedAt: now,
  };
  latestAttestation = null;
};

const registrationWithAttestation = () => ({
  ...registration,
  attestations: latestAttestation ? [latestAttestation] : [],
});

mockModule("config/database.js", {
  __esModule: true,
  default: {
    printerRegistration: {
      findFirst: async ({ where }) => {
        if (where?.userId === registration.userId) return registrationWithAttestation();
        return null;
      },
      findUnique: async ({ where }) => {
        const identity = where?.userId_deviceFingerprint;
        if (
          identity?.userId === registration.userId &&
          identity?.deviceFingerprint === registration.deviceFingerprint
        ) {
          return registration;
        }
        return null;
      },
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
          id: "attestation-launch",
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
const {
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} = require("../dist/services/localAgentProtocol");
const { getPrinterConnectionStatusForUser, upsertPrinterConnectionHeartbeat } = require("../dist/services/printerConnectionService");

const signedHeartbeatInput = (overrides = {}) => {
  const heartbeatIssuedAt = overrides.heartbeatIssuedAt || new Date().toISOString();
  const heartbeatNonce = overrides.heartbeatNonce || "launch-nonce-1";
  const agentId = overrides.agentId || registration.agentId;
  const deviceFingerprint = overrides.deviceFingerprint || registration.deviceFingerprint;
  const printerId = overrides.printerId || "zebra-zd421";
  const connected = overrides.connected ?? true;
  const payload = buildPrinterAgentHeartbeatPayload({
    userId: "manufacturer-browser-heartbeat",
    agentId,
    deviceFingerprint,
    printerId,
    connected,
    heartbeatNonce,
    heartbeatIssuedAt,
  });
  return {
    userId: registration.userId,
    role: UserRole.MANUFACTURER,
    licenseeId: registration.licenseeId,
    orgId: registration.orgId,
    connected,
    printerName: "Zebra ZD421",
    printerId,
    selectedPrinterId: printerId,
    selectedPrinterName: "Zebra ZD421",
    deviceName: "Factory Mac",
    agentVersion: overrides.agentVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: overrides.buildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: LOCAL_AGENT_CAPABILITIES,
    sourceIp: "198.51.100.10",
    userAgent: "MSCQR Connector 2026.6.16",
    agentId,
    deviceFingerprint,
    publicKeyPem,
    heartbeatNonce,
    heartbeatIssuedAt,
    heartbeatSignature: overrides.omitSignature ? null : signPrinterAgentPayload(privateKeyPem, payload),
    printers: [],
  };
};

(async () => {
  resetState();
  const valid = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput());
  assert.strictEqual(valid.status.trustMode, "SIGNED_ATTESTATION", "launch mode should be signed attestation");
  assert.strictEqual(valid.status.trusted, false, "signed heartbeat alone must not satisfy production print trust");
  assert.strictEqual(valid.status.eligibleForPrinting, false, "production print eligibility requires a connected persistent session");
  assert.strictEqual(valid.status.persistentSessionDisconnected, true, "valid connector should still wait for persistent session");
  assert.strictEqual(valid.status.securePrinterSession, false, "secure print session requires the WebSocket session gate");
  assert.strictEqual(valid.status.signedAttestation.signatureValid, true, "signature must validate");
  assert.strictEqual(valid.status.signedAttestation.fresh, true, "heartbeat must be fresh");
  assert(
    valid.status.missingFields.includes("helperConnection") || valid.status.missingFields.includes("securePrinterSession"),
    "fresh signed heartbeat should still report the missing persistent-session readiness field"
  );

  resetState();
  const oldConnector = await upsertPrinterConnectionHeartbeat(
    signedHeartbeatInput({ agentVersion: "2026.6.16", buildVersion: "2026.6.16" })
  );
  assert.strictEqual(oldConnector.status.trusted, false, "old connector must not be production print trusted");
  assert.strictEqual(oldConnector.status.eligibleForPrinting, false, "old connector must not be print-eligible");
  assert.strictEqual(oldConnector.status.persistentSessionUpdateRequired, true, "old connector should report update-required");
  assert.match(
    oldConnector.status.error || "",
    /persistent print session mode/i,
    "old connector should show persistent session update guidance"
  );

  resetState();
  const missingSignature = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput({ omitSignature: true }));
  assert.strictEqual(missingSignature.status.trusted, false, "missing signature must not be trusted");
  assert.strictEqual(missingSignature.status.eligibleForPrinting, false, "missing signature must not be print-eligible");
  assert(missingSignature.status.missingFields.includes("securePrinterSession"), "missing signature should report secure session missing");

  resetState();
  const staleIssuedAt = new Date(Date.now() - 10 * 60_000).toISOString();
  const stale = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput({ heartbeatIssuedAt: staleIssuedAt }));
  assert.strictEqual(stale.status.trusted, false, "stale heartbeat timestamp must not be trusted");
  assert.match(
    stale.status.signedAttestation.rejectReason || "",
    /timestamp skew/i,
    "stale heartbeat should explain timestamp skew in attestation details"
  );

  resetState();
  const wrongAgent = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput({ agentId: "agent-attacker" }));
  assert.strictEqual(wrongAgent.status.trusted, false, "wrong agent id must not be trusted");
  assert.match(
    wrongAgent.status.signedAttestation.rejectReason || "",
    /agent identity mismatch/i,
    "wrong agent should be diagnosed in attestation details"
  );

  resetState();
  const wrongDevice = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput({ deviceFingerprint: "device-attacker" }));
  const wrongDeviceStatus = await getPrinterConnectionStatusForUser(registration.userId);
  assert.strictEqual(wrongDevice.status.trusted, false, "wrong device fingerprint must not be trusted");
  assert.strictEqual(wrongDeviceStatus.eligibleForPrinting, false, "wrong device must not create a print-eligible registration");

  console.log("printer launch trust contract tests passed");
})().finally(closeRedisConnections).catch((error) => {
  console.error(error);
  process.exit(1);
});

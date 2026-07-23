const assert = require("node:assert/strict");
const path = require("node:path");
const { generateKeyPairSync } = require("node:crypto");
const { PrinterTrustStatus, UserRole } = require("@prisma/client");

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

const makeKeyPair = () => {
  const keyPair = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: keyPair.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
};

const oldKeys = makeKeyPair();
const newKeys = makeKeyPair();
const manufacturerId = "manufacturer-claim-1";
const licenseeId = "licensee-claim-1";
const orgId = "org-claim-1";
let registrations = [];
let attestations = [];
let idCounter = 1;

const cloneWithAttestations = (registration) => ({
  ...registration,
  attestations: attestations
    .filter((entry) => entry.printerRegistrationId === registration.id)
    .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
    .slice(0, 1),
});

const latestRegistrationForUser = (userId) =>
  registrations
    .filter((entry) => entry.userId === userId)
    .sort((a, b) => {
      const aSeen = a.lastSeenAt ? a.lastSeenAt.getTime() : 0;
      const bSeen = b.lastSeenAt ? b.lastSeenAt.getTime() : 0;
      if (aSeen !== bSeen) return bSeen - aSeen;
      return b.updatedAt.getTime() - a.updatedAt.getTime();
    })[0] || null;

const resetState = () => {
  idCounter = 1;
  attestations = [];
  registrations = [
    {
      id: "registration-old",
      userId: manufacturerId,
      orgId,
      licenseeId,
      deviceFingerprint: "device-old",
      agentId: "agent-old",
      publicKeyPem: oldKeys.publicKeyPem,
      certFingerprint: null,
      trustStatus: PrinterTrustStatus.TRUSTED,
      trustReason: null,
      approvedAt: new Date(Date.now() - 60_000),
      revokedAt: null,
      lastSeenAt: new Date(Date.now() - 60_000),
      updatedAt: new Date(Date.now() - 60_000),
    },
  ];
};

mockModule("config/database.js", {
  __esModule: true,
  default: {
    printerRegistration: {
      findUnique: async ({ where }) => {
        const identity = where?.userId_deviceFingerprint;
        return registrations.find((entry) => entry.userId === identity?.userId && entry.deviceFingerprint === identity?.deviceFingerprint) || null;
      },
      findFirst: async ({ where }) => {
        if (where?.id) {
          const row = registrations.find(
            (entry) => entry.id === where.id && (where.revokedAt === undefined || entry.revokedAt === where.revokedAt)
          );
          return row ? cloneWithAttestations(row) : null;
        }
        if (where?.agentId && where?.deviceFingerprint) {
          return (
            registrations.find(
              (entry) =>
                entry.agentId === where.agentId &&
                entry.deviceFingerprint === where.deviceFingerprint &&
                (where.revokedAt === undefined || entry.revokedAt === where.revokedAt)
            ) || null
          );
        }
        if (where?.userId) {
          const latest = latestRegistrationForUser(where.userId);
          if (!latest) return null;
          if (where.revokedAt === null && latest.revokedAt !== null) {
            return registrations.find((entry) => entry.userId === where.userId && entry.revokedAt === null) || null;
          }
          return cloneWithAttestations(latest);
        }
        return null;
      },
      create: async ({ data }) => {
        const row = {
          id: `registration-new-${idCounter++}`,
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
        registrations.push(row);
        return row;
      },
      update: async ({ where, data }) => {
        const index = registrations.findIndex((entry) => entry.id === where.id);
        assert(index >= 0, "registration update target should exist");
        registrations[index] = {
          ...registrations[index],
          ...data,
          updatedAt: new Date(),
        };
        return registrations[index];
      },
      updateMany: async ({ where, data }) => {
        let count = 0;
        registrations = registrations.map((entry) => {
          if (entry.userId !== where.userId) return entry;
          if (where.revokedAt === null && entry.revokedAt !== null) return entry;
          if (where.id?.not && entry.id === where.id.not) return entry;
          count += 1;
          return { ...entry, ...data, updatedAt: new Date() };
        });
        return { count };
      },
    },
    printerAttestation: {
      create: async ({ data }) => {
        const row = {
          id: `attestation-${attestations.length + 1}`,
          printerRegistrationId: data.printerRegistrationId,
          attestedAt: data.attestedAt,
          expiresAt: data.expiresAt,
          signatureValid: data.signatureValid,
          trustValid: data.trustValid,
          rejectionReason: data.rejectionReason,
          mtlsFingerprint: data.mtlsFingerprint,
          metadata: data.metadata,
          createdAt: data.attestedAt,
        };
        attestations.push(row);
        return row;
      },
    },
    printer: {
      findFirst: async () => null,
    },
  },
});
mockModule("rls-waves/session-c/c02/printingLifecycleRepository.js", {
  resolvePrintingConnectorIdentity: async ({ agentId, deviceFingerprint, printerSelector }) => {
    const registration = registrations.find(
      (entry) =>
        entry.agentId === agentId &&
        entry.deviceFingerprint === deviceFingerprint &&
        entry.revokedAt === null &&
        entry.trustStatus === PrinterTrustStatus.TRUSTED
    );
    if (!registration) throw new Error("CONNECTOR_BOUNDARY_DENIED");
    return {
      registration,
      printer: { id: "printer-db-1", nativePrinterId: printerSelector, isActive: true },
      eligibleForPrinting: false,
    };
  },
  recordConnectorEvent: async () => ({ available: false }),
});

const {
  buildPrinterAgentActionPayload,
  buildPrinterAgentHeartbeatPayload,
  signPrinterAgentPayload,
} = require("../dist/services/printerAgentSigningService");
const {
  LOCAL_AGENT_CAPABILITIES,
  LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
  LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION,
  LOCAL_AGENT_MIN_VERSION_HINT,
  LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
} = require("../dist/services/localAgentProtocol");
const { upsertPrinterConnectionHeartbeat } = require("../dist/services/printerConnectionService");
const { verifyLocalAgentRequest } = require("../dist/services/localAgentRequestAuthService");
const { claimLocalAgentPrintJob } = require("../dist/controllers/printerAgentJobController");

const signedHeartbeatInput = (overrides = {}) => {
  const agentId = overrides.agentId || "agent-951f9252-f7e6-4cec-8c06-ce871f75f0c6";
  const deviceFingerprint = overrides.deviceFingerprint || "device-b6bbcae-live";
  const printerId = overrides.printerId || "ZDesigner-ZT410-300dpi-ZPL";
  const connected = overrides.connected ?? true;
  const heartbeatNonce = overrides.heartbeatNonce || `heartbeat-${Date.now()}`;
  const heartbeatIssuedAt = overrides.heartbeatIssuedAt || new Date().toISOString();
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
    userId: manufacturerId,
    role: UserRole.MANUFACTURER,
    licenseeId,
    orgId,
    connected,
    printerName: "ZDesigner ZT410-300dpi ZPL",
    printerId,
    selectedPrinterId: printerId,
    selectedPrinterName: "ZDesigner ZT410-300dpi ZPL",
    deviceName: "Factory Windows",
    agentVersion: LOCAL_AGENT_MIN_VERSION_HINT,
    protocolVersion: LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: LOCAL_AGENT_CAPABILITIES,
    agentId,
    deviceFingerprint,
    publicKeyPem: newKeys.publicKeyPem,
    heartbeatNonce,
    heartbeatIssuedAt,
    heartbeatSignature: signPrinterAgentPayload(overrides.privateKeyPem || newKeys.privateKeyPem, payload),
    printers: [{ printerId, printerName: "ZDesigner ZT410-300dpi ZPL", online: true, usbAvailable: true }],
  };
};

const signedClaim = (overrides = {}) => {
  const issuedAt = overrides.issuedAt || new Date().toISOString();
  const body = {
    agentId: overrides.agentId || "agent-951f9252-f7e6-4cec-8c06-ce871f75f0c6",
    deviceFingerprint: overrides.deviceFingerprint || "device-b6bbcae-live",
    printerId: overrides.printerId || "ZDesigner-ZT410-300dpi-ZPL",
    nonce: overrides.nonce || `claim-${Date.now()}`,
    issuedAt,
  };
  const payload = buildPrinterAgentActionPayload({
    action: "claim",
    ...body,
  });
  return {
    ...body,
    protocolVersion: overrides.protocolVersion || LOCAL_AGENT_DIRECT_PROTOCOL_VERSION,
    buildVersion: overrides.buildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    transportDiagnosticsVersion: overrides.transportDiagnosticsVersion || LOCAL_AGENT_TRANSPORT_DIAGNOSTICS_VERSION,
    capabilities: overrides.capabilities || LOCAL_AGENT_CAPABILITIES,
    agentVersion: overrides.agentVersion || overrides.buildVersion || LOCAL_AGENT_MIN_VERSION_HINT,
    signature: overrides.signature || signPrinterAgentPayload(overrides.privateKeyPem || newKeys.privateKeyPem, payload),
  };
};

const invokeClaim = async (body) => {
  const res = {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
  await claimLocalAgentPrintJob({ body }, res);
  return res;
};

(async () => {
  resetState();
  const heartbeat = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput());
  assert.strictEqual(heartbeat.status.trusted, false, "fresh signed replacement heartbeat alone should not be production trusted");
  assert.strictEqual(heartbeat.status.eligibleForPrinting, false, "fresh signed replacement heartbeat alone should not be print eligible");
  assert.strictEqual(heartbeat.status.persistentSessionDisconnected, true, "production printing should require a connected persistent session");
  assert.strictEqual(heartbeat.status.registrationId.startsWith("registration-new-"), true, "replacement heartbeat should create a new registration");
  assert.strictEqual(registrations.find((entry) => entry.id === "registration-old").trustStatus, PrinterTrustStatus.REVOKED, "older registration should be revoked only after replacement trust succeeds");
  registrations = registrations.map((entry) =>
    entry.id === "registration-old" ? { ...entry, updatedAt: new Date(Date.now() + 60_000) } : entry
  );
  await assert.rejects(
    () => verifyLocalAgentRequest(signedClaim(), "claim"),
    (error) => error.statusCode === 409 && error.errorCode === "PRINTER_ATTESTATION_STALE",
    "REST local-agent claim must not be trusted without a connected persistent session"
  );

  const oldClaimResponse = await invokeClaim(
    signedClaim({
      agentVersion: LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION,
      buildVersion: LOCAL_AGENT_REST_FALLBACK_MIN_BUILD_VERSION,
    })
  );
  assert.strictEqual(oldClaimResponse.statusCode, 426, "old REST connector claim should require update");
  assert.strictEqual(oldClaimResponse.body.errorCode, "CONNECTOR_UPDATE_REQUIRED", "old REST connector claim should return update-required code");

  const newRestClaimResponse = await invokeClaim(signedClaim());
  assert.strictEqual(newRestClaimResponse.statusCode, 409, "new connector must use WebSocket session instead of REST claim");
  assert.strictEqual(newRestClaimResponse.body.errorCode, "PRINTER_SESSION_REQUIRED", "REST claim path should require persistent printer session");

  await assert.rejects(
    () => verifyLocalAgentRequest(signedClaim({ agentId: "agent-unknown", deviceFingerprint: "device-unknown" }), "claim"),
    (error) => error.statusCode === 401,
    "unknown local agent should not be trusted"
  );

  await assert.rejects(
    () => verifyLocalAgentRequest(signedClaim({ signature: "bad-signature-value" }), "claim"),
    (error) => error.statusCode === 401,
    "bad claim signature should not be trusted"
  );

  await assert.rejects(
    () => verifyLocalAgentRequest(signedClaim({ printerId: "different-printer" }), "claim"),
    (error) => error.statusCode === 409 && error.errorCode === "PRINTER_ATTESTATION_STALE",
    "claim printer mismatch should be blocked by trusted readiness binding"
  );

  resetState();
  const staleIssuedAt = new Date(Date.now() - 10 * 60_000).toISOString();
  const stale = await upsertPrinterConnectionHeartbeat(signedHeartbeatInput({ heartbeatIssuedAt: staleIssuedAt }));
  assert.strictEqual(stale.status.trusted, false, "stale heartbeat should not become trusted");
  assert.strictEqual(registrations.some((entry) => entry.id !== "registration-old" && entry.trustStatus === PrinterTrustStatus.TRUSTED), false, "stale replacement heartbeat must not create a trusted replacement");

  console.log("printer heartbeat claim integration tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

const assert = require("node:assert/strict");
const path = require("node:path");
const { generateKeyPairSync } = require("node:crypto");
const { PrinterConnectionType, PrinterTrustStatus } = require("@prisma/client");

process.env.PRINT_AGENT_REQUIRE_SIGNATURE = "true";
process.env.PRINT_AGENT_REQUIRE_MTLS = "false";
process.env.PRINT_AGENT_SESSION_MODE = "websocket";

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

const registration = {
  id: "registration-session-1",
  userId: "manufacturer-session-1",
  agentId: "agent-session-1",
  deviceFingerprint: "device-session-1",
  publicKeyPem,
  certFingerprint: null,
  trustStatus: PrinterTrustStatus.TRUSTED,
  approvedAt: new Date(),
  revokedAt: null,
  lastSeenAt: new Date(),
  updatedAt: new Date(),
};

const printer = {
  id: "printer-session-1",
  name: "ZDesigner ZT410-300dpi ZPL",
  nativePrinterId: "usb-zebra-session",
  connectionType: PrinterConnectionType.LOCAL_AGENT,
  isActive: true,
  profile: { id: "printer-profile-session-1" },
};

let createdSessions = [];
let supersedeCalls = [];

mockModule("config/database.js", {
  __esModule: true,
  default: {
    printerRegistration: {
      findFirst: async ({ where }) => {
        if (where?.agentId === registration.agentId && where?.deviceFingerprint === registration.deviceFingerprint) {
          return registration;
        }
        return null;
      },
      findUnique: async ({ where }) => (where?.id === registration.id ? registration : null),
    },
    printer: {
      findFirst: async ({ where }) => {
        const selected = where?.OR?.some((item) => item.nativePrinterId === printer.nativePrinterId || item.id === printer.id);
        return where?.printerRegistrationId === registration.id && selected ? printer : null;
      },
    },
    printerAgentSession: {
      updateMany: async ({ where, data }) => {
        supersedeCalls.push({ where, data });
        return { count: createdSessions.filter((row) => row.connectionState === "CONNECTED").length };
      },
      create: async ({ data }) => {
        const row = {
          id: `agent-session-row-${createdSessions.length + 1}`,
          ...data,
          connectionState: "CONNECTED",
        };
        createdSessions.push(row);
        return row;
      },
      findUnique: async ({ where }) => createdSessions.find((row) => row.id === where.id) || null,
    },
  },
});

mockModule("services/printerConnectionService.js", {
  publishPrinterConnectionStatusForUser: async () => null,
});

const { buildPrinterAgentSessionPayload, signPrinterAgentPayload } = require("../dist/services/printerAgentSigningService");
const { openTrustedPrinterAgentSession } = require("../dist/services/printerAgentSessionService");

const signedHello = (overrides = {}) => {
  const issuedAt = new Date().toISOString();
  const connectorVersion = overrides.connectorVersion || "2026.6.25";
  const selectedPrinterId = overrides.selectedPrinterId || printer.nativePrinterId;
  const payload = buildPrinterAgentSessionPayload({
    messageType: "hello",
    registrationId: registration.id,
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    selectedPrinterId,
    connectorVersion,
    nonce: "session-hello-nonce-1",
    issuedAt,
  });
  return {
    type: "hello",
    registrationId: registration.id,
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    selectedPrinterId,
    selectedPrinterName: printer.name,
    connectorVersion,
    nonce: "session-hello-nonce-1",
    issuedAt,
    signature: signPrinterAgentPayload(privateKeyPem, payload),
  };
};

(async () => {
  const first = await openTrustedPrinterAgentSession(signedHello());
  assert.equal(first.registrationId, registration.id, "valid signed hello should open a trusted session");
  assert.equal(first.connectorVersion, "2026.6.25", "trusted session should retain connector version");

  const second = await openTrustedPrinterAgentSession(signedHello({ connectorVersion: "2026.6.26" }));
  assert.equal(second.registrationId, registration.id, "second valid signed hello should open a trusted session");
  assert(
    supersedeCalls.some((call) => call.data.connectionState === "SUPERSEDED"),
    "new session should supersede older connected sessions for the same registration/printer"
  );

  await assert.rejects(
    () => openTrustedPrinterAgentSession(signedHello({ connectorVersion: "2026.6.16" })),
    (error) => error.statusCode === 426 && error.errorCode === "persistent_session_connector_update_required",
    "old connector version must not open persistent WebSocket mode"
  );

  console.log("printer agent persistent session runtime tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

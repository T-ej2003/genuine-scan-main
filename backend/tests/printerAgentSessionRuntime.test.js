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

const revokedRegistration = {
  ...registration,
  id: "registration-session-revoked",
  publicKeyPem: "compat:revoked-null-key",
  trustStatus: PrinterTrustStatus.REVOKED,
  approvedAt: null,
  revokedAt: null,
  lastSeenAt: new Date(Date.now() + 1000),
  updatedAt: new Date(Date.now() + 1000),
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
let activeRegistrations = [revokedRegistration, registration];

mockModule("config/database.js", {
  __esModule: true,
  default: {
	    printerRegistration: {
	      findMany: async ({ where }) => {
	        const ids = new Set((where?.OR || []).map((item) => item.id).filter(Boolean));
	        return activeRegistrations.filter(
	          (row) =>
	            ids.has(row.id) ||
	            (where?.OR || []).some(
	              (item) => item.agentId === row.agentId && item.deviceFingerprint === row.deviceFingerprint
	            )
	        );
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
const { openTrustedPrinterAgentSession, sessionClientMessageSchema } = require("../dist/services/printerAgentSessionService");

const signedHello = (overrides = {}) => {
  const issuedAt = new Date().toISOString();
  const connectorVersion = overrides.connectorVersion || "2026.6.26";
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
	    printerHealth: {
	      buildVersion: connectorVersion,
	      capabilities: {
	        supportsPersistentPrintSession: overrides.supportsPersistentPrintSession !== false,
	      },
	    },
	  };
	};

(async () => {
	  const first = await openTrustedPrinterAgentSession(signedHello());
	  assert.equal(first.registrationId, registration.id, "valid signed hello should open a trusted session");
	  assert.equal(first.connectorVersion, "2026.6.26", "trusted session should retain connector version");
	  assert.equal(first.publicKeyFingerprint.length, 64, "trusted session should bind the enrolled public-key fingerprint");

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

	  await assert.rejects(
	    () => openTrustedPrinterAgentSession(signedHello({ supportsPersistentPrintSession: false })),
	    (error) => error.statusCode === 403 && error.errorCode === "persistent_session_capability_required",
	    "connector must advertise persistent WebSocket capability"
	  );

	  await assert.rejects(
	    () => openTrustedPrinterAgentSession({ ...signedHello(), signature: "not-a-valid-signature" }),
	    (error) => error.statusCode === 403 && error.errorCode === "bad_session_signature",
	    "invalid session signature must be rejected"
	  );

	  await assert.rejects(
	    () => openTrustedPrinterAgentSession(signedHello({ selectedPrinterId: "missing-printer" })),
	    (error) => error.statusCode === 403 && error.errorCode === "selected_printer_mismatch",
	    "selected printer mismatch must be rejected"
	  );

	  const previousRegistrations = activeRegistrations;
	  activeRegistrations = [revokedRegistration];
	  await assert.rejects(
	    () => openTrustedPrinterAgentSession(signedHello()),
	    (error) => error.statusCode === 403 && error.errorCode === "registration_not_trusted",
	    "session admission must reject when only revoked registrations exist"
	  );
	  activeRegistrations = previousRegistrations;

  const heartbeatFrame = {
    type: "heartbeat",
    sessionId: "11111111-1111-4111-8111-111111111111",
    messageSeq: 1,
    nonce: "session-heartbeat-nonce-1",
    issuedAt: new Date().toISOString(),
    signature: "signed-session-heartbeat-frame",
  };
  assert.equal(sessionClientMessageSchema.safeParse(heartbeatFrame).success, true, "post-hello heartbeat frames should match the strict session schema");
  assert.equal(
    sessionClientMessageSchema.safeParse({
      ...heartbeatFrame,
      agentId: registration.agentId,
      deviceFingerprint: registration.deviceFingerprint,
      selectedPrinterId: printer.nativePrinterId,
      connectorVersion: "2026.6.26",
    }).success,
    false,
    "post-hello frames must not include hello-only connector identity fields"
  );

  console.log("printer agent persistent session runtime tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

const assert = require("assert");
const path = require("path");
const { generateKeyPairSync } = require("crypto");
const { PrinterTrustStatus } = require("@prisma/client");

process.env.PRINT_AGENT_REQUIRE_SIGNATURE = "true";
process.env.PRINT_AGENT_REQUIRE_MTLS = "false";

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
  id: "registration-action-1",
  userId: "manufacturer-1",
  agentId: "agent-action",
  deviceFingerprint: "device-action",
  publicKeyPem,
  trustStatus: PrinterTrustStatus.TRUSTED,
  revokedAt: null,
};

let printerStatus = {
  connected: true,
  trusted: true,
  compatibilityMode: false,
  eligibleForPrinting: true,
  connectionClass: "TRUSTED",
  stale: false,
  registrationId: registration.id,
  agentId: registration.agentId,
  deviceFingerprint: registration.deviceFingerprint,
  selectedPrinterId: "zebra-zd421",
  printerId: "zebra-zd421",
};

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
    },
  },
});

mockModule("services/printerConnectionService.js", {
  getPrinterConnectionStatusForUser: async () => printerStatus,
});

const { buildPrinterAgentActionPayload, signPrinterAgentPayload } = require("../dist/services/printerAgentSigningService");
const { verifyLocalAgentRequest } = require("../dist/services/localAgentRequestAuthService");

const signedRequest = (overrides = {}) => {
  const issuedAt = new Date().toISOString();
  const payload = {
    agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    printerId: overrides.printerId || "zebra-zd421",
    nonce: "action-nonce-1",
    issuedAt,
    printJobId: "job-1",
    printItemId: "item-1",
  };
  const signedPayload = buildPrinterAgentActionPayload({
    action: "confirm",
    ...payload,
  });
  return {
    ...payload,
    signature: signPrinterAgentPayload(privateKeyPem, signedPayload),
  };
};

(async () => {
  await verifyLocalAgentRequest(signedRequest(), "confirm", { printJobId: "job-1", printItemId: "item-1" });

  printerStatus = { ...printerStatus, eligibleForPrinting: false, trusted: false, connectionClass: "BLOCKED" };
  await assert.rejects(
    () => verifyLocalAgentRequest(signedRequest(), "confirm", { printJobId: "job-1", printItemId: "item-1" }),
    (error) => error.statusCode === 409 && error.errorCode === "PRINTER_ATTESTATION_STALE",
    "connector confirm must be blocked when current trusted heartbeat is stale or failed"
  );

  printerStatus = {
    ...printerStatus,
    connected: true,
    trusted: true,
    compatibilityMode: false,
    eligibleForPrinting: true,
    connectionClass: "TRUSTED",
    selectedPrinterId: "different-printer",
    printerId: "different-printer",
  };
  await assert.rejects(
    () => verifyLocalAgentRequest(signedRequest(), "confirm", { printJobId: "job-1", printItemId: "item-1" }),
    (error) => error.statusCode === 409 && error.errorCode === "PRINTER_ATTESTATION_STALE",
    "connector confirm must be blocked when action printer does not match the trusted selected printer"
  );

  console.log("local agent request trust gate tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

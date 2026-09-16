const assert = require("node:assert/strict");
const path = require("node:path");
const { generateKeyPairSync, randomUUID } = require("node:crypto");
const { test } = require("node:test");

const dist = path.resolve(__dirname, "../dist");
const mock = (name, exports) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports };
};
const pair = generateKeyPairSync("ed25519");
const privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const registration = {
  id: randomUUID(), userId: randomUUID(), agentId: "connector-test",
  deviceFingerprint: "device-test-fingerprint",
  publicKeyPem: pair.publicKey.export({ type: "spki", format: "pem" }).toString(),
};
const operations = [];
const published = [];
const claim = { available: true, printJobId: "job-fixture", printItemId: "item-fixture",
  manufacturerId: registration.userId, batch: { id: "batch-fixture", licenseeId: "tenant-fixture" },
  printer: { id: "printer-db-id" }, qrCode: {},
};
mock("rls-waves/session-c/c02/printingLifecycleRepository", {
  resolvePrintingConnectorIdentity: async () => ({
    registration, printer: { id: "printer-db-id", nativePrinterId: "native-printer" },
  }),
  recordConnectorEvent: async (input) => { operations.push(input.operation); return input.operation === "CLAIM" ? claim : {}; },
});
const sessionContract = { PRINT_AGENT_REQUIRE_MTLS: false };
mock("services/printerAgentSessionService", sessionContract);
mock("services/printPayloadService", { buildApprovedPrintPayload: () => ({ payloadHash: "payload-fixture" }) });
mock("services/printerTestLabelService", { claimLocalAgentPrinterTestJob: async () => null });
mock("services/printJobRealtimeService", { publishPrintJobViewEvent: async (event) => { published.push(event); } });
mock("local-print-agent/state", { loadAgentState: async () => ({ ...registration, privateKeyPem: privateKey }) });
mock("local-print-agent/cups", {});
mock("local-print-agent/render", {});
const signing = require(path.join(dist, "services/printerAgentSigningService"));
const { LOCAL_AGENT_PERSISTENT_SESSION_MIN_BUILD_VERSION: version } = require(path.join(dist, "services/localAgentProtocol"));
const boundary = require(path.join(dist, "services/printerAgentSessionBoundaryService"));
const { buildSignedSessionMessage } = require(path.join(dist, "local-print-agent/directPrintWorker"));

function hello(overrides = {}) {
  const message = {
    type: "hello", agentId: registration.agentId,
    deviceFingerprint: registration.deviceFingerprint,
    selectedPrinterId: "printer-db-id", connectorVersion: version,
    nonce: randomUUID(), issuedAt: new Date().toISOString(),
    printerHealth: { capabilities: { supportsPersistentPrintSession: true } },
    ...overrides,
  };
  message.signature = signing.signPrinterAgentPayload(privateKey, signing.buildPrinterAgentSessionPayload({
    ...message, messageType: "hello", registrationId: message.registrationId || null,
  }));
  return message;
}

for (const selectedPrinterId of ["printer-db-id", "native-printer"]) {
test(`connector continuation preserves authenticated selector ${selectedPrinterId}`, async () => {
  operations.length = 0;
  const wire = await buildSignedSessionMessage({ type: "hello", selectedPrinterId,
    printerHealth: { capabilities: { supportsPersistentPrintSession: true } },
  });
  assert.equal(wire.registrationId, null);
  const session = await boundary.openTrustedPrinterAgentSession(wire);
  assert.equal(session.registrationId, registration.id);
  assert.equal(session.selectedPrinterId, selectedPrinterId);
  assert.equal(session.printerId, "printer-db-id");
  // Match session_ready handling: retain the connector's original selection.
  const connectorSession = { sessionId: session.id, registrationId: session.registrationId, messageSeq: 0 };
  const chunk = await boundary.buildNextPrintChunkForSession(session);
  const sign = (type, selector = selectedPrinterId, context = connectorSession) => buildSignedSessionMessage({
    type, selectedPrinterId: selector, session: context,
    chunkId: chunk.chunkId, printJobId: claim.printJobId, printItemId: claim.printItemId,
  });
  const heartbeat = await sign("heartbeat");
  await boundary.recordTrustedSessionHeartbeat(session, heartbeat);
  await assert.rejects(boundary.recordTrustedSessionHeartbeat(session, heartbeat), { errorCode: "message_replay" });
  for (const selector of [selectedPrinterId === "printer-db-id" ? "native-printer" : "printer-db-id", "foreign-printer"]) {
    await assert.rejects(boundary.recordTrustedSessionHeartbeat(session, await sign("heartbeat", selector)), {
      errorCode: "bad_session_signature",
    });
  }
  await assert.rejects(boundary.recordTrustedSessionHeartbeat(session, await sign("heartbeat", selectedPrinterId,
    { ...connectorSession, registrationId: randomUUID() })), { errorCode: "bad_session_signature" });
  await assert.rejects(boundary.recordTrustedSessionHeartbeat(session, await sign("heartbeat", selectedPrinterId,
    { ...connectorSession, sessionId: randomUUID() })), { errorCode: "session_identity_mismatch" });
  await assert.rejects(boundary.handleTrustedSessionProgressMessage(session, await sign("label_confirmed")), {
    errorCode: "print_ack_required",
  });
  for (const type of ["chunk_ack", "label_confirmed", "chunk_confirmed"]) {
    await boundary.handleTrustedSessionProgressMessage(session, await sign(type));
  }
  assert.deepEqual(operations, ["CLAIM", "ACK", "CONFIRM"]);
  await boundary.closeTrustedPrinterAgentSession(session.id, "test complete");
  await assert.rejects(boundary.recordTrustedSessionHeartbeat(session, await sign("heartbeat")), {
    errorCode: "session_not_active",
  });
});
}

test("signed caller identity cannot replace the independently resolved identity", async () => {
  for (const overrides of [
    { registrationId: randomUUID() }, { agentId: "other-agent" },
    { deviceFingerprint: "other-fingerprint" },
  ]) {
    await assert.rejects(boundary.openTrustedPrinterAgentSession(hello(overrides)), {
      errorCode: "registration_identity_mismatch",
    });
  }
});

test("tampered and expired hello messages fail closed", async () => {
  const tampered = hello();
  tampered.nonce = randomUUID();
  await assert.rejects(boundary.openTrustedPrinterAgentSession(tampered), { errorCode: "bad_session_signature" });
  await assert.rejects(boundary.openTrustedPrinterAgentSession(hello({ issuedAt: "2000-01-01T00:00:00.000Z" })), {
    errorCode: "agent_timestamp_expired",
  });
});

test("strict mTLS requires the trusted fingerprint and matches a pinned certificate", async () => {
  sessionContract.PRINT_AGENT_REQUIRE_MTLS = true;
  registration.certFingerprint = "certificate-fixture";
  try {
    for (const fingerprint of [undefined, "", "different-certificate"]) {
      await assert.rejects(boundary.openTrustedPrinterAgentSession(hello(), {
        mtlsFingerprintHeader: fingerprint,
      }), { errorCode: "mtls_required" });
    }
    const session = await boundary.openTrustedPrinterAgentSession(hello(), {
      mtlsFingerprintHeader: registration.certFingerprint,
    });
    await boundary.closeTrustedPrinterAgentSession(session.id, "test complete");
    const trimmed = await boundary.openTrustedPrinterAgentSession(hello(), {
      mtlsFingerprintHeader: ` ${registration.certFingerprint} `,
    });
    await boundary.closeTrustedPrinterAgentSession(trimmed.id, "test complete");
    delete registration.certFingerprint;
    for (const fingerprint of [undefined, "certificate-fixture"]) {
      await assert.rejects(boundary.openTrustedPrinterAgentSession(hello(), {
        mtlsFingerprintHeader: fingerprint,
      }), { errorCode: "mtls_required" });
    }
  } finally {
    sessionContract.PRINT_AGENT_REQUIRE_MTLS = false;
    delete registration.certFingerprint;
  }
});

test("label/chunk terminal receipts are deduplicated and conflicting identities fail closed", async () => {
  operations.length = 0;
  published.length = 0;
  const session = await boundary.openTrustedPrinterAgentSession(hello());
  const chunk = await boundary.buildNextPrintChunkForSession(session);
  let seq = 0;
  const message = (type, overrides = {}) => {
    const value = { type, sessionId: session.id, chunkId: chunk.chunkId,
      printJobId: claim.printJobId, printItemId: claim.printItemId,
      issuedAt: new Date().toISOString(), nonce: randomUUID(), messageSeq: ++seq, ...overrides };
    value.signature = signing.signPrinterAgentPayload(privateKey, signing.buildPrinterAgentSessionPayload({
      ...value, messageType: type, registrationId: registration.id, agentId: registration.agentId,
      deviceFingerprint: registration.deviceFingerprint, selectedPrinterId: session.selectedPrinterId,
      connectorVersion: version,
    }));
    return value;
  };
  await assert.rejects(boundary.handleTrustedSessionProgressMessage(session, message("label_confirmed")), { errorCode: "print_ack_required" });
  assert.deepEqual(operations, ["CLAIM"]);
  await boundary.handleTrustedSessionProgressMessage(session, message("label_spooled"));
  await boundary.handleTrustedSessionProgressMessage(session, message("label_confirmed"));
  await boundary.handleTrustedSessionProgressMessage(session, message("chunk_confirmed", { printItemId: null }));
  assert.deepEqual(operations, ["CLAIM", "ACK", "CONFIRM"]);
  assert.equal(published.length, 2);
  assert.equal(published[1].licenseeId, claim.batch.licenseeId);
  assert.equal(published[1].manufacturerId, registration.userId);
  await assert.rejects(boundary.handleTrustedSessionProgressMessage(session, message("chunk_failed")), { errorCode: "terminal_receipt_conflict" });
  await assert.rejects(boundary.handleTrustedSessionProgressMessage(session, message("chunk_confirmed", { printJobId: "foreign-job" })), { errorCode: "chunk_item_mismatch" });
  await assert.rejects(boundary.handleTrustedSessionProgressMessage(session, message("chunk_confirmed", { sessionId: randomUUID() })), { errorCode: "session_identity_mismatch" });
  assert.deepEqual(operations, ["CLAIM", "ACK", "CONFIRM"]);
  await boundary.closeTrustedPrinterAgentSession(session.id, "test complete");
});

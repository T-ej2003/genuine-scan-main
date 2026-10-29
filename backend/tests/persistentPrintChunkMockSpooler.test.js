const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { runPersistentPrintChunk } = require("../dist/local-print-agent/directPrintWorker");

const zpl = "^XA^FO20,20^FDTEST^FS^XZ";
const payloadHash = createHash("sha256").update(zpl).digest("hex");
const payload = {
  type: "print_chunk",
  chunkId: "isolated-chunk",
  printJobId: "isolated-job",
  printer: { name: "isolated-queue", languages: ["ZPL"] },
  labels: [{ printItemId: "isolated-item", code: "isolated-code", scanUrl: "https://example.test/scan",
    payloadType: "ZPL", payloadContent: zpl, payloadHash, commandLanguage: "ZPL" }],
};
const session = { sessionId: "isolated-session", registrationId: "isolated-registration",
  selectedPrinterId: "isolated-printer", connectorVersion: "test", messageSeq: 0 };

const run = async ({ print, wait } = {}) => {
  const events = [];
  const writes = [];
  await runPersistentPrintChunk({}, { ...session }, payload, session.selectedPrinterId, {
    send: async (_socket, _session, printerId, event) => {
      assert.equal(printerId, session.selectedPrinterId);
      events.push(event.type);
    },
    print: print || (async (request) => {
      assert.equal(request.printerId, session.selectedPrinterId);
      assert.equal(request.request.payloadContent, zpl);
      assert.equal(request.request.payloadHash, payloadHash);
      writes.push(request.request.payloadContent);
      return { printPath: "USB_RAW", labelLanguage: "ZPL", jobRef: "mock-queue-job", bytesWritten: Buffer.byteLength(zpl) };
    }),
    wait: wait || (async ({ jobRef }) => {
      assert.equal(jobRef, "mock-queue-job");
      return { confirmed: true };
    }),
  });
  return { events, writes };
};

(async () => {
  const success = await run();
  assert.deepEqual(success.writes, [zpl]);
  assert.deepEqual(success.events, ["chunk_ack", "label_spooled", "label_confirmed", "chunk_confirmed"]);

  const duplicateSession = { ...session };
  let duplicateWrites = 0;
  const duplicateAdapters = {
    send: async () => undefined,
    print: async () => {
      duplicateWrites += 1;
      return { printPath: "USB_RAW", labelLanguage: "ZPL", jobRef: "duplicate-check", bytesWritten: Buffer.byteLength(zpl) };
    },
    wait: async () => ({ confirmed: true }),
  };
  await runPersistentPrintChunk({}, duplicateSession, payload, session.selectedPrinterId, duplicateAdapters);
  await runPersistentPrintChunk({}, duplicateSession, payload, session.selectedPrinterId, duplicateAdapters);
  assert.equal(duplicateWrites, 1, "A duplicate chunk on the same authenticated session must not spool twice");
  const concurrentSession = { ...session };
  duplicateWrites = 0;
  await Promise.all([
    runPersistentPrintChunk({}, concurrentSession, payload, session.selectedPrinterId, duplicateAdapters),
    runPersistentPrintChunk({}, concurrentSession, payload, session.selectedPrinterId, duplicateAdapters),
  ]);
  assert.equal(duplicateWrites, 1, "Concurrent duplicate delivery must not spool twice");

  const unavailable = [];
  await assert.rejects(runPersistentPrintChunk({}, { ...session }, payload, session.selectedPrinterId, {
    send: async (_ws, _session, _printer, event) => unavailable.push(event.type),
    print: async () => { throw new Error("mock spooler unavailable"); },
    wait: async () => { throw new Error("must not wait after rejected submission"); },
  }), /mock spooler unavailable/);
  assert.deepEqual(unavailable, ["chunk_ack", "label_failed", "chunk_failed"]);

  const uncertain = [];
  await assert.rejects(runPersistentPrintChunk({}, { ...session }, payload, session.selectedPrinterId, {
    send: async (_ws, _session, _printer, event) => uncertain.push(event.type),
    print: async () => ({ printPath: "USB_RAW", labelLanguage: "ZPL", jobRef: "uncertain-job", bytesWritten: Buffer.byteLength(zpl) }),
    wait: async () => ({ confirmed: false, confirmationUnavailable: true }),
  }), { errorCode: "queue_confirmation_unavailable" });
  assert.deepEqual(uncertain, ["chunk_ack", "label_spooled", "label_failed", "chunk_failed"]);

  let acceptedWrites = 0;
  const lostReceipt = [];
  const lostReceiptSession = { ...session };
  const lostReceiptAdapters = {
    send: async (_ws, _session, _printer, event) => {
      lostReceipt.push(event.type);
      if (event.type === "label_spooled") throw new Error("signed receipt transport lost");
    },
    print: async () => {
      acceptedWrites += 1;
      return { printPath: "USB_RAW", labelLanguage: "ZPL", jobRef: "accepted-but-unacknowledged", bytesWritten: Buffer.byteLength(zpl) };
    },
    wait: async () => { throw new Error("confirmation must not run before a spool receipt is accepted"); },
  };
  await assert.rejects(runPersistentPrintChunk({}, lostReceiptSession, payload, session.selectedPrinterId, lostReceiptAdapters),
    /signed receipt transport lost/);
  await runPersistentPrintChunk({}, lostReceiptSession, payload, session.selectedPrinterId, lostReceiptAdapters);
  assert.equal(acceptedWrites, 1, "An accepted spool submission must not be retried after a lost receipt");
  assert.deepEqual(lostReceipt, ["chunk_ack", "label_spooled", "label_failed", "chunk_failed"]);

  let attempted = false;
  await assert.rejects(runPersistentPrintChunk({}, { ...session }, {
    ...payload, labels: [{ ...payload.labels[0], payloadHash: "invalid" }],
  }, session.selectedPrinterId, {
    send: async () => undefined,
    print: async () => { attempted = true; throw new Error("unexpected spooler call"); },
    wait: async () => ({ confirmed: true }),
  }), { errorCode: "chunk_label_payload_hash_mismatch" });
  assert.equal(attempted, false);
  console.log("persistent print chunk mock spooler tests passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { once } = require("node:events");
const { createServer } = require("node:http");
const path = require("node:path");
const WebSocket = require("ws");
const dist = path.resolve(__dirname, "../dist");
const mock = (name, exports) => {
  const id = require.resolve(path.join(dist, name));
  require.cache[id] = { id, filename: id, loaded: true, exports };
};
const entered = [], finished = [];
let releaseFirst;
const firstCommit = new Promise((resolve) => { releaseFirst = resolve; });
mock("utils/mtlsFingerprintHeader", { getTrustedMtlsFingerprintHeader: () => null });
mock("services/printerAgentSessionBoundaryService", {
  sessionHelloSchema: { safeParse: (data) => ({ success: true, data }) },
  sessionClientMessageSchema: { safeParse: (data) => ({ success: true, data }) },
  openTrustedPrinterAgentSession: async () => ({ id: "session", registrationId: "registration", connectionId: "connection" }),
  closeTrustedPrinterAgentSession: async () => {},
  buildNextPrintChunkForSession: async () => null,
  logPrinterSessionResolverOutcome: () => {},
  handleTrustedSessionProgressMessage: async (_session, message) => {
    entered.push(message.messageSeq);
    if (message.messageSeq === 1) await firstCommit;
    finished.push(message.messageSeq);
  },
});
const { attachPrinterAgentSessionWebSocket } = require(path.join(dist, "services/printerAgentSessionSocket"));

test("socket serializes receipts until the preceding commit completes", { timeout: 5_000 }, async () => {
  const server = createServer();
  const wss = attachPrinterAgentSessionWebSocket(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const ws = new WebSocket(`ws://127.0.0.1:${server.address().port}/api/printer-agent/session`);
  try {
    await once(ws, "open");
    const ready = once(ws, "message");
    ws.send(JSON.stringify({ type: "hello" }));
    assert.equal(JSON.parse(String((await ready)[0])).type, "session_ready");
    const acknowledgements = [];
    const done = new Promise((resolve) => ws.on("message", (raw) => {
      const message = JSON.parse(String(raw));
      if (message.type === "message_ack") acknowledgements.push(message.messageSeq);
      if (acknowledgements.length === 3) resolve();
    }));
    for (const [index, type] of ["chunk_ack", "label_confirmed", "chunk_confirmed"].entries()) {
      ws.send(JSON.stringify({ type, messageSeq: index + 1 }));
    }
    // A loopback round-trip barrier ensures all three frames arrived while commit #1 is held.
    const pong = once(ws, "pong"); ws.ping(); await pong;
    assert.deepEqual(entered, [1]);
    assert.deepEqual(finished, []);
    releaseFirst(); await done;
    assert.deepEqual(entered, [1, 2, 3]);
    assert.deepEqual(finished, [1, 2, 3]);
    assert.deepEqual(acknowledgements, [1, 2, 3]);
  } finally {
    releaseFirst(); ws.terminate();
    for (const socket of wss.clients) socket.terminate();
    await new Promise((resolve) => wss.close(resolve));
    await new Promise((resolve) => server.close(resolve));
  }
});

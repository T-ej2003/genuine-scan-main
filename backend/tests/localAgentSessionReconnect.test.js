const assert = require("node:assert/strict");
const { generateKeyPairSync } = require("node:crypto");
const http = require("node:http");
const path = require("node:path");
const WebSocket = require("ws");

process.env.PRINT_AGENT_DIRECT_POLL_MS = "2000";
const dist = path.resolve(__dirname, "../dist");
const keyPair = generateKeyPairSync("ed25519");
const state = {
  agentId: "test-agent",
  deviceFingerprint: "test-device",
  selectedPrinterId: "test-printer",
  backendUrl: null,
  privateKeyPem: keyPair.privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
};
const mockModule = (name, exportsValue) => {
  const filename = require.resolve(path.join(dist, name));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};
mockModule("local-print-agent/state.js", { loadAgentState: async () => state });
mockModule("local-print-agent/cups.js", {
  listLocalPrinters: async () => ({ printers: [{ printerId: "test-printer" }], error: null }),
  resolveSelectedPrinter: () => ({ printerId: "test-printer", printerName: "Test printer" }),
});
const { startDirectPrintWorker, getPersistentPrintSessionStatus } = require("../dist/local-print-agent/directPrintWorker");

const waitFor = async (condition) => {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("Timed out waiting for connector recovery");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

(async () => {
  let upgrades = 0;
  let firstSocket;
  let rejectedSocketClosed = false;
  let signedHello = false;
  let signedHeartbeats = 0;
  let lastCloseAt = 0;
  const retryDelays = [];
  const server = http.createServer();
  const wss = new WebSocket.Server({ noServer: true });
  const originalInfo = console.info;
  console.info = (event, details) => {
    if (event === "persistent printer session socket closed") {
      if (details.sessionId === null) rejectedSocketClosed = true;
      lastCloseAt = Date.now();
    }
  };
  server.on("upgrade", (request, socket, head) => {
    upgrades += 1;
    if (upgrades === 1) {
      firstSocket = socket;
      socket.write("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n");
      socket.resume();
      return;
    }
    assert(rejectedSocketClosed, "rejected WebSocket must close before reconnecting");
    assert.equal(wss.clients.size, 0, "reconnect must not overlap an active session");
    retryDelays.push(Date.now() - lastCloseAt);
    wss.handleUpgrade(request, socket, head, (ws) => {
      ws.on("message", (raw) => {
        const message = JSON.parse(String(raw));
        if (message.type === "hello") {
          signedHello = Boolean(message.signature);
          ws.send(JSON.stringify({ type: "session_ready", sessionId: `test-session-${upgrades}`, registrationId: "test-registration" }));
        }
        if (message.type === "heartbeat" && message.signature) signedHeartbeats += 1;
      });
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  state.backendUrl = `http://127.0.0.1:${server.address().port}`;
  const stop = startDirectPrintWorker();
  try {
    await waitFor(() => signedHeartbeats === 1);
    assert.equal(upgrades, 2, "connector must reconnect once after the rejected upgrade");
    assert(signedHello && getPersistentPrintSessionStatus().connected, "authenticated session must recover automatically");
    [...wss.clients][0].close(4003, "session_not_trusted");
    await waitFor(() => !getPersistentPrintSessionStatus().connected);
    await waitFor(() => signedHeartbeats === 2);
    assert.equal(upgrades, 3, "server closure must trigger one authenticated reconnect");
    [...wss.clients][0]._socket.destroy();
    await waitFor(() => !getPersistentPrintSessionStatus().connected);
    await waitFor(() => signedHeartbeats === 3);
    assert.equal(upgrades, 4, "network interruption must trigger one authenticated reconnect");
    assert(retryDelays.every((ms) => ms >= 2_000 && ms < 4_000), "reconnect delay must stay bounded with jitter");
  } finally {
    stop();
    console.info = originalInfo;
    for (const ws of wss.clients) ws.terminate();
    firstSocket?.destroy();
    wss.close();
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
  console.log(`local agent session reconnect tests passed; retry delays ms: ${retryDelays.join(", ")}`);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

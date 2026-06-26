const assert = require("node:assert/strict");
const http = require("node:http");
const path = require("node:path");
const WebSocket = require("ws");

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

mockModule("utils/mtlsFingerprintHeader.js", {
  getTrustedMtlsFingerprintHeader: () => null,
});

mockModule("services/printerAgentSessionService.js", {
  buildNextPrintChunkForSession: async () => null,
  closeTrustedPrinterAgentSession: async () => null,
  handleTrustedSessionProgressMessage: async () => null,
  logPrinterSessionResolverOutcome: () => null,
  openTrustedPrinterAgentSession: async () => {
    throw Object.assign(new Error("not expected before hello"), { statusCode: 500 });
  },
  recordTrustedSessionHeartbeat: async () => null,
  sessionClientMessageSchema: { safeParse: () => ({ success: false, error: { errors: [{ message: "invalid" }] } }) },
  sessionHelloSchema: { safeParse: () => ({ success: false, error: { errors: [{ message: "invalid" }] } }) },
});

const { attachPrinterAgentSessionWebSocket } = require("../dist/services/printerAgentSessionSocket");

const listen = (server) =>
  new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });

const openWebSocket = (url) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(url, {
      headers: {
        "user-agent": "mscqr-test-connector/2026.6.25",
        "x-forwarded-for": "203.0.113.44",
      },
    });
    ws.once("open", () => resolve(ws));
    ws.once("unexpected-response", (_request, response) => {
      reject(Object.assign(new Error(`unexpected response ${response.statusCode}`), { statusCode: response.statusCode }));
    });
    ws.once("error", reject);
  });

const expectUnexpectedResponse = (url) =>
  new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.once("open", () => {
      ws.close();
      reject(new Error("expected upgrade to be rejected"));
    });
    ws.once("unexpected-response", (_request, response) => resolve(response.statusCode));
    ws.once("error", reject);
  });

(async () => {
  const logs = [];
  const originalInfo = console.info;
  const originalWarn = console.warn;
  console.info = (event, details) => {
    logs.push({ level: "info", event, details });
  };
  console.warn = (event, details) => {
    logs.push({ level: "warn", event, details });
  };

  const server = http.createServer((_request, response) => {
    response.writeHead(404).end();
  });
  const wss = attachPrinterAgentSessionWebSocket(server);
  const port = await listen(server);

  try {
    const ws = await openWebSocket(`ws://127.0.0.1:${port}/api/printer-agent/session`);
    assert.equal(ws.readyState, WebSocket.OPEN, "standard session WebSocket upgrade should be accepted before hello");
    ws.close();

    const upgradeSeen = logs.find((entry) => entry.event === "printer_session_upgrade_seen");
    assert(upgradeSeen, "session upgrade should be logged before hello processing");
    assert.equal(upgradeSeen.details.requestPath, "/api/printer-agent/session");
    assert.equal(upgradeSeen.details.secWebSocketVersion, "13");
    assert.equal(upgradeSeen.details.xForwardedForPresent, true);
    assert.equal(typeof upgradeSeen.details.xForwardedForHash, "string");
    assert(!JSON.stringify(upgradeSeen).includes("203.0.113.44"), "raw forwarded IP must not be logged");

    const statusCode = await expectUnexpectedResponse(`ws://127.0.0.1:${port}/api/printer-agent/session/`);
    assert.equal(statusCode, 404, "session-shaped unhandled upgrade path should not return 403");
    assert(
      logs.some((entry) => entry.event === "printer_session_upgrade_unhandled_path"),
      "unhandled session-shaped upgrade path should be logged"
    );
  } finally {
    console.info = originalInfo;
    console.warn = originalWarn;
    wss.close();
    await new Promise((resolve) => server.close(resolve));
  }

  console.log("printer agent session socket upgrade tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

const net = require("net");
const express = require("express");

const TCP_HOST = process.env.MOCK_PRINTER_HOST || "0.0.0.0";
const TCP_PORT = Number(process.env.MOCK_PRINTER_PORT || 9100);
const HTTP_HOST = process.env.MOCK_PRINTER_CONTROL_HOST || "0.0.0.0";
const HTTP_PORT = Number(process.env.MOCK_PRINTER_CONTROL_PORT || 3001);

const STX = "\x02";
const ETX = "\x03";
const CRLF = "\r\n";

const PRINTER_STATES = {
  READY: "ready",
  PAPER_OUT: "paper-out",
  HEAD_OPEN: "head-open",
  OFFLINE: "offline",
};

const FAULTED_PRINT_STATES = new Set([PRINTER_STATES.PAPER_OUT, PRINTER_STATES.HEAD_OPEN]);

const runtime = {
  state: PRINTER_STATES.READY,
  startedAt: new Date().toISOString(),
  tcpServer: null,
  httpServer: null,
  openSockets: new Set(),
  stats: {
    connections: 0,
    statusQueries: 0,
    printJobsAccepted: 0,
    printJobsRejected: 0,
  },
  printerMeta: {
    labelsRemainingInBatch: 1200,
    formatWhilePrinting: false,
    passwordSet: false,
  },
  lastPayload: null,
};

const log = (message, extra) => {
  const timestamp = new Date().toISOString();
  if (extra) {
    console.log(`[${timestamp}] ${message}`, extra);
    return;
  }
  console.log(`[${timestamp}] ${message}`);
};

const sanitizeAsciiPreview = (buffer) =>
  buffer
    .toString("latin1")
    .replace(/[^\x20-\x7e\r\n\t]/g, ".")
    .slice(0, 240);

const summarizePayload = (buffer, kind) => ({
  kind,
  receivedAt: new Date().toISOString(),
  bytes: buffer.length,
  asciiPreview: sanitizeAsciiPreview(buffer),
  hexPreview: buffer.toString("hex").slice(0, 240),
});

const pad = (value, width) => String(Math.max(0, Number(value) || 0)).padStart(width, "0");

const getStatusFlags = (state) => {
  const base = {
    paperOut: 0,
    pause: 0,
    bufferFull: 0,
    corruptRam: 0,
    underTemperature: 0,
    overTemperature: 0,
    headOpen: 0,
    ribbonOut: 0,
    thermalTransferMode: 0,
    printMode: 2,
    labelWaiting: 0,
  };

  if (state === PRINTER_STATES.PAPER_OUT) {
    return {
      ...base,
      paperOut: 1,
      labelWaiting: 1,
    };
  }

  if (state === PRINTER_STATES.HEAD_OPEN) {
    return {
      ...base,
      headOpen: 1,
      labelWaiting: 1,
    };
  }

  return base;
};

const buildHostStatusResponse = (state) => {
  const flags = getStatusFlags(state);

  // Zebra ~HS replies are three STX/ETX-framed records terminated by CRLF.
  // This mock keeps most fields at healthy defaults and only toggles the
  // state-specific flags your app typically cares about:
  // - String 1, field b: paper out
  // - String 2, field o: printhead open
  // - String 1, fields k/l: under-temp / over-temp
  // - String 2, field r: print mode (2 = tear-off in this mock)
  const string1 = [
    pad(0, 3),
    flags.paperOut,
    flags.pause,
    pad(0, 4),
    pad(0, 3),
    flags.bufferFull,
    0,
    0,
    pad(0, 3),
    flags.corruptRam,
    flags.underTemperature,
    flags.overTemperature,
  ].join(",");

  const string2 = [
    pad(0, 3),
    0,
    flags.headOpen,
    flags.ribbonOut,
    flags.thermalTransferMode,
    flags.printMode,
    runtime.printerMeta.formatWhilePrinting ? 1 : 0,
    flags.labelWaiting,
    pad(runtime.printerMeta.labelsRemainingInBatch, 8),
    runtime.printerMeta.passwordSet ? 1 : 0,
    pad(3, 3),
  ].join(",");

  const string3 = [pad(0, 4), 0].join(",");

  return Buffer.from(
    `${STX}${string1}${ETX}${CRLF}${STX}${string2}${ETX}${CRLF}${STX}${string3}${ETX}${CRLF}`,
    "ascii"
  );
};

const normalizeQueryText = (buffer) =>
  buffer
    .toString("latin1")
    .replace(/\0/g, "")
    .trim();

const isHostStatusQuery = (buffer) => {
  const text = normalizeQueryText(buffer);
  if (!text) return false;

  return (
    /^~HS$/i.test(text) ||
    /^\^XA\s*~HS\s*\^XZ$/i.test(text) ||
    /device\.host_status/i.test(text)
  );
};

const resetSocket = (socket) => {
  if (typeof socket.resetAndDestroy === "function") {
    socket.resetAndDestroy();
    return;
  }
  socket.destroy();
};

const snapshot = () => ({
  state: runtime.state,
  tcp: {
    host: TCP_HOST,
    port: TCP_PORT,
    listening: Boolean(runtime.tcpServer && runtime.tcpServer.listening),
  },
  http: {
    host: HTTP_HOST,
    port: HTTP_PORT,
  },
  stats: runtime.stats,
  lastPayload: runtime.lastPayload,
  startedAt: runtime.startedAt,
});

const createTcpServer = () => {
  const server = net.createServer((socket) => {
    runtime.stats.connections += 1;
    runtime.openSockets.add(socket);
    socket.setNoDelay(true);

    const remote = `${socket.remoteAddress || "unknown"}:${socket.remotePort || "?"}`;
    let received = Buffer.alloc(0);
    let handled = false;

    log("TCP connection opened", { remote, state: runtime.state });

    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);

      if (handled) return;

      if (isHostStatusQuery(received)) {
        handled = true;
        runtime.stats.statusQueries += 1;
        runtime.lastPayload = summarizePayload(received, "status-query");

        const response = buildHostStatusResponse(runtime.state);
        log("Responding to Zebra host-status query", {
          remote,
          state: runtime.state,
          bytes: response.length,
        });
        socket.end(response);
        return;
      }

      if (FAULTED_PRINT_STATES.has(runtime.state)) {
        handled = true;
        runtime.stats.printJobsRejected += 1;
        runtime.lastPayload = summarizePayload(received, "print-job");

        log("Rejecting print payload because the mock printer is faulted", {
          remote,
          state: runtime.state,
          payload: runtime.lastPayload,
        });

        // A hard reset produces a real client-side socket failure, which is
        // more useful for exercising error handling than a graceful close.
        resetSocket(socket);
      }
    });

    socket.on("end", () => {
      if (!handled && received.length > 0) {
        runtime.stats.printJobsAccepted += 1;
        runtime.lastPayload = summarizePayload(received, "print-job");
        log("Accepted raw print payload", {
          remote,
          state: runtime.state,
          payload: runtime.lastPayload,
        });
      }
    });

    socket.on("error", (error) => {
      log("TCP socket error", {
        remote,
        state: runtime.state,
        error: error.message,
      });
    });

    socket.on("close", () => {
      runtime.openSockets.delete(socket);
      log("TCP connection closed", { remote, state: runtime.state });
    });
  });

  server.on("error", (error) => {
    log("TCP server error", { error: error.message });
  });

  return server;
};

const startTcpServer = async () => {
  if (runtime.tcpServer && runtime.tcpServer.listening) return;

  const server = createTcpServer();
  await new Promise((resolve, reject) => {
    const onError = (error) => {
      server.off("listening", onListening);
      reject(error);
    };
    const onListening = () => {
      server.off("error", onError);
      resolve();
    };

    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(TCP_PORT, TCP_HOST);
  });

  runtime.tcpServer = server;
  log("Mock printer TCP server listening", { host: TCP_HOST, port: TCP_PORT });
};

const stopTcpServer = async (reason) => {
  if (!runtime.tcpServer) return;

  const server = runtime.tcpServer;
  runtime.tcpServer = null;

  for (const socket of runtime.openSockets) {
    socket.destroy();
  }
  runtime.openSockets.clear();

  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  log("Mock printer TCP server stopped", { reason });
};

const setPrinterState = async (nextState) => {
  if (!Object.values(PRINTER_STATES).includes(nextState)) {
    throw new Error(`Unsupported printer state: ${nextState}`);
  }

  if (nextState === PRINTER_STATES.OFFLINE) {
    runtime.state = nextState;
    await stopTcpServer("state switched to offline");
    return snapshot();
  }

  await startTcpServer();
  runtime.state = nextState;
  log("Mock printer state updated", { state: runtime.state });
  return snapshot();
};

const app = express();

app.get("/", (_req, res) => {
  res.json({
    message: "Mock Zebra-style printer control panel",
    endpoints: [
      "GET /status",
      "GET /state/ready",
      "GET /state/paper-out",
      "GET /state/head-open",
      "GET /state/offline",
    ],
    ...snapshot(),
  });
});

app.get("/status", (_req, res) => {
  res.json(snapshot());
});

app.get("/state/ready", async (_req, res, next) => {
  try {
    res.json(await setPrinterState(PRINTER_STATES.READY));
  } catch (error) {
    next(error);
  }
});

app.get("/state/paper-out", async (_req, res, next) => {
  try {
    res.json(await setPrinterState(PRINTER_STATES.PAPER_OUT));
  } catch (error) {
    next(error);
  }
});

app.get("/state/head-open", async (_req, res, next) => {
  try {
    res.json(await setPrinterState(PRINTER_STATES.HEAD_OPEN));
  } catch (error) {
    next(error);
  }
});

app.get("/state/offline", async (_req, res, next) => {
  try {
    res.json(await setPrinterState(PRINTER_STATES.OFFLINE));
  } catch (error) {
    next(error);
  }
});

app.use((error, _req, res, _next) => {
  log("HTTP control panel error", { error: error.message });
  res.status(500).json({ error: error.message });
});

const startHttpServer = async () => {
  await new Promise((resolve) => {
    runtime.httpServer = app.listen(HTTP_PORT, HTTP_HOST, resolve);
  });
  log("Mock printer HTTP control panel listening", { host: HTTP_HOST, port: HTTP_PORT });
};

const shutdown = async (signal) => {
  log("Shutting down mock printer", { signal });

  try {
    await stopTcpServer(`received ${signal}`);
  } catch (error) {
    log("Error while stopping TCP server", { error: error.message });
  }

  if (runtime.httpServer) {
    await new Promise((resolve) => {
      runtime.httpServer.close(() => resolve());
    });
  }

  process.exit(0);
};

process.on("SIGINT", () => {
  shutdown("SIGINT");
});

process.on("SIGTERM", () => {
  shutdown("SIGTERM");
});

const bootstrap = async () => {
  await startTcpServer();
  await startHttpServer();
  log("Mock printer is ready", snapshot());
};

bootstrap().catch((error) => {
  log("Failed to start mock printer", { error: error.message });
  process.exit(1);
});

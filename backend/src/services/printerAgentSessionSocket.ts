import { createHash } from "crypto";
import type { IncomingMessage, Server } from "http";
import type { Duplex } from "stream";
import { WebSocketServer, WebSocket } from "ws";

import { releaseMetadata } from "../observability/release";
import { getTrustedMtlsFingerprintHeader } from "../utils/mtlsFingerprintHeader";
import {
  buildNextPrintChunkForSession,
  closeTrustedPrinterAgentSession,
  handleTrustedSessionProgressMessage,
  logPrinterSessionResolverOutcome,
  openTrustedPrinterAgentSession,
  recordTrustedSessionHeartbeat,
  sessionClientMessageSchema,
  sessionHelloSchema,
  type TrustedPrinterAgentSession,
} from "./printerAgentSessionService";

type SessionSocketState = {
  trusted: TrustedPrinterAgentSession | null;
  dispatching: boolean;
  closed: boolean;
};

const SESSION_SOCKET_PATHS = new Set([
  "/api/printer-agent/session",
  "/api/api/printer-agent/session",
  "/printer-agent/session",
]);

const sha256Short = (value: unknown) => {
  const normalized = String(value || "").trim();
  return normalized ? createHash("sha256").update(normalized).digest("hex").slice(0, 16) : null;
};

const safeHeaderValue = (value: unknown, max = 120) => {
  const source = Array.isArray(value) ? value.join(",") : String(value || "");
  const normalized = source.replace(/[\r\n\t]+/g, " ").replace(/\s+/g, " ").trim();
  return normalized ? normalized.slice(0, max) : null;
};

const safeWebSocketProtocolPresence = (value: unknown) => {
  const normalized = safeHeaderValue(value, 160);
  const looksSensitive =
    /\b(bearer|token|jwt|secret|signature|cookie|csrf)\b/i.test(normalized || "") ||
    /\beyJ[a-z0-9_-]{20,}/i.test(normalized || "");
  return {
    present: Boolean(normalized),
    value: normalized && looksSensitive ? "<redacted>" : normalized,
  };
};

const safeUserAgentFamily = (value: unknown) => {
  const normalized = safeHeaderValue(value, 160);
  if (!normalized) return null;
  const family = normalized.split(/[\/\s;]/)[0]?.trim() || normalized;
  return family.slice(0, 80);
};

const isSessionLikeUpgradePath = (pathname: string) =>
  pathname.includes("/printer-agent/session") || pathname.includes("printer-agent") && pathname.includes("session");

export const buildPrinterSessionUpgradeDiagnostics = (request: IncomingMessage) => {
  const url = new URL(request.url || "/", "http://localhost");
  const forwardedFor = safeHeaderValue(request.headers["x-forwarded-for"], 512);
  return {
    requestPath: url.pathname,
    method: safeHeaderValue(request.method, 16),
    host: safeHeaderValue(request.headers.host, 160),
    originPresent: Boolean(safeHeaderValue(request.headers.origin, 512)),
    userAgentFamily: safeUserAgentFamily(request.headers["user-agent"]),
    connectionHeader: safeHeaderValue(request.headers.connection, 120),
    upgradeHeader: safeHeaderValue(request.headers.upgrade, 80),
    secWebSocketVersion: safeHeaderValue(request.headers["sec-websocket-version"], 16),
    secWebSocketProtocol: safeWebSocketProtocolPresence(request.headers["sec-websocket-protocol"]),
    xForwardedForPresent: Boolean(forwardedFor),
    xForwardedForHash: sha256Short(forwardedFor),
    release: releaseMetadata.release,
  };
};

const writeUpgradeFailureAndDestroy = (socket: Duplex, statusCode: number, reason: string) => {
  if (socket.destroyed) return;
  try {
    socket.write(
      `HTTP/1.1 ${statusCode} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`
    );
  } catch {
    // Best effort only; the socket is destroyed immediately below.
  } finally {
    socket.destroy();
  }
};

const sendJson = (ws: WebSocket, payload: Record<string, unknown>) => {
  if (ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify(payload));
};

const closeWithReason = (ws: WebSocket, code: number, reason: string) => {
  if (ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) return;
  ws.close(code, reason.slice(0, 120));
};

const errorPayload = (error: any) => ({
  type: "error",
  error: error?.message || "Printer session error",
  errorCode: error?.errorCode || null,
  statusCode: error?.statusCode || 500,
  serverTime: new Date().toISOString(),
});

const dispatchNextChunk = async (ws: WebSocket, state: SessionSocketState) => {
  if (!state.trusted || state.dispatching || state.closed || ws.readyState !== WebSocket.OPEN) return;
  state.dispatching = true;
  try {
    const chunk = await buildNextPrintChunkForSession(state.trusted);
    if (chunk) {
      sendJson(ws, {
        ...chunk,
        serverTime: new Date().toISOString(),
      });
    }
  } catch (error: any) {
    sendJson(ws, errorPayload(error));
    if (Number(error?.statusCode || 0) === 401) closeWithReason(ws, 4003, "printer_session_not_trusted");
  } finally {
    state.dispatching = false;
  }
};

export const attachPrinterAgentSessionWebSocket = (server: Server) => {
  const wss = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024 });

  server.on("upgrade", (request, socket, head) => {
    const url = new URL(request.url || "/", "http://localhost");
    if (!SESSION_SOCKET_PATHS.has(url.pathname)) {
      if (isSessionLikeUpgradePath(url.pathname)) {
        console.warn("printer_session_upgrade_unhandled_path", {
          ...buildPrinterSessionUpgradeDiagnostics(request),
          httpStatus: 404,
          socketDestroyed: true,
        });
        writeUpgradeFailureAndDestroy(socket, 404, "Not Found");
      }
      return;
    }
    console.info("printer_session_upgrade_seen", buildPrinterSessionUpgradeDiagnostics(request));
    try {
      wss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
        wss.emit("connection", ws, request);
      });
    } catch (error: any) {
      console.error("printer_session_upgrade_handle_error", {
        ...buildPrinterSessionUpgradeDiagnostics(request),
        error: safeHeaderValue(error?.message || error, 240),
        httpStatus: 400,
        socketDestroyed: true,
      });
      writeUpgradeFailureAndDestroy(socket, 400, "Bad Request");
    }
  });

  wss.on("connection", (ws: WebSocket, request: IncomingMessage) => {
    const state: SessionSocketState = {
      trusted: null,
      dispatching: false,
      closed: false,
    };

    const keepAlive = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) return;
      ws.ping();
    }, 25_000);

    ws.on("message", (raw: any) => {
      void (async () => {
        let payload: unknown;
        try {
          payload = JSON.parse(String(raw));
        } catch {
          sendJson(ws, { type: "error", error: "Invalid JSON message.", errorCode: "invalid_json" });
          return;
        }

        if (!state.trusted) {
          const parsed = sessionHelloSchema.safeParse(payload);
          if (!parsed.success) {
            const url = new URL(request.url || "/", "http://localhost");
            logPrinterSessionResolverOutcome("printer_session_rejected", {
              reasonCode: "invalid_session_hello",
              requestPath: url.pathname,
              agentIdHash: null,
              deviceFingerprintHash: null,
              registrationCandidateCount: 0,
              trustedCandidateCount: 0,
              revokedCandidateCount: 0,
              selectedRegistrationIdHashOrShortId: null,
              selectedTrustStatus: null,
              signatureVerified: false,
              selectedPrinterIdPresent: false,
              selectedPrinterMatch: false,
              buildVersion: null,
              supportsPersistentPrintSession: false,
              connectorVersionAccepted: false,
              httpStatus: 403,
            });
            sendJson(ws, { type: "error", error: parsed.error.errors[0]?.message || "Invalid session hello.", errorCode: "invalid_session_hello" });
            closeWithReason(ws, 4002, "invalid_session_hello");
            return;
          }

          try {
            const url = new URL(request.url || "/", "http://localhost");
            const trusted = await openTrustedPrinterAgentSession(parsed.data, {
              mtlsFingerprintHeader: getTrustedMtlsFingerprintHeader({
                ip: String(request.headers["x-forwarded-for"] || request.socket.remoteAddress || "").split(",")[0]?.trim() || "",
                socket: request.socket,
                get: (name: string) => {
                  const value = request.headers[name.toLowerCase()];
                  return Array.isArray(value) ? value.join(",") : value || "";
                },
              } as any),
            });
            state.trusted = trusted;
            console.info("printer_session_socket_ready", {
              sessionId: trusted.id,
              registrationIdHashOrShortId: trusted.registrationId ? trusted.registrationId.slice(0, 8) : null,
              requestPath: url.pathname,
            });
            sendJson(ws, {
              type: "session_ready",
              sessionId: trusted.id,
              connectionId: trusted.connectionId,
              registrationId: trusted.registrationId,
              selectedPrinterId: trusted.selectedPrinterId,
              serverTime: new Date().toISOString(),
            });
            void dispatchNextChunk(ws, state);
          } catch (error: any) {
            const url = new URL(request.url || "/", "http://localhost");
            const summary = error?.resolverSummary;
            logPrinterSessionResolverOutcome("printer_session_rejected", {
              ...(summary && typeof summary === "object" ? summary : {
                reasonCode: error?.errorCode || "session_rejected",
                agentIdHash: null,
                deviceFingerprintHash: null,
                registrationCandidateCount: 0,
                trustedCandidateCount: 0,
                revokedCandidateCount: 0,
                selectedRegistrationIdHashOrShortId: null,
                selectedTrustStatus: null,
                signatureVerified: false,
                selectedPrinterIdPresent: false,
                selectedPrinterMatch: false,
                buildVersion: null,
                supportsPersistentPrintSession: false,
                connectorVersionAccepted: false,
                httpStatus: Number(error?.statusCode || 403),
              }),
              requestPath: url.pathname,
              httpStatus: Number(error?.statusCode || summary?.httpStatus || 403),
            });
            sendJson(ws, errorPayload(error));
            closeWithReason(ws, Number(error?.statusCode || 0) === 409 ? 4009 : 4003, error?.errorCode || "session_rejected");
          }
          return;
        }

        const parsed = sessionClientMessageSchema.safeParse(payload);
        if (!parsed.success) {
          sendJson(ws, { type: "error", error: parsed.error.errors[0]?.message || "Invalid session message.", errorCode: "invalid_session_message" });
          return;
        }

        try {
          if (parsed.data.type === "heartbeat") {
            await recordTrustedSessionHeartbeat(state.trusted, parsed.data);
          } else {
            await handleTrustedSessionProgressMessage(state.trusted, parsed.data);
          }
          sendJson(ws, {
            type: "message_ack",
            sessionId: state.trusted.id,
            messageType: parsed.data.type,
            messageSeq: parsed.data.messageSeq,
            serverTime: new Date().toISOString(),
          });
          void dispatchNextChunk(ws, state);
        } catch (error: any) {
          sendJson(ws, errorPayload(error));
          if (Number(error?.statusCode || 0) === 401) closeWithReason(ws, 4003, error?.errorCode || "session_not_trusted");
        }
      })();
    });

    ws.on("close", () => {
      state.closed = true;
      clearInterval(keepAlive);
      if (state.trusted) void closeTrustedPrinterAgentSession(state.trusted.id, "websocket_closed").catch(() => undefined);
    });

    ws.on("error", () => {
      state.closed = true;
      clearInterval(keepAlive);
      if (state.trusted) void closeTrustedPrinterAgentSession(state.trusted.id, "websocket_error").catch(() => undefined);
    });
  });

  return wss;
};

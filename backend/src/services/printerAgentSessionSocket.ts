import type { IncomingMessage, Server } from "http";
import { WebSocketServer, WebSocket } from "ws";

import { getTrustedMtlsFingerprintHeader } from "../utils/mtlsFingerprintHeader";
import {
  buildNextPrintChunkForSession,
  closeTrustedPrinterAgentSession,
  handleTrustedSessionProgressMessage,
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
    if (url.pathname !== "/api/printer-agent/session") return;
    wss.handleUpgrade(request, socket, head, (ws: WebSocket) => {
      wss.emit("connection", ws, request);
    });
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
            sendJson(ws, { type: "error", error: parsed.error.errors[0]?.message || "Invalid session hello.", errorCode: "invalid_session_hello" });
            closeWithReason(ws, 4002, "invalid_session_hello");
            return;
          }

          try {
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

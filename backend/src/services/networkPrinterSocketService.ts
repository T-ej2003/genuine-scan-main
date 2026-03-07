import net from "net";

import { logger } from "../utils/logger";

const parsePositiveIntEnv = (name: string, fallback: number, min: number, max: number) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const CONNECT_TIMEOUT_MS = parsePositiveIntEnv("NETWORK_DIRECT_CONNECT_TIMEOUT_MS", 4000, 500, 30000);
const WRITE_TIMEOUT_MS = parsePositiveIntEnv("NETWORK_DIRECT_WRITE_TIMEOUT_MS", 8000, 1000, 60000);

const createTimeoutError = (message: string) => Object.assign(new Error(message), { code: "NETWORK_PRINTER_TIMEOUT" });

export const testNetworkPrinterConnectivity = async (params: { ipAddress: string; port: number }) => {
  return new Promise<{ ok: true; latencyMs: number }>((resolve, reject) => {
    const startedAt = Date.now();
    const socket = net.createConnection({ host: params.ipAddress, port: params.port });
    let settled = false;

    const cleanup = () => {
      socket.removeAllListeners();
      socket.destroy();
    };

    socket.setTimeout(CONNECT_TIMEOUT_MS);

    socket.once("connect", () => {
      if (settled) return;
      settled = true;
      const latencyMs = Date.now() - startedAt;
      cleanup();
      resolve({ ok: true, latencyMs });
    });

    socket.once("timeout", () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(createTimeoutError(`Timed out connecting to ${params.ipAddress}:${params.port}`));
    });

    socket.once("error", (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    });
  });
};

export const sendRawPayloadToNetworkPrinter = async (params: {
  ipAddress: string;
  port: number;
  payload: string | Buffer;
}) => {
  const bytes = Buffer.isBuffer(params.payload) ? params.payload : Buffer.from(String(params.payload || ""), "utf8");
  return new Promise<{ ok: true; bytesWritten: number }>((resolve, reject) => {
    const socket = net.createConnection({ host: params.ipAddress, port: params.port });
    let settled = false;

    const cleanup = () => {
      socket.removeAllListeners();
      socket.destroy();
    };

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      logger.warn("Network printer dispatch failed", {
        host: params.ipAddress,
        port: params.port,
        error: error.message,
      });
      cleanup();
      reject(error);
    };

    socket.setTimeout(WRITE_TIMEOUT_MS);

    socket.once("connect", () => {
      socket.write(bytes, (error) => {
        if (error) {
          fail(error);
          return;
        }
        socket.end();
      });
    });

    socket.once("close", (hadError) => {
      if (settled) return;
      if (hadError) {
        fail(new Error(`Network printer socket closed with error for ${params.ipAddress}:${params.port}`));
        return;
      }
      settled = true;
      cleanup();
      resolve({ ok: true, bytesWritten: bytes.byteLength });
    });

    socket.once("timeout", () => {
      fail(createTimeoutError(`Timed out writing to ${params.ipAddress}:${params.port}`));
    });

    socket.once("error", (error) => {
      fail(error);
    });
  });
};

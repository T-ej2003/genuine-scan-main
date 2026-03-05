import { UserRole } from "@prisma/client";

type PrinterConnectionRecord = {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  orgId?: string | null;
  connected: boolean;
  printerName?: string | null;
  printerId?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  error?: string | null;
  sourceIp?: string | null;
  updatedAt: Date;
};

export type PrinterConnectionStatus = {
  connected: boolean;
  stale: boolean;
  requiredForPrinting: boolean;
  lastHeartbeatAt: string | null;
  ageSeconds: number | null;
  printerName?: string | null;
  printerId?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  error?: string | null;
};

const parsePositiveIntEnv = (name: string, fallback: number, min = 5, max = 600) => {
  const raw = Number(String(process.env[name] || "").trim());
  if (!Number.isFinite(raw) || raw <= 0) return fallback;
  return Math.max(min, Math.min(max, Math.floor(raw)));
};

const HEARTBEAT_TTL_SECONDS = parsePositiveIntEnv("PRINT_AGENT_HEARTBEAT_TTL_SECONDS", 35);
const HEARTBEAT_TTL_MS = HEARTBEAT_TTL_SECONDS * 1000;

const records = new Map<string, PrinterConnectionRecord>();

const buildStatus = (record: PrinterConnectionRecord | null | undefined): PrinterConnectionStatus => {
  if (!record) {
    return {
      connected: false,
      stale: true,
      requiredForPrinting: true,
      lastHeartbeatAt: null,
      ageSeconds: null,
      printerName: null,
      printerId: null,
      deviceName: null,
      agentVersion: null,
      error: "No printer heartbeat yet",
    };
  }

  const now = Date.now();
  const ageMs = Math.max(0, now - record.updatedAt.getTime());
  const stale = ageMs > HEARTBEAT_TTL_MS;
  const connected = Boolean(record.connected) && !stale;

  return {
    connected,
    stale,
    requiredForPrinting: true,
    lastHeartbeatAt: record.updatedAt.toISOString(),
    ageSeconds: Math.floor(ageMs / 1000),
    printerName: record.printerName || null,
    printerId: record.printerId || null,
    deviceName: record.deviceName || null,
    agentVersion: record.agentVersion || null,
    error: stale ? "Printer heartbeat stale" : record.error || null,
  };
};

export const upsertPrinterConnectionHeartbeat = (input: {
  userId: string;
  role: UserRole;
  licenseeId?: string | null;
  orgId?: string | null;
  connected: boolean;
  printerName?: string | null;
  printerId?: string | null;
  deviceName?: string | null;
  agentVersion?: string | null;
  error?: string | null;
  sourceIp?: string | null;
}) => {
  const previous = records.get(input.userId) || null;
  const next: PrinterConnectionRecord = {
    userId: input.userId,
    role: input.role,
    licenseeId: input.licenseeId || null,
    orgId: input.orgId || null,
    connected: Boolean(input.connected),
    printerName: input.printerName || null,
    printerId: input.printerId || null,
    deviceName: input.deviceName || null,
    agentVersion: input.agentVersion || null,
    error: input.error || null,
    sourceIp: input.sourceIp || null,
    updatedAt: new Date(),
  };

  records.set(input.userId, next);

  const changed =
    !previous ||
    previous.connected !== next.connected ||
    String(previous.printerName || "") !== String(next.printerName || "") ||
    String(previous.printerId || "") !== String(next.printerId || "") ||
    String(previous.deviceName || "") !== String(next.deviceName || "") ||
    String(previous.error || "") !== String(next.error || "");

  return {
    changed,
    previousConnected: previous?.connected ?? null,
    status: buildStatus(next),
  };
};

export const getPrinterConnectionStatusForUser = (userId: string): PrinterConnectionStatus =>
  buildStatus(records.get(userId));

export const isPrinterConnectedForUser = (userId: string): boolean =>
  getPrinterConnectionStatusForUser(userId).connected;


type LogLevel = "debug" | "info" | "warn" | "error";

type LogMeta = Record<string, unknown>;

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const configuredLevel = (process.env.LOG_LEVEL || "info").toLowerCase() as LogLevel;
const minLevel = LOG_LEVELS[configuredLevel] ?? LOG_LEVELS.info;
const useJson = process.env.LOG_FORMAT === "json" || process.env.LOG_JSON === "true" || process.env.LOG_JSON === "1";

const baseFields = {
  service: process.env.SERVICE_NAME || "mscqr-backend",
  env: process.env.NODE_ENV || "development",
};

const formatPayload = (level: LogLevel, message: string, meta?: LogMeta) => {
  const payload: Record<string, unknown> = {
    level,
    message,
    timestamp: new Date().toISOString(),
    ...baseFields,
  };

  if (meta && Object.keys(meta).length > 0) {
    payload.meta = meta;
  }

  return JSON.stringify(payload);
};

const log = (level: LogLevel, message: string, meta?: LogMeta) => {
  if (LOG_LEVELS[level] < minLevel) return;

  const sink = level === "debug" ? console.log : console[level];
  if (useJson) {
    sink(formatPayload(level, message, meta));
    return;
  }

  if (meta && Object.keys(meta).length > 0) {
    sink(message, meta);
    return;
  }

  sink(message);
};

export const logger = {
  debug: (message: string, meta?: LogMeta) => log("debug", message, meta),
  info: (message: string, meta?: LogMeta) => log("info", message, meta),
  warn: (message: string, meta?: LogMeta) => log("warn", message, meta),
  error: (message: string, meta?: LogMeta) => log("error", message, meta),
};

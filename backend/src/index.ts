import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import { randomUUID } from "crypto";
import cookieParser from "cookie-parser";
import packageJson from "../package.json";
import routes from "./routes";
import prisma from "./config/database";
import { logger } from "./utils/logger";
import { startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } from "./services/siemOutboxService";
import { startAuditLogOutboxWorker, stopAuditLogOutboxWorker } from "./services/auditLogOutboxService";
import { startCompliancePackScheduler, stopCompliancePackScheduler } from "./services/compliancePackService";
import { resumePendingNetworkDirectJobs } from "./services/networkDirectPrintService";
import { resumePendingNetworkIppJobs } from "./services/networkIppPrintService";
import { startPrintConfirmationReconciler } from "./services/printConfirmationReconciler";
import { startAnalyticsRollupWorker } from "./services/analyticsRollupService";
import { releaseMetadata } from "./observability/release";
import { captureBackendException, flushBackendMonitoring, initBackendMonitoring } from "./observability/sentry";
import { getLatencySummary, recordRequestMetric } from "./observability/requestMetrics";
import { sanitizeRequestInput } from "./middleware/requestSanitizer";
import {
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromUserAgent,
  parsePositiveIntEnv,
} from "./middleware/publicRateLimit";
import { hasConfiguredSecret } from "./utils/secretConfig";
import { buildReadyPayload } from "./controllers/healthController";
import { isObjectStorageConfigured } from "./services/objectStorageService";
import { isRedisConfigured } from "./services/redisService";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const hasAnyConfiguredSecret = (...keys: string[]) => keys.some((key) => hasConfiguredSecret(key));
const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

const missingRequiredEnv = ["DATABASE_URL"].filter((k) => !process.env[k]);
if (!hasAnyConfiguredSecret("JWT_SECRET_CURRENT", "JWT_SECRET")) {
  missingRequiredEnv.push("JWT_SECRET_CURRENT or JWT_SECRET");
}
if (missingRequiredEnv.length > 0) {
  logger.error(`Missing required environment variables: ${missingRequiredEnv.join(", ")}`);
  process.exit(1);
}

const smtpConfigured = Boolean(
  (process.env.SMTP_USER || process.env.SMTP_USERNAME || process.env.EMAIL_USER || process.env.MAIL_USER) &&
    (process.env.SMTP_PASS || process.env.SMTP_PASSWORD || process.env.EMAIL_PASS || process.env.MAIL_PASS || process.env.MAIL_PASSWORD)
);
if (!smtpConfigured) {
  logger.warn(
    "⚠️ SMTP is not configured. Incident/customer emails will fail until SMTP_USER/SMTP_PASS (or EMAIL_/MAIL_ aliases) are set."
  );
}

const isPlaceholderValue = (value: string | undefined) => {
  const v = String(value || "").trim().toLowerCase();
  if (!v) return false;
  return (
    v.includes("your_rds_postgres_url_here") ||
    v.includes("your_strong_secret_here") ||
    v.includes("your_namecheap_private_email_password") ||
    v.includes("changeme") ||
    v.includes("replace_me")
  );
};

if (process.env.NODE_ENV === "production") {
  const placeholderEnv = [
    "DATABASE_URL",
    "JWT_SECRET",
    "SMTP_PASS",
    "SUPER_ADMIN_EMAIL",
    "PUBLIC_SCAN_WEB_BASE_URL",
    "PUBLIC_VERIFY_WEB_BASE_URL",
    "PUBLIC_ADMIN_WEB_BASE_URL",
  ].filter((key) => isPlaceholderValue(process.env[key]));

  if (placeholderEnv.length > 0) {
    logger.error(`Refusing to start: placeholder values detected in ${placeholderEnv.join(", ")}`);
    process.exit(1);
  }

  if (String(process.env.COOKIE_SECURE || "").trim().toLowerCase() !== "true") {
    logger.error("Refusing to start: COOKIE_SECURE must be 'true' in production.");
    process.exit(1);
  }

  const insecurePublicUrls = [
    "PUBLIC_SCAN_WEB_BASE_URL",
    "PUBLIC_VERIFY_WEB_BASE_URL",
    "PUBLIC_ADMIN_WEB_BASE_URL",
    "WEB_APP_BASE_URL",
  ].filter((key) => {
    const value = String(process.env[key] || "").trim();
    return value && !value.toLowerCase().startsWith("https://");
  });

  if (insecurePublicUrls.length > 0) {
    logger.error(`Refusing to start: production public URLs must use HTTPS (${insecurePublicUrls.join(", ")})`);
    process.exit(1);
  }

  const hasQrEd25519 = hasAnyConfiguredSecret("QR_SIGN_PRIVATE_KEY") && hasAnyConfiguredSecret("QR_SIGN_PUBLIC_KEY");
  const hasQrHmac = hasAnyConfiguredSecret("QR_SIGN_HMAC_SECRET_CURRENT", "QR_SIGN_HMAC_SECRET");

  const missingStrongSecurityEnv = [
    !hasQrEd25519 && !hasQrHmac ? "QR signing keys (QR_SIGN_PRIVATE_KEY + QR_SIGN_PUBLIC_KEY or QR_SIGN_HMAC_SECRET_CURRENT/QR_SIGN_HMAC_SECRET)" : "",
    !hasAnyConfiguredSecret("TOKEN_HASH_SECRET_CURRENT", "TOKEN_HASH_SECRET") ? "TOKEN_HASH_SECRET_CURRENT or TOKEN_HASH_SECRET" : "",
    !hasAnyConfiguredSecret("IP_HASH_SALT_CURRENT", "IP_HASH_SALT") ? "IP_HASH_SALT_CURRENT or IP_HASH_SALT" : "",
    !String(process.env.CUSTOMER_VERIFY_OTP_SECRET || "").trim() ? "CUSTOMER_VERIFY_OTP_SECRET" : "",
    !String(process.env.CUSTOMER_VERIFY_TOKEN_SECRET || "").trim() ? "CUSTOMER_VERIFY_TOKEN_SECRET" : "",
    !String(process.env.SCAN_FINGERPRINT_SECRET || "").trim() ? "SCAN_FINGERPRINT_SECRET" : "",
    !hasAnyConfiguredSecret("PRINTER_SSE_SIGN_SECRET_CURRENT", "PRINTER_SSE_SIGN_SECRET") ? "PRINTER_SSE_SIGN_SECRET_CURRENT or PRINTER_SSE_SIGN_SECRET" : "",
    !hasAnyConfiguredSecret("INCIDENT_HASH_SALT_CURRENT", "INCIDENT_HASH_SALT") ? "INCIDENT_HASH_SALT_CURRENT or INCIDENT_HASH_SALT" : "",
    !String(process.env.AUTH_MFA_ENCRYPTION_KEY || "").trim() ? "AUTH_MFA_ENCRYPTION_KEY" : "",
  ].filter(Boolean);

  if (missingStrongSecurityEnv.length > 0) {
    logger.error(
      `Refusing to start: production security hardening requires ${missingStrongSecurityEnv.join(", ")}`
    );
    process.exit(1);
  }

  if (!isRedisConfigured()) {
    logger.error("Refusing to start: production requires Redis coordination (REDIS_URL or REDIS_HOST/REDIS_PORT).");
    process.exit(1);
  }

  if (!isObjectStorageConfigured()) {
    logger.error(
      "Refusing to start: production requires S3-compatible object storage (OBJECT_STORAGE_* / S3_* / MINIO_*)."
    );
    process.exit(1);
  }
}

const usesLegacyFallback = (primaryKeys: string[], fallbackKeys: string[] = []) =>
  !primaryKeys.some((key) => hasConfiguredSecret(key)) && fallbackKeys.some((key) => hasConfiguredSecret(key));

const legacyFallbackWarnings = [
  {
    primaryKeys: ["QR_SIGN_HMAC_SECRET_CURRENT", "QR_SIGN_HMAC_SECRET"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: !hasConfiguredSecret("QR_SIGN_PRIVATE_KEY"),
    message:
      "QR signing HMAC is falling back to JWT_SECRET. Configure QR_SIGN_HMAC_SECRET_CURRENT so it can be rotated independently.",
  },
  {
    primaryKeys: ["PRINTER_SSE_SIGN_SECRET_CURRENT", "PRINTER_SSE_SIGN_SECRET"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: true,
    message:
      "Printer SSE signing is falling back to JWT_SECRET. Configure PRINTER_SSE_SIGN_SECRET_CURRENT to isolate that channel.",
  },
  {
    primaryKeys: ["INCIDENT_HASH_SALT_CURRENT", "INCIDENT_HASH_SALT"],
    fallbackKeys: ["JWT_SECRET"],
    enabled: true,
    message:
      "Incident hashing is falling back to JWT_SECRET. Configure INCIDENT_HASH_SALT_CURRENT for independent rotation.",
  },
];

for (const warning of legacyFallbackWarnings) {
  if (warning.enabled && usesLegacyFallback(warning.primaryKeys, warning.fallbackKeys)) {
    logger.warn(warning.message);
  }
}

const app = express();
app.disable("etag");
app.set("trust proxy", 1);
const PORT = process.env.PORT || 4000;
const runBackgroundWorkers = parseBool(process.env.RUN_BACKGROUND_WORKERS, true);
const sentryEnabled = initBackendMonitoring();

if (sentryEnabled) {
  logger.info("Sentry monitoring enabled", {
    environment: releaseMetadata.environment,
    release: releaseMetadata.release,
  });
}

// ✅ Allow multiple dev frontends (WEB APP 1 on 8081, landing on 8080, default Vite on 5173)
const allowedOrigins = new Set<string>([
  "http://localhost:5173",
  "http://localhost:8080",
  "http://localhost:8081",
]);

// ✅ Support env override: CORS_ORIGIN can be a comma-separated list
// Example: CORS_ORIGIN=http://localhost:8081,http://localhost:8080
if (process.env.CORS_ORIGIN) {
  process.env.CORS_ORIGIN.split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((o) => allowedOrigins.add(o));
}

app.use(
  cors({
    origin: (origin, cb) => {
      // Allow non-browser requests (no Origin header)
      if (!origin) return cb(null, true);

      if (allowedOrigins.has(origin)) return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`), false);
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Device-Fp",
      "X-CSRF-Token",
      "X-Captcha-Token",
      "Cache-Control",
      "Pragma",
    ],
  })
);

app.use(express.urlencoded({ extended: false, limit: "1mb" }));
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(sanitizeRequestInput);

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");

  const forwardedProto = String(req.get("x-forwarded-proto") || "").toLowerCase();
  const isHttps = req.secure || forwardedProto.includes("https");
  if (process.env.NODE_ENV === "production" && isHttps) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
  }
  next();
});

const requestTelemetryDebugPaths = new Set(["/health", "/healthz", "/health/db", "/health/latency", "/version"]);

app.use((req, res, next) => {
  const requestId = String(req.get("x-request-id") || randomUUID());
  const startedAt = process.hrtime.bigint();

  (req as express.Request & { requestId?: string }).requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  res.setHeader("X-Release-Version", releaseMetadata.version);
  res.setHeader("X-Release-Sha", releaseMetadata.shortGitSha);

  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
    const pathName = req.originalUrl.split("?")[0] || req.path || "/";
    const claims = (req as express.Request & { user?: any }).user || null;

    recordRequestMetric({
      at: Date.now(),
      method: req.method,
      route: pathName,
      status: res.statusCode,
      durationMs,
    });

    const meta = {
      requestId,
      method: req.method,
      path: pathName,
      status: res.statusCode,
      durationMs: Math.round(durationMs * 10) / 10,
      release: releaseMetadata.release,
      actorUserId: claims?.userId || null,
      actorRole: claims?.role || null,
      actorLicenseeId: claims?.licenseeId || null,
      actorOrgId: claims?.orgId || null,
      sessionStage: claims?.sessionStage || null,
      authAssurance: claims?.authAssurance || null,
    };

    if (requestTelemetryDebugPaths.has(pathName)) {
      logger.debug("HTTP request completed", meta);
      return;
    }

    if (res.statusCode >= 500) {
      logger.error("HTTP request failed", meta);
      return;
    }

    if (res.statusCode >= 400 || durationMs >= 1500) {
      logger.warn("HTTP request completed", meta);
      return;
    }

    logger.info("HTTP request completed", meta);
  });

  next();
});

const healthPayload = () => ({
  status: "ok",
  timestamp: new Date().toISOString(),
  release: {
    name: releaseMetadata.name,
    version: releaseMetadata.version,
    gitSha: releaseMetadata.shortGitSha,
    environment: releaseMetadata.environment,
  },
});

const publicStatusIpLimiter = createPublicIpRateLimiter({
  scope: "status.direct:ip",
  windowMs: 60 * 1000,
  max: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  message: "Too many status checks. Please wait before retrying.",
});
const publicStatusActorLimiter = createPublicActorRateLimiter({
  scope: "status.direct:actor",
  windowMs: 60 * 1000,
  max: parsePositiveIntEnv("PUBLIC_STATUS_RATE_LIMIT_PER_MIN", 240, 60, 5000),
  message: "Too many status checks. Please wait before retrying.",
  actorResolver: fromUserAgent,
});

app.get("/health", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
  res.json(healthPayload());
});

app.get("/healthz", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
  res.json(healthPayload());
});

app.get("/health/live", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
  res.json({
    ...healthPayload(),
    status: "live",
  });
});

app.get("/version", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
  res.json({
    name: releaseMetadata.name,
    version: releaseMetadata.version,
    gitSha: releaseMetadata.gitSha,
    release: releaseMetadata.release,
    environment: releaseMetadata.environment,
  });
});

app.get("/health/latency", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
  res.json({
    ...healthPayload(),
    latency: getLatencySummary(),
  });
});

app.get("/health/ready", publicStatusIpLimiter, publicStatusActorLimiter, async (_req, res) => {
  const payload = await buildReadyPayload();
  return res.status(payload.success ? 200 : 503).json(payload);
});

app.get("/health/db", publicStatusIpLimiter, publicStatusActorLimiter, async (_req, res) => {
  const payload = await buildReadyPayload();
  if (payload.dependencies.database.ready) {
    return res.json({
      status: "ok",
      database: "reachable",
      redis: payload.dependencies.redis.ready || !payload.dependencies.redis.configured ? "ready" : "unreachable",
      objectStorage:
        payload.dependencies.objectStorage.ready || !payload.dependencies.objectStorage.configured ? "ready" : "unreachable",
      timestamp: new Date().toISOString(),
    });
  }

  const detail =
    process.env.NODE_ENV === "development"
      ? payload.dependencies.database.error || "Database connectivity failed"
      : "Database connectivity failed";
  return res.status(503).json({
    status: "degraded",
    database: "unreachable",
    error: detail,
    timestamp: new Date().toISOString(),
  });
});

app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  next();
});

app.use("/api", routes);

app.use((err: any, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const requestId = (req as express.Request & { requestId?: string }).requestId;
  captureBackendException(err, {
    requestId,
    method: req.method,
    path: req.originalUrl,
    status: 500,
  });
  logger.error("Unhandled error", {
    requestId,
    method: req.method,
    path: req.originalUrl,
    error: err?.message || err,
  });
  res.status(500).json({
    success: false,
    requestId,
    error: process.env.NODE_ENV === "development" ? err.message : "Internal server error",
  });
});

app.use((_req, res) => {
  res.status(404).json({ success: false, error: "Endpoint not found" });
});

const server = app.listen(PORT, () => {
  logger.info("Release metadata loaded", {
    environment: releaseMetadata.environment,
    release: releaseMetadata.release,
    gitSha: releaseMetadata.shortGitSha,
  });
  logger.info(`🚀 Server running on http://localhost:${PORT}`);
  logger.info(`📚 API available at http://localhost:${PORT}/api`);
  logger.info(`🔍 Health check at http://localhost:${PORT}/health`);
  logger.info(`⏱️ Latency summary at http://localhost:${PORT}/health/latency`);
  if (runBackgroundWorkers) {
    startAuditLogOutboxWorker();
    startSecurityEventOutboxWorker();
    startCompliancePackScheduler();
    void resumePendingNetworkDirectJobs().catch((error) => {
      logger.error("Failed to resume pending network-direct jobs", { error: error?.message || error });
    });
    void resumePendingNetworkIppJobs().catch((error) => {
      logger.error("Failed to resume pending network IPP jobs", { error: error?.message || error });
    });
    stopPrintConfirmationReconcilerWorker = startPrintConfirmationReconciler();
    stopAnalyticsRollupWorker = startAnalyticsRollupWorker();
  } else {
    logger.info("Background workers disabled for this HTTP process");
  }
});

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EADDRINUSE") {
    logger.error(`Port ${PORT} is already in use. Stop the existing process or set a different PORT in backend/.env.`);
    process.exit(1);
  }
  logger.error("Server failed to start", { error: err?.message || err });
  process.exit(1);
});

let shuttingDown = false;
let stopPrintConfirmationReconcilerWorker: (() => void) | null = null;
let stopAnalyticsRollupWorker: (() => void) | null = null;
const shutdown = async (signal: string) => {
  if (shuttingDown) return;
  shuttingDown = true;

  logger.info(`Received ${signal}; shutting down gracefully...`);

  const forceExit = setTimeout(() => {
    logger.error("Forced shutdown after timeout");
    process.exit(1);
  }, 10000);
  forceExit.unref?.();

  try {
    await new Promise<void>((resolve, reject) => {
      server.close((err) => (err ? reject(err) : resolve()));
    });
  stopSecurityEventOutboxWorker();
  stopAuditLogOutboxWorker();
  stopCompliancePackScheduler();
    stopPrintConfirmationReconcilerWorker?.();
    stopPrintConfirmationReconcilerWorker = null;
    stopAnalyticsRollupWorker?.();
    stopAnalyticsRollupWorker = null;
    await prisma.$disconnect();
    await flushBackendMonitoring();
    clearTimeout(forceExit);
    logger.info("Shutdown complete");
    process.exit(0);
  } catch (error: any) {
    clearTimeout(forceExit);
    logger.error("Graceful shutdown failed", { error: error?.message || error });
    process.exit(1);
  }
};

process.on("SIGTERM", () => {
  void shutdown("SIGTERM");
});

process.on("SIGINT", () => {
  void shutdown("SIGINT");
});

process.on("unhandledRejection", (reason) => {
  captureBackendException(reason);
  logger.error("Unhandled promise rejection", { error: reason instanceof Error ? reason.message : String(reason) });
});

process.on("uncaughtException", (error) => {
  captureBackendException(error);
  logger.error("Uncaught exception", { error: error?.message || String(error) });
  void shutdown("uncaughtException");
});

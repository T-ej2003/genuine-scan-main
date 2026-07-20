import express from "express";
import cors from "cors";
import { randomUUID } from "crypto";

import routes from "./routes";
import { releaseMetadata } from "./observability/release";
import { captureBackendException } from "./observability/sentry";
import { getLatencySummary, recordRequestMetric } from "./observability/requestMetrics";
import { classifyStagingRlsBatchReadContext } from "./observability/stagingRlsBatchReadProof";
import { classifyStagingRlsManufacturerPrintersReadContext } from "./observability/stagingRlsManufacturerPrintersReadProof";
import {
  isStagingRlsBatchAllocationMapEnabled,
  isStagingRlsBatchesReadEnabled,
  isStagingRlsManufacturerPrintersReadEnabled,
} from "./lib/stagingRlsBatchReadContext";
import { sanitizeRequestInput } from "./middleware/requestSanitizer";
import {
  createPublicActorRateLimiter,
  createPublicIpRateLimiter,
  fromUserAgent,
  parsePositiveIntEnv,
} from "./middleware/publicRateLimit";
import { buildReadyPayload } from "./controllers/healthController";
import { isRedisConfigured } from "./services/redisService";
import { logger } from "./utils/logger";

const parseBool = (value: unknown, fallback = false) => {
  const normalized = String(value || "").trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
};

type RequestClaimsSnapshot = {
  userId?: string | null;
  role?: string | null;
  licenseeId?: string | null;
  orgId?: string | null;
  sessionStage?: string | null;
  authAssurance?: string | null;
};

const getErrorMessage = (error: unknown) => (error instanceof Error ? error.message : String(error || "Unknown error"));
const stagingRlsBatchReadTelemetryPaths = new Set(["/api/qr/batches", "/api/qr/batches/"]);
const isStagingRlsBatchReadTelemetryRoute = (method: string, pathName: string) =>
  method === "GET" && stagingRlsBatchReadTelemetryPaths.has(pathName);
const STAGING_RLS_BATCH_ALLOCATION_MAP_TELEMETRY_PATH = "/api/qr/batches/:id/allocation-map";
const stagingRlsBatchAllocationMapTelemetryPattern = /^\/api\/qr\/batches\/[^/]+\/allocation-map\/?$/;
const isStagingRlsBatchAllocationMapTelemetryRoute = (method: string, pathName: string) =>
  method === "GET" && stagingRlsBatchAllocationMapTelemetryPattern.test(pathName);
const stagingRlsManufacturerPrintersReadTelemetryPaths = new Set([
  "/api/manufacturer/printers",
  "/api/manufacturer/printers/",
]);
const STAGING_RLS_MANUFACTURER_PRINTERS_READ_TELEMETRY_PATH = "/api/manufacturer/printers";
const UNSUPPORTED_WORKFLOW_DENIAL_TELEMETRY_PATH = "/api/UNRESOLVED_PROTECTED_ROUTE";
const isStagingRlsManufacturerPrintersReadTelemetryRoute = (method: string, pathName: string) =>
  method === "GET" && stagingRlsManufacturerPrintersReadTelemetryPaths.has(pathName);

export const createBackendApp = () => {
  const redisRequired =
    process.env.NODE_ENV === "production" &&
    String(process.env.REQUIRE_REDIS_FOR_SHARED_STATE || "true").trim().toLowerCase() !== "false";
  if (redisRequired && !isRedisConfigured()) {
    logger.error("Redis shared state is required in production but REDIS_URL/REDIS_HOST is not configured", {
      event: "redis_required_missing",
      nodeEnv: process.env.NODE_ENV,
    });
    throw new Error("REDIS_URL is required for production shared rate-limit/cache state");
  }

  const app = express();
  app.disable("etag");
  app.set("trust proxy", 1);

  const publicVersionEndpointEnabled = parseBool(process.env.PUBLIC_VERSION_ENDPOINT_ENABLED, false);

  const allowedOrigins = new Set<string>([
    "http://localhost:5173",
    "http://localhost:8080",
    "http://localhost:8081",
  ]);

  if (process.env.CORS_ORIGIN) {
    process.env.CORS_ORIGIN.split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((origin) => allowedOrigins.add(origin));
  }

  app.use(
    cors({
      origin: (origin, cb) => {
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

  const requestTelemetryDebugPaths = new Set(["/health", "/healthz", "/health/db", "/health/latency"]);

  app.use((req, res, next) => {
    const requestId = String(req.get("x-request-id") || randomUUID());
    const startedAt = process.hrtime.bigint();

    (req as express.Request & { requestId?: string }).requestId = requestId;
    res.setHeader("X-Request-Id", requestId);

    res.on("finish", () => {
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1_000_000;
      const unsupportedWorkflowDenial =
        (req as express.Request & { unsupportedWorkflowDenial?: boolean }).unsupportedWorkflowDenial === true;
      const pathName = unsupportedWorkflowDenial
        ? UNSUPPORTED_WORKFLOW_DENIAL_TELEMETRY_PATH
        : req.originalUrl.split("?")[0] || req.path || "/";
      const claims = (req as express.Request & { user?: RequestClaimsSnapshot }).user || null;
      const isStagingRlsAllocationMapTelemetry =
        isStagingRlsBatchAllocationMapTelemetryRoute(req.method, pathName) &&
        isStagingRlsBatchAllocationMapEnabled();
      const isStagingRlsManufacturerPrintersTelemetry =
        isStagingRlsManufacturerPrintersReadTelemetryRoute(req.method, pathName) &&
        isStagingRlsManufacturerPrintersReadEnabled();
      const redactStagingRlsBatchActor =
        (isStagingRlsBatchReadTelemetryRoute(req.method, pathName) && isStagingRlsBatchesReadEnabled()) ||
        isStagingRlsAllocationMapTelemetry ||
        isStagingRlsManufacturerPrintersTelemetry;
      const telemetryPath = isStagingRlsAllocationMapTelemetry
        ? STAGING_RLS_BATCH_ALLOCATION_MAP_TELEMETRY_PATH
        : isStagingRlsManufacturerPrintersTelemetry
          ? STAGING_RLS_MANUFACTURER_PRINTERS_READ_TELEMETRY_PATH
        : pathName;
      const actorContextClass =
        redactStagingRlsBatchActor && claims?.role
          ? isStagingRlsManufacturerPrintersTelemetry
            ? classifyStagingRlsManufacturerPrintersReadContext({ role: claims.role })
            : classifyStagingRlsBatchReadContext({ role: claims.role })
          : null;

      recordRequestMetric({
        at: Date.now(),
        method: req.method,
        route: telemetryPath,
        status: res.statusCode,
        durationMs,
      });

      // The shutdown middleware emits its own bounded, identifier-free denial
      // events. Emitting the generic per-request completion event as well would
      // reintroduce an unbounded log stream during a denial burst.
      if (unsupportedWorkflowDenial) return;

      const meta = {
        requestId,
        method: req.method,
        path: telemetryPath,
        status: res.statusCode,
        durationMs: Math.round(durationMs * 10) / 10,
        release: releaseMetadata.release,
        actorContextClass,
        actorUserId: redactStagingRlsBatchActor ? null : claims?.userId || null,
        actorRole: redactStagingRlsBatchActor ? null : claims?.role || null,
        actorLicenseeId: redactStagingRlsBatchActor ? null : claims?.licenseeId || null,
        actorOrgId: redactStagingRlsBatchActor ? null : claims?.orgId || null,
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
      gitSha: releaseMetadata.gitSha,
      shortGitSha: releaseMetadata.shortGitSha,
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

  app.get("/health/live", (_req, res) => {
    res.json({
      ...healthPayload(),
      status: "live",
    });
  });

  if (publicVersionEndpointEnabled) {
    app.get("/version", publicStatusIpLimiter, publicStatusActorLimiter, (_req, res) => {
      res.json({
        name: releaseMetadata.name,
        version: releaseMetadata.version,
        gitSha: releaseMetadata.gitSha,
        shortGitSha: releaseMetadata.shortGitSha,
        release: releaseMetadata.release,
        environment: releaseMetadata.environment,
      });
    });
  }

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
    if (payload.dependencies.database.ready && payload.dependencies.rlsReadDatabase.ready) {
      return res.json({
        status: "ok",
        database: "reachable",
        rlsReadDatabase: payload.dependencies.rlsReadDatabase.required ? "reachable" : "disabled",
        redis: payload.dependencies.redis.ready || !payload.dependencies.redis.configured ? "ready" : "unreachable",
        objectStorage:
          payload.dependencies.objectStorage.ready || !payload.dependencies.objectStorage.configured ? "ready" : "unreachable",
        timestamp: new Date().toISOString(),
      });
    }

    const detail =
      process.env.NODE_ENV === "development"
        ? payload.dependencies.database.error || payload.dependencies.rlsReadDatabase.error || "Database connectivity failed"
        : "Database connectivity failed";
    return res.status(503).json({
      status: "degraded",
      database: payload.dependencies.database.ready ? "reachable" : "unreachable",
      rlsReadDatabase: payload.dependencies.rlsReadDatabase.ready ? "ready" : "unreachable",
      error: detail,
      timestamp: new Date().toISOString(),
    });
  });

  const integrationShutdownToken = String(process.env.INTEGRATION_TEST_SHUTDOWN_TOKEN || "").trim();
  if (process.env.NODE_ENV === "test" && integrationShutdownToken) {
    app.post("/__integration/shutdown", (req, res) => {
      const providedToken = String(req.get("x-integration-shutdown-token") || "").trim();
      if (providedToken !== integrationShutdownToken) {
        return res.status(404).json({ success: false, error: "Endpoint not found" });
      }

      res.status(202).json({ success: true });
      setImmediate(() => {
        (process as NodeJS.Process & { emit(event: "mscqr:integration-shutdown-requested"): boolean }).emit(
          "mscqr:integration-shutdown-requested"
        );
      });
    });
  }

  const scannerProbePattern =
    /(?:^|\/)(?:\.env(?:\.|$)|\.git(?:\/|$)|actuator(?:\/|$)|phpinfo\.php$|docker-compose\.ya?ml$|secrets\.json$|config\.json$|application\.ya?ml$|aws\.json$|database\.ya?ml$|wp-config\.php$|server-status$)/i;

  app.use("/api", (req, res, next) => {
    const pathName = req.originalUrl.split("?")[0] || req.path || "/";
    if (scannerProbePattern.test(pathName)) {
      logger.warn("Blocked scanner probe", {
        event: "scanner_probe_blocked",
        method: req.method,
        path: pathName,
        userAgent: req.get("user-agent") || null,
      });
      res.setHeader("Cache-Control", "no-store");
      return res.status(404).json({ success: false, error: "Endpoint not found" });
    }
    next();
  });

  app.use("/api", (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    next();
  });

  app.use("/api", routes);

  app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
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
      error: getErrorMessage(err),
    });
    res.status(500).json({
      success: false,
      requestId,
      error: process.env.NODE_ENV === "development" ? getErrorMessage(err) : "Internal server error",
    });
  });

  app.use((_req, res) => {
    res.status(404).json({ success: false, error: "Endpoint not found" });
  });

  return app;
};

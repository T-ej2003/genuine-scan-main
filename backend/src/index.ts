import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import cookieParser from "cookie-parser";
import packageJson from "../package.json";
import routes from "./routes";
import prisma from "./config/database";
import { logger } from "./utils/logger";
import { startSecurityEventOutboxWorker, stopSecurityEventOutboxWorker } from "./services/siemOutboxService";
import { startCompliancePackScheduler, stopCompliancePackScheduler } from "./services/compliancePackService";
import { resumePendingNetworkDirectJobs } from "./services/networkDirectPrintService";

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const missingRequiredEnv = ["DATABASE_URL", "JWT_SECRET"].filter((k) => !process.env[k]);
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
    logger.warn("COOKIE_SECURE is not 'true' in production. Session cookie security may be weaker than intended.");
  }

  const missingStrongSecurityEnv = [
    "QR_SIGN_PRIVATE_KEY",
    "QR_SIGN_PUBLIC_KEY",
    "TOKEN_HASH_SECRET",
    "IP_HASH_SALT",
    "CUSTOMER_VERIFY_OTP_SECRET",
    "CUSTOMER_VERIFY_TOKEN_SECRET",
    "SCAN_FINGERPRINT_SECRET",
  ].filter((key) => !String(process.env[key] || "").trim());

  if (missingStrongSecurityEnv.length > 0) {
    logger.error(
      `Refusing to start: production security hardening requires ${missingStrongSecurityEnv.join(", ")}`
    );
    process.exit(1);
  }
}

const app = express();
app.disable("etag");
app.set("trust proxy", 1);
const PORT = process.env.PORT || 4000;
const APP_NAME = packageJson.name;
const APP_VERSION = packageJson.version;
const GIT_SHA =
  process.env.GIT_SHA ||
  process.env.GITHUB_SHA ||
  process.env.COMMIT_SHA ||
  process.env.RENDER_GIT_COMMIT ||
  process.env.VERCEL_GIT_COMMIT_SHA ||
  "unknown";

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

app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());

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

const healthPayload = () => ({ status: "ok", timestamp: new Date().toISOString() });

app.get("/health", (_req, res) => {
  res.json(healthPayload());
});

app.get("/healthz", (_req, res) => {
  res.json(healthPayload());
});

app.get("/version", (_req, res) => {
  res.json({ name: APP_NAME, version: APP_VERSION, gitSha: GIT_SHA });
});

app.get("/health/db", async (_req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return res.json({
      status: "ok",
      database: "reachable",
      timestamp: new Date().toISOString(),
    });
  } catch (e: any) {
    const detail =
      process.env.NODE_ENV === "development"
        ? e?.message || "Database connectivity failed"
        : "Database connectivity failed";
    return res.status(503).json({
      status: "degraded",
      database: "unreachable",
      error: detail,
      timestamp: new Date().toISOString(),
    });
  }
});

app.use("/api", (_req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  next();
});

app.use("/api", routes);

app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("Unhandled error:", { error: err?.message || err });
  res.status(500).json({
    success: false,
    error: process.env.NODE_ENV === "development" ? err.message : "Internal server error",
  });
});

app.use((_req, res) => {
  res.status(404).json({ success: false, error: "Endpoint not found" });
});

const server = app.listen(PORT, () => {
  logger.info(`🚀 Server running on http://localhost:${PORT}`);
  logger.info(`📚 API available at http://localhost:${PORT}/api`);
  logger.info(`🔍 Health check at http://localhost:${PORT}/health`);
  startSecurityEventOutboxWorker();
  startCompliancePackScheduler();
  void resumePendingNetworkDirectJobs().catch((error) => {
    logger.error("Failed to resume pending network-direct jobs", { error: error?.message || error });
  });
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
    stopCompliancePackScheduler();
    await prisma.$disconnect();
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
  logger.error("Unhandled promise rejection", { error: reason instanceof Error ? reason.message : String(reason) });
});

process.on("uncaughtException", (error) => {
  logger.error("Uncaught exception", { error: error?.message || String(error) });
  void shutdown("uncaughtException");
});

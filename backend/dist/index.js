"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const package_json_1 = __importDefault(require("../package.json"));
const routes_1 = __importDefault(require("./routes"));
const database_1 = __importDefault(require("./config/database"));
const logger_1 = require("./utils/logger");
const siemOutboxService_1 = require("./services/siemOutboxService");
const compliancePackService_1 = require("./services/compliancePackService");
const networkDirectPrintService_1 = require("./services/networkDirectPrintService");
dotenv_1.default.config();
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, "../.env") });
const missingRequiredEnv = ["DATABASE_URL", "JWT_SECRET"].filter((k) => !process.env[k]);
if (missingRequiredEnv.length > 0) {
    logger_1.logger.error(`Missing required environment variables: ${missingRequiredEnv.join(", ")}`);
    process.exit(1);
}
const smtpConfigured = Boolean((process.env.SMTP_USER || process.env.SMTP_USERNAME || process.env.EMAIL_USER || process.env.MAIL_USER) &&
    (process.env.SMTP_PASS || process.env.SMTP_PASSWORD || process.env.EMAIL_PASS || process.env.MAIL_PASS || process.env.MAIL_PASSWORD));
if (!smtpConfigured) {
    logger_1.logger.warn("⚠️ SMTP is not configured. Incident/customer emails will fail until SMTP_USER/SMTP_PASS (or EMAIL_/MAIL_ aliases) are set.");
}
const isPlaceholderValue = (value) => {
    const v = String(value || "").trim().toLowerCase();
    if (!v)
        return false;
    return (v.includes("your_rds_postgres_url_here") ||
        v.includes("your_strong_secret_here") ||
        v.includes("your_namecheap_private_email_password") ||
        v.includes("changeme") ||
        v.includes("replace_me"));
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
        logger_1.logger.error(`Refusing to start: placeholder values detected in ${placeholderEnv.join(", ")}`);
        process.exit(1);
    }
    if (String(process.env.COOKIE_SECURE || "").trim().toLowerCase() !== "true") {
        logger_1.logger.warn("COOKIE_SECURE is not 'true' in production. Session cookie security may be weaker than intended.");
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
        logger_1.logger.error(`Refusing to start: production security hardening requires ${missingStrongSecurityEnv.join(", ")}`);
        process.exit(1);
    }
}
const app = (0, express_1.default)();
app.disable("etag");
app.set("trust proxy", 1);
const PORT = process.env.PORT || 4000;
const APP_NAME = package_json_1.default.name;
const APP_VERSION = package_json_1.default.version;
const GIT_SHA = process.env.GIT_SHA ||
    process.env.GITHUB_SHA ||
    process.env.COMMIT_SHA ||
    process.env.RENDER_GIT_COMMIT ||
    process.env.VERCEL_GIT_COMMIT_SHA ||
    "unknown";
// ✅ Allow multiple dev frontends (WEB APP 1 on 8081, landing on 8080, default Vite on 5173)
const allowedOrigins = new Set([
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
app.use((0, cors_1.default)({
    origin: (origin, cb) => {
        // Allow non-browser requests (no Origin header)
        if (!origin)
            return cb(null, true);
        if (allowedOrigins.has(origin))
            return cb(null, true);
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
}));
app.use(express_1.default.json({ limit: "1mb" }));
app.use((0, cookie_parser_1.default)());
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
        await database_1.default.$queryRaw `SELECT 1`;
        return res.json({
            status: "ok",
            database: "reachable",
            timestamp: new Date().toISOString(),
        });
    }
    catch (e) {
        const detail = process.env.NODE_ENV === "development"
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
app.use("/api", routes_1.default);
app.use((err, _req, res, _next) => {
    logger_1.logger.error("Unhandled error:", { error: err?.message || err });
    res.status(500).json({
        success: false,
        error: process.env.NODE_ENV === "development" ? err.message : "Internal server error",
    });
});
app.use((_req, res) => {
    res.status(404).json({ success: false, error: "Endpoint not found" });
});
const server = app.listen(PORT, () => {
    logger_1.logger.info(`🚀 Server running on http://localhost:${PORT}`);
    logger_1.logger.info(`📚 API available at http://localhost:${PORT}/api`);
    logger_1.logger.info(`🔍 Health check at http://localhost:${PORT}/health`);
    (0, siemOutboxService_1.startSecurityEventOutboxWorker)();
    (0, compliancePackService_1.startCompliancePackScheduler)();
    void (0, networkDirectPrintService_1.resumePendingNetworkDirectJobs)().catch((error) => {
        logger_1.logger.error("Failed to resume pending network-direct jobs", { error: error?.message || error });
    });
});
server.on("error", (err) => {
    if (err.code === "EADDRINUSE") {
        logger_1.logger.error(`Port ${PORT} is already in use. Stop the existing process or set a different PORT in backend/.env.`);
        process.exit(1);
    }
    logger_1.logger.error("Server failed to start", { error: err?.message || err });
    process.exit(1);
});
let shuttingDown = false;
const shutdown = async (signal) => {
    if (shuttingDown)
        return;
    shuttingDown = true;
    logger_1.logger.info(`Received ${signal}; shutting down gracefully...`);
    const forceExit = setTimeout(() => {
        logger_1.logger.error("Forced shutdown after timeout");
        process.exit(1);
    }, 10000);
    forceExit.unref?.();
    try {
        await new Promise((resolve, reject) => {
            server.close((err) => (err ? reject(err) : resolve()));
        });
        (0, siemOutboxService_1.stopSecurityEventOutboxWorker)();
        (0, compliancePackService_1.stopCompliancePackScheduler)();
        await database_1.default.$disconnect();
        clearTimeout(forceExit);
        logger_1.logger.info("Shutdown complete");
        process.exit(0);
    }
    catch (error) {
        clearTimeout(forceExit);
        logger_1.logger.error("Graceful shutdown failed", { error: error?.message || error });
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
    logger_1.logger.error("Unhandled promise rejection", { error: reason instanceof Error ? reason.message : String(reason) });
});
process.on("uncaughtException", (error) => {
    logger_1.logger.error("Uncaught exception", { error: error?.message || String(error) });
    void shutdown("uncaughtException");
});
//# sourceMappingURL=index.js.map
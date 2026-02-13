"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const path_1 = __importDefault(require("path"));
const routes_1 = __importDefault(require("./routes"));
const database_1 = __importDefault(require("./config/database"));
dotenv_1.default.config();
dotenv_1.default.config({ path: path_1.default.resolve(__dirname, "../.env") });
const missingRequiredEnv = ["DATABASE_URL", "JWT_SECRET"].filter((k) => !process.env[k]);
if (missingRequiredEnv.length > 0) {
    console.error(`Missing required environment variables: ${missingRequiredEnv.join(", ")}`);
    process.exit(1);
}
const smtpConfigured = Boolean((process.env.SMTP_USER || process.env.SMTP_USERNAME || process.env.EMAIL_USER || process.env.MAIL_USER) &&
    (process.env.SMTP_PASS || process.env.SMTP_PASSWORD || process.env.EMAIL_PASS || process.env.MAIL_PASS || process.env.MAIL_PASSWORD));
if (!smtpConfigured) {
    console.warn("⚠️ SMTP is not configured. Incident/customer emails will fail until SMTP_USER/SMTP_PASS (or EMAIL_/MAIL_ aliases) are set.");
}
const app = (0, express_1.default)();
app.disable("etag");
const PORT = process.env.PORT || 4000;
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
    allowedHeaders: ["Content-Type", "Authorization", "X-Device-Fp", "Cache-Control", "Pragma"],
}));
app.use(express_1.default.json({ limit: "1mb" }));
app.get("/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
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
    console.error("Unhandled error:", err);
    res.status(500).json({
        success: false,
        error: process.env.NODE_ENV === "development" ? err.message : "Internal server error",
    });
});
app.use((_req, res) => {
    res.status(404).json({ success: false, error: "Endpoint not found" });
});
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📚 API available at http://localhost:${PORT}/api`);
    console.log(`🔍 Health check at http://localhost:${PORT}/health`);
});
//# sourceMappingURL=index.js.map
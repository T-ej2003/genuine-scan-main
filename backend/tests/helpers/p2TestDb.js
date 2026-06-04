const assert = require("assert");
const { randomBytes } = require("crypto");
const { execFileSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");

class P2TestDbSkip extends Error {
  constructor(message) {
    super(message);
    this.name = "P2TestDbSkip";
  }
}

const backendRoot = path.resolve(__dirname, "../..");
const distRoot = path.join(backendRoot, "dist");

const isTruthy = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());
const randomSecret = () => randomBytes(32).toString("hex");

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i, "Unsafe database identifier");
  return `"${value.replace(/"/g, '""')}"`;
};

const parseDatabaseName = (databaseUrl) => {
  try {
    const parsed = new URL(databaseUrl);
    return decodeURIComponent(parsed.pathname.replace(/^\//, ""));
  } catch {
    return "";
  }
};

const assertSafeTestDatabaseUrl = (databaseUrl) => {
  const raw = String(databaseUrl || "").trim();
  if (!raw) throw new Error("Missing database URL");
  const parsed = new URL(raw);
  if (parsed.protocol !== "postgresql:" && parsed.protocol !== "postgres:") {
    throw new Error("P2 disposable DB harness only supports PostgreSQL URLs.");
  }

  const databaseName = parseDatabaseName(raw).toLowerCase();
  const host = String(parsed.hostname || "").toLowerCase();
  const urlLower = raw.toLowerCase();
  const clearlyTest = /\b(test|tests|p2|ci|tmp|temporary)\b/.test(databaseName.replace(/[_-]/g, " "));
  const productionMarkers = ["prod", "production", "rds.amazonaws.com", "database.azure.com", "supabase", "neon.tech", "railway.app", "render.com"];

  if (!clearlyTest) {
    throw new Error(`Refusing to use database "${databaseName}". P2 DB name must clearly contain test, p2, ci, tmp, or temporary.`);
  }
  if (productionMarkers.some((marker) => urlLower.includes(marker))) {
    throw new Error("Refusing to use a production-looking database URL for P2 tests.");
  }
  if (host && !["localhost", "127.0.0.1", "::1"].includes(host) && !host.endsWith(".local") && !isTruthy(process.env.P2_TEST_DATABASE_ALLOW_REMOTE)) {
    throw new Error("Refusing non-local P2 database host without P2_TEST_DATABASE_ALLOW_REMOTE=true.");
  }
};

const runPsql = (adminUrl, sql) => {
  execFileSync("psql", [adminUrl, "-v", "ON_ERROR_STOP=1", "-c", sql], {
    cwd: backendRoot,
    env: { ...process.env },
    stdio: "pipe",
  });
};

const buildUrlForDatabase = (adminUrl, databaseName) => {
  const parsed = new URL(adminUrl);
  parsed.pathname = `/${databaseName}`;
  return parsed.toString();
};

const resolveDatabase = () => {
  const directUrl = String(process.env.P2_TEST_DATABASE_URL || "").trim();
  if (directUrl) {
    assertSafeTestDatabaseUrl(directUrl);
    return { databaseUrl: directUrl, createdDatabaseName: null, adminUrl: null };
  }

  const adminUrl = String(process.env.P2_TEST_DATABASE_ADMIN_URL || "").trim();
  if (!adminUrl) {
    throw new P2TestDbSkip("Set P2_TEST_DATABASE_URL or P2_TEST_DATABASE_ADMIN_URL to run real DB-backed P2 tests.");
  }

  const databaseName = `mscqr_p2_test_${process.pid}_${Date.now()}`.toLowerCase();
  const databaseUrl = buildUrlForDatabase(adminUrl, databaseName);
  assertSafeTestDatabaseUrl(databaseUrl);
  runPsql(adminUrl, `CREATE DATABASE ${quoteIdent(databaseName)}`);
  return { databaseUrl, createdDatabaseName: databaseName, adminUrl };
};

const dropDatabase = ({ adminUrl, createdDatabaseName }) => {
  if (!adminUrl || !createdDatabaseName) return;
  runPsql(adminUrl, `DROP DATABASE IF EXISTS ${quoteIdent(createdDatabaseName)} WITH (FORCE)`);
};

const hasMigrationHistory = () => {
  const migrationsDir = path.join(backendRoot, "prisma/migrations");
  if (!fs.existsSync(migrationsDir)) return false;
  return fs.readdirSync(migrationsDir, { withFileTypes: true }).some((entry) => entry.isDirectory());
};

const runPrisma = (databaseUrl, args) => {
  execFileSync("npx", ["prisma", ...args, "--schema", "prisma/schema.prisma"], {
    cwd: backendRoot,
    env: { ...process.env, NODE_ENV: "test", DATABASE_URL: databaseUrl },
    stdio: "inherit",
  });
};

const runPrismaSchemaSetup = (databaseUrl) => {
  console.log("p2 test db: validating Prisma schema");
  runPrisma(databaseUrl, ["validate"]);

  if (hasMigrationHistory()) {
    console.log("p2 test db: applying Prisma migrations with migrate deploy");
    runPrisma(databaseUrl, ["migrate", "deploy"]);
    return;
  }

  console.log("p2 test db: no migration folders found; using prisma db push for disposable schema setup");
  runPrisma(databaseUrl, ["db", "push", "--skip-generate"]);
};

const clearDistRequireCache = () => {
  for (const key of Object.keys(require.cache)) {
    if (key.startsWith(distRoot)) delete require.cache[key];
  }
};

const request = async (baseUrl, method, route, body, options = {}) => {
  const headers = { ...(options.headers || {}) };
  const hasBody = body !== undefined && body !== null;
  if (hasBody && !headers["content-type"] && !headers["Content-Type"]) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${route}`, {
    method,
    headers,
    body: hasBody ? JSON.stringify(body) : undefined,
  });
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  return { status: response.status, headers: response.headers, text, payload };
};

const withP2TestApp = async (callback) => {
  let databaseInfo = null;
  let server = null;
  let prisma = null;

  process.env.NODE_ENV = "test";
  process.env.JWT_SECRET = process.env.JWT_SECRET || randomSecret();
  process.env.JWT_SECRET_CURRENT = process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET;
  process.env.QR_SIGN_HMAC_SECRET = process.env.QR_SIGN_HMAC_SECRET || randomSecret();
  process.env.AUTH_COOKIE_SECRET_CURRENT = process.env.AUTH_COOKIE_SECRET_CURRENT || randomSecret();
  process.env.EMAIL_USE_JSON_TRANSPORT = "true";
  process.env.EMAIL_DRY_RUN = process.env.EMAIL_DRY_RUN || "true";
  process.env.PUBLIC_VERIFY_RATE_LIMIT_PER_MIN = "1000";
  process.env.SCAN_RATE_LIMIT_PER_MIN = "1000";

  try {
    databaseInfo = resolveDatabase();
    process.env.DATABASE_URL = databaseInfo.databaseUrl;
    runPrismaSchemaSetup(databaseInfo.databaseUrl);
    clearDistRequireCache();

    const databaseModule = require("../../dist/config/database");
    prisma = databaseModule.default || databaseModule;
    const { createBackendApp } = require("../../dist/app");
    const app = createBackendApp();

    await new Promise((resolve) => {
      server = http.createServer(app).listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;
    await callback({ baseUrl, prisma, request: (method, route, body, options) => request(baseUrl, method, route, body, options) });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (prisma?.$disconnect) await prisma.$disconnect().catch(() => {});
    if (databaseInfo?.createdDatabaseName) dropDatabase(databaseInfo);
  }
};

module.exports = {
  P2TestDbSkip,
  assertSafeTestDatabaseUrl,
  dropP2TestDatabase: dropDatabase,
  request,
  resolveP2TestDatabase: resolveDatabase,
  runPrismaSchemaSetup,
  withP2TestApp,
};

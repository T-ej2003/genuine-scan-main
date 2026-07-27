const assert = require("assert");
const { randomBytes } = require("crypto");
const { execFileSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");
const { assertSafeTestDatabaseUrl } = require("./testDbSafetyGuard");

class P2TestDbSkip extends Error {
  constructor(message) {
    super(message);
    this.name = "P2TestDbSkip";
  }
}

const backendRoot = path.resolve(__dirname, "../..");
const repoRoot = path.resolve(backendRoot, "..");
const distRoot = path.join(backendRoot, "dist");
const generatedRlsRoot = path.join(repoRoot, "scripts/rls/sql/generated");
const certificationAdministrator = "certification-administrator";
const quotedCertificationAdministrator = `"${certificationAdministrator}"`;
const certificationAdministratorSql = path.join(repoRoot, "scripts/p2-postgres18-init.sql");

const randomSecret = () => randomBytes(32).toString("hex");

const quoteIdent = (value) => {
  assert.match(value, /^[a-z0-9_]+$/i, "Unsafe database identifier");
  return `"${value.replace(/"/g, '""')}"`;
};

const runPsql = (adminUrl, sql) => {
  execFileSync("psql", [adminUrl, "-v", "ON_ERROR_STOP=1", "-c", sql], {
    cwd: backendRoot,
    env: { ...process.env },
    stdio: "pipe",
  });
};

const runPsqlFile = (databaseUrl, file, variables = {}) => {
  const args = [databaseUrl, "-v", "ON_ERROR_STOP=1"];
  for (const [name, value] of Object.entries(variables)) args.push("-v", `${name}=${value}`);
  args.push("-f", path.join(generatedRlsRoot, file));
  execFileSync("psql", args, {
    cwd: generatedRlsRoot,
    env: { ...process.env },
    stdio: "pipe",
  });
};

const runPsqlSourceFile = (databaseUrl, file) => {
  execFileSync("psql", [databaseUrl, "-v", "ON_ERROR_STOP=1", "-f", file], {
    cwd: repoRoot,
    env: { ...process.env },
    stdio: "pipe",
  });
};

const psqlScalar = (databaseUrl, sql) =>
  execFileSync("psql", [databaseUrl, "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql], {
    cwd: backendRoot,
    env: { ...process.env },
    encoding: "utf8",
  }).trim();

const buildUrlForDatabase = (adminUrl, databaseName) => {
  const parsed = new URL(adminUrl);
  parsed.pathname = `/${databaseName}`;
  return parsed.toString();
};

const buildUrlForRole = (databaseUrl, role) => {
  const parsed = new URL(databaseUrl);
  parsed.username = role;
  parsed.password = "";
  return parsed.toString();
};

const bootstrapUser = (adminUrl) => {
  const adminUser = decodeURIComponent(new URL(adminUrl).username);
  return String(process.env.P2_TEST_DB_BOOTSTRAP_USER
    || (adminUser === "certification-administrator" ? "mscqr_p2_test" : adminUser)).trim();
};

const ensureCertificationAdministrator = (adminUrl) => {
  const bootstrapUrl = buildUrlForRole(adminUrl, bootstrapUser(adminUrl));
  if (psqlScalar(bootstrapUrl, `SELECT count(*) FROM pg_roles WHERE rolname='${certificationAdministrator}'`) === "1") return false;
  runPsqlSourceFile(bootstrapUrl, certificationAdministratorSql);
  return true;
};

const buildP2DatabaseUrlFromParts = () => {
  const protocol = String(process.env.P2_TEST_DB_PROTOCOL || "postgresql").trim();
  const user = String(process.env.P2_TEST_DB_USER || "").trim();
  const password = String(process.env.P2_TEST_DB_PASSWORD || "").trim();
  const host = String(process.env.P2_TEST_DB_HOST || "").trim();
  const port = String(process.env.P2_TEST_DB_PORT || "5432").trim();
  const name = String(process.env.P2_TEST_DB_NAME || "").trim();

  if (!user || !host || !name) return "";

  const auth = password
    ? `${encodeURIComponent(user)}:${encodeURIComponent(password)}`
    : encodeURIComponent(user);

  return `${protocol}://${auth}@${host}:${port}/${name}`;
};

const resolveDatabase = () => {
  const builtUrl = buildP2DatabaseUrlFromParts();
  const directUrl = String(process.env.P2_TEST_DATABASE_URL || "").trim();
  if (directUrl) {
    assertSafeTestDatabaseUrl(directUrl);
    return { databaseUrl: directUrl, createdDatabaseName: null, adminUrl: null };
  }

  const adminUrl = String(process.env.P2_TEST_DATABASE_ADMIN_URL || builtUrl).trim();
  if (!adminUrl) {
    throw new P2TestDbSkip("Set P2_TEST_DATABASE_URL/P2_TEST_DATABASE_ADMIN_URL or P2_TEST_DB_* parts to run real DB-backed P2 tests.");
  }

  const createdCertificationAdministrator = ensureCertificationAdministrator(adminUrl);
  try {
    const databaseName = `mscqr_full_rls_cert_p2_${process.pid}_${Date.now()}`.toLowerCase();
    const databaseUrl = buildUrlForDatabase(adminUrl, databaseName);
    assertSafeTestDatabaseUrl(databaseUrl);
    runPsql(adminUrl, `CREATE DATABASE ${quoteIdent(databaseName)} OWNER ${quotedCertificationAdministrator} TEMPLATE template0`);
    return { databaseUrl, createdDatabaseName: databaseName, adminUrl, createdCertificationAdministrator };
  } catch (error) {
    if (createdCertificationAdministrator) {
      runPsql(buildUrlForRole(adminUrl, bootstrapUser(adminUrl)), `DROP ROLE ${quotedCertificationAdministrator}`);
    }
    throw error;
  }
};

const cleanupGeneratedRlsRoles = ({ adminUrl, createdDatabaseName }) => {
  if (!adminUrl || !createdDatabaseName) return;
  runPsqlFile(buildUrlForRole(adminUrl, certificationAdministrator), "clean-room-cleanup.sql", { candidate_database: createdDatabaseName });
};

const dropDatabase = ({ adminUrl, createdDatabaseName }) => {
  if (!adminUrl || !createdDatabaseName) return;
  runPsql(buildUrlForRole(adminUrl, bootstrapUser(adminUrl)), `DROP DATABASE IF EXISTS ${quoteIdent(createdDatabaseName)} WITH (FORCE)`);
};

const cleanupCertificationAdministrator = ({ adminUrl, createdCertificationAdministrator }) => {
  if (adminUrl && createdCertificationAdministrator) {
    runPsql(buildUrlForRole(adminUrl, bootstrapUser(adminUrl)), `DROP ROLE ${quotedCertificationAdministrator}`);
  }
};

const dropP2TestDatabase = (databaseInfo) => {
  dropDatabase(databaseInfo);
  try {
    if (databaseInfo.packageBootstrapStarted) cleanupGeneratedRlsRoles(databaseInfo);
  } finally {
    cleanupCertificationAdministrator(databaseInfo);
  }
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

const runGeneratedRlsSchemaSetup = (databaseInfo) => {
  if (!databaseInfo.adminUrl || !databaseInfo.createdDatabaseName) {
    throw new Error("The full-RLS P2 harness requires a fresh disposable database created from P2_TEST_DATABASE_ADMIN_URL.");
  }

  const administratorUrl = buildUrlForRole(databaseInfo.databaseUrl, certificationAdministrator);
  const migrationUrl = buildUrlForRole(administratorUrl, "mscqr_rls_cert_migration");
  console.log("p2 test db: installing generated RF7 package bootstrap");
  databaseInfo.packageBootstrapStarted = true;
  runPsqlFile(administratorUrl, "admin-bootstrap.sql");
  runPsqlFile(migrationUrl, "migration.sql");
  runPrismaSchemaSetup(migrationUrl);
  runPsqlFile(administratorUrl, "admin-ownership.sql");
  runPsqlFile(administratorUrl, "runtime-policy.sql");
  runPsqlFile(administratorUrl, "verification.sql");
  databaseInfo.packageInstalled = true;
  return {
    administratorUrl,
    runtimeUrl: buildUrlForRole(administratorUrl, "mscqr_rls_cert_app"),
    preauthUrl: buildUrlForRole(administratorUrl, "mscqr_rls_cert_preauth"),
    seedUrl: buildUrlForRole(databaseInfo.databaseUrl, bootstrapUser(databaseInfo.adminUrl)),
  };
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
  let runtimePrisma = null;
  let seedPrisma = null;
  let preauthPrisma = null;

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
    const urls = runGeneratedRlsSchemaSetup(databaseInfo);
    process.env.DATABASE_URL = urls.runtimeUrl;
    process.env.PREAUTH_DATABASE_URL = urls.preauthUrl;
    process.env.AUTHENTICATED_APP_DATABASE_URL = urls.runtimeUrl;
    clearDistRequireCache();

    const databaseModule = require("../../dist/config/database");
    runtimePrisma = databaseModule.default || databaseModule;
    const { PrismaClient } = require("@prisma/client");
    seedPrisma = new PrismaClient({ datasources: { db: { url: urls.seedUrl } } });
    preauthPrisma = new PrismaClient({ datasources: { db: { url: urls.preauthUrl } } });
    const { createBackendApp } = require("../../dist/app");
    const app = createBackendApp();

    await new Promise((resolve) => {
      server = http.createServer(app).listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}`;
    await callback({
      baseUrl,
      prisma: seedPrisma,
      preauthPrisma,
      runtimePrisma,
      request: (method, route, body, options) => request(baseUrl, method, route, body, options),
    });
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    if (runtimePrisma?.$disconnect) await runtimePrisma.$disconnect().catch(() => {});
    if (seedPrisma?.$disconnect) await seedPrisma.$disconnect().catch(() => {});
    if (preauthPrisma?.$disconnect) await preauthPrisma.$disconnect().catch(() => {});
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

module.exports = {
  P2TestDbSkip,
  assertSafeTestDatabaseUrl,
  cleanupGeneratedRlsRoles,
  dropP2TestDatabase,
  request,
  resolveP2TestDatabase: resolveDatabase,
  runGeneratedRlsSchemaSetup,
  runPrismaSchemaSetup,
  withP2TestApp,
};

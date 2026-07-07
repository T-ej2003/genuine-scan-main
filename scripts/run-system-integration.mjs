import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import process from "node:process";

const require = createRequire(import.meta.url);
const {
  dropP2TestDatabase,
  request,
  resolveP2TestDatabase,
  runPrismaSchemaSetup,
} = require("../backend/tests/helpers/p2TestDb");
const { emails, ids, issueBearerTokens, passwords, seedP2Fixtures } = require("../backend/tests/helpers/p2SeedFactories");

const backendPort = Number(process.env.E2E_BACKEND_PORT || process.env.PORT || "4010");
const frontendPort = Number(process.env.E2E_FRONTEND_PORT || "8081");
const backendBaseUrl = `http://127.0.0.1:${backendPort}`;
const forbiddenPublicText =
  /DATABASE_URL|JWT_SECRET|QR_SIGN|TOKEN_HASH|passwordHash|tokenHash|PrismaClientKnownRequestError|stack trace|Bearer\s+[A-Za-z0-9._-]+|at\s+\S+\s+\(/i;

const randomSecret = () => randomBytes(32).toString("hex");

const run = (cmd, args, options = {}) => {
  const result = spawnSync(cmd, args, {
    cwd: process.cwd(),
    env: { ...process.env, ...(options.env || {}) },
    stdio: "inherit",
    shell: false,
  });
  if (result.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed with exit code ${result.status}`);
  }
};

const waitForReady = async (url, label, attempts = 90) => {
  let lastError = "";
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url);
      const text = await response.text();
      if (response.ok) return { response, text };
      lastError = `HTTP ${response.status}: ${text.slice(0, 300)}`;
    } catch (error) {
      lastError = error?.message || String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`${label} did not become ready at ${url}. Last error: ${lastError}`);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForFrontendTrafficDrain = async (ms = 5_000) => {
  console.log(`integration: draining frontend/browser traffic for ${ms}ms before backend shutdown`);
  await sleep(ms);
};

const startProcess = (cmd, args, env) => {
  const child = spawn(cmd, args, {
    cwd: process.cwd(),
    env,
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
  });
  child.stdout.on("data", (chunk) => process.stdout.write(chunk));
  child.stderr.on("data", (chunk) => process.stderr.write(chunk));
  return child;
};

const waitForChildExit = async (child, label, timeoutMs) => {
  if (!child) return { code: null, signal: null };
  if (child.exitCode !== null || child.signalCode !== null) {
    return { code: child.exitCode, signal: child.signalCode };
  }

  return new Promise((resolve, reject) => {
    const onExit = (code, signal) => {
      clearTimeout(timer);
      console.log(`integration: ${label} exited with code ${code ?? "null"} signal ${signal ?? "null"}`);
      resolve({ code, signal });
    };
    const timer = setTimeout(() => {
      child.off("exit", onExit);
      reject(new Error(`${label} did not exit within ${timeoutMs}ms.`));
    }, timeoutMs);

    child.once("exit", onExit);
  });
};

const stopProcess = async (child, label) => {
  if (!child) return;
  if (child.exitCode !== null || child.signalCode !== null) {
    console.log(
      `integration: ${label} already exited with code ${child.exitCode ?? "null"} signal ${child.signalCode ?? "null"}`
    );
    return;
  }

  console.log(`integration: stopping ${label} with SIGTERM`);
  const termWait = waitForChildExit(child, label, 10_000).catch(() => null);
  const termSent = child.kill("SIGTERM");
  if (!termSent && child.exitCode === null && child.signalCode === null) {
    throw new Error(`${label} could not be signalled with SIGTERM.`);
  }

  const termExit = await termWait;
  if (termExit) return;

  console.warn(`integration: ${label} did not exit after SIGTERM; sending SIGKILL`);
  const killWait = waitForChildExit(child, label, 5_000).catch(() => null);
  const killSent = child.kill("SIGKILL");
  if (!killSent && child.exitCode === null && child.signalCode === null) {
    throw new Error(`${label} could not be signalled with SIGKILL.`);
  }

  const killExit = await killWait;
  if (!killExit) throw new Error(`${label} did not exit after SIGTERM/SIGKILL.`);
};

const jsonRequest = async (method, path, body, options = {}) => {
  const response = await request(backendBaseUrl, method, path, body, options);
  if (forbiddenPublicText.test(response.text || "")) {
    throw new Error(`${method} ${path} leaked internal text: ${response.text.slice(0, 300)}`);
  }
  return response;
};

const assertStatus = (response, expected, label) => {
  if (response.status !== expected) {
    throw new Error(`${label}: expected HTTP ${expected}, got ${response.status}: ${response.text}`);
  }
};

const bearer = (token) => ({ authorization: `Bearer ${token}` });

const main = async () => {
  const testEnv = {
    ...process.env,
    NODE_ENV: "test",
    PORT: String(backendPort),
    JWT_SECRET: process.env.JWT_SECRET || randomSecret(),
    JWT_SECRET_CURRENT: process.env.JWT_SECRET_CURRENT || process.env.JWT_SECRET || randomSecret(),
    QR_SIGN_HMAC_SECRET: process.env.QR_SIGN_HMAC_SECRET || randomSecret(),
    QR_SIGN_HMAC_SECRET_CURRENT: process.env.QR_SIGN_HMAC_SECRET_CURRENT || process.env.QR_SIGN_HMAC_SECRET || randomSecret(),
    TOKEN_HASH_SECRET_CURRENT: process.env.TOKEN_HASH_SECRET_CURRENT || randomSecret(),
    IP_HASH_SALT_CURRENT: process.env.IP_HASH_SALT_CURRENT || randomSecret(),
    INCIDENT_HASH_SALT_CURRENT: process.env.INCIDENT_HASH_SALT_CURRENT || randomSecret(),
    PRINTER_SSE_SIGN_SECRET_CURRENT: process.env.PRINTER_SSE_SIGN_SECRET_CURRENT || randomSecret(),
    CUSTOMER_VERIFY_TOKEN_SECRET: process.env.CUSTOMER_VERIFY_TOKEN_SECRET || randomSecret(),
    CUSTOMER_VERIFY_OTP_SECRET: process.env.CUSTOMER_VERIFY_OTP_SECRET || randomSecret(),
    SCAN_FINGERPRINT_SECRET: process.env.SCAN_FINGERPRINT_SECRET || randomSecret(),
    AUTH_MFA_ENCRYPTION_KEY: process.env.AUTH_MFA_ENCRYPTION_KEY || randomSecret(),
    COOKIE_SECURE: "false",
    AUTH_LEGACY_TOKEN_RESPONSE_ENABLED: "false",
    EMAIL_USE_JSON_TRANSPORT: "true",
    EMAIL_DRY_RUN: "true",
    PUBLIC_VERIFY_RATE_LIMIT_PER_MIN: "1000",
    SCAN_RATE_LIMIT_PER_MIN: "1000",
    PUBLIC_STATUS_RATE_LIMIT_PER_MIN: "5000",
    INTEGRATION_DISABLE_BACKGROUND_LOOPS: "true",
    RUN_BACKGROUND_WORKERS: "false",
    RUN_AUDIT_OUTBOX_WORKER: "false",
    RUN_SECURITY_EVENT_OUTBOX_WORKER: "false",
    RUN_PRINT_RECONCILER: "false",
    RUN_ANALYTICS_ROLLUP_WORKER: "false",
    RUN_COMPLIANCE_PACK_SCHEDULER: "false",
    RUN_LEGACY_QR_RISK_REPORT_SCHEDULER: "false",
    RUN_HOT_EVENT_PARTITION_MAINTENANCE: "false",
    RUN_DISTRIBUTED_LEASES: "false",
    REQUIRE_REDIS_FOR_SHARED_STATE: "false",
    CORS_ORIGIN: `http://127.0.0.1:${frontendPort},http://localhost:${frontendPort}`,
    PUBLIC_VERIFY_WEB_BASE_URL: `http://127.0.0.1:${frontendPort}`,
    PUBLIC_SCAN_WEB_BASE_URL: `http://127.0.0.1:${frontendPort}`,
    PUBLIC_ADMIN_WEB_BASE_URL: `http://127.0.0.1:${frontendPort}`,
    WEB_APP_BASE_URL: `http://127.0.0.1:${frontendPort}`,
    E2E_BASE_URL: `http://127.0.0.1:${frontendPort}`,
    E2E_API_BASE_URL: backendBaseUrl,
    E2E_FRONTEND_PORT: String(frontendPort),
    E2E_SYSTEM_VALID_CODE: "P2A000001",
    E2E_SYSTEM_INVALID_CODE: "MSCQR-INTEGRATION-NOT-FOUND",
    E2E_MANUFACTURER_EMAIL: emails.manufacturerA,
    E2E_MANUFACTURER_PASSWORD: passwords.manufacturerA,
    VITE_API_PROXY_TARGET: backendBaseUrl,
    VITE_E2E_DISABLE_TELEMETRY: "true",
    VITE_E2E_DISABLE_AUTH_POLLING: "true",
    VITE_E2E_DISABLE_VERIFY_SESSION_POLLING: "true",
    VITE_E2E_DISABLE_PRINTER_AGENT_POLLING: "true",
  };

  Object.assign(process.env, testEnv);

  console.log("integration: building backend");
  run("npm", ["--prefix", "backend", "run", "build"], { env: testEnv });
  console.log("integration: building frontend");
  run("npm", ["run", "build"], { env: testEnv });

  const databaseInfo = resolveP2TestDatabase();
  testEnv.DATABASE_URL = databaseInfo.databaseUrl;
  process.env.DATABASE_URL = databaseInfo.databaseUrl;

  let backend = null;
  let worker = null;
  let prisma = null;
  try {
    runPrismaSchemaSetup(databaseInfo.databaseUrl);
    const databaseModule = require("../backend/dist/config/database");
    prisma = databaseModule.default || databaseModule;
    await seedP2Fixtures(prisma);
    const tokens = await issueBearerTokens();

    backend = startProcess("npm", ["--prefix", "backend", "start"], testEnv);
    await waitForReady(`${backendBaseUrl}/health/ready`, "backend");

    if (testEnv.REDIS_URL && String(process.env.INTEGRATION_START_WORKER || "true").toLowerCase() !== "false") {
      worker = startProcess("npm", ["--prefix", "backend", "run", "worker"], {
        ...testEnv,
        RUN_BACKGROUND_WORKERS: "true",
        INTEGRATION_DISABLE_BACKGROUND_LOOPS: "true",
        INTEGRATION_WORKER_BOOT_ONLY: "true",
        INTEGRATION_WORKER_ASSERT_REDIS_READY: "true",
      });
      const workerExit = await waitForChildExit(worker, "worker boot proof", 20_000);
      if (workerExit.code !== 0 || workerExit.signal) {
        throw new Error(
          `worker boot proof failed with code ${workerExit.code ?? "null"} signal ${workerExit.signal ?? "null"}`
        );
      }
      worker = null;
    }

    const ready = await jsonRequest("GET", "/health/ready");
    assertStatus(ready, 200, "backend readiness");
    if (!ready.payload?.dependencies?.database?.ready) throw new Error("backend readiness did not report database ready");
    if (testEnv.REDIS_URL && !ready.payload?.dependencies?.redis?.ready) throw new Error("backend readiness did not report Redis ready");

    const login = await jsonRequest("POST", "/api/auth/login", {
      email: emails.manufacturerA,
      password: passwords.manufacturerA,
    });
    assertStatus(login, 200, "seeded manufacturer login");
    if (!/MANUFACTURER/i.test(login.text)) throw new Error("seeded manufacturer login did not return manufacturer role");

    const me = await jsonRequest("GET", "/api/auth/me", null, { headers: bearer(tokens.licenseeAdminA) });
    assertStatus(me, 200, "bearer auth/me");
    if (!/p2-licensee-a@mscqr\.test/i.test(me.text)) throw new Error("auth/me did not return seeded licensee admin");

    const tenantTamper = await jsonRequest("GET", `/api/qr/batches?licenseeId=${ids.licenseeB}`, null, {
      headers: bearer(tokens.licenseeAdminA),
    });
    if (![401, 403, 404, 410, 428].includes(tenantTamper.status)) {
      throw new Error(`cross-tenant batch query was not denied safely: ${tenantTamper.status} ${tenantTamper.text}`);
    }

    const validVerify = await jsonRequest("GET", "/api/verify/P2A000001");
    assertStatus(validVerify, 200, "valid public verification");
    if (!validVerify.payload?.success || !/P2 Brand A|registered|verified|authentic/i.test(validVerify.text)) {
      throw new Error(`valid public verification did not return a customer-safe valid result: ${validVerify.text.slice(0, 500)}`);
    }

    const invalidVerify = await jsonRequest("GET", "/api/verify/MSCQR-INTEGRATION-NOT-FOUND");
    assertStatus(invalidVerify, 200, "invalid public verification");
    if (!/not found|could not match|NOT_FOUND/i.test(invalidVerify.text)) {
      throw new Error(`invalid public verification did not fail safely: ${invalidVerify.text.slice(0, 500)}`);
    }

    const audit = await prisma.auditLog.findFirst({
      where: { action: "VERIFY_FAILED", entityId: "MSCQR-INTEGRATION-NOT-FOUND" },
      orderBy: { createdAt: "desc" },
    });
    if (!audit) throw new Error("invalid public verification did not write VERIFY_FAILED audit log");

    console.log("integration: running Playwright system tests");
    run("npx", ["playwright", "test", "--config=playwright.system.config.ts", "e2e/system-integration.spec.ts"], {
      env: testEnv,
    });
    await waitForFrontendTrafficDrain();

    console.log("MSCQR system integration tests passed");
  } finally {
    process.env.INTEGRATION_SHUTDOWN_STARTED = "true";
    console.log("integration: shutdown started");
    let stopFailure = null;

    try {
      await waitForFrontendTrafficDrain(2_000);
      await stopProcess(worker, "worker");
      await stopProcess(backend, "backend");
    } catch (error) {
      stopFailure = error;
    }

    if (prisma?.$disconnect) await prisma.$disconnect().catch(() => undefined);
    if (stopFailure) throw stopFailure;
    if (databaseInfo?.createdDatabaseName) dropP2TestDatabase(databaseInfo);
  }
};

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

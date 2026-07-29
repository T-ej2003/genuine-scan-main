#!/usr/bin/env node
import process from "node:process";
import { spawn } from "node:child_process";
import { PRODUCTION_GREEN_CANARY_IDS } from "./production-green-canary-provision.mjs";

const waitForReady = async () => {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    try {
      const response = await fetch("http://127.0.0.1:4000/api/health/ready");
      if (response.ok) return;
    } catch {
      // Backend is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error("Green backend did not become ready for the application canary.");
};

const child = (command, args, env) => new Promise((resolve, reject) => {
  const processHandle = spawn(command, args, { env, stdio: "inherit" });
  processHandle.once("error", reject);
  processHandle.once("exit", (code, signal) => code === 0
    ? resolve()
    : reject(new Error(`Canary child failed (${signal || code}).`)));
});

const assertConfiguration = () => {
  const required = [
    "DATABASE_URL", "PREAUTH_DATABASE_URL", "AUTHENTICATED_APP_DATABASE_URL", "MSCQR_C03_PREAUTH_DATABASE_URL",
    "MSCQR_CANARY_ORDINARY_EMAIL", "MSCQR_CANARY_ORDINARY_PASSWORD", "MSCQR_CANARY_ORDINARY_MFA_SECRET",
    "MSCQR_CANARY_ADMIN_EMAIL", "MSCQR_CANARY_ADMIN_PASSWORD", "MSCQR_CANARY_ADMIN_MFA_SECRET",
  ];
  if (required.some((name) => !process.env[name])) throw new Error("Green application canary configuration is incomplete.");
};

const smokeEnvironment = (kind) => ({
  ...process.env,
  SMOKE_BASE_URL: "http://127.0.0.1:4000",
  SMOKE_API_BASE_URL: "http://127.0.0.1:4000/api",
  SMOKE_REQUIRED: "true",
  SMOKE_AUTHENTICATED_REQUIRED: "true",
  SMOKE_LOGIN_EMAIL: process.env[`MSCQR_CANARY_${kind}_EMAIL`],
  SMOKE_LOGIN_PASSWORD: process.env[`MSCQR_CANARY_${kind}_PASSWORD`],
  SMOKE_ADMIN_MFA_SECRET: process.env[`MSCQR_CANARY_${kind}_MFA_SECRET`],
  ...(kind === "ORDINARY" ? {
    SMOKE_TENANT_ISOLATION_FORBIDDEN_PATH: `/licensees/${PRODUCTION_GREEN_CANARY_IDS.isolationLicensee}`,
  } : {}),
});

const run = async () => {
  assertConfiguration();
  const backend = spawn("/usr/local/bin/start-runtime.sh", [], { env: process.env, stdio: "inherit" });
  try {
    await waitForReady();
    await child(process.execPath, ["scripts/release-smoke/smoke-release.mjs"], smokeEnvironment("ORDINARY"));
    await child(process.execPath, ["scripts/release-smoke/smoke-release.mjs"], smokeEnvironment("ADMIN"));
  } finally {
    backend.kill("SIGTERM");
    await new Promise((resolve) => {
      backend.once("exit", resolve);
      setTimeout(() => { backend.kill("SIGKILL"); resolve(); }, 10_000).unref();
    });
  }
};

run().then(
  () => process.stdout.write('{"status":"passed","canary":"production-green-authentication-journey"}\n'),
  () => {
    process.stderr.write('{"status":"blocked","canary":"production-green-authentication-journey"}\n');
    process.exitCode = 1;
  }
);

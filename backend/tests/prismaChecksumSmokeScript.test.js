const assert = require("assert");
const { spawnSync } = require("child_process");
const path = require("path");

const backendRoot = path.resolve(__dirname, "..");
const scriptPath = path.join(backendRoot, "scripts", "smoke-prisma-checksum.js");

const runScript = (extraEnv = {}) =>
  spawnSync(process.execPath, [scriptPath], {
    cwd: backendRoot,
    env: {
      ...process.env,
      DATABASE_URL: "",
      PRISMA_CHECKSUM_DATABASE_URL: "",
      PRISMA_CHECKSUM_ENABLED: "",
      PRISMA_CHECKSUM_REQUIRED: "",
      ...extraEnv,
    },
    encoding: "utf8",
  });

const parseJson = (result) => {
  assert.strictEqual(result.stderr, "", `script wrote unexpected stderr: ${result.stderr}`);
  return JSON.parse(result.stdout);
};

const safeSkip = runScript();
assert.strictEqual(safeSkip.status, 0, safeSkip.stdout || safeSkip.stderr);
const safeSkipPayload = parseJson(safeSkip);
assert.strictEqual(safeSkipPayload.ok, true, "default mode should safe-skip without DB context");
assert.strictEqual(safeSkipPayload.skipped, true, "default mode should report skipped");
assert.doesNotMatch(safeSkip.stdout, /DATABASE_URL|postgres:\/\/|postgresql:\/\/|password|secret/i, "default skip leaked secret-like output");

const requiredMissingDb = runScript({ PRISMA_CHECKSUM_REQUIRED: "true" });
assert.strictEqual(requiredMissingDb.status, 1, requiredMissingDb.stdout || requiredMissingDb.stderr);
const requiredPayload = parseJson(requiredMissingDb);
assert.strictEqual(requiredPayload.ok, false, "required mode should fail without DB context");
assert.strictEqual(requiredPayload.required, true, "required mode should report required=true");
assert.match(requiredPayload.reason, /Missing PRISMA_CHECKSUM_DATABASE_URL/i);
assert.doesNotMatch(requiredMissingDb.stdout, /postgres:\/\/|postgresql:\/\/|password|secret/i, "required failure leaked secret-like output");

console.log("prisma checksum smoke script tests passed");

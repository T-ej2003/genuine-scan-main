const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");

const workerPath = path.resolve(__dirname, "../dist/worker.js");
const run = (overrides) => spawnSync(process.execPath, [workerPath], {
  cwd: path.resolve(__dirname, ".."),
  env: {
    ...process.env,
    NODE_ENV: "test", MSCQR_WORKER_MODE: "printing", REDIS_URL: "", REDIS_HOST: "",
    INTEGRATION_WORKER_BOOT_ONLY: "false", INTEGRATION_DISABLE_BACKGROUND_LOOPS: "false",
    RUN_PRINT_RECONCILER: "true", RUN_DISTRIBUTED_LEASES: "true",
    ...overrides,
  },
  encoding: "utf8",
  timeout: 10_000,
});

for (const overrides of [
  { RUN_PRINT_RECONCILER: "false" },
  { RUN_DISTRIBUTED_LEASES: "false" },
  { DATABASE_URL: "postgresql://worker@127.0.0.1:1/disposable" },
]) {
  const result = run(overrides);
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, 1, output);
  assert.doesNotMatch(output, /Printing worker started/);
  assert.match(output, overrides.DATABASE_URL ? /Can't reach database server|Connection refused|P1001/ : /Printing worker reconciliation and leases must be enabled/);
}

console.log("Printing worker fails closed on disabled scheduling and unavailable PostgreSQL");

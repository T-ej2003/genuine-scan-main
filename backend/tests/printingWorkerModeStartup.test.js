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
  { REDIS_URL: "", REDIS_HOST: "" },
  { REDIS_URL: "redis://127.0.0.1:1" },
]) {
  const result = run(overrides);
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  assert.equal(result.status, 1, output);
  assert.doesNotMatch(output, /Printing worker started/);
  assert.match(output, overrides.REDIS_URL === "" ? /Printing worker requires configured Redis for distributed leases/ : overrides.REDIS_URL ? /Connection refused|ECONNREFUSED|Printing worker requires healthy Redis/ : /Printing worker reconciliation and leases must be enabled/);
}

console.log("Printing worker fails closed on disabled scheduling and unavailable Redis");

const unleasedReconciler = spawnSync(process.execPath, ["-e", `
  const stop = require('./dist/services/printConfirmationReconciler').startPrintConfirmationReconciler();
  setTimeout(() => { stop(); process.exit(0); }, 100);
`], {
  cwd: path.resolve(__dirname, ".."),
  env: {
    ...process.env, REDIS_URL: "", REDIS_HOST: "", RUN_PRINT_RECONCILER: "true",
    INTEGRATION_DISABLE_BACKGROUND_LOOPS: "false",
  },
  encoding: "utf8", timeout: 5000,
});
assert.equal(unleasedReconciler.status, 0, unleasedReconciler.stderr);
assert.match(`${unleasedReconciler.stdout}${unleasedReconciler.stderr}`, /Printing reconciliation requires configured Redis for distributed leases/);

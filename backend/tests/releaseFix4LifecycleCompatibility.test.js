const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const read = (relative) => fs.readFileSync(path.join(root, relative), "utf8");

const worker = read("backend/src/worker.ts");
const http = read("backend/src/index.ts");
const rollup = read("backend/src/services/analyticsRollupService.ts");
const dashboard = read("src/pages/Dashboard.tsx");
const qrClient = read("src/lib/api/internal-client-licensee-qr.ts");

assert.match(worker, /stopAnalyticsRollupWorker = startAnalyticsRollupWorker\(\)/);
assert.match(worker, /stopAnalyticsRollupWorker\?\.\(\)/);
assert.doesNotMatch(http, /startAnalyticsRollupWorker/);
assert.match(rollup, /if \(activeAnalyticsRollupStop\) return activeAnalyticsRollupStop/);

for (const source of [dashboard, qrClient]) {
  assert.doesNotMatch(
    source,
    /legacy-report|legacy-rotate|Legacy public code report|getLegacyPublicCodeReport|rotateLegacyPublicCodes/
  );
}

const distRoot = path.resolve(root, "backend/dist");
const leasePath = require.resolve(path.join(distRoot, "services/distributedLeaseService.js"));
let leaseAttempts = 0;
require.cache[leasePath] = {
  id: leasePath,
  filename: leasePath,
  loaded: true,
  exports: {
    withDistributedLease: async () => {
      leaseAttempts += 1;
      return { acquired: false };
    },
  },
};

process.env.RUN_ANALYTICS_ROLLUP_WORKER = "true";
delete process.env.INTEGRATION_DISABLE_BACKGROUND_LOOPS;

const realSetTimeout = global.setTimeout;
const realClearTimeout = global.clearTimeout;
const timers = [];
global.setTimeout = (callback, delay) => {
  const timer = { callback, delay };
  timers.push(timer);
  return timer;
};
global.clearTimeout = (timer) => {
  const index = timers.indexOf(timer);
  if (index >= 0) timers.splice(index, 1);
};

(async () => {
  try {
    const { startAnalyticsRollupWorker } = require(path.join(distRoot, "services/analyticsRollupService.js"));
    const firstStop = startAnalyticsRollupWorker();
    const duplicateStop = startAnalyticsRollupWorker();
    assert.equal(duplicateStop, firstStop, "repeat startup must reuse the active loop");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(leaseAttempts, 1);
    assert.equal(timers.length, 1);
    firstStop();
    assert.equal(timers.length, 0);

    const restartedStop = startAnalyticsRollupWorker();
    assert.notEqual(restartedStop, firstStop, "a stopped worker may be started cleanly");
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(leaseAttempts, 2);
    assert.equal(timers.length, 1);
    restartedStop();
    assert.equal(timers.length, 0);
    console.log("Release Fix 4 lifecycle compatibility: PASS");
  } finally {
    global.setTimeout = realSetTimeout;
    global.clearTimeout = realClearTimeout;
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

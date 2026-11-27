const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../dist");
const runtimePath = require.resolve(path.join(distRoot, "rls-waves/session-b/b01/runtimeClients.js"));
let dailyCount = 0;
let failDaily = false;
const calls = [];
require.cache[runtimePath] = {
  id: runtimePath, filename: runtimePath, loaded: true,
  exports: { getB01AuthenticatedPrisma: () => ({
    $queryRaw: async (parts, ...values) => {
      const sql = parts.join("?");
      calls.push({ sql, values });
      if (sql.includes("qr_scan_analytics")) {
        if (failDaily) throw new Error("scan analytics unavailable");
        return [{ result: { scope: { mode: "daily-count" }, scansToday: dailyCount } }];
      }
      return [{ result: { total: 4, byStatus: { DORMANT: 4 } } }];
    },
  }) },
};

const { readStats, readDailyScanCount } = require(path.join(distRoot, "rls-waves/session-c/c01/qrSystemRepository.js"));
(async () => {
  const input = { capability: "local-capability", requestId: "local-request", licenseeId: "local-tenant" };
  assert.equal((await readStats(input)).scansToday, 0);
  dailyCount = 3;
  assert.equal((await readStats(input)).scansToday, 3);
  assert(calls.some(({ sql, values }) => sql.includes("qr_scan_analytics") && values.includes('{"dailyCount":true}')));
  const before = calls.length;
  assert.equal((await readStats({ ...input, licenseeId: null })).scansToday, undefined);
  assert.equal(calls.length, before + 1);
  dailyCount = 5;
  assert.equal(await readDailyScanCount({ ...input, licenseeId: null }), 5);
  assert(calls.at(-1).values.includes(null));
  failDaily = true;
  await assert.rejects(readStats(input), /scan analytics unavailable/);
  console.log("QR daily stats mapping passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

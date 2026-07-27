const assert = require("node:assert/strict");
const path = require("node:path");

const distRoot = path.resolve(__dirname, "../dist");
const mockModule = (relativePath, exportsValue) => {
  const filename = require.resolve(path.join(distRoot, relativePath));
  require.cache[filename] = { id: filename, filename, loaded: true, exports: exportsValue };
};

let queryIndex = 0;
const queryResults = [
  [{ scanEvents: 3, matchedBatches: 2 }],
  [{
    totalScanEvents: 3, firstScanEvents: 2, repeatScanEvents: 1, blockedEvents: 0,
    trustedOwnerEvents: 0, externalEvents: 3, namedLocationEvents: 0, knownDeviceEvents: 0,
  }],
  [{ batchId: "batch-a", scanEvents: 2 }, { batchId: "batch-b", scanEvents: 1 }],
  [{ label: "Jan 01", scanEvents: 3 }],
];
mockModule("config/database.js", {
  __esModule: true,
  default: { $queryRaw: async () => queryResults[queryIndex++ % queryResults.length] },
});
mockModule("services/locationService.js", {
  compactDeviceLabel: () => null,
  reverseGeocode: async () => null,
});
mockModule("services/scanLogReportingService.js", {
  getScanLogReportingRelationName: async () => "QrScanLog",
  listScanLogsForReporting: async () => ({ logs: [], total: 0 }),
});
mockModule("services/verificationDecisionReadService.js", {
  listLatestDecisionByBatchIds: async () => new Map(),
  listLatestDecisionByQrCodeIds: async () => new Map(),
});

const aggregate = {
  totals: { total: 3, dormant: 2, allocated: 1, printed: 0, redeemed: 0, blocked: 0, created: 2 },
  trend: [{ label: "Jan 01", total: 3, dormant: 2, allocated: 1, printed: 0, redeemed: 0, blocked: 0, scanEvents: 0 }],
};
mockModule("rls-waves/session-c/c01/qrSystemRepository.js", {
  readInventoryProjection: async ({ offset }) => ({
    total: 2,
    aggregate,
    rows: [{
      batchId: offset ? "batch-b" : "batch-a",
      name: offset ? "Batch B" : "Batch A",
      licenseeId: "licensee-a",
      startCode: offset ? "B1" : "A1",
      endCode: offset ? "B1" : "A2",
      totalCodes: offset ? 1 : 2,
      createdAt: offset ? "2026-01-02T00:00:00.000Z" : "2026-01-01T00:00:00.000Z",
      status: offset ? "ALLOCATED" : "DORMANT",
      count: offset ? 1 : 2,
    }],
  }),
});

(async () => {
  const { getQrTrackingAnalytics } = require("../dist/services/qrTrackingAnalyticsService");
  const base = {
    databaseSessionCapability: "capability",
    requestId: "request",
    licenseeId: "licensee-a",
    limit: 1,
  };
  const first = await getQrTrackingAnalytics({ ...base, offset: 0 });
  const second = await getQrTrackingAnalytics({ ...base, offset: 1 });

  assert.deepEqual(first.totals, aggregate.totals);
  assert.deepEqual(second.totals, aggregate.totals);
  assert.deepEqual(first.trend, second.trend);
  assert.equal(first.scope.quantities.distinctCodes, 3);
  assert.equal(second.scope.quantities.distinctCodes, 3);
  assert.equal(first.scope.quantities.matchedBatches, 2);
  assert.equal(second.scope.quantities.matchedBatches, 2);
  assert.deepEqual(first.batches.map((row) => row.id), ["batch-a"]);
  assert.deepEqual(second.batches.map((row) => row.id), ["batch-b"]);
  console.log("QR analytics pagination regression tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

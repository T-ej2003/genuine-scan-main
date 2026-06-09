const assert = require("assert");

const {
  buildLegacyQrRiskObjectKeys,
  buildLegacyQrRiskReportArtifacts,
  compareLegacyRiskTotals,
} = require("../dist/services/legacyQrRiskReportJobService");

const report = {
  generatedAt: "2026-06-09T00:00:00.000Z",
  totalLegacyCodes: 3,
  knownUnsafeLegacyCodes: 2,
  potentiallyRotatableLegacyCodes: 1,
  blockerReasonCounts: {
    printed_at_present: 1,
    scanned_at_present: 1,
  },
  note: "test report",
  groups: [
    {
      brandId: "brand-1",
      brandName: "Brand One",
      brandPrefix: "B1",
      batchId: "batch-1",
      batchName: "Batch One",
      batchStartCode: "B1001",
      batchEndCode: "B1003",
      batchPrintedAt: "2026-06-08T00:00:00.000Z",
      batchPrintPackDownloadedAt: null,
      batchLifecycleState: "PRINT_CONFIRMED",
      batchReleasedAt: null,
      status: "PRINTED",
      count: 3,
      knownUnsafeCount: 2,
      potentiallyRotatableCount: 1,
    },
  ],
};

const artifacts = buildLegacyQrRiskReportArtifacts(report);
assert.match(artifacts.json, /"generatedAt": "2026-06-09T00:00:00.000Z"/);
assert.match(artifacts.json, /"totalLegacyCodes": 3/);
assert.match(artifacts.json, /"blockerReasonCounts"/);
assert.match(artifacts.csv, /generatedAt,totalLegacyCodes,knownUnsafeLegacyCodes,potentiallyRotatableLegacyCodes,blockerReasonCounts/);
assert.match(artifacts.csv, /2026-06-09T00:00:00.000Z,3,2,1/);
assert.match(artifacts.csv, /printed_at_present/);

const noPrevious = compareLegacyRiskTotals(null, report);
assert.strictEqual(noPrevious.previousTotal, null);
assert.strictEqual(noPrevious.currentTotal, 3);
assert.strictEqual(noPrevious.increased, false);

const increased = compareLegacyRiskTotals({ totalLegacyCodes: 2 }, report);
assert.strictEqual(increased.previousTotal, 2);
assert.strictEqual(increased.currentTotal, 3);
assert.strictEqual(increased.increased, true);

const decreased = compareLegacyRiskTotals({ totalLegacyCodes: 4 }, report);
assert.strictEqual(decreased.increased, false);

const keys = buildLegacyQrRiskObjectKeys({
  prefix: "risk/legacy",
  now: new Date("2026-06-09T12:34:56.789Z"),
});
assert.strictEqual(keys.json, "risk/legacy/2026-06-09T12-34-56-789Z.json");
assert.strictEqual(keys.csv, "risk/legacy/2026-06-09T12-34-56-789Z.csv");
assert.strictEqual(keys.latestJson, "risk/legacy/latest.json");

console.log("legacy QR risk report job tests passed");

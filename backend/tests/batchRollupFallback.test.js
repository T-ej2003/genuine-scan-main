const assert = require("node:assert/strict");
const { QRStatus } = require("@prisma/client");
const { enrichBatchSummaries } = require("../dist/services/batchAllocationService");

const batchId = "40000000-0000-4000-8000-000000000701";
const licenseeId = "40000000-0000-4000-8000-000000000201";
const boundary = {
  databaseSessionCapability: "B".repeat(43), purpose: "batch-operational-read",
  requestId: "40000000-0000-4000-8000-000000000702",
  auditId: "40000000-0000-4000-8000-000000000703",
  requestedLicenseeId: licenseeId, routeSurface: "GET /api/qr/batches",
  focusBatchId: null, scopeFingerprint: "a".repeat(32),
};
const batch = {
  id: batchId, name: "Source", licenseeId, manufacturerId: null, parentBatchId: null, rootBatchId: null,
  startCode: "L0011", endCode: "L0150", totalCodes: 140, lifecycleState: "CODES_GENERATED",
  printedAt: null, releasedAt: null,
};

(async () => {
  let fallbackCalls = 0;
  let rollupCount = 150;
  const db = { async $queryRaw(strings, ...values) {
    const sql = strings.join("?");
    assert(values.includes(licenseeId), "every summary read keeps the authorized tenant selector");
    if (sql.includes("batch_inventory_rollups")) return [{ batch_id: batchId,
      dormant: rollupCount, active: 0, allocated: 0, activated: 0,
      printed: 0, redeemed: 0, blocked: 0, scanned: 0 }];
    if (sql.includes("batch_unassigned_ranges")) return [{ batch_id: batchId, start_code: "L0011", end_code: "L0150" }];
    if (sql.includes("batch_reservable_qr_summaries")) return [];
    if (sql.includes("batch_status_fallback")) {
      fallbackCalls += 1;
      return [{ batch_id: batchId, status: QRStatus.DORMANT, count: batch._count?.qrCodes ?? batch.totalCodes }];
    }
    throw new Error(`Unexpected summary query: ${sql}`);
  } };

  const [reconciled] = await enrichBatchSummaries([batch], db, boundary);
  assert.equal(reconciled.unassignedRemainingCodes, 140);
  assert.equal(fallbackCalls, 1);
  rollupCount = 140;
  await enrichBatchSummaries([batch], db, boundary);
  assert.equal(fallbackCalls, 1, "matching rollups avoid extra QR status reads");
  batch._count = { qrCodes: 130 };
  rollupCount = 130;
  const [allocated] = await enrichBatchSummaries([batch], db, boundary);
  assert.equal(allocated.unassignedRemainingCodes, 130);
  assert.equal(fallbackCalls, 1, "parent allocation does not make a correct live rollup stale");
  rollupCount = 129;
  await enrichBatchSummaries([batch], db, boundary);
  assert.equal(fallbackCalls, 2, "a true mismatch still checks live QR status");

  const parent = { ...batch, _count: { qrCodes: 140 } };
  const childId = "40000000-0000-4000-8000-000000000704";
  const child = { ...batch, id: childId, manufacturerId: "40000000-0000-4000-8000-000000000705", totalCodes: 1, _count: { qrCodes: 1 } };
  const calls = [];
  const mixedDb = { async $queryRaw(strings, ...values) {
    const sql = strings.join("?");
    if (sql.includes("batch_inventory_rollups")) return [batchId, childId].map((id) => ({
      batch_id: id, dormant: id === batchId ? 140 : 0, active: 0, allocated: id === childId ? 1 : 0,
      activated: 0, printed: 0, redeemed: 0, blocked: 0, scanned: 0,
    }));
    if (sql.includes("batch_unassigned_ranges")) {
      calls.push(["parent", values]);
      return [{ batch_id: batchId, start_code: "L0011", end_code: "L0150" }];
    }
    if (sql.includes("batch_reservable_qr_summaries")) {
      calls.push(["child", values]);
      return [{ batch_id: childId, count: 1, start_code: "L0151", end_code: "L0151" }];
    }
    throw new Error(`Unexpected summary query: ${sql}`);
  } };
  const [parentSummary, childSummary] = await enrichBatchSummaries([parent, child], mixedDb, boundary);
  assert.equal(parentSummary.unassignedRemainingCodes, 140);
  assert.equal(childSummary.printableCodes, 1);
  assert.equal(calls.length, 2);
  assert(JSON.stringify(calls[0][1]).includes(batchId) && !JSON.stringify(calls[0][1]).includes(childId));
  assert(JSON.stringify(calls[1][1]).includes(childId) && !JSON.stringify(calls[1][1]).includes(batchId));
  console.log("Stale batch rollup fallback passed");
})().catch((error) => { console.error(error); process.exitCode = 1; });

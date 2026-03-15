const {
  countDormantInventory,
  countAllocatedInventory,
  countPrintedInventory,
  countRedeemedInventory,
  countBlockedInventory,
  summarizeQrStatusCounts,
} = require("../dist/services/qrStatusMetrics");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const run = () => {
  const counts = {
    DORMANT: 12,
    ACTIVE: 8,
    ALLOCATED: 30,
    ACTIVATED: 5,
    PRINTED: 11,
    REDEEMED: 7,
    SCANNED: 3,
    BLOCKED: 2,
  };

  assert(countDormantInventory(counts) === 20, "Dormant inventory should include ACTIVE stock");
  assert(countAllocatedInventory(counts) === 35, "Allocated inventory should exclude ACTIVE stock");
  assert(countPrintedInventory(counts) === 11, "Printed inventory should use PRINTED only");
  assert(countRedeemedInventory(counts) === 10, "Redeemed inventory should include SCANNED");
  assert(countBlockedInventory(counts) === 2, "Blocked inventory should use BLOCKED only");

  const summary = summarizeQrStatusCounts(counts);
  assert(summary.dormant === 20, "Summaries should expose dormant inventory using DORMANT plus ACTIVE");
  assert(summary.allocated === 35, "Summaries should expose allocated inventory using ALLOCATED plus ACTIVATED");
  assert(summary.printed === 11, "Summaries should expose printed inventory");
  assert(summary.redeemed === 10, "Summaries should expose redeemed inventory");
  assert(summary.blocked === 2, "Summaries should expose blocked inventory");

  console.log("qr status metrics tests passed");
};

run();

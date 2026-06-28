const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { PrintItemState, PrintJobStatus, PrintPipelineState, PrintSessionStatus } = require("@prisma/client");
const { describeOriginalPrintJobForReissue } = require("../dist/services/printReissueService");

const repoRoot = path.resolve(__dirname, "..", "..");
const read = (relativePath) => fs.readFileSync(path.join(repoRoot, relativePath), "utf8");

const item = (code, state, confirmed = false) => ({
  code: `internal-${code}`,
  state,
  printConfirmedAt: confirmed ? new Date("2026-06-28T10:00:00.000Z") : null,
  confirmationEvidence: confirmed ? { source: "connector" } : null,
  qrCode: { displayCode: code },
});

const stoppedJob = (items) => ({
  id: "job-original",
  jobNumber: "PJ-ORIGINAL",
  status: PrintJobStatus.PARTIALLY_COMPLETED,
  pipelineState: PrintPipelineState.STOPPED,
  quantity: items.length,
  itemCount: items.length,
  rangeStart: items[0]?.qrCode?.displayCode || null,
  rangeEnd: items[items.length - 1]?.qrCode?.displayCode || null,
  printSession: {
    id: "session-original",
    status: PrintSessionStatus.STOPPED,
    items,
  },
});

const zeroConfirmed = describeOriginalPrintJobForReissue(
  stoppedJob([
    item("QR-000001", PrintItemState.CANCELLED),
    item("QR-000002", PrintItemState.CANCELLED),
    item("QR-000003", PrintItemState.CANCELLED),
  ])
);

assert.equal(zeroConfirmed.originalConfirmedCount, 0, "Zero-confirmed recovery must not count browser/user intent as printed");
assert.equal(zeroConfirmed.originalPendingCount, 3, "Zero-confirmed recovery should keep all labels pending");
assert.equal(zeroConfirmed.recoveryStartLabel, "QR-000001", "Zero-confirmed recovery starts at original first label");
assert.equal(zeroConfirmed.recoveryEndLabel, "QR-000003", "Zero-confirmed recovery ends at original requested range end");
assert.equal(zeroConfirmed.requestedCount, 3, "Zero-confirmed replacement count should equal the unconfirmed range");

const partial = describeOriginalPrintJobForReissue(
  stoppedJob([
    item("QR-000001", PrintItemState.CLOSED, true),
    item("QR-000002", PrintItemState.PRINT_CONFIRMED, true),
    item("QR-000003", PrintItemState.CANCELLED),
    item("QR-000004", PrintItemState.CANCELLED),
  ])
);

assert.equal(partial.originalConfirmedCount, 2, "Confirmed connector evidence should remain counted");
assert.equal(partial.originalPendingCount, 2, "Only unconfirmed labels should be pending");
assert.equal(partial.recoveryStartLabel, "QR-000003", "Partial recovery starts at the first unconfirmed label");
assert.equal(partial.recoveryEndLabel, "QR-000004", "Partial recovery ends at the original range end");
assert.equal(partial.requestedCount, 2, "Partial replacement count should equal remaining unconfirmed labels");

const projectedLargeRun = describeOriginalPrintJobForReissue(
  {
    id: "job-large",
    jobNumber: "PJ-LARGE",
    status: PrintJobStatus.PARTIALLY_COMPLETED,
    pipelineState: PrintPipelineState.STOPPED,
    itemCount: 100000,
    rangeStart: "QR-000001",
    rangeEnd: "QR-100000",
    printSession: { id: "session-large", status: PrintSessionStatus.STOPPED },
  },
  {
    printJobId: "job-large",
    requestedCount: 100000,
    requestedRangeStart: "QR-000001",
    requestedRangeEnd: "QR-100000",
    confirmedCount: 99990,
    pendingCount: 10,
    failedCount: 1,
    recoveryStartLabel: "QR-099991",
    recoveryEndLabel: "QR-100000",
  }
);

assert.equal(projectedLargeRun.originalConfirmedCount, 99990, "Projection should supply confirmed count without hydrating items");
assert.equal(projectedLargeRun.originalPendingCount, 10, "Projection should supply pending count without hydrating items");
assert.equal(projectedLargeRun.recoveryStartLabel, "QR-099991", "Projection should supply first unconfirmed label");
assert.equal(projectedLargeRun.recoveryEndLabel, "QR-100000", "Projection should supply recovery end label");
assert.equal(projectedLargeRun.requestedCount, 10, "Projected replacement count should use pending labels for recovery");

const serviceSource = read("backend/src/services/printReissueService.ts");
const workflowSource = read("backend/src/services/printReissueRequestWorkflowService.ts");
const controllerSource = read("backend/src/controllers/print-job/queryHandlers.ts");

assert(serviceSource.includes("findUnresolvedRecoveryRangeForBatch"), "Replacement printing must check unresolved recovery before allocating labels");
assert(serviceSource.includes("replacementRangeStart") && serviceSource.includes("replacementRangeEnd"), "Replacement print jobs must carry backend-calculated recovery ranges");
assert(serviceSource.includes("rangeStart: replacementRangeStart") && serviceSource.includes("rangeEnd: replacementRangeEnd"), "Replacement reservation must use the calculated range");
assert(serviceSource.includes("projectPrintJobReissueSummaries"), "Large print jobs need an aggregate projection for reissue summaries");
assert(workflowSource.includes("projectPrintJobReissueSummaries"), "Reissue list/create responses must use projected recovery summaries");
assert(!workflowSource.includes("items:"), "Reissue request list/review queries must not hydrate print session items");
assert(serviceSource.includes("PRINT_REISSUE_ORIGINAL_NOT_RECOVERABLE"), "Invalid original lifecycle must be a typed business conflict");
assert(serviceSource.includes("NOT_ENOUGH_RECOVERABLE_LABELS"), "Invalid recovery range must return a typed 422-style conflict");
assert(controllerSource.includes("error.statusCode") && controllerSource.includes("error?.details"), "Reissue print endpoint must return structured safe business errors");
assert(!/displayCode\s*\|\|\s*[^,\n]*code/i.test(serviceSource), "Print reissue service must not fall back from displayCode to public QR identity");
assert(serviceSource.includes("REPLACEMENT_QR_PUBLIC_CODE_MISSING"), "Replacement printing must fail closed when QRCode.code is missing");

console.log("print reissue recovery range tests passed");

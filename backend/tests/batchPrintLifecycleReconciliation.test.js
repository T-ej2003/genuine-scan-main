const prisma = require("../dist/config/database").default;
const {
  BatchLifecycleState,
  PrintJobStatus,
  PrintSessionStatus,
  QRStatus,
} = require("@prisma/client");
const {
  buildBatchPrintReadinessFromSummary,
  reconcileBatchPrintLifecycle,
} = require("../dist/services/batchPrintLifecycleReconciliationService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const backup = (target, key) => {
  const original = target[key];
  return () => {
    target[key] = original;
  };
};

const installReconciliationMocks = (overrides = {}) => {
  const restore = [
    backup(prisma.batch, "findUnique"),
    backup(prisma.batch, "updateMany"),
    backup(prisma.qRCode, "count"),
    backup(prisma.printJob, "count"),
    backup(prisma.printJob, "findFirst"),
    backup(prisma.printSession, "count"),
    backup(prisma.printAuditEvent, "create"),
    backup(prisma.auditLog, "create"),
    backup(prisma, "$queryRaw"),
  ];
  const calls = { batchUpdates: [], auditEvents: [], auditLogs: [], printJobCountArgs: [], printJobFindArgs: [] };
  const batch = {
    id: "batch-1",
    licenseeId: "licensee-1",
    manufacturerId: "manufacturer-1",
    parentBatchId: "source-batch-1",
    rootBatchId: "source-batch-1",
    lifecycleState: BatchLifecycleState.DRAFT,
    releasedAt: null,
    printedAt: null,
    ...overrides.batch,
  };

  prisma.batch.findUnique = async (args) => {
    if (args.select?.printedAt && !args.select?.lifecycleState) return { printedAt: batch.printedAt };
    return batch;
  };
  prisma.batch.updateMany = async (args) => {
    calls.batchUpdates.push(args);
    if (args.data?.lifecycleState) batch.lifecycleState = args.data.lifecycleState;
    return { count: 1 };
  };
  prisma.qRCode.count = async (args) => {
    const status = args.where?.status;
    if (status === QRStatus.ALLOCATED) return overrides.allocatedQrCount ?? 3;
    if (status?.in) return overrides.printedQrCount ?? 0;
    return overrides.qrCount ?? 3;
  };
  prisma.printJob.count = async (args) => {
    calls.printJobCountArgs.push(args);
    return overrides.confirmedPrintJobCount ?? 0;
  };
  prisma.printJob.findFirst = async (args) => {
    calls.printJobFindArgs.push(args);
    return (overrides.confirmedPrintJobCount ?? 0) > 0 ? { id: "print-job-1" } : null;
  };
  prisma.printSession.count = async () => overrides.completedPrintSessionCount ?? 0;
  prisma.printAuditEvent.create = async (args) => {
    calls.auditEvents.push(args);
    return {};
  };
  prisma.auditLog.create = async (args) => {
    calls.auditLogs.push(args);
    return {};
  };
  prisma.$queryRaw = async () => [{ count: overrides.availableToPrint ?? 3 }];

  return { restore, calls, batch };
};

const runDryRunTest = async () => {
  const { restore, calls } = installReconciliationMocks({ confirmedPrintJobCount: 1 });
  try {
    const result = await reconcileBatchPrintLifecycle({ batchId: "batch-1", apply: false });
    assert(result.targetState === BatchLifecycleState.PRINT_CONFIRMED, "dry-run should detect print evidence drift");
    assert(result.mutated === false, "dry-run must not mutate");
    assert(calls.batchUpdates.length === 0, "dry-run must not update the batch");
    const printJobFilters = JSON.stringify([calls.printJobCountArgs, calls.printJobFindArgs]);
    assert(!printJobFilters.includes("completedAt"), "completedAt must not count as physical print confirmation evidence");
  } finally {
    restore.reverse().forEach((fn) => fn());
  }
};

const runApplyTest = async () => {
  const { restore, calls, batch } = installReconciliationMocks({
    printedQrCount: 2,
    confirmedPrintJobCount: 1,
  });
  try {
    const result = await reconcileBatchPrintLifecycle({
      batchId: "batch-1",
      actorUserId: "operator-1",
      apply: true,
    });
    assert(result.mutated === true, "apply should mutate detected drift");
    assert(result.afterState === BatchLifecycleState.PRINT_CONFIRMED, "apply should repair to PRINT_CONFIRMED");
    assert(batch.lifecycleState === BatchLifecycleState.PRINT_CONFIRMED, "mock batch should reflect repair");
    assert(calls.auditEvents.length === 1, "apply should record print audit evidence");
    assert(calls.auditLogs.length === 1, "apply should record audit evidence");
  } finally {
    restore.reverse().forEach((fn) => fn());
  }
};

const runTrueDraftReadinessTest = () => {
  const readiness = buildBatchPrintReadinessFromSummary({
    batchId: "batch-2",
    lifecycleState: BatchLifecycleState.DRAFT,
    availableToPrint: 10,
    printedCodes: 0,
    allocatedCodes: 0,
    manufacturerId: null,
  });
  assert(readiness.printable === false, "truly DRAFT batches must not be printable");
  assert(readiness.requiredPreviousStep, "blocked readiness should include next step");
};

const runPartialBatchReadinessTest = () => {
  const partial = buildBatchPrintReadinessFromSummary({
    batchId: "partial-batch",
    lifecycleState: BatchLifecycleState.PRINT_CONFIRMED,
    printedAt: "2026-11-18T20:09:30.390Z",
    availableToPrint: 19,
    printedCodes: 1,
    allocatedCodes: 19,
    manufacturerId: "manufacturer-1",
  });
  assert(partial.printable === true, "a confirmed print run must not block 19 untouched QR codes");
  assert(partial.availableToPrint === 19, "readiness must retain the available count");
  assert(buildBatchPrintReadinessFromSummary({
    batchId: "sampled-batch", lifecycleState: BatchLifecycleState.SAMPLE_VERIFIED,
    availableToPrint: 19,
  }).printable === false, "a prior sample cannot authorize another print run without resetting sample evidence");
  assert(buildBatchPrintReadinessFromSummary({
    batchId: "suspended-batch", lifecycleState: BatchLifecycleState.PRINT_CONFIRMED,
    suspendedAt: "2026-11-24T16:00:00Z", availableToPrint: 19,
  }).printable === false, "suspended batches must match the database create guard");
};

Promise.resolve()
  .then(runDryRunTest)
  .then(runApplyTest)
  .then(runTrueDraftReadinessTest)
  .then(runPartialBatchReadinessTest)
  .then(() => {
    console.log("batch print lifecycle reconciliation tests passed");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

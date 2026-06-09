const {
  assertBatchTransitionAllowed,
  BatchStateTransitionError,
} = require("../dist/services/batchStateMachineService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const expectCode = (code, fn) => {
  try {
    fn();
  } catch (error) {
    assert(error instanceof BatchStateTransitionError, `${code} should throw BatchStateTransitionError`);
    assert(error.code === code, `expected ${code}, got ${error.code}`);
    return;
  }
  throw new Error(`${code} should have been rejected`);
};

const batch = (lifecycleState, overrides = {}) => ({
  id: "batch-1",
  lifecycleState,
  releasedAt: null,
  totalCodes: 10,
  ...overrides,
});

const confirmedJob = {
  id: "job-1",
  status: "CONFIRMED",
  sentAt: new Date("2026-06-09T09:00:00.000Z"),
  confirmedAt: new Date("2026-06-09T09:05:00.000Z"),
};

const run = () => {
  expectCode("QR_CODES_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("DRAFT", { totalCodes: 0 }),
      toStatus: "RELEASED",
      actor: { userId: "operator-1" },
      context: { qrCodeCount: 0 },
    })
  );

  expectCode("PRINT_ACK_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("CODES_GENERATED"),
      toStatus: "RELEASED",
      actor: { userId: "operator-1" },
      context: { qrCodeCount: 10 },
    })
  );

  expectCode("PRINT_ACK_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("CODES_GENERATED"),
      toStatus: "PHYSICAL_PRINT_CONFIRMED",
      actor: { userId: "operator-1" },
      context: { qrCodeCount: 10 },
    })
  );

  expectCode("PHYSICAL_CONFIRMATION_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("PRINT_ACKNOWLEDGED"),
      toStatus: "SAMPLE_SCAN_VERIFIED",
      actor: { userId: "operator-1" },
      context: {
        qrCodeCount: 10,
        printJob: { id: "job-1", status: "SENT", sentAt: new Date("2026-06-09T09:00:00.000Z") },
      },
    })
  );

  expectCode("SAMPLE_SCAN_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("PRINT_CONFIRMED"),
      toStatus: "RELEASED",
      actor: { userId: "operator-1" },
      context: {
        qrCodeCount: 10,
        printJob: confirmedJob,
        sampleScanSatisfied: false,
      },
    })
  );

  expectCode("APPROVAL_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("SAMPLE_VERIFIED"),
      toStatus: "RELEASED",
      actor: { userId: "operator-1" },
      context: {
        qrCodeCount: 10,
        printJob: confirmedJob,
        sampleScanSatisfied: true,
        approvalRequired: true,
        approvalSatisfied: false,
      },
    })
  );

  expectCode("MAKER_CANNOT_APPROVE", () =>
    assertBatchTransitionAllowed({
      batch: batch("SAMPLE_VERIFIED"),
      toStatus: "RELEASED",
      actor: { userId: "operator-1" },
      context: {
        qrCodeCount: 10,
        printJob: confirmedJob,
        sampleScanSatisfied: true,
        approvalRequired: true,
        approvalSatisfied: true,
        makerUserId: "operator-1",
      },
    })
  );

  expectCode("CHECKER_REQUIRED", () =>
    assertBatchTransitionAllowed({
      batch: batch("SAMPLE_VERIFIED"),
      toStatus: "RELEASED",
      actor: { userId: "operator-2" },
      context: {
        qrCodeCount: 10,
        printJob: confirmedJob,
        sampleScanSatisfied: true,
        approvalRequired: true,
        approvalSatisfied: true,
        prerequisiteActorUserIds: ["operator-2"],
      },
    })
  );

  expectCode("BATCH_ALREADY_RELEASED", () =>
    assertBatchTransitionAllowed({
      batch: batch("RELEASED", { releasedAt: new Date("2026-06-09T10:00:00.000Z") }),
      toStatus: "SAMPLE_SCAN_VERIFIED",
      actor: { userId: "operator-1" },
      context: { qrCodeCount: 10, printJob: confirmedJob },
    })
  );

  assertBatchTransitionAllowed({
    batch: batch("SAMPLE_VERIFIED"),
    toStatus: "RELEASED",
    actor: { userId: "checker-1" },
    context: {
      qrCodeCount: 10,
      printJob: confirmedJob,
      sampleScanSatisfied: true,
      approvalRequired: true,
      approvalSatisfied: true,
      makerUserId: "operator-1",
      prerequisiteActorUserIds: ["operator-1"],
    },
  });

  console.log("batch state machine tests passed");
};

run();

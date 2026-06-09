const assert = require("assert");
const prisma = require("../dist/config/database").default;
const {
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintSessionStatus,
  QRStatus,
  UserRole,
} = require("@prisma/client");
const auditService = require("../dist/services/auditService");
const networkDirectPrintService = require("../dist/services/networkDirectPrintService");
const {
  pausePrintJob,
  stopPrintJob,
  validatePrintOperationReason,
} = require("../dist/services/printOperationControlService");

const backup = (target, key) => {
  const original = target[key];
  return () => {
    target[key] = original;
  };
};

const scope = {
  role: UserRole.MANUFACTURER,
  userId: "manufacturer-1",
  licenseeId: "licensee-1",
};

const activeJob = () => ({
  id: "job-1",
  batchId: "batch-1",
  manufacturerId: "manufacturer-1",
  status: PrintJobStatus.SENT,
  pipelineState: PrintPipelineState.SENT_TO_PRINTER,
  sentAt: new Date("2026-06-09T10:00:00.000Z"),
  batch: { id: "batch-1", licenseeId: "licensee-1", name: "Factory labels" },
  printSession: {
    id: "session-1",
    status: PrintSessionStatus.ACTIVE,
    items: [
      { id: "item-printed", qrCodeId: "qr-printed", state: PrintItemState.PRINT_CONFIRMED, code: "A001" },
      { id: "item-pending", qrCodeId: "qr-pending", state: PrintItemState.ISSUED, code: "A002" },
      { id: "item-failed", qrCodeId: "qr-failed", state: PrintItemState.FAILED, code: "A003" },
    ],
  },
});

const installPrismaMocks = (jobFactory = activeJob) => {
  const calls = {
    sessionUpdates: [],
    jobUpdates: [],
    itemUpdates: [],
    itemEvents: [],
    qrUpdates: [],
    printAudits: [],
    auditLogs: [],
  };
  const restore = [
    backup(prisma, "$transaction"),
    backup(prisma.printJob, "findFirst"),
    backup(prisma.printSession, "update"),
    backup(prisma.printJob, "update"),
    backup(prisma.printItem, "updateMany"),
    backup(prisma.printItemEvent, "createMany"),
    backup(prisma.qRCode, "updateMany"),
    backup(prisma.printAuditEvent, "create"),
    backup(auditService, "createAuditLog"),
    backup(networkDirectPrintService, "getPrintJobOperationalView"),
  ];

  prisma.$transaction = async (callback) => callback(prisma);
  prisma.printJob.findFirst = async (args) => {
    calls.findFirstArgs = args;
    return jobFactory();
  };
  prisma.printSession.update = async (args) => {
    calls.sessionUpdates.push(args);
    return {};
  };
  prisma.printJob.update = async (args) => {
    calls.jobUpdates.push(args);
    return {};
  };
  prisma.printItem.updateMany = async (args) => {
    calls.itemUpdates.push(args);
    return { count: args.where?.id?.in?.length || 0 };
  };
  prisma.printItemEvent.createMany = async (args) => {
    calls.itemEvents.push(args);
    return { count: args.data?.length || 0 };
  };
  prisma.qRCode.updateMany = async (args) => {
    calls.qrUpdates.push(args);
    return { count: args.where?.id?.in?.length || 0 };
  };
  prisma.printAuditEvent.create = async (args) => {
    calls.printAudits.push(args);
    return {};
  };
  auditService.createAuditLog = async (args) => {
    calls.auditLogs.push(args);
    return {};
  };
  networkDirectPrintService.getPrintJobOperationalView = async () => ({ id: "job-1", status: "mocked" });

  return {
    calls,
    restore: () => restore.reverse().forEach((fn) => fn()),
  };
};

const runReasonTest = () => {
  assert.throws(
    () => validatePrintOperationReason("short"),
    (error) => error.statusCode === 400 && /reason/i.test(error.message),
    "Pause and stop should require a useful reason"
  );
};

const runPauseTest = async () => {
  const { calls, restore } = installPrismaMocks();
  try {
    await pausePrintJob({
      printJobId: "job-1",
      scope,
      reason: "Operator is checking label alignment",
    });

    assert(calls.findFirstArgs.where.manufacturerId === "manufacturer-1", "Pause lookup should be manufacturer-scoped");
    assert.strictEqual(calls.sessionUpdates[0].data.status, PrintSessionStatus.PAUSED, "Pause should pause the session");
    assert.strictEqual(calls.jobUpdates[0].data.status, PrintJobStatus.PAUSED, "Pause should pause the job");
    assert.strictEqual(calls.jobUpdates[0].data.pipelineState, PrintPipelineState.PAUSED, "Pause should update pipeline state");
    assert.strictEqual(calls.printAudits[0].data.eventType, "print_job_paused", "Pause should create print audit evidence");
    assert.strictEqual(calls.auditLogs[0].action, "PRINT_JOB_PAUSED", "Pause should create an audit log");
  } finally {
    restore();
  }
};

const runStopTest = async () => {
  const { calls, restore } = installPrismaMocks();
  try {
    await stopPrintJob({
      printJobId: "job-1",
      scope,
      reason: "Operator stopped because media jammed",
    });

    assert.strictEqual(calls.sessionUpdates[0].data.status, PrintSessionStatus.STOPPED, "Stop should stop the session");
    assert.strictEqual(calls.jobUpdates[0].data.status, PrintJobStatus.PARTIALLY_COMPLETED, "Confirmed items should make the run partially completed");
    assert.strictEqual(calls.itemUpdates[0].data.state, PrintItemState.CANCELLED, "Stop should cancel unconfirmed items");
    assert.strictEqual(calls.itemEvents[0].data[0].eventType, PrintItemEventType.CANCELLED, "Stop should write cancellation item events");
    assert.strictEqual(calls.qrUpdates[0].data.status, QRStatus.ALLOCATED, "Stop should release unconfirmed QR codes");
    assert.strictEqual(calls.auditLogs[0].action, "PRINT_JOB_STOPPED", "Stop should create an audit log");
  } finally {
    restore();
  }
};

Promise.resolve()
  .then(runReasonTest)
  .then(runPauseTest)
  .then(runStopTest)
  .then(() => {
    console.log("print operation control service tests passed");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

const prisma = require("../dist/config/database").default;
const {
  BatchLifecycleState,
  PrintDispatchMode,
  PrintItemEventType,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintPayloadType,
  QRStatus,
} = require("@prisma/client");
const {
  acknowledgePrintItemDispatch,
  confirmPrintItemDispatch,
} = require("../dist/services/printConfirmationService");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const backup = (target, key) => {
  const original = target[key];
  return () => {
    target[key] = original;
  };
};

const makeIssuedItem = () => ({
  id: "item-1",
  state: PrintItemState.ISSUED,
  pipelineState: PrintPipelineState.SENT_TO_PRINTER,
  qrCodeId: "qr-1",
  dispatchedAt: null,
  deviceJobRef: null,
  dispatchMetadata: null,
  confirmationEvidence: null,
  confirmationDeadlineAt: null,
  printConfirmedAt: null,
  qrCode: { status: QRStatus.ACTIVATED },
});

const runAckTest = async () => {
  const restore = [
    backup(prisma.printItem, "findUnique"),
    backup(prisma.printItem, "update"),
    backup(prisma.printItemEvent, "create"),
  ];
  const updates = [];
  const events = [];

  prisma.printItem.findUnique = async () => makeIssuedItem();
  prisma.printItem.update = async (args) => {
    updates.push(args);
    return {};
  };
  prisma.printItemEvent.create = async (args) => {
    events.push(args);
    return {};
  };

  try {
    await acknowledgePrintItemDispatch({
      printItemId: "item-1",
      actorUserId: "manufacturer-1",
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: PrintPayloadType.ZPL,
      payloadHash: "payload-hash",
      deviceJobRef: "winspool:ZDesigner:42",
      dispatchMetadata: { printPath: "windows-spooler" },
    });

    assert(updates[0].data.state === PrintItemState.AGENT_ACKED, "ACK should move ISSUED items to AGENT_ACKED");
    assert(
      updates[0].data.pipelineState === PrintPipelineState.PRINTER_ACKNOWLEDGED,
      "ACK should mark the item printer-acknowledged"
    );
    assert(updates[0].data.agentAckedAt instanceof Date, "ACK should store agentAckedAt");
    assert(updates[0].data.dispatchedAt instanceof Date, "ACK should store dispatchedAt");
    assert(updates[0].data.confirmationDeadlineAt instanceof Date, "ACK should store a confirmation deadline");
    assert(events[0].data.eventType === PrintItemEventType.AGENT_ACKED, "ACK should create an AGENT_ACKED event");
  } finally {
    restore.reverse().forEach((fn) => fn());
  }
};

const runClaimAckTest = async () => {
  const restore = [
    backup(prisma.printItem, "findUnique"),
    backup(prisma.printItem, "update"),
    backup(prisma.printItemEvent, "create"),
  ];
  const updates = [];

  prisma.printItem.findUnique = async () => makeIssuedItem();
  prisma.printItem.update = async (args) => {
    updates.push(args);
    return {};
  };
  prisma.printItemEvent.create = async () => ({});

  try {
    await acknowledgePrintItemDispatch({
      printItemId: "item-1",
      actorUserId: "manufacturer-1",
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: PrintPayloadType.ZPL,
      payloadHash: "payload-hash",
      dispatchMetadata: { printPath: "agent-claimed" },
      markDispatched: false,
    });

    assert(updates[0].data.agentAckedAt instanceof Date, "Claim ACK should store agentAckedAt");
    assert(updates[0].data.dispatchedAt === null, "Claim ACK should not mark dispatchedAt before spooler handoff");
    assert(updates[0].data.confirmationDeadlineAt instanceof Date, "Claim ACK should store a confirmation deadline");
  } finally {
    restore.reverse().forEach((fn) => fn());
  }
};

const runConfirmTest = async () => {
  const restore = [
    backup(prisma.printItem, "findUnique"),
    backup(prisma.printItem, "update"),
    backup(prisma.printItem, "count"),
    backup(prisma.printItem, "findMany"),
    backup(prisma.printItem, "updateMany"),
    backup(prisma.printItemEvent, "create"),
    backup(prisma.printItemEvent, "createMany"),
    backup(prisma.qRCode, "updateMany"),
    backup(prisma.qRCode, "count"),
    backup(prisma.printSession, "update"),
    backup(prisma.printJob, "findUnique"),
    backup(prisma.printJob, "update"),
    backup(prisma.printJob, "updateMany"),
    backup(prisma.printAuditEvent, "groupBy"),
    backup(prisma.batch, "findUnique"),
    backup(prisma.batch, "update"),
    backup(prisma.batch, "updateMany"),
  ];
  const updates = [];
  const sessionUpdates = [];
  const jobUpdates = [];
  let findUniqueCalls = 0;

  prisma.printItem.findUnique = async () => {
    findUniqueCalls += 1;
    if (findUniqueCalls === 1) return makeIssuedItem();
    return {
      ...makeIssuedItem(),
      state: PrintItemState.AGENT_ACKED,
      pipelineState: PrintPipelineState.PRINTER_ACKNOWLEDGED,
      dispatchedAt: new Date("2026-05-19T18:01:30.000Z"),
      deviceJobRef: "winspool:ZDesigner:42",
    };
  };
  prisma.printItem.update = async (args) => {
    updates.push(args);
    return {};
  };
  prisma.printItem.count = async () => 0;
  prisma.printItem.findMany = async () => [{ id: "item-1" }];
  prisma.printItem.updateMany = async () => ({ count: 1 });
  prisma.printItemEvent.create = async () => ({});
  prisma.printItemEvent.createMany = async () => ({ count: 1 });
  prisma.qRCode.updateMany = async () => ({ count: 1 });
  prisma.qRCode.count = async () => 1;
  prisma.printSession.update = async (args) => {
    sessionUpdates.push(args);
    return {};
  };
  prisma.printJob.findUnique = async () => ({
    id: "job-1",
    status: PrintJobStatus.CONFIRMED,
    sentAt: new Date("2026-05-19T18:01:00.000Z"),
    confirmedAt: new Date("2026-05-19T18:02:00.000Z"),
    itemCount: 1,
    quantity: 1,
  });
  prisma.printJob.update = async (args) => {
    jobUpdates.push(args);
    return {};
  };
  prisma.printJob.updateMany = async () => ({ count: 1 });
  prisma.printAuditEvent.groupBy = async () => [];
  prisma.batch.findUnique = async () => ({
    id: "batch-1",
    lifecycleState: BatchLifecycleState.PRINT_ACKNOWLEDGED,
    releasedAt: null,
    totalCodes: 1,
    sampleScanPolicy: null,
  });
  prisma.batch.update = async () => ({});
  prisma.batch.updateMany = async () => ({ count: 1 });

  try {
    const result = await confirmPrintItemDispatch({
      printSessionId: "session-1",
      printJobId: "job-1",
      batchId: "batch-1",
      printItemId: "item-1",
      actorUserId: "manufacturer-1",
      dispatchMode: PrintDispatchMode.LOCAL_AGENT,
      payloadType: PrintPayloadType.ZPL,
      payloadHash: "payload-hash",
      deviceJobRef: "winspool:ZDesigner:42",
      confirmationEvidence: { queueConfirmed: true },
    });

    assert(result.jobConfirmed === true, "Confirm should complete the one-item job");
    assert(
      updates.some((entry) => entry.data.state === PrintItemState.PRINT_CONFIRMED),
      "Confirm should mark the item PRINT_CONFIRMED"
    );
    assert(
      sessionUpdates.some((entry) => entry.data.confirmedItems?.increment === 1),
      "Confirm should increment session confirmedItems"
    );
    assert(
      jobUpdates.some((entry) => entry.data.pipelineState === PrintPipelineState.PRINT_CONFIRMED),
      "Confirm should mark the job pipeline print-confirmed before finalization"
    );
  } finally {
    restore.reverse().forEach((fn) => fn());
  }
};

Promise.resolve()
  .then(runAckTest)
  .then(runClaimAckTest)
  .then(runConfirmTest)
  .then(() => {
    console.log("local agent print flow tests passed");
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

const prisma = require("../dist/config/database").default;
const {
  getPrintJobOperationalView,
  listPrintJobsForManufacturer,
} = require("../dist/services/networkDirectPrintService");
const { PrintDispatchMode, PrintItemState, PrintJobStatus, PrintSessionStatus, PrinterConnectionType } = require("@prisma/client");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const makeJob = () => ({
  id: "job-1",
  manufacturerId: "user-1",
  jobNumber: "PJ-TEST-1",
  status: PrintJobStatus.CONFIRMED,
  printMode: PrintDispatchMode.LOCAL_AGENT,
  quantity: 1,
  itemCount: 1,
  failureReason: null,
  createdAt: new Date("2026-03-20T09:00:00.000Z"),
  updatedAt: new Date("2026-03-20T09:05:00.000Z"),
  sentAt: new Date("2026-03-20T09:01:00.000Z"),
  confirmedAt: new Date("2026-03-20T09:05:00.000Z"),
  completedAt: new Date("2026-03-20T09:05:00.000Z"),
  batch: { id: "batch-1", name: "Batch 1", licenseeId: "lic-1" },
  printer: {
    id: "printer-1",
    name: "Canon TS4100i series 2",
    connectionType: PrinterConnectionType.LOCAL_AGENT,
    commandLanguage: "ZPL",
  },
  printSession: {
    id: "session-1",
    status: PrintSessionStatus.COMPLETED,
    totalItems: 1,
    issuedItems: 1,
    confirmedItems: 0,
    frozenItems: 0,
    failedReason: null,
    startedAt: new Date("2026-03-20T09:00:00.000Z"),
    completedAt: new Date("2026-03-20T09:05:00.000Z"),
  },
});

const run = async () => {
  const backupFindFirst = prisma.printJob.findFirst;
  const backupFindMany = prisma.printJob.findMany;
  const backupGroupBy = prisma.printItem.groupBy;

  prisma.printJob.findFirst = async () => makeJob();
  prisma.printJob.findMany = async () => [makeJob()];
  prisma.printItem.groupBy = async () => [
    {
      printSessionId: "session-1",
      state: PrintItemState.CLOSED,
      _count: { _all: 1 },
    },
  ];

  try {
    const view = await getPrintJobOperationalView({ jobId: "job-1", userId: "user-1" });
    assert(view, "Operational view should exist");
    assert(view.session.confirmedItems === 1, "Operational view should derive confirmedItems from print item state");
    assert(view.session.remainingToPrint === 0, "Operational view should derive remainingToPrint from print item state");

    const rows = await listPrintJobsForManufacturer({ userId: "user-1", batchId: "batch-1", limit: 10 });
    assert(rows.length === 1, "List should return the mocked print job");
    assert(rows[0].session.confirmedItems === 1, "List should derive confirmedItems from print item state");
    assert(rows[0].session.remainingToPrint === 0, "List should derive remainingToPrint from print item state");

    console.log("print job operational view tests passed");
  } finally {
    prisma.printJob.findFirst = backupFindFirst;
    prisma.printJob.findMany = backupFindMany;
    prisma.printItem.groupBy = backupGroupBy;
  }
};

run().catch((error) => {
  console.error(error);
  process.exit(1);
});

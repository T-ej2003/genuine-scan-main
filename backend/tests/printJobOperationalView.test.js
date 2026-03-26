const prisma = require("../dist/config/database").default;
const {
  getPrintJobOperationalView,
  listPrintJobsForManufacturer,
} = require("../dist/services/networkDirectPrintService");
const {
  PrintDispatchMode,
  PrintItemState,
  PrintJobStatus,
  PrintPipelineState,
  PrintSessionStatus,
  PrinterConnectionType,
  UserRole,
} = require("@prisma/client");

const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};

const makeJob = () => ({
  id: "job-1",
  manufacturerId: "user-1",
  jobNumber: "PJ-TEST-1",
  status: PrintJobStatus.CONFIRMED,
  pipelineState: PrintPipelineState.LOCKED,
  printMode: PrintDispatchMode.LOCAL_AGENT,
  quantity: 1,
  itemCount: 1,
  reprintOfJobId: "job-root-1",
  reprintReason: "Damaged labels on first pass",
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
  let lastFindFirstArgs = null;
  let lastFindManyArgs = null;

  prisma.printJob.findFirst = async (args) => {
    lastFindFirstArgs = args;
    return makeJob();
  };
  prisma.printJob.findMany = async (args) => {
    lastFindManyArgs = args;
    return [makeJob()];
  };
  prisma.printItem.groupBy = async () => [
    {
      printSessionId: "session-1",
      state: PrintItemState.CLOSED,
      _count: { _all: 1 },
    },
  ];

  try {
    const view = await getPrintJobOperationalView({
      jobId: "job-1",
      scope: {
        role: UserRole.LICENSEE_ADMIN,
        userId: "licensee-user-1",
        licenseeId: "lic-1",
      },
    });
    assert(view, "Operational view should exist");
    assert(view.session.confirmedItems === 1, "Operational view should derive confirmedItems from print item state");
    assert(view.session.remainingToPrint === 0, "Operational view should derive remainingToPrint from print item state");
    assert(view.reprintOfJobId === "job-root-1", "Operational view should expose the original job link");
    assert(view.reprintReason === "Damaged labels on first pass", "Operational view should expose the reissue reason");
    assert(
      lastFindFirstArgs.where.batch.is.licenseeId === "lic-1",
      "Licensee-admin reads should be scoped to the effective licensee"
    );

    const rows = await listPrintJobsForManufacturer({
      scope: {
        role: UserRole.MANUFACTURER,
        userId: "user-1",
      },
      batchId: "batch-1",
      limit: 10,
    });
    assert(rows.length === 1, "List should return the mocked print job");
    assert(rows[0].session.confirmedItems === 1, "List should derive confirmedItems from print item state");
    assert(rows[0].session.remainingToPrint === 0, "List should derive remainingToPrint from print item state");
    assert(rows[0].reprintOfJobId === "job-root-1", "List rows should expose the original job link");
    assert(rows[0].reprintReason === "Damaged labels on first pass", "List rows should expose the reissue reason");
    assert(
      lastFindManyArgs.where.manufacturerId === "user-1",
      "Manufacturer reads should stay scoped to the manufacturer owner"
    );

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

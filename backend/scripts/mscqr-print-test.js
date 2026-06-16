#!/usr/bin/env node
const path = require("path");
const dotenv = require("dotenv");

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, "../.env") });

const prisma = require("../dist/config/database").default;
const { ensureSelectedPrinterReady } = require("../dist/controllers/print-job/shared");
const { generateHumanLabelSerial } = require("../dist/services/labelSerialService");
const { createPrintJobRecords } = require("../dist/services/printJobCreationTransactionService");
const { buildApprovedPrintPayload } = require("../dist/services/printPayloadService");
const { startNetworkDirectDispatch } = require("../dist/services/networkDirectPrintService");

const args = new Map();
for (let i = 2; i < process.argv.length; i += 1) {
  const arg = process.argv[i];
  if (!arg.startsWith("--")) continue;
  const key = arg.slice(2);
  const next = process.argv[i + 1];
  if (!next || next.startsWith("--")) {
    args.set(key, true);
  } else {
    args.set(key, next);
    i += 1;
  }
}

const required = (key) => {
  const value = args.get(key);
  if (typeof value !== "string" || !value.trim()) throw new Error(`Missing required --${key}`);
  return value.trim();
};

const main = async () => {
  if (process.env.NODE_ENV === "production") {
    throw new Error("Refusing to run manual print-test script with NODE_ENV=production.");
  }

  const batchId = required("batch");
  const printerId = required("printer");
  const count = Math.max(1, Math.min(250, Number(args.get("count") || 10) || 10));
  const shouldSend = args.has("send");
  const batch = await prisma.batch.findUnique({
    where: { id: batchId },
    select: {
      id: true,
      name: true,
      licenseeId: true,
      manufacturerId: true,
      metadata: true,
      licensee: { select: { id: true, name: true, prefix: true, location: true, metadata: true } },
      manufacturer: { select: { id: true, name: true, location: true, metadata: true } },
    },
  });
  if (!batch?.manufacturerId) throw new Error("Batch must exist and be assigned to a manufacturer before manual print validation.");

  const available = await prisma.qRCode.count({ where: { batchId, status: "ALLOCATED", printJobId: null } });
  if (available < count) throw new Error(`Refusing to print: only ${available} DB-issued allocated labels are available for this batch.`);

  const printerSelection = await ensureSelectedPrinterReady({ printerId, userId: batch.manufacturerId, licenseeId: batch.licenseeId });
  const created = await createPrintJobRecords({
    batch,
    userId: batch.manufacturerId,
    printerSelection,
    quantity: count,
    printLockTokenHash: null,
    onEvent: () => undefined,
    onStage: () => undefined,
  });

  const firstItem = await prisma.printItem.findFirst({
    where: { printSessionId: created.session.id },
    orderBy: [{ issueSequence: "asc" }, { code: "asc" }],
    include: {
      qrCode: {
        select: {
          id: true,
          code: true,
          displayCode: true,
          batchId: true,
          licenseeId: true,
          tokenNonce: true,
          tokenIssuedAt: true,
          tokenExpiresAt: true,
          tokenHash: true,
          replayEpoch: true,
        },
      },
    },
  });
  if (!firstItem) throw new Error("Print job was created without print items.");

  const samplePayload = buildApprovedPrintPayload({
    printer: printerSelection.printer,
    qr: firstItem.qrCode,
    manufacturerId: batch.manufacturerId,
    printJobId: created.job.id,
    printItemId: firstItem.id,
    jobNumber: created.job.jobNumber,
    serialContext: {
      sequence: firstItem.issueSequence || 1,
      issuedAt: firstItem.issuedAt || new Date(),
      batch,
      licensee: batch.licensee,
      manufacturer: batch.manufacturer,
      printer: printerSelection.printer,
    },
  });

  if (shouldSend) await startNetworkDirectDispatch({ jobId: created.job.id, actorUserId: batch.manufacturerId });

  const sampleLabels = await prisma.printItem.findMany({
    where: { printSessionId: created.session.id },
    take: 5,
    orderBy: [{ code: "asc" }],
    include: { qrCode: { select: { id: true, code: true, displayCode: true } } },
  });

  console.log(
    JSON.stringify(
      {
        batchId,
        batchName: batch.name,
        count,
        printer: {
          id: printerSelection.printer.id,
          host: printerSelection.printer.ipAddress || printerSelection.printer.host || null,
          port: printerSelection.printer.port || null,
          mode: printerSelection.printMode,
        },
        printJobId: created.job.id,
        printSessionId: created.session.id,
        payloadHash: samplePayload.payloadHash,
        status: shouldSend ? "dispatch_started" : "created_preview_only",
        sampleVerifyUrls: sampleLabels.map((item) => ({
          humanSerial: generateHumanLabelSerial({
            qrId: item.qrCode.id,
            sequence: item.issueSequence || 1,
            issuedAt: item.issuedAt || new Date(),
            batch,
            licensee: batch.licensee,
            manufacturer: batch.manufacturer,
            printer: printerSelection.printer,
          }).humanSerial,
          verifyUrl: `${String(process.env.PUBLIC_VERIFY_WEB_BASE_URL || process.env.CORS_ORIGIN || "http://localhost:8080").replace(/\/+$/, "")}/verify/${encodeURIComponent(item.qrCode.code)}`,
        })),
      },
      null,
      2
    )
  );
};

main()
  .catch((error) => {
    console.error(error?.message || error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

const assert = require("node:assert/strict");
const path = require("node:path");
const { PrinterConnectionType, PrinterDeliveryMode, PrinterCommandLanguage } = require("@prisma/client");

const distRoot = path.resolve(__dirname, "../dist");

const mockModule = (relativePath, exportsValue) => {
  const resolved = require.resolve(path.join(distRoot, relativePath));
  require.cache[resolved] = {
    id: resolved,
    filename: resolved,
    loaded: true,
    exports: exportsValue,
  };
};

let printer;

const resetPrinter = () => {
  printer = {
    id: "printer-local-test-1",
    name: "ZDesigner ZT410-300dpi ZPL",
    vendor: "Zebra",
    model: "ZT410",
    connectionType: PrinterConnectionType.LOCAL_AGENT,
    commandLanguage: PrinterCommandLanguage.ZPL,
    deliveryMode: PrinterDeliveryMode.DIRECT,
    nativePrinterId: "ZDesigner-ZT410-300dpi-ZPL",
    printerRegistrationId: "registration-local-test-1",
    agentId: "agent-local-test-1",
    deviceFingerprint: "device-local-test-1",
    licenseeId: "licensee-local-test-1",
    orgId: "org-local-test-1",
    isActive: true,
    metadata: {},
    calibrationProfile: null,
    profile: { activeLanguage: "ZPL", statusConfig: null },
  };
};

resetPrinter();

mockModule("config/database.js", {
  __esModule: true,
  default: {
    printer: {
      findMany: async ({ where }) => {
        const ids = where?.id?.in || [];
        return ids.includes(printer.id) && printer.isActive ? [printer] : [];
      },
      findUnique: async ({ where }) => (where?.id === printer.id ? printer : null),
      update: async ({ where, data }) => {
        assert.equal(where.id, printer.id, "test should update the target printer");
        printer = {
          ...printer,
          ...data,
          metadata: data.metadata === undefined ? printer.metadata : data.metadata,
        };
        return printer;
      },
    },
  },
});

const {
  acknowledgeLocalAgentPrinterTestJob,
  claimLocalAgentPrinterTestJob,
  confirmLocalAgentPrinterTestJob,
  printTestLabelForRegisteredPrinter,
} = require("../dist/services/printerTestLabelService");
const { assertPrinterTestLabelConfirmed } = require("../dist/services/printerTestLabelGateService");

(async () => {
  await assert.rejects(
    async () => assertPrinterTestLabelConfirmed(printer),
    /PRINTER_TEST_LABEL_REQUIRED/,
    "production gate should block before connector-confirmed setup test"
  );

  const queued = await printTestLabelForRegisteredPrinter({
    printer,
    actorUserId: "manufacturer-local-test-1",
  });
  assert.equal(queued.outcome, "queued", "local-agent setup test endpoint should report queued");
  assert(printer.metadata.pendingLocalAgentTestLabel, "queued setup test job should be persisted on printer metadata");
  assert(!printer.metadata.lastTestLabelConfirmedAt, "queued setup test must not mark the printer confirmed");

  const claim = await claimLocalAgentPrinterTestJob({ printerIds: [printer.id] });
  assert(claim, "persisted setup test job should be claimable by any backend task");
  assert.equal(claim.printer.id, printer.id, "claim should carry the backend printer profile id for connector test ack");
  assert.equal(claim.printer.nativePrinterId, printer.nativePrinterId, "claim should bind the selected native printer");
  assert.equal(printer.metadata.pendingLocalAgentTestLabel.status, "CLAIMED", "claim should advance persistent job state");

  const acknowledged = await acknowledgeLocalAgentPrinterTestJob({
    printerId: printer.id,
    testJobId: claim.testJobId,
    metadata: { payloadHash: claim.payloadHash, deviceJobRef: "winspool:79" },
  });
  assert.equal(acknowledged, true, "connector ack should update the persistent setup test job");
  assert.equal(printer.metadata.pendingLocalAgentTestLabel.status, "ACKED", "ack should be persisted");

  const confirmed = await confirmLocalAgentPrinterTestJob({
    printerId: printer.id,
    testJobId: claim.testJobId,
    payloadType: claim.payloadType,
    deviceJobRef: "winspool:79",
    confirmationMode: "LOCAL_QUEUE",
    metadata: { payloadHash: claim.payloadHash },
  });
  assert.equal(confirmed, true, "connector confirm should update the persistent setup test job");
  assert(printer.metadata.lastTestLabelConfirmedAt, "connector confirm should record setup test proof");
  assert.doesNotThrow(
    () => assertPrinterTestLabelConfirmed(printer),
    "production gate should pass only after connector-confirmed setup test"
  );

  resetPrinter();
  const other = await printTestLabelForRegisteredPrinter({
    printer,
    actorUserId: "manufacturer-local-test-1",
  });
  const otherClaim = await claimLocalAgentPrinterTestJob({ printerIds: [printer.id] });
  assert(otherClaim, "second queued setup test should be claimable");
  const wrongConfirm = await confirmLocalAgentPrinterTestJob({
    printerId: printer.id,
    testJobId: `${otherClaim.testJobId}-wrong`,
    payloadType: otherClaim.payloadType,
    deviceJobRef: "winspool:80",
    confirmationMode: "LOCAL_QUEUE",
  });
  assert.equal(wrongConfirm, false, "wrong setup-test id must not satisfy production gate");
  assert(!printer.metadata.lastTestLabelConfirmedAt, "wrong confirm must not mark setup test proof");
  assert.equal(other.outcome, "queued");

  console.log("printer persistent test label lifecycle tests passed");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});

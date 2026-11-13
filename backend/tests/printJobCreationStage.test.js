const assert = require("node:assert/strict");
const path = require("node:path");

const dist = path.join(__dirname, "../dist");
const repository = require(path.join(dist, "rls-waves/session-c/c02/printingLifecycleRepository"));
const tokens = require(path.join(dist, "services/qrTokenService"));
const originals = {
  readPrintingProjection: repository.readPrintingProjection,
  createPrintingJob: repository.createPrintingJob,
  signQrPayload: tokens.signQrPayload,
  hashToken: tokens.hashToken,
  randomNonce: tokens.randomNonce,
  getQrTokenExpiryDate: tokens.getQrTokenExpiryDate,
};

const batchId = "40000000-0000-4000-8000-000000000001";
const printerId = "40000000-0000-4000-8000-000000000002";
const jobId = "40000000-0000-4000-8000-000000000003";
const sessionId = "40000000-0000-4000-8000-000000000004";
const events = [];

const run = async () => {
  repository.readPrintingProjection = async ({ operation }) => operation === "PRINTABLE_ITEMS"
    ? { batch: { id: batchId, manufacturerId: "maker" }, printableItems: [{ id: "qr", batchId, licenseeId: "licensee" }] }
    : { id: printerId, connectionType: "LOCAL_AGENT", commandLanguage: "ZPL" };
  tokens.signQrPayload = () => "signed-fixture";
  tokens.hashToken = () => "token-hash";
  tokens.randomNonce = () => "nonce";
  tokens.getQrTokenExpiryDate = () => new Date(Date.now() + 60_000);
  const { createPrintJobRecords } = require(path.join(dist, "services/printJobCreationTransactionService"));
  const params = {
    capability: "C".repeat(43), requestId: "40000000-0000-4000-8000-000000000005",
    batchId, printerId, quantity: 1,
    onEvent: (name) => events.push(name),
    onStage: (_stage, name, data) => events.push({ name, data }),
  };

  repository.createPrintingJob = async () => { throw new Error("ACTIVE_PRINT_JOB_EXISTS"); };
  await assert.rejects(createPrintJobRecords(params), /ACTIVE_PRINT_JOB_EXISTS/);
  assert.equal(events.some((event) => event.name === "print_job_created"), false,
    "a rejected create must never emit a committed-job stage");
  assert.equal(events.find((event) => event.name === "print_job_creation_started")?.data.itemCount, 1);

  events.length = 0;
  repository.createPrintingJob = async () => {
    events.push("database_commit");
    return { job: { id: jobId }, session: { id: sessionId }, preparedCount: 1 };
  };
  await createPrintJobRecords(params);
  const committed = events.findIndex((event) => event === "database_commit");
  const started = events.findIndex((event) => event.name === "print_job_creation_started");
  const created = events.findIndex((event) => event === "print_items_created");
  assert(started >= 0 && committed > started && created > committed);
};

run().then(() => console.log("Print job creation stage follows committed SQL"))
  .catch((error) => { console.error(error); process.exitCode = 1; })
  .finally(() => {
    for (const [name, value] of Object.entries(originals)) {
      (name in repository ? repository : tokens)[name] = value;
    }
  });

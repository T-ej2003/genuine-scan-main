const assert = require("node:assert/strict");

const repository = require("../dist/rls-waves/session-c/c02/printingLifecycleRepository");
const calls = [];
repository.controlPrintingJob = async (input) => {
  calls.push(["control", input]);
  return { idempotent: false };
};
repository.readPrintingProjection = async (input) => {
  calls.push(["read", input]);
  return { id: input.subjectId, status: "PAUSED" };
};
const { pausePrintJob, resumePrintJob, stopPrintJob, validatePrintOperationReason } =
  require("../dist/services/printOperationControlService");

const boundary = { capability: "C".repeat(43), requestId: "50000000-0000-4000-8000-000000000901" };
const scope = { role: "MANUFACTURER_ADMIN", userId: "manufacturer-1", licenseeId: "licensee-1" };

assert.throws(() => validatePrintOperationReason("short"), /clear reason/i);

async function main() {
  const paused = await pausePrintJob({
    printJobId: "job-1",
    scope,
    boundary,
    reason: "Operator is checking label alignment",
  });
  assert.equal(paused.view.status, "PAUSED");
  assert.deepEqual(calls[0], ["control", {
    capability: boundary.capability,
    requestId: boundary.requestId,
    jobId: "job-1",
    operation: "PAUSE",
    reason: "Operator is checking label alignment",
  }]);
  assert.equal(calls[1][0], "read");

  await resumePrintJob({ printJobId: "job-1", scope, boundary });
  assert.equal(calls[2][1].operation, "RESUME");
  await stopPrintJob({
    printJobId: "job-1",
    scope,
    boundary,
    reason: "Operator stopped because media jammed",
  });
  assert.equal(calls[4][1].operation, "STOP");
  assert.equal(calls[4][1].capability, boundary.capability);
  assert(!JSON.stringify(calls).includes("install_actor_context"));
  console.log("print operation control capability-bound tests passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

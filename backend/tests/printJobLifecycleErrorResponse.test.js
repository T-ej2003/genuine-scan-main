const assert = require("assert");
const { BatchStateTransitionError } = require("../dist/services/batchStateMachineService");
const { describePrintJobCreateFailure } = require("../dist/controllers/print-job/errorResponses");

const error = new BatchStateTransitionError(
  "INVALID_STATE_TRANSITION",
  "Complete the previous batch step first.",
  {
    batchId: "batch-1",
    currentLifecycleState: "DRAFT",
    requiredPreviousStep: "Allocate QR labels to this manufacturer before printing.",
    userMessage: "This batch needs to be allocated before printing.",
    recoveryAction: "complete_previous_batch_step",
    canRetry: false,
    canRepairAutomatically: false,
  }
);

const failure = describePrintJobCreateFailure(error, {
  requestId: "req-1",
  failureStage: "transaction_started",
});

assert.strictEqual(failure.status, 409);
assert.strictEqual(failure.payload.code, "INVALID_STATE_TRANSITION");
assert.strictEqual(failure.payload.batchId, "batch-1");
assert.strictEqual(failure.payload.currentLifecycleState, "DRAFT");
assert.strictEqual(failure.payload.requiredPreviousStep, "Allocate QR labels to this manufacturer before printing.");
assert.strictEqual(failure.payload.userMessage, "This batch needs to be allocated before printing.");
assert.strictEqual(failure.payload.recoveryAction, "complete_previous_batch_step");
assert.strictEqual(failure.payload.canRetry, false);
assert.strictEqual(failure.payload.canRepairAutomatically, false);
assert.strictEqual(failure.payload.failureStage, "transaction_started");

const wrappedQrMembershipFailure = describePrintJobCreateFailure(
  Object.assign(new Error("Prisma raw query failed"), {
    code: "P2010",
    meta: { code: "P0001", message: "ERROR: QR_NOT_IN_PRINT_JOB" },
  })
);
assert.strictEqual(wrappedQrMembershipFailure.status, 409);
assert.strictEqual(wrappedQrMembershipFailure.payload.code, "QR_NOT_IN_PRINT_JOB");
assert.strictEqual(
  wrappedQrMembershipFailure.payload.message,
  "This sample QR does not belong to this print job."
);
assert.doesNotMatch(JSON.stringify(wrappedQrMembershipFailure.payload), /P2010|P0001|Prisma|queryRaw/i);

for (const error of [
  Object.assign(new Error("unknown raw query failure"), {
    code: "P2010",
    meta: { code: "P0001", message: "ERROR: UNREVIEWED_DATABASE_ERROR" },
  }),
  Object.assign(new Error("permission denied"), {
    code: "P2010",
    meta: { code: "42501", message: "ERROR: permission denied for table QRCode" },
  }),
  Object.assign(new Error("unrelated SQL failure"), {
    code: "P2010",
    meta: { code: "22000", message: "ERROR: unrelated SQL failure" },
  }),
]) {
  const unknown = describePrintJobCreateFailure(error);
  assert.strictEqual(unknown.status, 500);
  assert.strictEqual(unknown.payload.code, "internal_print_job_create_failed");
  assert.notStrictEqual(unknown.payload.code, "QR_NOT_IN_PRINT_JOB");
  assert.doesNotMatch(JSON.stringify(unknown.payload), /permission denied|QRCode|P2010|P0001|22000|Prisma|queryRaw/i);
}

console.log("print job lifecycle error response tests passed");

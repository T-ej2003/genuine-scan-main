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

console.log("print job lifecycle error response tests passed");

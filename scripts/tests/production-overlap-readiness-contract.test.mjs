import assert from "node:assert/strict";
import test from "node:test";
import { assertReadyForOverlapDeployment, READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";

const completeEvidence = () => Object.fromEntries([
  ...READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((stage) => [stage, true]),
  ["rotationPrepared", true],
  ["ecsUpdateServiceCount", 0],
]);

test("offline cutover sequence reaches READY_FOR_OVERLAP_DEPLOYMENT only before service mutation", () => {
  assert.deepEqual(assertReadyForOverlapDeployment(completeEvidence()).readyForOverlapDeployment, true);
});

test("every required pre-overlap stage is fail-closed", () => {
  for (const stage of READY_FOR_OVERLAP_DEPLOYMENT_STAGES) {
    const evidence = completeEvidence();
    evidence[stage] = false;
    assert.throws(() => assertReadyForOverlapDeployment(evidence), new RegExp(stage));
  }
});

test("rotation preparation and UpdateService boundary are fail-closed", () => {
  const withoutPrepare = completeEvidence();
  withoutPrepare.rotationPrepared = false;
  assert.throws(() => assertReadyForOverlapDeployment(withoutPrepare), /rotationPrepared/);

  const afterServiceMutation = completeEvidence();
  afterServiceMutation.ecsUpdateServiceCount = 1;
  assert.throws(() => assertReadyForOverlapDeployment(afterServiceMutation), /UpdateService/);
});

import assert from "node:assert/strict";
import test from "node:test";
import {
  assertStageBDeploymentEvidenceFreshness,
  STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS,
  STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS,
  STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS,
} from "../aws/stage-b-evidence-freshness.mjs";

const now = new Date("2026-08-05T15:00:00.000Z");
const types = ["Administrator capability evidence", "Plan-bound permission evidence", "Stage B reference audit"];

for (const evidenceType of types) {
  test(`${evidenceType} uses the shared 60-minute boundary`, () => {
    for (const ageSeconds of [0, 899, 900, 1800, 3599]) {
      const timestamp = new Date(now.getTime() - ageSeconds * 1000).toISOString();
      assert.doesNotThrow(() => assertStageBDeploymentEvidenceFreshness(timestamp, { now, evidenceType }));
    }
    for (const ageSeconds of [3600, 3601]) {
      const timestamp = new Date(now.getTime() - ageSeconds * 1000).toISOString();
      assert.throws(() => assertStageBDeploymentEvidenceFreshness(timestamp, { now, evidenceType }), /expired/);
    }
  });
}

test("freshness parsing is strict and reports the evidence boundary", () => {
  assert.equal(STAGE_B_DEPLOYMENT_EVIDENCE_TTL_SECONDS, 3600);
  assert.equal(STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS, 3600000);
  assert.throws(() => assertStageBDeploymentEvidenceFreshness(undefined, { now, evidenceType: "Permission report" }), /malformed/);
  assert.throws(() => assertStageBDeploymentEvidenceFreshness("2026-08-05T15:00:00Z", { now, evidenceType: "Permission report" }), /malformed/);
  assert.throws(() => assertStageBDeploymentEvidenceFreshness(new Date(now.getTime() + STAGE_B_DEPLOYMENT_EVIDENCE_CLOCK_SKEW_MS + 1).toISOString(), { now, evidenceType: "Reference audit" }), /future/);
  assert.throws(() => assertStageBDeploymentEvidenceFreshness(new Date(now.getTime() - STAGE_B_DEPLOYMENT_EVIDENCE_TTL_MS).toISOString(), { now, evidenceType: "Reference audit" }), /allowedTtlSeconds=3600/);
});

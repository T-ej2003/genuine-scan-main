import assert from "node:assert/strict";
import test from "node:test";
import { assertStageBApplyFailureArtifact, createStageBApplyFailureArtifact } from "../aws/stage-b-apply-failure-contract.mjs";

const base = () => createStageBApplyFailureArtifact({ producerCallerArn: "arn:aws:iam::368992683803:root", protectedSourceSha: "5".repeat(40), lineage: "4e438e59-8b8b-194d-030c-5ede0c26344a", preApplySerial: 78, plan: { savedPlanSha256: "a".repeat(64), planJsonSha256: "b".repeat(64), logicalCanonicalPlanSha256: "c".repeat(64) }, mutation: { terraformAddress: "aws_lambda_alias.reviewed", operation: "UpdateAlias", result: "FAILED", failureClass: "AUTHORIZATION" }, stdoutBytes: Buffer.from("stdout"), stderrBytes: Buffer.from("stderr") });

test("future apply failures have structured, hashed identity without changing old-log trust", () => {
  const report = base();
  assert.equal(report.evidenceKind, "STAGE_B_APPLY_FAILURE");
  assert.match(report.providerFailure.stdoutSha256, /^[a-f0-9]{64}$/);
  assert.doesNotThrow(() => assertStageBApplyFailureArtifact(report));
  assert.throws(() => assertStageBApplyFailureArtifact({ ...report, plan: { ...report.plan, planJsonSha256: "bad" } }), /malformed/);
});

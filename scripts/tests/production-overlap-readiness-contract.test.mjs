import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { assertReadyForOverlapDeployment, readAndAssertReadyForOverlapDeployment, rotationExpectedImageReleaseSha, READY_FOR_OVERLAP_DEPLOYMENT_STAGES } from "../aws/production-overlap-readiness-contract.mjs";

const completeEvidence = () => Object.fromEntries([
  ["evidenceVersion", 1],
  ["sourceSha", "a".repeat(40)],
  ["rotationId", "rotation-test-1234"],
  ["rotationStateSha256", "b".repeat(64)],
  ["generatedAt", new Date().toISOString()],
  ...READY_FOR_OVERLAP_DEPLOYMENT_STAGES.map((stage) => [stage, { valid: true, evidenceRef: `evidence://${stage}`, evidenceSha256: "c".repeat(64), identityBindings: { sourceSha: "a".repeat(40) } }]),
  ["rotationPrepared", true],
  ["ecsUpdateServiceCount", 0],
]);

test("offline cutover sequence reaches READY_FOR_OVERLAP_DEPLOYMENT only before service mutation", () => {
  assert.deepEqual(assertReadyForOverlapDeployment(completeEvidence(), { sourceSha: "a".repeat(40), rotationId: "rotation-test-1234", rotationStateSha256: "b".repeat(64) }).readyForOverlapDeployment, true);
});

test("every required pre-overlap stage is fail-closed", () => {
  for (const stage of READY_FOR_OVERLAP_DEPLOYMENT_STAGES) {
    const evidence = completeEvidence();
    evidence[stage].valid = false;
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

test("readiness evidence is persisted, hash-bound, and exact before mutation", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "overlap-readiness-"));
  const file = path.join(dir, "readiness.json");
  const raw = `${JSON.stringify(completeEvidence())}\n`;
  writeFileSync(file, raw, { mode: 0o600 });
  const evidenceSha256 = createHash("sha256").update(raw).digest("hex");
  assert.doesNotThrow(() => readAndAssertReadyForOverlapDeployment({
    filePath: file,
    evidenceSha256,
    sourceSha: "a".repeat(40),
    rotationId: "rotation-test-1234",
    rotationStateSha256: "b".repeat(64),
  }));
  assert.throws(() => readAndAssertReadyForOverlapDeployment({ filePath: file, evidenceSha256: "d".repeat(64), sourceSha: "a".repeat(40), rotationId: "rotation-test-1234", rotationStateSha256: "b".repeat(64) }), /does not match/);
});

test("release gate and deploy wrapper enforce the same checkpoint immediately before UpdateService", () => {
  const releaseGate = readFileSync(".github/workflows/release-gate.yml", "utf8");
  const deploy = readFileSync("scripts/aws/deploy-ecs-service.sh", "utf8");
  assert.ok(releaseGate.indexOf("Authorize rotation transition readiness immediately before mutation") < releaseGate.indexOf("Deploy rotation transition backend ECS service"));
  assert.match(releaseGate, /OVERLAP_READINESS_EVIDENCE_FILE/);
  assert.match(releaseGate, /run-production-cutover\.mjs/);
  assert.match(deploy, /require_existing_activation_authorization/);
  assert.ok(deploy.indexOf("require_existing_activation_authorization") < deploy.indexOf("aws ecs update-service"));
});

test("the release-gate cutover wrapper deploys only the exact readiness task definition", () => {
  const source = readFileSync("scripts/aws/run-production-cutover.mjs", "utf8");
  assert.match(source, /overlapTaskDefinition\?\.identityBindings\?\.taskDefinitionArn/);
  assert.match(source, /taskDefinitionArn !== authorizedTaskDefinitionArn/);
});

test("rotation overlap and cleanup use authenticated image SHA independent of tooling SHA", () => {
  const evidence = completeEvidence();
  evidence.evidenceVersion = 2;
  evidence.imageAuthorization.identityBindings.imageReleaseSha = "d".repeat(40);
  evidence.overlapTaskDefinition.identityBindings.imageReleaseSha = "d".repeat(40);
  assert.equal(rotationExpectedImageReleaseSha(evidence), "d".repeat(40));
  evidence.overlapTaskDefinition.identityBindings.imageReleaseSha = "e".repeat(40);
  assert.throws(() => rotationExpectedImageReleaseSha(evidence), /authenticated readiness/);
  const releaseGate = readFileSync(".github/workflows/release-gate.yml", "utf8");
  const rotationStep = releaseGate.slice(releaseGate.indexOf("- name: Deploy rotation transition backend ECS service"), releaseGate.indexOf("- name: Upload overlap deployment receipt"));
  assert.doesNotMatch(rotationStep, /steps\.images\.outputs\.image_release_sha/);
  assert.match(rotationStep, /rotation-overlap.*rotation-cleanup/);
  const cutover = readFileSync("scripts/aws/run-production-cutover.mjs", "utf8");
  assert.match(cutover, /rotationExpectedImageReleaseSha\(readiness\.evidence\)/);
  assert.match(cutover, /expectedGitSha \}/);
});

 test("legacy hashed readiness retains its original single-SHA cleanup semantics", () => {
  const evidence = completeEvidence();
  Object.assign(evidence.overlapTaskDefinition.identityBindings, { taskDefinitionArn: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:19", imageDigest: `sha256:${"d".repeat(64)}` });
  assert.equal(rotationExpectedImageReleaseSha(evidence), evidence.sourceSha);
  evidence.imageAuthorization.identityBindings.imageReleaseSha = "e".repeat(40);
  assert.throws(() => rotationExpectedImageReleaseSha(evidence), /legacy image authorization bindings/);
  evidence.evidenceVersion = 2;
  assert.throws(() => rotationExpectedImageReleaseSha(evidence), /authenticated readiness/);
 });

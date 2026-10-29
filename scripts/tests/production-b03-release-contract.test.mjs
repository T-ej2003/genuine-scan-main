import test from "node:test";
import assert from "node:assert/strict";
import { B03_RELEASE, buildB03ExecutorDefinition, b03RunTaskRequest, authenticateB03ExecutorResult,
  buildB03ReleaseReceipt, assertB03ReleaseReceipt } from "../aws/production-b03-release-contract.mjs";
import { canonicalSha256 } from "../aws/production-green-stage-b-contract.mjs";

const sourceSha = "4".repeat(40), digest = `sha256:${"a".repeat(64)}`;
const backendImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const taskDefinitionArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-production-b03-incremental:3";
const taskArn = `arn:aws:ecs:eu-west-2:368992683803:task/mscqr-prod-euw2-main/${"a".repeat(32)}`;
const catalogue = Object.fromEntries(["routines", "tables", "policies", "schemas", "roles"].map((name) => [name, "b".repeat(64)]));
const pkg = { sourceSha, predecessorSourceSha: "d785aa7f1e154f37c0dc621082e3f6c46d5d5aec",
  predecessorRequirementsSha256: "c".repeat(64), successorRequirementsSha256: "d".repeat(64),
  predecessorCatalogue: catalogue, successorCatalogue: catalogue, packageSha256: "e".repeat(64) };
const resultBody = { schemaVersion: 1, kind: "PRODUCTION_B03_INCREMENTAL_RESULT", sourceSha,
  packageSha256: pkg.packageSha256, database: B03_RELEASE.database, databaseRole: B03_RELEASE.administrator,
  successorCatalogue: catalogue, status: "APPLIED", writeCount: 44 };
const result = { ...resultBody, evidenceSha256: canonicalSha256(resultBody) };
const approvalEvidence = { sourceSha, workflowRunId: "100", environment: "production",
  actualApproval: { userLogin: "T-ej2003" }, evidenceSha256: "f".repeat(64), observedAt: "2026-10-28T12:00:00.000Z" };
const taskState = { taskArn, taskDefinitionArn, lastStatus: "STOPPED",
  containers: [{ name: B03_RELEASE.container, exitCode: 0, image: backendImage, imageDigest: digest }] };
const receipt = () => buildB03ReleaseReceipt({ sourceSha, backendImage, approvalId: "release-approval", approvalEvidence,
  pkg, taskArn, taskDefinitionArn, taskState, result, workflowRunId: "100", releaseTrainRunId: "99",
  verifiedAt: "2026-10-28T12:05:00.000Z" });

test("B03 runner binds exact image, family, cluster, secret and no ECS Exec", () => {
  const definition = buildB03ExecutorDefinition({ sourceSha, backendImage, package: pkg, databaseHostname: "db.example.internal" });
  assert.equal(definition.family, B03_RELEASE.family);
  assert.equal(definition.containerDefinitions[0].image, backendImage);
  assert.equal(definition.containerDefinitions[0].secrets[0].valueFrom, B03_RELEASE.administratorSecretArn);
  assert.equal(definition.containerDefinitions[0].privileged, false);
  assert.deepEqual(definition.containerDefinitions[0].command, []);
  assert.deepEqual(definition.containerDefinitions[0].entryPoint.slice(0, 8),
    ["/usr/bin/env", "-u", "NODE_OPTIONS", "-u", "NODE_PATH", "-u", "LD_PRELOAD", "/usr/local/bin/node"]);
  assert.equal(definition.containerDefinitions[0].entryPoint.length, 12);
  const request = b03RunTaskRequest({ taskDefinitionArn, sourceSha, packageSha256: pkg.packageSha256 });
  assert.equal(request.cluster, B03_RELEASE.cluster); assert.equal(request.enableExecuteCommand, false);
  assert.throws(() => b03RunTaskRequest({ taskDefinitionArn: taskDefinitionArn.replace(B03_RELEASE.family, "other"), sourceSha,
    packageSha256: pkg.packageSha256 }));
  assert.throws(() => buildB03ExecutorDefinition({ sourceSha, backendImage: backendImage.replace("mscqr-backend", "other"),
    package: pkg, databaseHostname: "db.example.internal" }));
});

test("legacy self-hashed B03 receipt cannot authorize backend activation", () => {
  assert.deepEqual(authenticateB03ExecutorResult({ message: JSON.stringify(result), pkg, sourceSha }), result);
  const value = receipt();
  assert.throws(() => assertB03ReleaseReceipt(value, { sourceSha, imageDigest: digest, approvalId: "release-approval", workflowRunId: "100" }), /Self-hashed legacy/);
  assert.throws(() => assertB03ReleaseReceipt({ ...value, taskResult: { ...result, status: "FAILED" } },
    { sourceSha, imageDigest: digest, approvalId: "release-approval" }));
  assert.throws(() => assertB03ReleaseReceipt(value, { sourceSha: "5".repeat(40), imageDigest: digest, approvalId: "release-approval" }));
  assert.throws(() => assertB03ReleaseReceipt(value, { sourceSha, imageDigest: `sha256:${"0".repeat(64)}`, approvalId: "release-approval" }));
  assert.throws(() => buildB03ReleaseReceipt({ sourceSha, backendImage, approvalId: "release-approval", approvalEvidence,
    pkg, taskArn, taskDefinitionArn, taskState: { ...taskState, containers: [{ ...taskState.containers[0], exitCode: 1 }] },
    result, workflowRunId: "100", releaseTrainRunId: "99", verifiedAt: "2026-10-28T12:05:00.000Z" }));
});

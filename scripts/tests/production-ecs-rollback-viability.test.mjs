import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { ROLLBACK_VIABILITY, assertFreshRollbackEquivalence, assertRollbackSupersessionProof, classifyRollbackViability, collectRollbackViability, exactEcrImageResult } from "../aws/production-ecs-rollback-viability.mjs";

const serviceArn = "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2";
const clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main";
const deploymentArn = "arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-deployment-N";
const forwardRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-revision-N";
const rollbackRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-revision-N-minus-1";
const extraSourceRevisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-revision-N-minus-2";
const td47 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:47";
const td48 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
const td46 = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:46";
const digest47 = `sha256:${"b".repeat(64)}`;
const digest48 = `sha256:${"a".repeat(64)}`;
const digest46 = `sha256:${"c".repeat(64)}`;
const service = { serviceArn, clusterArn, taskDefinition: td47, desiredCount: 2, runningCount: 0, pendingCount: 0 };
const deployment = {
  serviceDeploymentArn: deploymentArn,
  status: "ROLLBACK_IN_PROGRESS",
  targetServiceRevision: { arn: forwardRevisionArn },
  sourceServiceRevisions: [{ arn: rollbackRevisionArn }],
  rollback: { serviceRevisionArn: rollbackRevisionArn },
};
const resolved = (serviceRevisionArn, taskDefinitionArn, digest, imageExists, imageFailure = null) => ({ serviceRevisionArn, taskDefinitionArn, digest, repository: "mscqr-backend", imageExists, imageFailure });
const forwardTarget = resolved(forwardRevisionArn, td48, digest48, true);
const rollbackTarget = resolved(rollbackRevisionArn, td47, digest47, false);
const sourceRevisions = [rollbackTarget];
const taskAttempts = [1, 2].map((index) => ({ taskArn: `task-${index}`, taskDefinitionArn: td47, classification: "CANNOT_PULL_IMAGE", digest: digest47 }));
const classify = (overrides = {}) => classifyRollbackViability({ service, deployment, forwardTarget, sourceRevisions, rollbackTarget, taskAttempts, observationStart: "2026-08-24T10:00:00.000Z", observationEnd: "2026-08-24T10:01:00.000Z", ...overrides });

function awsFixture({ snapshots = [{}], ecr = {}, sourceArns, deploymentPatch = {}, revisionPatch = {} } = {}) {
  let observation = -1;
  const calls = [];
  const aws = (args) => {
    calls.push(args);
    const command = args.slice(0, 2).join(" ");
    if (command === "ecs describe-services") { observation += 1; return { failures: [], services: [{ ...service, ...(snapshots[observation] || snapshots.at(-1))?.service }] }; }
    const state = snapshots[observation] || snapshots.at(-1) || {};
    const currentDeploymentArn = state.deploymentArn || deploymentArn;
    if (command === "ecs list-service-deployments") return { serviceDeployments: [{ serviceDeploymentArn: currentDeploymentArn, status: "ROLLBACK_IN_PROGRESS" }] };
    if (command === "ecs describe-service-deployments") return { failures: [], serviceDeployments: [{ ...deployment, ...deploymentPatch, ...state.deployment, serviceDeploymentArn: currentDeploymentArn, sourceServiceRevisions: sourceArns ?? deployment.sourceServiceRevisions }] };
    if (command === "ecs describe-service-revisions") {
      const arn = args.at(-1);
      const definitions = {
        [forwardRevisionArn]: { taskDefinition: td48, digest: digest48 },
        [rollbackRevisionArn]: { taskDefinition: td47, digest: digest47 },
        [extraSourceRevisionArn]: { taskDefinition: td46, digest: digest46 },
        ...(state.revisions || {}), ...revisionPatch,
      };
      const value = definitions[arn];
      if (!value) return { failures: [{ arn, reason: "MISSING" }], serviceRevisions: [] };
      return { failures: [], serviceRevisions: [{ serviceRevisionArn: arn, serviceArn: value.serviceArn || serviceArn, clusterArn: value.clusterArn || clusterArn, taskDefinition: value.taskDefinition }] };
    }
    if (command === "ecs describe-task-definition") {
      const arn = args.at(-1);
      const byTask = { [td48]: digest48, [td47]: digest47, [td46]: digest46, ...(state.taskDigests || {}) };
      const family = state.taskFamily?.[arn] || arn;
      return { taskDefinition: { taskDefinitionArn: state.taskDefinitionReadbackArn?.[arn] || family, containerDefinitions: [{ name: "backend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${byTask[arn]}` }] } };
    }
    if (command === "ecr describe-images") {
      const digest = args.find((value) => value.startsWith("imageDigest="))?.slice(12);
      const result = ecr[digest] ?? (digest === digest47 ? false : true);
      if (result === true) return { imageDetails: [{ imageDigest: digest }] };
      if (result === false) throw { stderr: "An error occurred (ImageNotFoundException) when calling the DescribeImages operation: image not found" };
      throw result;
    }
    if (command === "ecs list-tasks") return { taskArns: ["task-1", "task-2"] };
    if (command === "ecs describe-tasks") return { tasks: taskAttempts.map((attempt) => ({ taskArn: attempt.taskArn, taskDefinitionArn: td47, stoppedReason: `CannotPullContainerError ${digest47} manifest not found` })) };
    throw new Error(`Unexpected command: ${args.join(" ")}`);
  };
  return { aws, calls };
}

test("real AWS rollback shape keeps forward, source, and rollback identities separate", async () => {
  const { aws, calls } = awsFixture();
  const proof = await collectRollbackViability({ aws, observationMilliseconds: 0 });
  assert.equal(proof.classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert.equal(proof.forwardTargetServiceRevisionArn, forwardRevisionArn);
  assert.equal(proof.forwardTargetTaskDefinitionArn, td48);
  assert.equal(proof.forwardTargetImageExists, true);
  assert.deepEqual(proof.sourceServiceRevisions, [rollbackTarget]);
  assert.equal(proof.rollbackServiceRevisionArn, rollbackRevisionArn);
  assert.equal(proof.rollbackTargetTaskDefinitionArn, td47);
  assert.equal(proof.rollbackTargetImageExists, false);
  assert.equal(assertRollbackSupersessionProof(proof, { serviceArn, rollbackDeploymentArn: deploymentArn, rollbackTargetTaskDefinitionArn: td47, rollbackTargetDigest: digest47 }), proof);
  assert(calls.some((args) => args[0] === "ecs" && args[1] === "describe-service-revisions" && args.includes(forwardRevisionArn)));
  assert(calls.some((args) => args[0] === "ecs" && args[1] === "describe-service-revisions" && args.includes(rollbackRevisionArn)));
});

test("image viability always belongs to the actual rollback revision", () => {
  assert.equal(classify().classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert.equal(classify({ forwardTarget: { ...forwardTarget, imageExists: false } }).classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert.equal(classify({ rollbackTarget: { ...rollbackTarget, imageExists: true } }).classification, ROLLBACK_VIABILITY.STALLED_RECOVERABLE);
  assert.equal(classify({ forwardTarget: { ...forwardTarget, imageExists: false }, rollbackTarget: { ...rollbackTarget, imageExists: true } }).classification, ROLLBACK_VIABILITY.STALLED_RECOVERABLE);
});

test("only exact ImageNotFoundException establishes rollback artifact absence", () => {
  assert.equal(exactEcrImageResult({ repository: "mscqr-backend", digest: digest47, error: { stderr: "An error occurred (ImageNotFoundException) when calling the DescribeImages operation" } }).exists, false);
  for (const error of [new Error("AccessDeniedException"), new Error("request timeout"), new Error("other AWS error"), { stderr: "An error occurred (AccessDeniedException) when calling the DescribeImages operation" }]) {
    const unknown = exactEcrImageResult({ repository: "mscqr-backend", digest: digest47, error });
    assert.equal(unknown.exists, "UNKNOWN");
    assert.equal(classify({ rollbackTarget: { ...rollbackTarget, imageExists: unknown.exists, imageFailure: unknown.failure } }).classification, ROLLBACK_VIABILITY.AMBIGUOUS);
  }
});

test("rollback status and independently resolved source relationships fail closed", () => {
  assert.equal(classifyRollbackViability({ service }).classification, ROLLBACK_VIABILITY.NONE);
  assert.equal(classify({ service: { ...service, runningCount: 1 } }).classification, ROLLBACK_VIABILITY.PROGRESSING);
  assert.equal(classify({ service: { ...service, pendingCount: 1 } }).classification, ROLLBACK_VIABILITY.PROGRESSING);
  assert.equal(classify({ deployment: { ...deployment, status: "ROLLBACK_SUCCESSFUL" } }).classification, ROLLBACK_VIABILITY.SUCCESSFUL);
  assert.equal(classify({ deployment: { ...deployment, status: "ROLLBACK_FAILED" } }).classification, ROLLBACK_VIABILITY.FAILED);
  assert.equal(classify({ sourceRevisions: [] }).classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert.equal(classify({ sourceRevisions: [rollbackTarget, resolved(extraSourceRevisionArn, td46, digest46, true)] }).classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  for (const invalid of [
    { deployment: { ...deployment, rollback: undefined } },
    { deployment: { ...deployment, rollback: {} } },
    { deployment: { ...deployment, targetServiceRevision: undefined } },
    { deployment: { ...deployment, targetServiceRevision: { arn: rollbackRevisionArn } }, forwardTarget: rollbackTarget },
    { rollbackTarget: { ...rollbackTarget, serviceRevisionArn: "malformed" } },
  ]) assert.equal(classify(invalid).classification, ROLLBACK_VIABILITY.AMBIGUOUS);
});

test("malformed and cross-boundary service revision responses are rejected", async () => {
  for (const fixture of [
    { revisionPatch: { [rollbackRevisionArn]: { taskDefinition: td47, digest: digest47, serviceArn: serviceArn.replace("backend", "other") } } },
    { revisionPatch: { [rollbackRevisionArn]: { taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/other:47", digest: digest47 } } },
    { snapshots: [{ taskDefinitionReadbackArn: { [td47]: td48 } }] },
    { deploymentPatch: { rollback: { serviceRevisionArn: "malformed" } } },
    { deploymentPatch: { targetServiceRevision: undefined } },
  ]) await assert.rejects(() => collectRollbackViability({ ...awsFixture(fixture), observationMilliseconds: 0 }), /revision|relationships|boundary/i);
});

test("source revisions may be empty or multiple but each supplied identity is authenticated", async () => {
  assert.equal((await collectRollbackViability({ ...awsFixture({ sourceArns: [] }), observationMilliseconds: 0 })).classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  const proof = await collectRollbackViability({ ...awsFixture({ sourceArns: [{ arn: rollbackRevisionArn }, { arn: extraSourceRevisionArn }] }), observationMilliseconds: 0 });
  assert.deepEqual(proof.sourceServiceRevisions.map(({ serviceRevisionArn }) => serviceRevisionArn), [extraSourceRevisionArn, rollbackRevisionArn].sort());
  await assert.rejects(() => collectRollbackViability({ ...awsFixture({ sourceArns: [{ arn: "malformed" }] }), observationMilliseconds: 0 }), /relationships/);
});

test("bounded snapshots reject deployment, rollback revision, task definition, digest, and viability changes", async () => {
  const cases = [
    [{}, { deploymentArn: deploymentArn.replace("future-deployment-N", "changed") }],
    [{}, { deployment: { rollback: { serviceRevisionArn: extraSourceRevisionArn } } }],
    [{}, { revisions: { [rollbackRevisionArn]: { taskDefinition: td46, digest: digest46 } } }],
    [{}, { taskDigests: { [td47]: digest46 } }],
  ];
  for (const snapshots of cases) await assert.rejects(() => collectRollbackViability({ ...awsFixture({ snapshots }), observationMilliseconds: 1, sleep: async () => {} }), /changed|incomplete|boundary/i);
});

test("pre-mutation equivalence binds every forward, source, rollback, and service identity", () => {
  const proof = classify();
  assert.equal(assertFreshRollbackEquivalence(proof, classify()), true);
  for (const fresh of [
    classify({ service: { ...service, runningCount: 1 } }),
    classify({ forwardTarget: { ...forwardTarget, digest: digest46 } }),
    classify({ sourceRevisions: [] }),
    classify({ rollbackTarget: { ...rollbackTarget, taskDefinitionArn: td46 } }),
    classify({ rollbackTarget: { ...rollbackTarget, digest: digest46 } }),
  ]) assert.throws(() => assertFreshRollbackEquivalence(proof, fresh), /stalled-unrecoverable|changed/);
});

test("CI invariant forbids sourcing rollback authority from targetServiceRevision", () => {
  const source = fs.readFileSync("scripts/aws/production-ecs-rollback-viability.mjs", "utf8");
  assert.match(source, /const forwardArn = deployment\?\.targetServiceRevision\?\.arn/);
  assert.match(source, /const rollbackArn = deployment\?\.rollback\?\.serviceRevisionArn/);
  assert.doesNotMatch(source, /rollbackArn\s*=\s*deployment\?\.targetServiceRevision/);
  assert.doesNotMatch(source, /rollbackServiceRevisionArn:\s*deployment\?\.targetServiceRevision/);
});

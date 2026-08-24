import assert from "node:assert/strict";
import test from "node:test";
import { ROLLBACK_VIABILITY, assertFreshRollbackEquivalence, assertRollbackSupersessionProof, classifyRollbackViability, collectRollbackViability, exactEcrImageResult } from "../aws/production-ecs-rollback-viability.mjs";

const deploymentId = "future-deployment-N";
const deploymentArn = `arn:aws:ecs:eu-west-2:368992683803:service-deployment/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/${deploymentId}`;
const revisionArn = "arn:aws:ecs:eu-west-2:368992683803:service-revision/mscqr-prod-euw2-main/mscqr-backend-servi-euw2/future-revision-N-minus-1";
const targetArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:998";
const digest = `sha256:${"b".repeat(64)}`;
const service = { serviceArn: "arn:aws:ecs:eu-west-2:368992683803:service/mscqr-prod-euw2-main/mscqr-backend-servi-euw2", taskDefinition: targetArn, desiredCount: 2, runningCount: 0, pendingCount: 0 };
const attempts = [1, 2].map((index) => ({ taskArn: `task-${index}`, taskDefinitionArn: targetArn, classification: "CANNOT_PULL_IMAGE", digest }));
const image = (exists) => exactEcrImageResult({ repository: "mscqr-backend", digest, ...(exists === false ? { error: Object.assign(new Error("ImageNotFoundException"), { name: "ImageNotFoundException" }) } : { response: { imageDetails: [{ imageDigest: digest }] } }) });
const classify = (overrides = {}) => classifyRollbackViability({ service, deployment: { serviceDeploymentArn: deploymentArn, status: "ROLLBACK_IN_PROGRESS", targetServiceRevision: { arn: revisionArn } }, rollbackTargetTaskDefinitionArn: targetArn, rollbackTargetDigest: digest, imageResult: image(false), taskAttempts: attempts, observationStart: "2026-08-24T10:00:00.000Z", observationEnd: "2026-08-24T10:01:00.000Z", ...overrides });

test("exact missing digest and repeated exact failures authenticate a generic stalled rollback", () => {
  const proof = classify();
  assert.equal(proof.classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert.equal(assertRollbackSupersessionProof(proof, { serviceArn: service.serviceArn, rollbackDeploymentArn: deploymentArn, rollbackTargetTaskDefinitionArn: targetArn, rollbackTargetDigest: digest }), proof);
  assert.equal(proof.rollbackDeploymentId, deploymentId);
});

test("progress, terminal states, recoverable target, and unknown observability fail closed", () => {
  assert.equal(classifyRollbackViability({ service }).classification, ROLLBACK_VIABILITY.NONE);
  assert.equal(classify({ service: { ...service, pendingCount: 1 } }).classification, ROLLBACK_VIABILITY.PROGRESSING);
  assert.equal(classify({ service: { ...service, runningCount: 1 } }).classification, ROLLBACK_VIABILITY.PROGRESSING);
  assert.equal(classify({ deployment: { serviceDeploymentArn: deploymentArn, status: "ROLLBACK_SUCCESSFUL", targetServiceRevision: { arn: revisionArn } } }).classification, ROLLBACK_VIABILITY.SUCCESSFUL);
  assert.equal(classify({ deployment: { serviceDeploymentArn: deploymentArn, status: "ROLLBACK_FAILED", targetServiceRevision: { arn: revisionArn } } }).classification, ROLLBACK_VIABILITY.FAILED);
  assert.equal(classify({ imageResult: image(true) }).classification, ROLLBACK_VIABILITY.STALLED_RECOVERABLE);
  for (const error of [new Error("AccessDeniedException"), new Error("request timeout"), new Error("repository unavailable")]) {
    const unknown = exactEcrImageResult({ repository: "mscqr-backend", digest, error });
    assert.equal(unknown.exists, "UNKNOWN");
    assert.equal(classify({ imageResult: unknown }).classification, ROLLBACK_VIABILITY.AMBIGUOUS);
  }
  assert.equal(exactEcrImageResult({ repository: "mscqr-backend", digest, error: new Error("ImageNotFoundException") }).exists, "UNKNOWN");
  assert.equal(exactEcrImageResult({ repository: "mscqr-backend", digest, error: { stderr: "An error occurred (ImageNotFoundException) when calling the DescribeImages operation: image not found" } }).exists, false);
});

test("time, wrong identities, wrong digest, and weak task evidence never authorize supersession", () => {
  const cases = [
    { observationStart: "2020-01-01T00:00:00.000Z", taskAttempts: [] },
    { taskAttempts: attempts.slice(0, 1) },
    { taskAttempts: attempts.map((attempt) => ({ ...attempt, digest: `sha256:${"c".repeat(64)}` })) },
    { rollbackTargetTaskDefinitionArn: targetArn.replace(":998", ":997") },
    { service: { ...service, taskDefinition: targetArn.replace(":998", ":997") } },
    { deployment: { serviceDeploymentArn: deploymentArn.replace(deploymentId, "other"), status: "ROLLBACK_IN_PROGRESS", targetServiceRevision: { arn: revisionArn } } },
  ];
  for (const value of cases) assert.throws(() => assertRollbackSupersessionProof(classify(value), { serviceArn: service.serviceArn, rollbackDeploymentArn: deploymentArn, rollbackTargetTaskDefinitionArn: targetArn, rollbackTargetDigest: digest }), /stalled-unrecoverable/);
});

test("fresh state equivalence rejects every pre-mutation TOCTOU change", () => {
  const proof = classify();
  assert.equal(assertFreshRollbackEquivalence(proof, classify()), true);
  for (const fresh of [
    classify({ service: { ...service, runningCount: 1 } }),
    classify({ service: { ...service, desiredCount: 1 } }),
    classify({ imageResult: image(true) }),
    classify({ deployment: { serviceDeploymentArn: deploymentArn.replace(deploymentId, "replacement"), status: "ROLLBACK_IN_PROGRESS", targetServiceRevision: { arn: revisionArn } } }),
  ]) assert.throws(() => assertFreshRollbackEquivalence(proof, fresh), /stalled-unrecoverable|changed/);
});

test("bounded collector binds actual ECS/ECR argv and only exact ImageNotFound absence", async () => {
  const commands = [];
  const aws = (args) => {
    commands.push(args);
    const command = args.slice(0, 2).join(" ");
    if (command === "ecs describe-services") return { failures: [], services: [{ ...service, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", serviceName: "mscqr-backend-servi-euw2", taskDefinition: targetArn }] };
    if (command === "ecs list-service-deployments") return { serviceDeployments: [{ serviceDeploymentArn: deploymentArn, status: "ROLLBACK_IN_PROGRESS" }] };
    if (command === "ecs describe-service-deployments") return { failures: [], serviceDeployments: [{ serviceDeploymentArn: deploymentArn, status: "ROLLBACK_IN_PROGRESS", targetServiceRevision: { arn: revisionArn } }] };
    if (command === "ecs describe-service-revisions") return { failures: [], serviceRevisions: [{ serviceRevisionArn: revisionArn, serviceArn: service.serviceArn, clusterArn: "arn:aws:ecs:eu-west-2:368992683803:cluster/mscqr-prod-euw2-main", taskDefinition: targetArn }] };
    if (command === "ecs describe-task-definition") return { taskDefinition: { taskDefinitionArn: targetArn, containerDefinitions: [{ name: "backend", image: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}` }] } };
    if (command === "ecr describe-images") throw Object.assign(new Error("ImageNotFoundException"), { name: "ImageNotFoundException" });
    if (command === "ecs list-tasks") return { taskArns: ["task-1", "task-2"] };
    if (command === "ecs describe-tasks") return { tasks: attempts.map((attempt) => ({ ...attempt, stoppedReason: `CannotPullContainerError ${digest} manifest not found` })) };
    throw new Error(`unexpected ${args.join(" ")}`);
  };
  const proof = await collectRollbackViability({ aws, sleep: async () => {}, observationMilliseconds: 1 });
  assert.equal(proof.classification, ROLLBACK_VIABILITY.STALLED_UNRECOVERABLE);
  assert(commands.some((args) => args[0] === "ecs" && args[1] === "list-service-deployments" && args.includes("mscqr-backend-servi-euw2")));
  assert(commands.some((args) => args[0] === "ecs" && args[1] === "describe-service-revisions" && args.includes(revisionArn)));
  assert(commands.some((args) => args[0] === "ecr" && args.includes(`imageDigest=${digest}`)));
});

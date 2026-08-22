import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { NORMAL_ACTIVATION, assertNormalActivationPolicy, buildNormalActivationPolicy, collectNormalActivationLiveEvidence, convergeNormalActivationPolicy, deriveNormalBackendCandidate, executeNormalBackendActivation } from "../aws/production-normal-backend-activation.mjs";
import { assertNormalActivationPolicyDeltaOnly } from "../aws/production-normal-backend-activation-policy.mjs";

const sourceSha = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const targetArn = `${NORMAL_ACTIVATION.clusterArn.replace("cluster/mscqr-prod-euw2-main", "task-definition/mscqr-production-rls-green-backend-candidate")}:12`;
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const imageAuthorization = { images: [{ service: "backend", digest }] };
const state = (arn = targetArn, releaseSha = sourceSha, serial = 103) => ({
  version: 4, lineage: NORMAL_ACTIVATION.lineage, serial,
  outputs: { task_definition_arns: { value: { backend: arn } }, bound_images: { value: { backend: image } } },
  resources: [{ mode: "managed", type: "aws_ecs_task_definition", name: "candidate", instances: [{ index_key: "backend", attributes: {
    arn, family: NORMAL_ACTIVATION.family, container_definitions: JSON.stringify([{ name: "backend", image, environment: [{ name: "RELEASE_GIT_SHA", value: releaseSha }] }]),
    tags_all: { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-b", MSCQRExecTarget: "production-backend" },
  } }] }],
});
const validate = () => true;

test("normal activation derives one exact current-source candidate from Stage-B state", () => {
  const candidate = deriveNormalBackendCandidate({ state: state(), sourceSha, imageAuthorization, validateImageAuthorization: validate });
  assert.equal(candidate.targetArn, targetArn);
  assert.equal(candidate.digest, digest);
  assert.equal(candidate.stateSerial, 103);
  for (const mutate of [
    (value) => { value.serial = 102; value.outputs.task_definition_arns.value.backend = targetArn.replace(":12", ":11"); },
    (value) => { value.resources[0].instances[0].attributes.arn = targetArn.replace(":12", ":11"); },
    (value) => { value.resources[0].instances[0].attributes.container_definitions = value.resources[0].instances[0].attributes.container_definitions.replace(sourceSha, "c".repeat(40)); },
    (value) => { value.resources[0].instances[0].attributes.container_definitions = value.resources[0].instances[0].attributes.container_definitions.replace(digest, `sha256:${"d".repeat(64)}`); },
  ]) {
    const candidateState = structuredClone(state()); mutate(candidateState);
    assert.throws(() => deriveNormalBackendCandidate({ state: candidateState, sourceSha, imageAuthorization, validateImageAuthorization: validate }), /candidate|source|image|output/);
  }
  assert.throws(() => deriveNormalBackendCandidate({ state: state(), sourceSha: "c".repeat(40), imageAuthorization, validateImageAuthorization: validate }), /source/);
});

test("normal activation policy binds only candidate N while preserving separate recovery authority", () => {
  const policy = buildNormalActivationPolicy(targetArn);
  assertNormalActivationPolicy(policy, targetArn);
  assert.equal(policy.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate").Condition.ArnEquals["ecs:task-definition"], targetArn);
  assert.equal(policy.Statement.find(({ Sid }) => Sid === "RecoverLegacyBackend").Condition.ArnLike["ecs:task-definition"], "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*");
  assert.doesNotMatch(JSON.stringify(policy), /mscqr-production-rls-green-backend-candidate:\*/);
  for (const arn of [targetArn.replace(":12", ":11"), targetArn.replace(":12", ":13"), "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48"]) assert.throws(() => assertNormalActivationPolicy(policy, arn), /does not exactly match|requires/);
  assert.equal(assertNormalActivationPolicyDeltaOnly(policy), targetArn);
  const broadened = structuredClone(policy); broadened.Statement[0].Condition.ArnEquals["ecs:task-definition"] = `${NORMAL_ACTIVATION.family}:*`;
  assert.throws(() => assertNormalActivationPolicyDeltaOnly(broadened), /exact normal candidate revision/);
});

test("live preparation authenticates caller, state, exact policy, target, service, and current revision", () => {
  const service = { serviceArn: NORMAL_ACTIVATION.serviceArn, clusterArn: NORMAL_ACTIVATION.clusterArn, status: "ACTIVE", taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", desiredCount: 2, deployments: [{ status: "PRIMARY", taskDefinition: "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48", pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" }] };
  const responses = (command) => {
    const joined = command.join(" ");
    if (joined.startsWith("sts get-caller-identity")) return { Account: NORMAL_ACTIVATION.account, Arn: `arn:aws:sts::${NORMAL_ACTIVATION.account}:assumed-role/mscqr-production-release-deployer/test` };
    if (joined.startsWith("s3 cp")) return state();
    if (joined.startsWith("iam get-policy ")) return { Policy: { DefaultVersionId: "v3" } };
    if (joined.startsWith("iam get-policy-version")) return { PolicyVersion: { Document: buildNormalActivationPolicy(targetArn) } };
    if (joined.startsWith("ecs describe-task-definition")) return { taskDefinition: { taskDefinitionArn: targetArn, family: NORMAL_ACTIVATION.family, status: "ACTIVE", containerDefinitions: [{ name: "backend", image }] }, tags: [] };
    if (joined.startsWith("ecs describe-services")) return { services: [service] };
    throw new Error(`unexpected command ${joined}`);
  };
  const run = (command) => {
    const value = responses(command);
    return command[0] === "s3" ? JSON.stringify(value) : JSON.stringify(value);
  };
  const evidence = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, validateImageAuthorization: validate });
  assert.equal(evidence.targetArn, targetArn);
  assert.equal(evidence.expectedCurrentTaskDefinitionArn, service.taskDefinition);
  for (const mutate of [
    () => { service.taskDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49"; },
    () => { service.clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/other"; },
    () => { service.deployments[0].pendingCount = 1; },
  ]) {
    const snapshot = structuredClone(service); mutate();
    assert.throws(() => collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: evidence.expectedCurrentTaskDefinitionArn, validateImageAuthorization: validate }), /service changed|service identity/);
    Object.assign(service, snapshot);
  }
});

test("administrator convergence changes only the exact candidate binding and is idempotent", () => {
  const predecessor = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  let livePolicy = predecessor;
  let writes = 0;
  const run = (command) => {
    const joined = command.join(" ");
    let response;
    if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
    else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
    else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: writes ? "v4" : "v3" } };
    else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: livePolicy } };
    else if (joined.startsWith("iam list-policy-versions")) response = { Versions: [{ VersionId: "v3", IsDefaultVersion: true, CreateDate: "2026-08-01T00:00:00Z" }] };
    else if (joined.startsWith("iam create-policy-version")) { livePolicy = JSON.parse(command[command.indexOf("--policy-document") + 1]); writes += 1; return ""; }
    else if (joined.startsWith("iam simulate-principal-policy")) response = { EvaluationResults: [{ EvalDecision: joined.includes(`${NORMAL_ACTIVATION.family}:12`) ? "allowed" : "implicitDeny" }] };
    else throw new Error(`unexpected command ${joined}`);
    return JSON.stringify(response);
  };
  const converged = convergeNormalActivationPolicy({ run, sourceSha });
  assert.equal(converged.status, "CONVERGED");
  assert.equal(converged.iamWrites, 1);
  assertNormalActivationPolicy(livePolicy, targetArn);
  const noOp = convergeNormalActivationPolicy({ run, sourceSha });
  assert.equal(noOp.status, "ALREADY_CONVERGED");
  assert.equal(noOp.iamWrites, 0);
  assert.equal(writes, 1);
  const wrongCaller = (command) => command[0] === "sts" ? JSON.stringify({ Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.roleArn }) : run(command);
  assert.throws(() => convergeNormalActivationPolicy({ run: wrongCaller, sourceSha }), /root administrator/);
});

test("normal activation rejects a receipt with the wrong Stage-B approval before AWS readback", () => {
  const receipt = {
    schemaVersion: 2,
    environment: "production",
    releaseSha: sourceSha,
    approvalId: "wrong-approval",
    images: { backend: image },
  };
  receipt.receiptBundleSha256 = createHash("sha256").update(`${JSON.stringify(receipt)}\n`).digest("hex");
  let awsReads = 0;
  assert.throws(() => executeNormalBackendActivation({
    run: () => { awsReads += 1; return "{}"; },
    sourceSha,
    imageAuthorization,
    releaseReceipt: receipt,
    binding: {},
  }), /release receipt/);
  assert.equal(awsReads, 0);
});

test("Release Gate prepares exact normal activation before database mutation and never registers or updates a worker service", () => {
  const workflow = fs.readFileSync(".github/workflows/release-gate.yml", "utf8");
  yaml.load(workflow);
  const prepare = workflow.indexOf("Authorize exact Stage-B backend candidate before database mutation");
  const database = workflow.indexOf("Apply and verify checksum-bound production RLS package");
  const execute = workflow.indexOf("Activate exact Stage-B backend candidate");
  assert(prepare > 0 && prepare < database && database < execute);
  assert.match(workflow, /production-normal-backend-activation\.mjs[\s\S]*--mode prepare/);
  assert.match(workflow, /production-normal-backend-activation\.mjs[\s\S]*--mode execute/);
  assert.doesNotMatch(workflow, /name: Deploy worker ECS service|PRODUCTION_WORKER_SERVICE_NAME|WORKER_TASK_DEFINITION/);
  const normal = workflow.slice(workflow.indexOf("Verify checksum-bound production RLS package"), workflow.indexOf("Authorize rotation transition readiness"));
  assert.doesNotMatch(normal, /deploy-ecs-service\.sh|register-task-definition|TASK_DEFINITION: mscqr-backend/);
  assert.match(workflow, /recover-production-backend-health\.mjs[\s\S]*--execute/);
});

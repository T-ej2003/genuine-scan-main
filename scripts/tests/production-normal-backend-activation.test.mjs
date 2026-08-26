import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import yaml from "js-yaml";
import { NORMAL_ACTIVATION, NormalActivationPolicyConvergenceError, assertNormalActivationPolicy, assertNormalActivationTransactionPolicy, buildNormalActivationPolicy, buildNormalActivationTransactionPolicy, classifyNormalActivationLiveOutcome, collectNormalActivationLiveEvidence, contractNormalActivationPolicy, convergeNormalActivationPolicy, deriveNormalBackendCandidate, executeNormalBackendActivation, normalActivationSimulationContext } from "../aws/production-normal-backend-activation.mjs";
import { iamSimulationContextArgs } from "../aws/iam-simulation-context.mjs";
import { assertNormalActivationPolicyDeltaOnly } from "../aws/production-normal-backend-activation-policy.mjs";

const sourceSha = "a".repeat(40);
const digest = `sha256:${"b".repeat(64)}`;
const targetArn = `${NORMAL_ACTIVATION.clusterArn.replace("cluster/mscqr-prod-euw2-main", "task-definition/mscqr-production-rls-green-backend-candidate")}:12`;
const image = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${digest}`;
const sourceArn = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48";
const sourceDigest = `sha256:${"c".repeat(64)}`;
const sourceImage = `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@${sourceDigest}`;
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
const stableService = (taskDefinition = sourceArn) => ({ serviceArn: NORMAL_ACTIVATION.serviceArn, clusterArn: NORMAL_ACTIVATION.clusterArn, status: "ACTIVE", taskDefinition, desiredCount: 2, deployments: [{ id: "ecs-svc/123456789", status: "PRIMARY", taskDefinition, pendingCount: 0, runningCount: 2, rolloutState: "COMPLETED" }] });
const sourceTask = (arn = sourceArn) => ({ taskDefinition: { taskDefinitionArn: arn, family: arn.includes("mscqr-backend:") ? "mscqr-backend" : NORMAL_ACTIVATION.family, status: "ACTIVE", containerDefinitions: [{ name: "backend", image: sourceImage }] }, tags: [] });
const listedTasks = { taskArns: ["task-1", "task-2"] };
const describedTasks = (taskDefinitionArn = sourceArn, imageDigest = sourceDigest) => ({ failures: [], tasks: [1, 2].map(() => ({ lastStatus: "RUNNING", taskDefinitionArn, containers: [{ name: "backend", imageDigest }] })) });
const contextArgsFor = (arn) => [
  "ContextKeyName=aws:RequestedRegion,ContextKeyValues=eu-west-2,ContextKeyType=string",
  `ContextKeyName=ecs:cluster,ContextKeyValues=${NORMAL_ACTIVATION.clusterArn},ContextKeyType=string`,
  `ContextKeyName=ecs:task-definition,ContextKeyValues=${arn},ContextKeyType=string`,
];

function simulatedTarget(args) {
  const start = args.indexOf("--context-entries");
  const end = args.indexOf("--output");
  assert(start > 0 && end > start);
  const entries = args.slice(start + 1, end);
  assert.deepEqual(entries, contextArgsFor(entries[2]?.split("ContextKeyValues=")[1]?.split(",ContextKeyType=")[0]));
  return entries[2].split("ContextKeyValues=")[1].split(",ContextKeyType=")[0];
}

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

test("normal activation policies separate steady recovery from exact SOURCE/TARGET transaction authority", () => {
  const policy = buildNormalActivationPolicy(targetArn);
  assertNormalActivationPolicy(policy, targetArn);
  assert.equal(policy.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate").Condition.ArnEquals["ecs:task-definition"], targetArn);
  assert.equal(policy.Statement.find(({ Sid }) => Sid === "RecoverLegacyBackend").Condition.ArnLike["ecs:task-definition"], "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:*");
  assert.doesNotMatch(JSON.stringify(policy), /mscqr-production-rls-green-backend-candidate:\*/);
  for (const arn of [targetArn.replace(":12", ":11"), targetArn.replace(":12", ":13"), "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:48"]) assert.throws(() => assertNormalActivationPolicy(policy, arn), /does not exactly match|requires/);
  assert.equal(assertNormalActivationPolicyDeltaOnly(policy), targetArn);
  const broadened = structuredClone(policy); broadened.Statement[0].Condition.ArnEquals["ecs:task-definition"] = `${NORMAL_ACTIVATION.family}:*`;
  assert.throws(() => assertNormalActivationPolicyDeltaOnly(broadened), /exact normal candidate revision/);
  assert.throws(() => buildNormalActivationPolicy(targetArn.replace(":12", ":12345678901234567890")), /managed-policy document limit/);
  const transaction = buildNormalActivationTransactionPolicy({ sourceArn, targetArn });
  assertNormalActivationTransactionPolicy(transaction, { sourceArn, targetArn });
  assert.deepEqual(transaction.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate").Condition.ArnEquals["ecs:task-definition"], [sourceArn, targetArn].sort());
  assert.equal(transaction.Statement.some(({ Sid }) => Sid === "RecoverLegacyBackend"), false);
  assert.throws(() => assertNormalActivationTransactionPolicy(transaction, { sourceArn: sourceArn.replace(":48", ":49"), targetArn }), /does not exactly match/);
});

test("live preparation authenticates caller, state, exact policy, target, service, and current revision", () => {
  const service = stableService();
  let runningDigest = sourceDigest;
  const responses = (command) => {
    const joined = command.join(" ");
    if (joined.startsWith("sts get-caller-identity")) return { Account: NORMAL_ACTIVATION.account, Arn: `arn:aws:sts::${NORMAL_ACTIVATION.account}:assumed-role/mscqr-production-release-deployer/test` };
    if (joined.startsWith("s3 cp")) return state();
    if (joined.startsWith("iam get-policy ")) return { Policy: { DefaultVersionId: "v3" } };
    if (joined.startsWith("iam get-policy-version")) return { PolicyVersion: { Document: buildNormalActivationTransactionPolicy({ sourceArn, targetArn }) } };
    if (joined.startsWith("ecs describe-task-definition") && joined.includes(targetArn)) return { taskDefinition: { taskDefinitionArn: targetArn, family: NORMAL_ACTIVATION.family, status: "ACTIVE", containerDefinitions: [{ name: "backend", image }] }, tags: [] };
    if (joined.startsWith("ecs describe-task-definition") && joined.includes(sourceArn)) return sourceTask();
    if (joined.startsWith("ecr describe-images")) return { imageDetails: [{ imageDigest: sourceDigest }] };
    if (joined.startsWith("ecs describe-services")) return { services: [service] };
    if (joined.startsWith("ecs list-tasks")) return listedTasks;
    if (joined.startsWith("ecs describe-tasks")) return describedTasks(service.taskDefinition, runningDigest);
    throw new Error(`unexpected command ${joined}`);
  };
  const run = (command) => {
    const value = responses(command);
    return command[0] === "s3" ? JSON.stringify(value) : JSON.stringify(value);
  };
  const evidence = collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, validateImageAuthorization: validate });
  assert.equal(evidence.targetArn, targetArn);
  assert.equal(evidence.expectedCurrentTaskDefinitionArn, service.taskDefinition);
  assert.equal(evidence.expectedCurrentDeploymentId, "ecs-svc/123456789");
  assert.equal(evidence.sourceDigest, sourceDigest);
  for (const mutate of [
    () => { service.taskDefinition = "arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-backend:49"; },
    () => { service.clusterArn = "arn:aws:ecs:eu-west-2:368992683803:cluster/other"; },
    () => { service.deployments[0].pendingCount = 1; },
  ]) {
    const snapshot = structuredClone(service); mutate();
    assert.throws(() => collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: evidence.expectedCurrentTaskDefinitionArn, validateImageAuthorization: validate }), /service changed|service identity/);
    Object.assign(service, snapshot);
  }
  runningDigest = digest;
  assert.throws(() => collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: evidence.expectedCurrentTaskDefinitionArn, validateImageAuthorization: validate }), /running task/);
  runningDigest = sourceDigest;
  assert.throws(() => collectNormalActivationLiveEvidence({ run, sourceSha, imageAuthorization, expectedCurrentTaskDefinitionArn: evidence.expectedCurrentTaskDefinitionArn, expectedCurrentDeploymentId: "ecs-svc/987654321", validateImageAuthorization: validate }), /deployment identity/);
});

test("administrator convergence changes only the exact candidate binding and is idempotent", () => {
  const predecessor = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  let livePolicy = predecessor;
  let writes = 0;
  const commands = [];
  const run = (command) => {
    commands.push(command);
    const joined = command.join(" ");
    let response;
    if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
    else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
    else if (joined.startsWith("ecs describe-services")) response = { services: [stableService()] };
    else if (joined.startsWith("ecs describe-task-definition")) response = sourceTask();
    else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
    else if (joined.startsWith("ecs describe-tasks")) response = describedTasks();
    else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: writes ? "v4" : "v3" } };
    else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: livePolicy } };
    else if (joined.startsWith("iam list-policy-versions")) response = { Versions: [{ VersionId: "v3", IsDefaultVersion: true, CreateDate: "2026-08-01T00:00:00Z" }] };
    else if (joined.startsWith("iam create-policy-version")) { livePolicy = JSON.parse(command[command.indexOf("--policy-document") + 1]); writes += 1; return ""; }
    else if (joined.startsWith("iam simulate-principal-policy")) {
      const testedArn = simulatedTarget(command);
      response = { EvaluationResults: [{ EvalActionName: "ecs:UpdateService", EvalResourceName: NORMAL_ACTIVATION.serviceArn, EvalDecision: new Set([sourceArn, targetArn]).has(testedArn) ? "allowed" : "implicitDeny" }] };
    }
    else throw new Error(`unexpected command ${joined}`);
    return JSON.stringify(response);
  };
  const converged = convergeNormalActivationPolicy({ run, sourceSha });
  assert.equal(converged.status, "CONVERGED");
  assert.equal(converged.iamWrites, 1);
  assertNormalActivationTransactionPolicy(livePolicy, { sourceArn, targetArn });
  const noOp = convergeNormalActivationPolicy({ run, sourceSha });
  assert.equal(noOp.status, "ALREADY_CONVERGED");
  assert.equal(noOp.iamWrites, 0);
  assert.equal(writes, 1);
  const createIndex = commands.findIndex((args) => args[0] === "iam" && args[1] === "create-policy-version");
  const sourceDigestReadIndex = commands.findIndex((args) => args[0] === "ecs" && args[1] === "describe-tasks");
  const postWriteReadIndex = commands.findIndex((args, index) => index > createIndex && args[0] === "iam" && args[1] === "get-policy-version");
  const simulationIndex = commands.findIndex((args) => args[0] === "iam" && args[1] === "simulate-principal-policy");
  assert(sourceDigestReadIndex > 0 && createIndex > sourceDigestReadIndex && postWriteReadIndex > createIndex && simulationIndex > postWriteReadIndex);
  const simulatedArns = commands.filter((args) => args[0] === "iam" && args[1] === "simulate-principal-policy").map(simulatedTarget);
  assert(new Set(simulatedArns).has(sourceArn));
  assert(new Set(simulatedArns).has(targetArn));
  assert(new Set(simulatedArns).has(sourceArn.replace(":48", ":1")));
  const wrongCaller = (command) => command[0] === "sts" ? JSON.stringify({ Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.roleArn }) : run(command);
  assert.throws(() => convergeNormalActivationPolicy({ run: wrongCaller, sourceSha }), /root administrator/);
});

test("candidate predecessor and already-target sources produce exact bounded transactions", () => {
  const predecessor = targetArn.replace(":12", ":11");
  const candidateTransaction = buildNormalActivationTransactionPolicy({ sourceArn: predecessor, targetArn });
  assertNormalActivationTransactionPolicy(candidateTransaction, { sourceArn: predecessor, targetArn });
  assert.deepEqual(candidateTransaction.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate").Condition.ArnEquals["ecs:task-definition"], [predecessor, targetArn]);
  const replay = buildNormalActivationTransactionPolicy({ sourceArn: targetArn, targetArn });
  assert.equal(replay.Statement.find(({ Sid }) => Sid === "ActivateBackendCandidate").Condition.ArnEquals["ecs:task-definition"], targetArn);
  assert.equal(replay.Statement.some(({ Sid }) => Sid === "RecoverLegacyBackend"), false);
});

test("post-success administrator contraction restores exact steady-state authority idempotently", () => {
  let livePolicy = buildNormalActivationTransactionPolicy({ sourceArn, targetArn });
  let writes = 0;
  let runningDigest = digest;
  const run = (command) => {
    const joined = command.join(" ");
    let response;
    if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
    else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
    else if (joined.startsWith("ecs describe-services")) response = { services: [stableService(targetArn)] };
    else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
    else if (joined.startsWith("ecs describe-tasks")) response = describedTasks(targetArn, runningDigest);
    else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: writes ? "v4" : "v3" } };
    else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: livePolicy } };
    else if (joined.startsWith("iam list-policy-versions")) response = { Versions: [{ VersionId: "v3", IsDefaultVersion: true, CreateDate: "2026-08-01T00:00:00Z" }] };
    else if (joined.startsWith("iam create-policy-version")) { livePolicy = JSON.parse(command[command.indexOf("--policy-document") + 1]); writes += 1; return ""; }
    else if (joined.startsWith("iam simulate-principal-policy")) response = { EvaluationResults: [{ EvalActionName: "ecs:UpdateService", EvalResourceName: NORMAL_ACTIVATION.serviceArn, EvalDecision: simulatedTarget(command) === targetArn ? "allowed" : "implicitDeny" }] };
    else throw new Error(`unexpected command ${joined}`);
    return JSON.stringify(response);
  };
  const contracted = contractNormalActivationPolicy({ run, sourceSha, sourceArn });
  assert.equal(contracted.status, "CONTRACTED");
  assertNormalActivationPolicy(livePolicy, targetArn);
  assert.equal(contractNormalActivationPolicy({ run, sourceSha, sourceArn }).status, "ALREADY_CONTRACTED");
  assert.equal(writes, 1);
  runningDigest = sourceDigest;
  assert.throws(() => contractNormalActivationPolicy({ run, sourceSha, sourceArn }), /running task/);
  assert.equal(writes, 1);
});

test("live outcome reconciliation verifies exact SOURCE/TARGET running digests", () => {
  const binding = { sourceArn, targetArn, sourceDigest, digest, desiredCount: 2 };
  const outcomeRun = ({ currentArn = sourceArn, runningDigest = sourceDigest } = {}) => (command) => {
    const joined = command.join(" ");
    if (joined.startsWith("ecs describe-services")) return JSON.stringify({ services: [stableService(currentArn)] });
    if (joined.startsWith("ecs list-tasks")) return JSON.stringify({ taskArns: ["task-1", "task-2"] });
    if (joined.startsWith("ecs describe-tasks")) return JSON.stringify({ failures: [], tasks: [1, 2].map((value) => ({ lastStatus: "RUNNING", taskDefinitionArn: currentArn, containers: [{ name: "backend", imageDigest: runningDigest }] })) });
    throw new Error(`unexpected command ${joined}`);
  };
  assert.equal(classifyNormalActivationLiveOutcome({ run: outcomeRun(), binding }).status, "SOURCE_STABLE");
  assert.equal(classifyNormalActivationLiveOutcome({ run: outcomeRun({ currentArn: targetArn, runningDigest: digest }), binding }).status, "TARGET_STABLE");
  assert.equal(classifyNormalActivationLiveOutcome({ run: outcomeRun({ runningDigest: digest }), binding }).status, "LIVE_STATE_UNAUTHENTICATED");
});

test("normal activation simulation uses canonical AWS CLI context structures for exact candidate and legacy SOURCE revisions", () => {
  assert.deepEqual(iamSimulationContextArgs(normalActivationSimulationContext(targetArn)), contextArgsFor(targetArn));
  assert.deepEqual(iamSimulationContextArgs(normalActivationSimulationContext(sourceArn)), contextArgsFor(sourceArn));
  assert.throws(() => normalActivationSimulationContext("arn:aws:ecs:eu-west-2:368992683803:task-definition/mscqr-worker:1"), /outside the permitted/);
});

test("ambiguous policy publication is reconciled only by authenticated exact readback", () => {
  const predecessor = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  const makeRun = ({ publishTarget, failReadback = false }) => {
    let livePolicy = predecessor;
    let createAttempted = false;
    return (command) => {
      const joined = command.join(" ");
      let response;
      if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
      else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
      else if (joined.startsWith("ecs describe-services")) response = { services: [stableService()] };
      else if (joined.startsWith("ecs describe-task-definition")) response = sourceTask();
      else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
      else if (joined.startsWith("ecs describe-tasks")) response = describedTasks();
      else if (joined.startsWith("iam get-policy ")) {
        if (createAttempted && failReadback) throw new Error("READBACK_DENIED");
        response = { Policy: { DefaultVersionId: createAttempted ? "v4" : "v3" } };
      } else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: livePolicy } };
      else if (joined.startsWith("iam list-policy-versions")) response = { Versions: [{ VersionId: "v3", IsDefaultVersion: true, CreateDate: "2026-08-01T00:00:00Z" }] };
      else if (joined.startsWith("iam create-policy-version")) {
        createAttempted = true;
        if (publishTarget) livePolicy = JSON.parse(command[command.indexOf("--policy-document") + 1]);
        throw new Error("AMBIGUOUS_CREATE_RESULT");
      } else if (joined.startsWith("iam simulate-principal-policy")) {
        const testedArn = simulatedTarget(command);
        response = { EvaluationResults: [{ EvalActionName: "ecs:UpdateService", EvalResourceName: NORMAL_ACTIVATION.serviceArn, EvalDecision: new Set([sourceArn, targetArn]).has(testedArn) ? "allowed" : "implicitDeny" }] };
      } else throw new Error(`unexpected command ${joined}`);
      return JSON.stringify(response);
    };
  };
  const reconciled = convergeNormalActivationPolicy({ run: makeRun({ publishTarget: true }), sourceSha });
  assert.equal(reconciled.status, "RECONCILED_AFTER_AMBIGUOUS_WRITE");
  assert.equal(reconciled.iamWrites, 1);
  assert.equal(reconciled.mutationOutcome, "CONFIRMED_SUCCESS_READBACK");
  assert.equal(reconciled.unknownMutations, 0);
  assert.equal(reconciled.readbackVerified, true);
  assert.equal(reconciled.validationComplete, true);

  for (const run of [makeRun({ publishTarget: false }), makeRun({ publishTarget: true, failReadback: true })]) {
    assert.throws(() => convergeNormalActivationPolicy({ run, sourceSha }), (error) => {
      assert(error instanceof NormalActivationPolicyConvergenceError);
      assert.equal(error.report.status, "PARTIAL_CONVERGENCE_LIVE_STATE_UNAUTHENTICATED");
      assert.equal(error.report.mutationAttempted, true);
      assert.equal(error.report.readbackVerified, false);
      assert.equal(error.report.unknownMutations, 1);
      assert.equal(error.report.rollbackAttempted, false);
      assert.match(error.report.exactNextAction, /RERUN_SAME_GOVERNED_CONVERGENCE/);
      return true;
    });
  }
});

test("post-mutation simulation failure reports authenticated convergence without false rollback", () => {
  let livePolicy = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  const run = (command) => {
    const joined = command.join(" ");
    let response;
    if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
    else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
    else if (joined.startsWith("ecs describe-services")) response = { services: [stableService()] };
    else if (joined.startsWith("ecs describe-task-definition")) response = sourceTask();
    else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
    else if (joined.startsWith("ecs describe-tasks")) response = describedTasks();
    else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: "v4" } };
    else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: livePolicy } };
    else if (joined.startsWith("iam list-policy-versions")) response = { Versions: [{ VersionId: "v4", IsDefaultVersion: true, CreateDate: "2026-08-01T00:00:00Z" }] };
    else if (joined.startsWith("iam create-policy-version")) { livePolicy = JSON.parse(command[command.indexOf("--policy-document") + 1]); return ""; }
    else if (joined.startsWith("iam simulate-principal-policy")) throw new Error("SIMULATION_UNAVAILABLE");
    else throw new Error(`unexpected command ${joined}`);
    return JSON.stringify(response);
  };
  assert.throws(() => convergeNormalActivationPolicy({ run, sourceSha }), (error) => {
    assert(error instanceof NormalActivationPolicyConvergenceError);
    assert.equal(error.report.status, "CONVERGENCE_MUTATION_READBACK_VERIFIED_VALIDATION_FAILED");
    assert.equal(error.report.readbackVerified, true);
    assert.equal(error.report.unknownMutations, 0);
    assert.equal(error.report.rollbackAttempted, false);
    return true;
  });
});

test("policy-version pruning plus failed publication reports partial convergence for reconciliation", () => {
  const predecessor = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  let deleted = false;
  const run = (command) => {
    const joined = command.join(" ");
    let response;
    if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
    else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
    else if (joined.startsWith("ecs describe-services")) response = { services: [stableService()] };
    else if (joined.startsWith("ecs describe-task-definition")) response = sourceTask();
    else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
    else if (joined.startsWith("ecs describe-tasks")) response = describedTasks();
    else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: "v5" } };
    else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: predecessor } };
    else if (joined.startsWith("iam list-policy-versions")) response = { Versions: Array.from({ length: 5 }, (_, index) => ({ VersionId: `v${index + 1}`, IsDefaultVersion: index === 4, CreateDate: `2026-08-0${index + 1}T00:00:00Z` })) };
    else if (joined.startsWith("iam delete-policy-version")) { deleted = true; return ""; }
    else if (joined.startsWith("iam create-policy-version")) throw new Error("PUBLICATION_FAILED");
    else throw new Error(`unexpected command ${joined}`);
    return JSON.stringify(response);
  };
  assert.throws(() => convergeNormalActivationPolicy({ run, sourceSha }), (error) => {
    assert(error instanceof NormalActivationPolicyConvergenceError);
    assert.equal(error.report.status, "PARTIAL_CONVERGENCE_LIVE_STATE_UNAUTHENTICATED");
    assert.equal(error.report.confirmedIamWrites, 1);
    assert.equal(error.report.unknownMutations, 1);
    assert.equal(error.report.rollbackAttempted, false);
    return true;
  });
  assert.equal(deleted, true);
});

test("pre-mutation rejection explicitly reports that no convergence mutation occurred", () => {
  const run = (command) => command[0] === "sts"
    ? JSON.stringify({ Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.roleArn })
    : (() => { throw new Error("unexpected post-authentication command"); })();
  assert.throws(() => convergeNormalActivationPolicy({ run, sourceSha }), (error) => {
    assert(error instanceof NormalActivationPolicyConvergenceError);
    assert.equal(error.report.status, "NO_MUTATION_CONVERGENCE_FAILED");
    assert.equal(error.report.mutationAttempted, false);
    assert.equal(error.report.confirmedIamWrites, 0);
    assert.equal(error.report.unknownMutations, 0);
    return true;
  });
});

test("malformed policy-version topology is rejected before deletion or publication", () => {
  const predecessor = buildNormalActivationPolicy(targetArn.replace(":12", ":7"));
  for (const versions of [
    [{ VersionId: "v3", IsDefaultVersion: false, CreateDate: "2026-08-01T00:00:00Z" }],
    [{ VersionId: "v3", IsDefaultVersion: true, CreateDate: "invalid" }],
    Array.from({ length: 6 }, (_, index) => ({ VersionId: `v${index + 1}`, IsDefaultVersion: index === 2, CreateDate: `2026-08-0${index + 1}T00:00:00Z` })),
  ]) {
    let mutations = 0;
    const run = (command) => {
      const joined = command.join(" ");
      let response;
      if (joined.startsWith("sts get-caller-identity")) response = { Account: NORMAL_ACTIVATION.account, Arn: NORMAL_ACTIVATION.administratorArn };
      else if (joined.startsWith("s3 cp")) return JSON.stringify(state());
      else if (joined.startsWith("ecs describe-services")) response = { services: [stableService()] };
      else if (joined.startsWith("ecs describe-task-definition")) response = sourceTask();
      else if (joined.startsWith("ecs list-tasks")) response = listedTasks;
      else if (joined.startsWith("ecs describe-tasks")) response = describedTasks();
      else if (joined.startsWith("iam get-policy ")) response = { Policy: { DefaultVersionId: "v3" } };
      else if (joined.startsWith("iam get-policy-version")) response = { PolicyVersion: { Document: predecessor } };
      else if (joined.startsWith("iam list-policy-versions")) response = { Versions: versions };
      else if (joined.startsWith("iam delete-policy-version") || joined.startsWith("iam create-policy-version")) { mutations += 1; return ""; }
      else throw new Error(`unexpected command ${joined}`);
      return JSON.stringify(response);
    };
    assert.throws(() => convergeNormalActivationPolicy({ run, sourceSha }), (error) => error instanceof NormalActivationPolicyConvergenceError && error.report.status === "NO_MUTATION_CONVERGENCE_FAILED");
    assert.equal(mutations, 0);
  }
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

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertStageBPlan, assertStageBPlanCapture, assertStageBBrokerCaptureUpdateContract, classifyStageBBrokerActionShape, assertStageBTaskDefinitionStateMigrationPreconditions } from "../plan-production-green-stage-b.mjs";
import { buildStageBProtectedMainCheckoutEvidence } from "../aws/stage-b-deployment-identity.mjs";
import { STAGE_B_TASK_DEFINITION_FAMILIES } from "../aws/stage-b-reference-audit-contract.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const family = "mscqr-production-rls-green-backend-candidate";
const address = 'aws_ecs_task_definition.candidate["backend"]';
const oldArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const validationNow = new Date("2026-07-31T14:05:00.000Z");
const terraformConfiguration = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
const change = (type, actions = ["create"], after = {}, before = {}) => ({ address: type === "aws_ecs_task_definition" ? address : `test.${type}`, type, change: { actions, after, before } });
const rollover = () => {
  const value = change("aws_ecs_task_definition", ["delete", "create"], { family }, { family, arn: oldArn });
  value.mode = "managed";
  value.change.replace_paths = [["container_definitions"]];
  return value;
};
const retained = (historyKey = "aaaaaaaa-backend", taskFamily = family) => ({ address: `aws_ecs_task_definition.candidate_retained["${historyKey}"]`, type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family: taskFamily, arn: oldArn.replace(family, taskFamily) }, after: { family: taskFamily } } });
const retainedForAddress = (address, generation = "aaaaaaaa", revision = 1) => {
  const match = /^(aws_ecs_task_definition\.(candidate|executor))\["([^"]+)"\]$/.exec(address);
  const taskFamily = STAGE_B_TASK_DEFINITION_FAMILIES[address];
  return { address: `${match[1]}_retained["${generation}-${match[3]}"]`, type: "aws_ecs_task_definition", change: { actions: ["no-op"], before: { family: taskFamily, arn: oldArn.replace(family, taskFamily).replace(":1", `:${revision}`) }, after: { family: taskFamily } } };
};
const currentAddresses = Object.keys(STAGE_B_TASK_DEFINITION_FAMILIES);
const firstRolloverAddresses = currentAddresses.filter((taskAddress) => !taskAddress.includes("read_only_canary"));
const retryVariables = {
  tooling_sha: { value: "e".repeat(40) },
  image_release_sha: { value: "a".repeat(40) },
  canonical_image_evidence_sha256: { value: "f".repeat(64) },
  source_contract_sha256: { value: "b".repeat(64) },
  migration_set_digest: { value: "c".repeat(64) },
  package_checksum_sha256: { value: "d".repeat(64) },
  backend_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"1".repeat(64)}` },
  worker_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-worker@sha256:${"2".repeat(64)}` },
  executor_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"3".repeat(64)}` },
  canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"4".repeat(64)}` },
  read_only_canary_image: { value: `368992683803.dkr.ecr.eu-west-2.amazonaws.com/mscqr-backend@sha256:${"4".repeat(64)}` },
};
const retryChange = (address, family, actions, revision = 7) => {
  const key = /\["([^\"]+)"\]$/.exec(address)?.[1];
  const imageVariable = address.startsWith("aws_ecs_task_definition.executor[") ? "executor_image" : `${key}_image`;
  const metadata = {
    family,
    network_mode: "awsvpc",
    requires_compatibilities: ["FARGATE"],
    cpu: "1024",
    memory: "2048",
    execution_role_arn: `arn:aws:iam::368992683803:role/${key}-execution`,
    task_role_arn: `arn:aws:iam::368992683803:role/${key}-task`,
    runtime_platform: { operating_system_family: "LINUX", cpu_architecture: "X86_64" },
    volume: [],
    ipc_mode: "",
    pid_mode: "",
    tags: { Environment: "production", ManagedBy: "Terraform", Component: "full-rls-green-stage-b" },
    container_definitions: JSON.stringify([{ image: retryVariables[imageVariable].value, environment: [
      { name: "RELEASE_GIT_SHA", value: retryVariables.image_release_sha.value },
      { name: "SOURCE_CONTRACT_SHA256", value: retryVariables.source_contract_sha256.value },
      { name: "MIGRATION_SET_DIGEST", value: retryVariables.migration_set_digest.value },
      { name: "PACKAGE_CHECKSUM_SHA256", value: retryVariables.package_checksum_sha256.value },
    ] }]),
  };
  const arn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:${revision}`;
  return { address, type: "aws_ecs_task_definition", change: { actions, before: actions[0] === "no-op" ? { ...metadata, arn } : null, after: metadata } };
};
const currentRetryPlan = (noOpCount) => {
  const resource_changes = currentAddresses.map((address, index) => retryChange(address, STAGE_B_TASK_DEFINITION_FAMILIES[address], index < noOpCount ? ["no-op"] : ["create"]));
  return { variables: retryVariables, resource_changes, planned_values: { root_module: { resources: resource_changes.map((change) => ({ address: change.address, type: change.type, index: change.address.match(/\["([^\"]+)"\]$/)?.[1], values: change.change.after })) } } };
};
const currentCreates = () => Object.entries(STAGE_B_TASK_DEFINITION_FAMILIES).map(([taskAddress, taskFamily]) => ({
  address: taskAddress,
  type: "aws_ecs_task_definition",
  change: { actions: ["create"], after: { family: taskFamily }, before: null },
}));
const appendOnly = () => [
  ...currentCreates(),
  ...firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress)),
];
const auditFor = (overrides = {}) => ({
  schemaVersion: 1,
  auditedAt: "2026-07-31T14:00:00.000Z",
  ...overrides,
  planJsonSha256: "",
  oldTaskDefinitions: [{
    terraformAddress: address,
    oldTaskDefinitionArn: oldArn,
    family,
    proposedFamily: family,
    classification: "rollover",
    replacePaths: [["container_definitions"]],
    serviceReferences: [],
    runningTaskReferences: [],
    pendingTaskReferences: [],
    rollbackArn: oldArn,
    sameFamilyAsReplacement: true,
    ...overrides,
  }],
});
const validRollover = (overrides = {}, planOverrides = {}) => {
  const plan = { resource_changes: [rollover()], ...planOverrides };
  const planBytes = Buffer.from(JSON.stringify(plan));
  const audit = auditFor(overrides);
  audit.planJsonSha256 = sha256(planBytes);
  const auditBytes = Buffer.from(JSON.stringify(audit));
  return { plan, options: { referenceAudit: audit, referenceAuditBytes: auditBytes, referenceAuditSha256: sha256(auditBytes), planJsonBytes: planBytes, planJsonSha256: sha256(planBytes), now: validationNow, terraformConfiguration } };
};
const validAppendOnly = (planOverrides = {}) => {
  const plan = { resource_changes: appendOnly(), ...planOverrides };
  return { plan, options: { now: validationNow, terraformConfiguration } };
};

test("strict validation joins protected main to the plan tooling SHA before resource classification", () => {
  const toolingSha = "e".repeat(40);
  const imageReleaseSha = "a".repeat(40);
  const plan = {
    variables: {
      tooling_sha: { value: toolingSha },
      image_release_sha: { value: imageReleaseSha },
      canonical_image_evidence_sha256: { value: "f".repeat(64) },
    },
    resource_changes: [],
  };
  const checkout = buildStageBProtectedMainCheckoutEvidence({
    toolingSha,
    currentHead: toolingSha,
    originMainHead: toolingSha,
    isAncestor: true,
    porcelainStatus: "",
    repositoryState: { remoteDefaultBranch: "main", shallow: false, mergeInProgress: false, rebaseInProgress: false, cherryPickInProgress: false },
    mode: "production",
  });
  assert.doesNotThrow(() => assertStageBPlan(plan, { strictResourceContract: true, protectedMainCheckout: checkout }));
  assert.throws(() => assertStageBPlan({ ...plan, resource_changes: [{ address: "unclassified.resource", type: "unknown", change: { actions: ["create"] } }] }, { strictResourceContract: true, protectedMainCheckout: { ...checkout, toolingSha: imageReleaseSha } }), /does not match the approved plan tooling SHA/);
  assert.throws(() => assertStageBPlan(plan, { strictResourceContract: true, protectedMainCheckout: { ...checkout, currentHead: imageReleaseSha } }), /tooling HEAD/);
  assert.throws(() => assertStageBPlan(plan, { strictResourceContract: true }), /requires protected-main/);
});

test("fresh deployment has exactly twelve current creates and no retained creates", () => {
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: currentCreates() }, { terraformConfiguration }));
  assert.equal(currentCreates().filter((change) => change.address.includes("_retained")).length, 0);
});

test("PLAN_CAPTURED accepts only the reviewed three-resource broker update", () => {
  const plan = {
    resource_changes: [
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", change: { actions: ["update"], before: { policy: "old" }, after: {} } },
      { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "1" }, after: { function_version: "2" } } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["update"], before: { filename: "old.zip", source_code_hash: "old", environment: {}, code_sha256: "old-code-sha", source_code_size: 100, last_modified: "old", qualified_arn: "arn:aws:lambda:eu-west-2:368992683803:function:broker:2", qualified_invoke_arn: "arn:aws:apigateway:eu-west-2:lambda:path/2015-03-31/functions/arn:aws:lambda:eu-west-2:368992683803:function:broker:2/invocations", version: "2" }, after: { filename: "new.zip", source_code_hash: "new", environment: {} }, after_unknown: { code_sha256: true, source_code_size: true, last_modified: true, qualified_arn: true, qualified_invoke_arn: true, version: true } } },
      { address: "aws_iam_role_policy_attachment.broker", type: "aws_iam_role_policy_attachment", change: { actions: ["no-op"], before: {}, after: {} } },
    ],
  };
  assert.equal(classifyStageBBrokerActionShape(plan), "update");
  assert.deepEqual(assertStageBBrokerCaptureUpdateContract(plan), { brokerOperation: "update", brokerUpdatePresent: true, brokerActions: ["update"], brokerResourceAddresses: ["aws_iam_policy.broker", "aws_lambda_alias.reviewed", "aws_lambda_function.broker"], brokerReferenceValidationPending: true });
});

test("PLAN_CAPTURED rejects broker create, delete, replacement, and unsupported fields", () => {
  const base = {
    resource_changes: [
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", change: { actions: ["update"], before: { policy: "old" }, after: {} } },
      { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["update"], before: { function_version: "1" }, after: { function_version: "2" } } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["update"], before: { filename: "old.zip" }, after: { filename: "new.zip" } } },
    ],
  };
  for (const actions of [["create"], ["delete"], ["delete", "create"]]) {
    const changed = structuredClone(base); changed.resource_changes[2].change.actions = actions;
    assert.throws(() => assertStageBBrokerCaptureUpdateContract(changed), /exactly the reviewed|unsupported/);
  }
  const unsupported = structuredClone(base); unsupported.resource_changes[2].change.after.description = "unexpected";
  assert.throws(() => assertStageBBrokerCaptureUpdateContract(unsupported), /unsupported mutable field/);
});

test("broker capture action routing rejects partial and mixed initial shapes", () => {
  const update = {
    resource_changes: [
      { address: "aws_iam_policy.broker", type: "aws_iam_policy", change: { actions: ["update"] } },
      { address: "aws_lambda_alias.reviewed", type: "aws_lambda_alias", change: { actions: ["update"] } },
      { address: "aws_lambda_function.broker", type: "aws_lambda_function", change: { actions: ["update"] } },
    ],
  };
  const initial = structuredClone(update);
  for (const change of initial.resource_changes) change.change.actions = ["create"];
  assert.equal(classifyStageBBrokerActionShape(initial), "initial-create");
  const partial = structuredClone(initial); partial.resource_changes.pop();
  assert.equal(classifyStageBBrokerActionShape(partial), "unsupported");
  const mixed = structuredClone(initial); mixed.resource_changes[2].change.actions = ["update"];
  assert.equal(classifyStageBBrokerActionShape(mixed), "unsupported");
  const deleted = structuredClone(initial); deleted.resource_changes[0].change.actions = ["delete"];
  assert.equal(classifyStageBBrokerActionShape(deleted), "unsupported");
  const unknown = { resource_changes: [...initial.resource_changes, { address: "aws_lambda_function.unexpected_broker", type: "aws_lambda_function", change: { actions: ["create"] } }] };
  assert.throws(() => assertStageBPlanCapture(unknown, { terraformConfiguration }), /unsupported resources|no exact contract/);
});

test("partial append-only retries accept safe current create/no-op mixtures", () => {
  assert.deepEqual(assertStageBPlan(currentRetryPlan(0), { terraformConfiguration }).taskDefinitions, { currentCreates: 12, currentNoOps: 0, total: 12 });
  assert.doesNotThrow(() => assertStageBPlan(currentRetryPlan(1), { terraformConfiguration }));
  assert.doesNotThrow(() => assertStageBPlan(currentRetryPlan(11), { terraformConfiguration }));
  assert.doesNotThrow(() => assertStageBPlan(currentRetryPlan(12), { terraformConfiguration }));
  const missing = currentRetryPlan(11);
  missing.resource_changes.pop();
  assert.throws(() => assertStageBPlan(missing, { terraformConfiguration }), /exactly the twelve/);
});

test("current no-op retry rejects stale image, package, and retained ARN", () => {
  const staleImage = currentRetryPlan(1);
  staleImage.variables.backend_image.value = staleImage.variables.backend_image.value.replace(/1{64}$/, `${"9".repeat(64)}`);
  assert.throws(() => assertStageBPlan(staleImage, { terraformConfiguration }), /image digest is stale/);
  const stalePackage = currentRetryPlan(12);
  stalePackage.variables.package_checksum_sha256.value = "e".repeat(64);
  assert.throws(() => assertStageBPlan(stalePackage, { terraformConfiguration }), /package checksum is stale/);
  const missingImmutableField = currentRetryPlan(1);
  delete missingImmutableField.resource_changes[0].change.before.memory;
  assert.throws(() => assertStageBPlan(missingImmutableField, { terraformConfiguration }), /immutable field is missing|has drift/);
  const retainedArn = currentRetryPlan(12);
  const retained = retainedForAddress(address);
  retainedArn.resource_changes.push(retained);
  retainedArn.resource_changes[0].change.before.arn = retained.change.before.arn;
  retainedArn.resource_changes[0].change.after.arn = retained.change.before.arn;
  assert.throws(() => assertStageBPlan(retainedArn, { terraformConfiguration }), /retained ARN|duplicate/);
});

test("first and second revision-keyed rollovers retain history as no-op", () => {
  const first = { resource_changes: [...currentCreates(), ...firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress))] };
  assert.doesNotThrow(() => assertStageBPlan(first, { terraformConfiguration }));
  const secondGeneration = currentAddresses.map((taskAddress) => retainedForAddress(taskAddress, "bbbbbbbb", 2));
  const second = { resource_changes: [...first.resource_changes, ...secondGeneration] };
  assert.doesNotThrow(() => assertStageBPlan(second, { terraformConfiguration }));
  const thirdGeneration = currentAddresses.map((taskAddress) => retainedForAddress(taskAddress, "cccccccc", 3));
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [...second.resource_changes, ...thirdGeneration] }, { terraformConfiguration }));
});

test("multiple complete pre-canary generations are validated independently", () => {
  const generation = (key, revision) => firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress, key, revision));
  for (const generations of [
    [generation("aaaaaaaa", 1)],
    [generation("aaaaaaaa", 1), generation("bbbbbbbb", 2)],
    [generation("aaaaaaaa", 1), generation("bbbbbbbb", 2), generation("cccccccc", 3)],
  ]) {
    assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [...currentCreates(), ...generations.flat()] }, { terraformConfiguration }));
  }
});

test("incomplete or mixed pre-canary generations fail closed", () => {
  const generation = (key, revision) => firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress, key, revision));
  const missingFamily = { resource_changes: [...currentCreates(), ...generation("aaaaaaaa", 1), ...generation("bbbbbbbb", 2).slice(1)] };
  assert.throws(() => assertStageBPlan(missingFamily, { terraformConfiguration }), /complete task-definition families/);
  const mixedFamilies = { resource_changes: [...currentCreates(), ...generation("aaaaaaaa", 1), ...generation("bbbbbbbb", 2).slice(0, -1), retainedForAddress('aws_ecs_task_definition.candidate["read_only_canary"]', "bbbbbbbb", 1)] };
  assert.throws(() => assertStageBPlan(mixedFamilies, { terraformConfiguration }), /complete task-definition families/);
  const duplicate = { resource_changes: [...currentCreates(), ...generation("aaaaaaaa", 1), retainedForAddress('aws_ecs_task_definition.candidate["backend"]', "aaaaaaaa", 1)] };
  assert.throws(() => assertStageBPlan(duplicate, { terraformConfiguration }), /duplicated/);
});

test("mixed pre-canary and post-canary history is valid, but later twelve-family history is mandatory", () => {
  const preCanary = (key, revision) => firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress, key, revision));
  const postCanary = (key, revision) => currentAddresses.map((taskAddress) => retainedForAddress(taskAddress, key, revision));
  const valid = { resource_changes: [...currentCreates(), ...preCanary("aaaaaaaa", 1), ...preCanary("bbbbbbbb", 2), ...postCanary("cccccccc", 3), ...postCanary("dddddddd", 4)] };
  assert.doesNotThrow(() => assertStageBPlan(valid, { terraformConfiguration }));
  const missingReadOnly = { resource_changes: [...currentCreates(), ...preCanary("aaaaaaaa", 1), ...postCanary("cccccccc", 3), ...preCanary("dddddddd", 4)] };
  assert.throws(() => assertStageBPlan(missingReadOnly, { terraformConfiguration }), /post-canary|read-only-canary/);
  const mixedPostCanary = [
    retainedForAddress('aws_ecs_task_definition.candidate["backend"]', "eeeeeeee", 2),
    ...firstRolloverAddresses.filter((taskAddress) => !taskAddress.includes('["backend"]')).map((taskAddress) => retainedForAddress(taskAddress, "eeeeeeee", 4)),
  ];
  assert.throws(() => assertStageBPlan({ resource_changes: [...currentCreates(), ...preCanary("aaaaaaaa", 1), ...postCanary("cccccccc", 3), ...mixedPostCanary] }, { terraformConfiguration }), /post-canary|revision ordering/);
});

test("a later rollover missing the newest read-only-canary history entry fails", () => {
  const olderReadOnly = retainedForAddress('aws_ecs_task_definition.candidate["read_only_canary"]', "aaaaaaaa", 1);
  const laterWithoutReadOnly = firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress, "bbbbbbbb", 2));
  const plan = { resource_changes: [...currentCreates(), ...firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress)), olderReadOnly, ...laterWithoutReadOnly] };
  assert.throws(() => assertStageBPlan(plan, { terraformConfiguration }), /post-canary|read-only-canary|newest revision/);
});

test("read-only-canary replacement is rejected", () => {
  const plan = { resource_changes: currentCreates() };
  const readOnly = plan.resource_changes.find((change) => change.address.includes("read_only_canary"));
  readOnly.change.actions = ["no-op"];
  readOnly.change.before = { family: readOnly.change.after.family, arn: oldArn.replace(family, readOnly.change.after.family) };
  assert.throws(() => assertStageBPlan(plan, { terraformConfiguration }), /no-op/);
});

test("static retained keys and duplicate retained generations fail closed", () => {
  const staticKey = { resource_changes: [...currentCreates(), { ...retained(), address: 'aws_ecs_task_definition.candidate_retained["backend"]' }] };
  assert.throws(() => assertStageBPlan(staticKey, { terraformConfiguration }), /revision-keyed/);
  const duplicate = { resource_changes: [...currentCreates(), retained(), retained()] };
  assert.throws(() => assertStageBPlan(duplicate, { terraformConfiguration }), /duplicated/);
});

test("state migration requires present sources, absent destinations, and explicit addresses", () => {
  const firstMoves = firstRolloverAddresses.map((source) => ({ source, destination: retainedForAddress(source) .address }));
  assert.doesNotThrow(() => assertStageBTaskDefinitionStateMigrationPreconditions(firstRolloverAddresses, firstMoves));
  assert.throws(() => assertStageBTaskDefinitionStateMigrationPreconditions(currentAddresses, firstMoves), /eleven existing/);
  assert.throws(() => assertStageBTaskDefinitionStateMigrationPreconditions(firstRolloverAddresses.slice(1), firstMoves), /source is missing|eleven existing/);
  const laterMoves = currentAddresses.map((source) => ({ source, destination: retainedForAddress(source, "bbbbbbbb").address }));
  assert.doesNotThrow(() => assertStageBTaskDefinitionStateMigrationPreconditions(currentAddresses, laterMoves));
  assert.throws(() => assertStageBTaskDefinitionStateMigrationPreconditions(firstRolloverAddresses, laterMoves), /twelve current/);
  assert.throws(() => assertStageBTaskDefinitionStateMigrationPreconditions([...firstRolloverAddresses, firstMoves[0].destination], firstMoves), /destination is occupied/);
  assert.throws(() => assertStageBTaskDefinitionStateMigrationPreconditions(firstRolloverAddresses, firstMoves.map((move, index) => index === 0 ? { ...move, destination: 'aws_ecs_task_definition.candidate_retained["backend"]' } : move)), /revision-keyed/);
});

test("Stage B plan wrapper permits only non-destructive control-plane resources", () =>
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [...appendOnly(), { address: "aws_dynamodb_table.replay", type: "aws_dynamodb_table", change: { actions: ["create"], after: {} } }] }, { terraformConfiguration })));

test("append-only current create plus retained no-op passes", () => {
  const { plan, options } = validAppendOnly();
  assert.doesNotThrow(() => assertStageBPlan(plan, options));
  const replacement = { resource_changes: [rollover()] };
  assert.throws(() => assertStageBPlan(replacement, options), /rotation changes an immutable field/);
});

test("unknown task-definition address and family are rejected", () => {
  const unknownAddress = { resource_changes: [...appendOnly()] };
  unknownAddress.resource_changes[0].address = 'aws_ecs_task_definition.other["backend"]';
  assert.throws(() => assertStageBPlan(unknownAddress, { terraformConfiguration }), /address/);
  for (const familyName of ["mscqr-backend", "mscqr-frontend", "unknown-stage-b-family"]) {
    const { plan, options } = validAppendOnly();
    plan.resource_changes[0].change.after.family = familyName;
    assert.throws(() => assertStageBPlan(plan, options), /family/);
  }
});

test("mixed rollover plus unrelated destroy remains rejected", () => {
  const { plan, options } = validAppendOnly();
  plan.resource_changes.push(change("aws_cloudwatch_log_group", ["delete"]));
  assert.throws(() => assertStageBPlan(plan, options), /rejected/);
});

test("append-only contract covers current and retained task-definition collections", () => {
  assert.equal((terraformConfiguration.match(/skip_destroy\s*=\s*true/g) || []).length, 4);
  assert.match(terraformConfiguration, /resource "aws_ecs_task_definition" "candidate_retained"[\s\S]*ignore_changes\s*=\s*all/);
  assert.match(terraformConfiguration, /resource "aws_ecs_task_definition" "executor_retained"[\s\S]*ignore_changes\s*=\s*all/);
  const missing = validAppendOnly();
  missing.options.terraformConfiguration = terraformConfiguration.replace(/resource "aws_ecs_task_definition" "executor_retained"[\s\S]*?ignore_changes\s*=\s*all/, "resource \"aws_ecs_task_definition\" \"executor_retained\"");
  assert.throws(() => assertStageBPlan(missing.plan, missing.options), /task-definition retention contract/);
});

test("task-definition delete, replacement, and update actions are rejected", () => {
  const { plan, options } = validAppendOnly();
  plan.resource_changes[0].change.actions = ["delete"];
  assert.throws(() => assertStageBPlan(plan, options), /exact reviewed.*rotation/);
  const alternate = validAppendOnly();
  alternate.plan.resource_changes[0].change.actions = ["create", "delete"];
  assert.throws(() => assertStageBPlan(alternate.plan, alternate.options), /rotation (identity or action|action|replace paths)|exact reviewed.*rotation/);
  const update = validAppendOnly();
  update.plan.resource_changes[0].change.actions = ["update"];
  assert.throws(() => assertStageBPlan(update.plan, update.options), /exact reviewed.*rotation/);
});

test("Stage B plan wrapper rejects forbidden destroys and mutable images", () => {
  for (const item of [
    change("aws_ecs_service", ["delete"]),
    change("aws_ecs_service", ["update"]),
    change("aws_lb_listener", ["delete"]),
    change("aws_db_instance", ["delete"]),
    change("aws_secretsmanager_secret", ["delete"]),
    change("aws_security_group"),
    change("aws_ecs_task_definition", ["create"], { image: "repo:latest" }),
  ]) assert.throws(() => assertStageBPlan({ resource_changes: [item] }, { terraformConfiguration }), /rejected|tag|append-only/);
});

test("candidate object-storage policy keeps existing task keys and excludes only the read-only canary", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const expected = ["backend", "worker", "canary"];
  assert.match(main, /for_each = \{ for key, role in aws_iam_role\.task : key => role if key != "read_only_canary" \}/);
  const plan = { resource_changes: expected.map((key) => ({ address: `aws_iam_role_policy.candidate_object_storage[\"${key}\"]`, type: "aws_iam_role_policy", change: { actions: ["no-op"], after: {} } })) };
  assert.doesNotThrow(() => assertStageBPlan(plan));
  assert.equal(plan.resource_changes.some(({ address }) => address.includes("read_only_canary")), false);
});

test("Stage B Terraform root is control-plane-only and binds four digest images", () => {
  const root = "infra/aws/terraform/production-green-stage-b";
  const main = fs.readFileSync(`${root}/main.tf`, "utf8");
  const variables = fs.readFileSync(`${root}/variables.tf`, "utf8");
  assert.match(main, /aws_ecs_task_definition/);
  assert.match(main, /aws_dynamodb_table/);
  assert.match(main, /aws_lambda_alias/);
  assert.doesNotMatch(main, /aws_ecs_service|aws_db_|aws_rds_|aws_lb|aws_route53|aws_secretsmanager_secret/);
  assert.match(variables, /var\.deployment_environment == "production"/);
  assert.doesNotMatch(variables, /terraform\.workspace/);
  assert.match(variables, /@sha256/);
  for (const file of ["green-backend-candidate.json", "green-worker-candidate.json", "green-activation-executor.json", "green-application-canary.json"]) {
    assert.match(fs.readFileSync(`${root}/task-definitions/${file}`, "utf8"), /"readonlyRootFilesystem": true/);
  }
});

test("ECS resources pass one container array and render task-level volumes separately", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  assert.equal((main.match(/container_definitions\s*=\s*jsonencode\(each\.value\.containerDefinitions\)/g) || []).length, 2);
  assert.equal((main.match(/dynamic "volume"/g) || []).length, 4);
  assert.doesNotMatch(main, /container_definitions\s*=\s*(?:each\.value|replace\(local\.executor)/);
  for (const mode of [
    "full-rls-capability-preflight", "full-rls-admin-bootstrap", "full-rls-role-provision", "full-rls-role-verify",
    "full-rls-admin-ownership", "full-rls-runtime-policy", "full-rls-verification", "full-rls-rollback",
  ]) assert.match(main, new RegExp(mode));
  assert.match(main, /replace\(local\.executor_template, "\{\{MODE\}\}", mode\)[\s\S]*"\{\{CONFIRMATION\}\}"[\s\S]*confirmation/);
});

test("Stage A owns shared logs and reviewed executor networking while Stage B only consumes them", () => {
  const stageA = fs.readFileSync("infra/aws/terraform/production-green-stage-a/main.tf", "utf8");
  const outputs = fs.readFileSync("infra/aws/terraform/production-green-stage-a/outputs.tf", "utf8");
  const stageB = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  assert.doesNotMatch(stageB, /resource "aws_(?:security_group|vpc_security_group_(?:egress|ingress)_rule)"/);
  assert.match(stageB, /stage_a_executor_log_group_name/);
  assert.match(stageB, /stage_a_broker_log_group_name/);
  for (const output of ["database_security_group_id", "executor_security_group_id", "executor_log_group_name", "executor_log_group_arn", "broker_log_group_name", "broker_log_group_arn", "runtime_secret_arns"]) {
    assert.match(outputs, new RegExp(output));
  }
  assert.match(stageA, /resource "aws_vpc_security_group_egress_rule" "executor_database"[\s\S]*security_group_id\s*=\s*aws_security_group\.executor\.id[\s\S]*referenced_security_group_id\s*=\s*aws_security_group\.database\.id/);
  for (const rule of ["executor_interface_endpoints", "executor_s3", "executor_dns_udp", "executor_dns_tcp"]) assert.match(stageA, new RegExp(rule));
  for (const endpoint of ["ecr.api", "ecr.dkr", "logs", "secretsmanager", "kms"]) assert.match(stageA, new RegExp(`"${endpoint.replace(".", "\\.")}"`));
  assert.match(stageA, /resource "aws_vpc_endpoint" "executor"[\s\S]*vpc_endpoint_type\s*=\s*"Interface"[\s\S]*private_dns_enabled\s*=\s*true[\s\S]*subnet_ids\s*=\s*var\.private_subnet_ids[\s\S]*security_group_ids\s*=\s*\[aws_security_group\.executor_endpoints\.id\]/);
  assert.match(stageA, /resource "aws_vpc_security_group_ingress_rule" "executor_endpoints_https"[\s\S]*referenced_security_group_id\s*=\s*aws_security_group\.executor\.id[\s\S]*from_port\s*=\s*443[\s\S]*to_port\s*=\s*443/);
  assert.match(stageA, /resource "aws_vpc_security_group_ingress_rule" "runtime_endpoints_https"[\s\S]*for_each\s*=\s*var\.runtime_security_group_ids[\s\S]*referenced_security_group_id\s*=\s*each\.value[\s\S]*from_port\s*=\s*443[\s\S]*to_port\s*=\s*443/);
  assert.match(stageA, /resource "aws_vpc_security_group_egress_rule" "executor_interface_endpoints"[\s\S]*referenced_security_group_id\s*=\s*aws_security_group\.executor_endpoints\.id/);
  assert.doesNotMatch(stageA.match(/resource "aws_security_group" "executor"[\s\S]*?\n}/)?.[0] || "", /0\.0\.0\.0\/0|::\/0|egress\s*\{/);
});

test("broker Terraform runtime variables exactly cover runtimeConfig and publish a numbered reviewed alias", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const broker = fs.readFileSync("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs", "utf8");
  const runtimeConfig = broker.match(/const runtimeConfig = \(\) => \(\{[\s\S]*?\n}\);/)?.[0] || "";
  const required = [
    ...runtimeConfig.matchAll(/process\.env\.(BROKER_[A-Z0-9_]+)/g),
    ...runtimeConfig.matchAll(/parse\("(BROKER_[A-Z0-9_]+)"/g),
  ].map((match) => match[1]).sort();
  const environment = main.match(/environment \{[\s\S]*?\n  \}/)?.[0] || "";
  const supplied = [...environment.matchAll(/^\s+(BROKER_[A-Z0-9_]+)\s*=/gm)].map((match) => match[1]).sort();
  assert.deepEqual(supplied, required);
  assert.match(main, /publish\s*=\s*true/);
  assert.match(main, /function_version\s*=\s*var\.stage_b_recovery_only\s*\?[\s\S]*aws_lambda_function\.broker\.version/);
  assert.doesNotMatch(main, /function_version\s*=\s*"\$LATEST"/);
  assert.match(main, /qualifier\s*=\s*aws_lambda_alias\.reviewed\.name/);
  const hashes = main.match(/broker_template_hashes\s*=\s*\{([\s\S]*?)\n  \}/)?.[1] || "";
  assert.deepEqual([...hashes.matchAll(/^\s*(\w+)\s*=/gm)].map((match) => match[1]), ["backend", "worker", "executor", "canary"]);
});

test("broker and executor IAM match their exact AWS SDK writes and launch boundary", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const executor = fs.readFileSync("backend/scripts/full-rls-green-executor-core.mjs", "utf8");
  const broker = fs.readFileSync("infra/aws/terraform/lambda/production-rls-approval-broker/index.mjs", "utf8");
  for (const [command, action] of [["GetSecretValueCommand", "secretsmanager:GetSecretValue"], ["PutSecretValueCommand", "secretsmanager:PutSecretValue"], ["PutObjectCommand", "s3:PutObject"]]) {
    assert.match(executor, new RegExp(command));
    assert.match(main, new RegExp(action));
  }
  assert.match(main, /Resource\s*=\s*"\$\{var\.receipt_bucket_arn\}\/rls-receipts\/\*"/);
  assert.match(broker, /Key: `rls-broker-receipts\//);
  assert.match(main, /Resource\s*=\s*"\$\{var\.receipt_bucket_arn\}\/rls-broker-receipts\/\*"/);
  assert.doesNotMatch(main, /aws_ecs_task_definition\.candidate\["canary"\]\.arn/);
  assert.match(main, /current_candidate_task_definition_arns\s*=\s*\{[\s\S]*try\(aws_ecs_task_definition\.candidate\[kind\]\.arn, null\)/);
  assert.match(main, /current_executor_task_definition_arns\s*=\s*\{[\s\S]*for mode, task in aws_ecs_task_definition\.executor : mode => task\.arn/);
  assert.match(main, /broker_task_definition_arns\s*=\s*merge\([\s\S]*local\.current_executor_task_definition_arns[\s\S]*kind == "canary"/);
  assert.match(main, /active_broker_task_definition_arns\s*=\s*var\.stage_b_recovery_only\s*\?\s*var\.stage_b_recovery_task_definition_arns\s*:\s*local\.broker_task_definition_arns/);
  assert.match(main, /BROKER_TASK_DEFINITIONS_JSON\s*=\s*jsonencode\(local\.active_broker_task_definition_arns\)/);
  assert.match(main, /current_task_definition_mappings_complete\s*=\s*\([\s\S]*expected_current_task_definition_families/);
  assert.match(main, /broker_task_definition_mappings_complete\s*=\s*\([\s\S]*broker_expected_task_definition_families/);
  const runTaskPolicy = main.match(/Sid\s*=\s*"RunOnlyApprovedExecutorAndCanaryRevisions"[\s\S]*?\n      }/)?.[0] || "";
  assert.match(runTaskPolicy, /values\(local\.active_broker_task_definition_arns\)/);
  assert.doesNotMatch(runTaskPolicy, /candidate\["(?:backend|worker)"\]/);
  const brokerPolicy = main.match(/resource "aws_iam_policy" "broker" \{[\s\S]*?\n}/)?.[0] || "";
  const brokerFunction = main.match(/resource "aws_lambda_function" "broker" \{[\s\S]*?\n}/)?.[0] || "";
  assert.doesNotMatch(brokerPolicy, /precondition\s*\{/);
  assert.doesNotMatch(brokerFunction, /precondition\s*\{/);
  assert.match(main, /iam:PassedToService/);
  assert.match(main, /Sid\s*=\s*"ReadWriteOnlyProductionArtifactObjects"[\s\S]*s3:GetObject[\s\S]*s3:PutObject[\s\S]*Resource\s*=\s*"\$\{var\.receipt_bucket_arn\}\/\*"/);
  assert.doesNotMatch(main, /Action\s*=\s*\[[^\]]*iam:(?:Create|Update|Delete|Attach|Put)/);
});

test("broker current mappings are safe at a zero-current append-only checkpoint and complete for deployment", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const outputs = fs.readFileSync("infra/aws/terraform/production-green-stage-b/outputs.tf", "utf8");
  const brokerMappings = main.match(/broker_task_definition_arns\s*=\s*merge\([\s\S]*?\n  \)/)?.[0] || "";

  assert.doesNotMatch(`${main}\n${outputs}`, /aws_ecs_task_definition\.candidate\["(?:backend|worker|canary|read_only_canary)"\]\.arn/);
  assert.match(main, /for kind in keys\(local\.candidate_definitions\) : kind => try\(aws_ecs_task_definition\.candidate\[kind\]\.arn, null\)/);
  assert.match(main, /if try\(aws_ecs_task_definition\.candidate\[kind\]\.arn, null\) != null/);
  assert.match(main, /for mode, task in aws_ecs_task_definition\.executor : mode => task\.arn/);
  assert.match(brokerMappings, /local\.current_executor_task_definition_arns/);
  assert.match(brokerMappings, /local\.current_candidate_task_definition_arns/);
  assert.doesNotMatch(brokerMappings, /retained/);
  assert.match(main, /current_task_definition_mappings_complete/);
  assert.match(main, /broker_task_definition_mappings_complete/);
  assert.match(fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8"), /brokerMutationAddresses/);
  assert.match(fs.readFileSync("scripts/aws/stage-b-reference-audit-contract.mjs", "utf8"), /Broker mutation requires all twelve current task-definition mappings/);
});

test("zero-current checkpoint does not fail broker no-op refresh validation", () => {
  const main = fs.readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");
  const planValidator = fs.readFileSync("scripts/plan-production-green-stage-b.mjs", "utf8");
  assert.doesNotMatch(main, /resource "aws_(?:iam_policy|lambda_function)" "(?:broker)"[\s\S]*?precondition/);
  assert.match(planValidator, /!exactActions\(change\.change\?\.actions \|\| \[\], \["no-op"\]\)/);
  assert.match(planValidator, /assertStageBBrokerTaskDefinitionMapping\(plan, terraformConfiguration\)/);
});

test("Terraform 1.15.7 type-checks recovery ECS collections without configuring current resources", () => {
  const terraform = process.env.TERRAFORM_BINARY || "terraform";
  const moduleDir = fs.mkdtempSync(path.join(os.tmpdir(), "stage-b-recovery-type-"));
  const dataDir = path.join(moduleDir, "terraform-data");
  const candidateFiles = {
    backend: "green-backend-candidate.json",
    worker: "green-worker-candidate.json",
    canary: "green-application-canary.json",
    read_only_canary: "green-read-only-rls-canary.json",
  };
  const executorModes = {
    "full-rls-capability-preflight": "",
    "full-rls-admin-bootstrap": "MSCQR_PRODUCTION_GREEN_CREATE_AND_BOOTSTRAP_DATABASE",
    "full-rls-role-provision": "MSCQR_PRODUCTION_GREEN_PROVISION_RUNTIME_ROLES",
    "full-rls-role-verify": "",
    "full-rls-admin-ownership": "MSCQR_PRODUCTION_GREEN_INSTALL_OWNERSHIP_GRANTS",
    "full-rls-runtime-policy": "MSCQR_PRODUCTION_GREEN_INSTALL_RUNTIME_POLICIES",
    "full-rls-verification": "",
    "full-rls-rollback": "MSCQR_PRODUCTION_GREEN_ROLLBACK_EXACT_PACKAGE",
  };
  const taskDefinitionsDir = path.resolve("infra/aws/terraform/production-green-stage-b/task-definitions");
  const replacements = {
    "{{BACKEND_IMAGE}}": "backend-image",
    "{{WORKER_IMAGE}}": "worker-image",
    "{{CANARY_IMAGE}}": "canary-image",
    "{{READ_ONLY_CANARY_IMAGE}}": "read-only-canary-image",
    "{{READ_ONLY_CANARY_DATABASE_SECRET_ARN}}": "read-only-secret",
    "{{RELEASE_SHA}}": "a".repeat(40),
    "{{SOURCE_CONTRACT_SHA256}}": "b".repeat(64),
    "{{MIGRATION_SET_DIGEST}}": "c".repeat(64),
    "{{PACKAGE_CHECKSUM_SHA256}}": "d".repeat(64),
    "{{EXECUTOR_IMAGE}}": "executor-image",
    "{{RECEIPT_BUCKET}}": "receipt-bucket",
    "{{EXECUTOR_LOG_GROUP}}": "/ecs/executor",
    "{{BACKEND_LOG_GROUP}}": "/ecs/backend",
    "{{WORKER_LOG_GROUP}}": "/ecs/worker",
    "{{CANARY_LOG_GROUP}}": "/ecs/canary",
    "{{READ_ONLY_CANARY_LOG_GROUP}}": "/ecs/read-only-canary",
  };
  const render = (fileName, extra = {}) => {
    let rendered = fs.readFileSync(path.join(taskDefinitionsDir, fileName), "utf8");
    for (const [placeholder, value] of Object.entries({ ...replacements, ...extra })) rendered = rendered.split(placeholder).join(value);
    assert.doesNotMatch(rendered, /\{\{[^}]+\}\}/);
    return rendered;
  };
  const hclString = (value) => JSON.stringify(value);
  const candidateDefinitions = Object.entries(candidateFiles).map(([kind, fileName]) => `    ${kind} = jsondecode(${hclString(render(fileName))})`).join("\n");
  const executorDefinitions = Object.entries(executorModes).map(([mode, confirmation]) => `    ${JSON.stringify(mode)} = jsondecode(${hclString(render("green-activation-executor.json", { "{{MODE}}": mode, "{{CONFIRMATION}}": confirmation }))})`).join("\n");
  fs.writeFileSync(path.join(moduleDir, "main.tf"), `terraform { required_version = ">= 1.15.7" }

variable "stage_b_recovery_only" { type = bool }

locals {
  candidate_definitions = {
${candidateDefinitions}
  }
  executor_definitions = {
${executorDefinitions}
  }
  candidate_definitions_for_resources = {
    for kind, definition in local.candidate_definitions : kind => definition
    if !var.stage_b_recovery_only
  }
  executor_definitions_for_resources = {
    for mode, definition in local.executor_definitions : mode => definition
    if !var.stage_b_recovery_only
  }
  retained_candidate_definitions = { for kind, definition in local.candidate_definitions : "e689d4d-\${kind}" => definition }
  retained_executor_definitions = { for mode, definition in local.executor_definitions : "e689d4d-\${mode}" => definition }
}

output "candidate_count" { value = length(local.candidate_definitions_for_resources) }
output "executor_count" { value = length(local.executor_definitions_for_resources) }
output "retained_count" { value = length(local.retained_candidate_definitions) + length(local.retained_executor_definitions) }
output "candidate_keys" { value = keys(local.candidate_definitions_for_resources) }
output "executor_keys" { value = keys(local.executor_definitions_for_resources) }
`);
  const run = (args, options = {}) => execFileSync(terraform, [`-chdir=${moduleDir}`, ...args], { encoding: "utf8", env: { ...process.env, TF_DATA_DIR: dataDir }, ...options });
  const consoleValue = (recovery, expression) => run(["console", "-no-color", `-var=stage_b_recovery_only=${recovery}`], { input: `${expression}\n` }).trim();
  try {
    run(["init", "-backend=false", "-input=false", "-no-color"]);
    run(["validate", "-no-color"]);
    assert.equal(consoleValue(true, "length(local.candidate_definitions_for_resources)"), "0");
    assert.equal(consoleValue(true, "length(local.executor_definitions_for_resources)"), "0");
    assert.equal(consoleValue(true, "length(local.retained_candidate_definitions) + length(local.retained_executor_definitions)"), "12");
    assert.equal(consoleValue(false, "length(local.candidate_definitions_for_resources)"), "4");
    assert.equal(consoleValue(false, "length(local.executor_definitions_for_resources)"), "8");
    for (const key of Object.keys(candidateFiles)) assert.match(consoleValue(false, "keys(local.candidate_definitions_for_resources)"), new RegExp(key));
    for (const key of Object.keys(executorModes)) assert.match(consoleValue(false, "keys(local.executor_definitions_for_resources)"), new RegExp(key));
  } finally {
    fs.rmSync(moduleDir, { recursive: true, force: true });
  }
  assert.match(terraformConfiguration, /candidate_definitions_for_resources\s*=\s*\{[\s\S]*if !var\.stage_b_recovery_only/);
  assert.match(terraformConfiguration, /executor_definitions_for_resources\s*=\s*\{[\s\S]*if !var\.stage_b_recovery_only/);
  assert.doesNotMatch(terraformConfiguration, /candidate_definitions_for_resources\s*=\s*var\.stage_b_recovery_only\s*\?/);
  assert.doesNotMatch(terraformConfiguration, /executor_definitions_for_resources\s*=\s*var\.stage_b_recovery_only\s*\?/);
});

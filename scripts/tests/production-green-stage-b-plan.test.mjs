import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan, assertStageBTaskDefinitionStateMigrationPreconditions } from "../plan-production-green-stage-b.mjs";
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

test("fresh deployment has exactly twelve current creates and no retained creates", () => {
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: currentCreates() }, { terraformConfiguration }));
  assert.equal(currentCreates().filter((change) => change.address.includes("_retained")).length, 0);
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

test("a later rollover missing the newest read-only-canary history entry fails", () => {
  const olderReadOnly = retainedForAddress('aws_ecs_task_definition.candidate["read_only_canary"]', "aaaaaaaa", 1);
  const laterWithoutReadOnly = firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress, "bbbbbbbb", 2));
  const plan = { resource_changes: [...currentCreates(), ...firstRolloverAddresses.map((taskAddress) => retainedForAddress(taskAddress)), olderReadOnly, ...laterWithoutReadOnly] };
  assert.throws(() => assertStageBPlan(plan, { terraformConfiguration }), /later rollover|newest revision/);
});

test("read-only-canary replacement is rejected", () => {
  const plan = { resource_changes: currentCreates() };
  const readOnly = plan.resource_changes.find((change) => change.address.includes("read_only_canary"));
  readOnly.change.actions = ["no-op"];
  readOnly.change.before = { family: readOnly.change.after.family, arn: oldArn.replace(family, readOnly.change.after.family) };
  assert.throws(() => assertStageBPlan(plan, { terraformConfiguration }), /create-only/);
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
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [...appendOnly(), change("aws_dynamodb_table")] }, { terraformConfiguration })));

test("append-only current create plus retained no-op passes", () => {
  const { plan, options } = validAppendOnly();
  assert.doesNotThrow(() => assertStageBPlan(plan, options));
  const replacement = { resource_changes: [rollover()] };
  assert.throws(() => assertStageBPlan(replacement, options), /append-only/);
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
  assert.throws(() => assertStageBPlan(plan, options), /append-only|create-only/);
  const alternate = validAppendOnly();
  alternate.plan.resource_changes[0].change.actions = ["create", "delete"];
  assert.throws(() => assertStageBPlan(alternate.plan, alternate.options), /append-only/);
  const update = validAppendOnly();
  update.plan.resource_changes[0].change.actions = ["update"];
  assert.throws(() => assertStageBPlan(update.plan, update.options), /append-only/);
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
  assert.match(variables, /terraform\.workspace == "production"/);
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
  assert.match(main, /function_version\s*=\s*aws_lambda_function\.broker\.version/);
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
  assert.match(main, /full-rls-application-canary\s*=\s*aws_ecs_task_definition\.candidate\["canary"\]\.arn/);
  const runTaskPolicy = main.match(/Sid\s*=\s*"RunOnlyApprovedExecutorAndCanaryRevisions"[\s\S]*?\n      }/)?.[0] || "";
  assert.match(runTaskPolicy, /values\(local\.broker_task_definition_arns\)/);
  assert.doesNotMatch(runTaskPolicy, /candidate\["(?:backend|worker)"\]/);
  assert.match(main, /iam:PassedToService/);
  assert.match(main, /Sid\s*=\s*"ReadWriteOnlyProductionArtifactObjects"[\s\S]*s3:GetObject[\s\S]*s3:PutObject[\s\S]*Resource\s*=\s*"\$\{var\.receipt_bucket_arn\}\/\*"/);
  assert.doesNotMatch(main, /Action\s*=\s*\[[^\]]*iam:(?:Create|Update|Delete|Attach|Put)/);
});

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const family = "mscqr-production-rls-green-backend-candidate";
const address = 'aws_ecs_task_definition.candidate["backend"]';
const oldArn = `arn:aws:ecs:eu-west-2:368992683803:task-definition/${family}:1`;
const change = (type, actions = ["create"], after = {}, before = {}) => ({ address: type === "aws_ecs_task_definition" ? address : `test.${type}`, type, change: { actions, after, before } });
const rollover = () => {
  const value = change("aws_ecs_task_definition", ["delete", "create"], { family }, { family, arn: oldArn });
  value.change.replace_paths = [["container_definitions"]];
  return value;
};
const auditFor = (overrides = {}) => ({
  schemaVersion: 1,
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
  return { plan, options: { referenceAudit: audit, referenceAuditBytes: auditBytes, referenceAuditSha256: sha256(auditBytes), planJsonBytes: planBytes, planJsonSha256: sha256(planBytes) } };
};

test("Stage B plan wrapper permits only non-destructive control-plane resources", () =>
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [change("aws_ecs_task_definition"), change("aws_dynamodb_table")] })));

test("safe same-family rollover passes only with a plan-bound reference audit", () => {
  const { plan, options } = validRollover();
  assert.doesNotThrow(() => assertStageBPlan(plan, options));
  options.referenceAudit.planJsonSha256 = "0".repeat(64);
  assert.throws(() => assertStageBPlan(plan, options), /different plan JSON/);
});

test("rollover audit and scope failures remain fail-closed", () => {
  const cases = [
    ["missing audit", {}, /reference audit/],
    ["wrong audit SHA", {}, /reference audit SHA/],
    ["wrong plan SHA", {}, /plan JSON SHA/],
    ["service reference", { serviceReferences: ["service"] }, /service reference/],
    ["running reference", { runningTaskReferences: ["task"] }, /running-task reference/],
    ["pending reference", { pendingTaskReferences: ["task"] }, /pending-task reference/],
    ["different family", { family: "other", proposedFamily: "other" }, /family/],
    ["extra replace path", { replacePaths: [["container_definitions"], ["tags"]] }, /replace path/],
    ["missing rollback", { rollbackArn: "" }, /rollback/],
    ["old ARN mismatch", { oldTaskDefinitionArn: `${oldArn}-different` }, /old ARN/],
  ];
  for (const [name, auditOverrides, expected] of cases) {
    const { plan, options } = validRollover(auditOverrides);
    if (name === "missing audit") delete options.referenceAudit;
    if (name === "wrong audit SHA") options.referenceAuditSha256 = "0".repeat(64);
    if (name === "wrong plan SHA") options.planJsonSha256 = "0".repeat(64);
    assert.throws(() => assertStageBPlan(plan, options), expected, name);
  }
});

test("unknown task-definition address and family are rejected", () => {
  const unknownAddress = { resource_changes: [{ ...rollover(), address: 'aws_ecs_task_definition.other["backend"]' }] };
  assert.throws(() => assertStageBPlan(unknownAddress), /address/);
  for (const familyName of ["mscqr-backend", "mscqr-frontend", "unknown-stage-b-family"]) {
    const { plan, options } = validRollover({});
    plan.resource_changes[0].change.after.family = familyName;
    assert.throws(() => assertStageBPlan(plan, options), /family/);
  }
});

test("mixed rollover plus unrelated destroy remains rejected", () => {
  const { plan, options } = validRollover();
  plan.resource_changes.push(change("aws_cloudwatch_log_group", ["delete"]));
  assert.throws(() => assertStageBPlan(plan, options), /rejected/);
});

test("delete-only, extra replacement paths, and alternate actions are rejected", () => {
  const { plan, options } = validRollover();
  plan.resource_changes[0].change.actions = ["delete"];
  assert.throws(() => assertStageBPlan(plan, options), /rollover/);
  const alternate = validRollover();
  alternate.plan.resource_changes[0].change.actions = ["create", "delete"];
  assert.throws(() => assertStageBPlan(alternate.plan, alternate.options), /rollover/);
  const extra = validRollover();
  extra.plan.resource_changes[0].change.replace_paths = [["container_definitions"], ["tags"]];
  assert.throws(() => assertStageBPlan(extra.plan, extra.options), /rollover/);
});

test("Stage B plan wrapper rejects forbidden destroys and mutable images", () => {
  for (const item of [
    change("aws_ecs_service", ["delete"]),
    change("aws_lb_listener", ["delete"]),
    change("aws_db_instance", ["delete"]),
    change("aws_secretsmanager_secret", ["delete"]),
    change("aws_security_group"),
    change("aws_ecs_task_definition", ["create"], { image: "repo:latest" }),
  ]) assert.throws(() => assertStageBPlan({ resource_changes: [item] }), /rejected|tag/);
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
  assert.equal((main.match(/dynamic "volume"/g) || []).length, 2);
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

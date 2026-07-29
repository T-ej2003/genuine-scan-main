import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";

const change = (type, actions = ["create"], after = {}) => ({ address: `test.${type}`, type, change: { actions, after } });

test("Stage B plan wrapper permits only non-destructive control-plane resources", () =>
  assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [change("aws_ecs_task_definition"), change("aws_dynamodb_table")] })));

test("Stage B plan wrapper rejects deletes, services, traffic, databases, secrets, networking and tags", () => {
  for (const item of [
    change("aws_ecs_task_definition", ["delete"]),
    change("aws_ecs_service"),
    change("aws_lb_listener"),
    change("aws_db_instance"),
    change("aws_secretsmanager_secret"),
    change("aws_security_group"),
    change("aws_ecs_task_definition", ["create"], { image: "repo:latest" }),
  ]) assert.throws(() => assertStageBPlan({ resource_changes: [item] }), /rejected|tag/);
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
  const stageAVariables = fs.readFileSync("infra/aws/terraform/production-green-stage-a/variables.tf", "utf8");
  for (const endpoint of ["ecr_api", "ecr_dkr", "logs", "secretsmanager", "kms"]) assert.match(stageAVariables, new RegExp(endpoint));
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

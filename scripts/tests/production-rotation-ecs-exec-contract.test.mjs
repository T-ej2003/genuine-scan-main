import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const helper = readFileSync("scripts/aws/verify-production-rotation-via-ecs-exec.mjs", "utf8");
const pty = readFileSync("scripts/aws/ecs-exec-fixture-pty.py", "utf8");
const policy = JSON.parse(readFileSync("documents/ops/iam/MSCQR_PRODUCTION_ECS_EXEC_OPERATOR_POLICY.json", "utf8"));
const terraform = readFileSync("infra/aws/terraform/production-green-stage-b/main.tf", "utf8");

test("ECS Exec verifier binds the exact service, task definition, digest, and release", () => {
  for (const value of ["describe-services", "list-tasks", "describe-tasks", "describe-task-definition", "taskDefinitionArn", "imageDigest", "RELEASE_GIT_SHA", "group === `service:${service}`", "expected task definition is not the primary service deployment"]) {
    assert.ok(helper.includes(value), `missing ECS Exec contract: ${value}`);
  }
  assert.match(helper, /--fixture-stdin/);
  assert.doesNotMatch(helper, /--fixture-file.*remoteCommand|remoteCommand.*--fixture-file/s);
  assert.match(helper, /fixture appeared in the ECS Exec transcript/);
  assert.match(pty, /MSCQR_FIXTURE_READY/);
  assert.match(pty, /fixture in output/);
});

test("production ECS Exec policy is narrow and has no shell or mutation permissions", () => {
  const actions = policy.Statement.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]);
  assert(actions.includes("ecs:ExecuteCommand"));
  assert(actions.includes("ecs:DescribeTaskDefinition"));
  assert(!actions.includes("ecs:UpdateService"));
  assert(!actions.includes("ecs:RunTask"));
  assert(!actions.includes("ssm:StartSession"));
  assert.match(JSON.stringify(policy), /mscqr-prod-euw2-main/);
  assert.match(JSON.stringify(policy), /mscqr-backend-servi-euw2/);
});

test("backend task role receives only the four ECS Exec message-channel actions", () => {
  assert.match(terraform, /resource "aws_iam_role_policy" "backend_ecs_exec"/);
  assert.match(terraform, /ssmmessages:CreateControlChannel/);
  assert.match(terraform, /ssmmessages:CreateDataChannel/);
  assert.match(terraform, /ssmmessages:OpenControlChannel/);
  assert.match(terraform, /ssmmessages:OpenDataChannel/);
  assert.match(terraform, /role\s*=\s*aws_iam_role\.task\["backend"\]\.id/);
});

import assert from "node:assert/strict";
import test from "node:test";
import fs from "node:fs";
import { assertStageBPlan } from "../plan-production-green-stage-b.mjs";
const change = (type, actions = ["create"], after = {}) => ({ address: `test.${type}`, type, change: { actions, after } });
test("Stage B plan wrapper permits only non-destructive control-plane resources", () => assert.doesNotThrow(() => assertStageBPlan({ resource_changes: [change("aws_ecs_task_definition"), change("aws_dynamodb_table")] })));
test("Stage B plan wrapper rejects deletes, services, traffic, databases, secrets and tags", () => {
  for (const item of [change("aws_ecs_task_definition", ["delete"]), change("aws_ecs_service"), change("aws_lb_listener"), change("aws_db_instance"), change("aws_secretsmanager_secret"), change("aws_ecs_task_definition", ["create"], { image: "repo:latest" })]) assert.throws(() => assertStageBPlan({ resource_changes: [item] }), /rejected|tag/);
});

test("Stage B Terraform root is control-plane-only and binds four digest images", () => {
  const root = "infra/aws/terraform/production-green-stage-b";
  const main = fs.readFileSync(`${root}/main.tf`, "utf8");
  const variables = fs.readFileSync(`${root}/variables.tf`, "utf8");
  assert.match(main, /aws_ecs_task_definition/); assert.match(main, /aws_dynamodb_table/); assert.match(main, /aws_lambda_alias/);
  assert.doesNotMatch(main, /aws_ecs_service|aws_db_|aws_rds_|aws_lb|aws_route53|aws_secretsmanager_secret/);
  assert.match(variables, /terraform\.workspace == "production"/); assert.match(variables, /@sha256/);
  for (const file of ["green-backend-candidate.json", "green-worker-candidate.json", "green-activation-executor.json", "green-application-canary.json"]) assert.match(fs.readFileSync(`${root}/task-definitions/${file}`, "utf8"), /"readonlyRootFilesystem": true/);
});

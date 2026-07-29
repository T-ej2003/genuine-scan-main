#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const root = "infra/aws/terraform/production-green-stage-b";
const allowed = new Set(["aws_security_group", "aws_vpc_security_group_egress_rule", "aws_cloudwatch_log_group", "aws_iam_role", "aws_iam_role_policy_attachment", "aws_iam_role_policy", "aws_ecs_task_definition", "aws_dynamodb_table", "aws_lambda_function", "aws_lambda_alias", "aws_lambda_permission"]);
const forbidden = /aws_ecs_service|aws_(lb|alb|elbv2)|aws_db_|aws_rds_|aws_secretsmanager_secret(?:_version)?/;

export function assertStageBPlan(plan) {
  for (const change of plan.resource_changes || []) {
    const actions = change.change.actions || [];
    if (actions.includes("delete") || forbidden.test(change.type) || !allowed.has(change.type)) throw new Error(`Stage B plan rejected: ${change.address}`);
    const after = JSON.stringify(change.change.after || {});
    if ((after.match(/"image":"([^"@]+):[^"@]+"/) || after.match(/"image"\s*:\s*"[^"@]+:[^"@]+"/)) && !after.includes("@sha256:")) throw new Error(`Stage B image tag rejected: ${change.address}`);
  }
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  if (process.env.MSCQR_STAGE_B_PLAN_ENABLED !== "true" || process.env.MSCQR_STAGE_B_PLAN_CONFIRM !== "MSCQR_GENERATE_STAGE_B_PLAN_ONLY") throw new Error("Stage B planning requires both explicit plan-only confirmations.");
  const tfvars = process.argv[2];
  if (!tfvars || !path.isAbsolute(tfvars) || !fs.existsSync(tfvars)) throw new Error("Stage B requires an existing absolute private tfvars path.");
  const out = path.resolve(".terraform-plans/production-green-stage-b.tfplan");
  fs.mkdirSync(path.dirname(out), { recursive: true, mode: 0o700 });
  execFileSync("terraform", [`-chdir=${root}`, "workspace", "select", "production"], { stdio: "inherit" });
  execFileSync("terraform", [`-chdir=${root}`, "plan", `-var-file=${tfvars}`, `-out=${out}`], { stdio: "inherit" });
  const plan = JSON.parse(execFileSync("terraform", [`-chdir=${root}`, "show", "-json", out], { encoding: "utf8" }));
  assertStageBPlan(plan);
  process.stdout.write(JSON.stringify({ status: "approved-plan-only", plan: out }) + "\n");
}

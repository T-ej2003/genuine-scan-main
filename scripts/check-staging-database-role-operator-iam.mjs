#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const accountId = "368992683803";
const roleName = "mscqr-staging-database-role-operator";
const operatorUserArn = `arn:aws:iam::${accountId}:user/mscqr-staging-database-role-operator-user`;
const operatorRoleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
const brokerFunctionArn = `arn:aws:lambda:eu-west-2:${accountId}:function:mscqr-staging-database-role-executor-broker`;
const defaults = {
  trust: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_TRUST_POLICY_2026-07-12.json",
  assume: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_ASSUME_ROLE_POLICY_2026-07-12.json",
  role: "documents/ops/iam/MSCQR_STAGING_DATABASE_ROLE_OPERATOR_POLICY_2026-07-12.json",
};
const overrides = {
  trust: process.env.MSCQR_STAGING_DATABASE_ROLE_OPERATOR_TRUST_POLICY_PATH,
  assume: process.env.MSCQR_STAGING_DATABASE_ROLE_OPERATOR_ASSUME_POLICY_PATH,
  role: process.env.MSCQR_STAGING_DATABASE_ROLE_OPERATOR_POLICY_PATH,
};
const failures = [];
const terraformSource = fs.readFileSync(path.join(root, "infra/terraform/staging-api/main.tf"), "utf8");
const brokerRolePolicy = terraformSource.match(/resource "aws_iam_role_policy" "database_role_executor_broker"[\s\S]*?(?=\nresource "aws_lambda_function")/)?.[0] || "";
const asArray = (value) => Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
const same = (actual, expected) => JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
const read = (key) => {
  const file = overrides[key] ? path.resolve(overrides[key]) : path.join(root, defaults[key]);
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (error) { failures.push(`${defaults[key]}: ${error.message}`); return null; }
};
const statementFor = (policy, sid) => policy?.Statement?.find((statement) => statement.Sid === sid);
const requireStatement = (policy, sid) => {
  const statement = statementFor(policy, sid);
  if (!statement) failures.push(`Missing required statement ${sid}.`);
  return statement;
};
const rejectProduction = (value, label) => {
  if (/(^|[-_/])(prod|production)([-_/*]|$)/i.test(JSON.stringify(value))) failures.push(`${label} contains a production-looking resource.`);
};

const trust = read("trust");
const assume = read("assume");
const role = read("role");
for (const [label, policy] of [["Trust policy", trust], ["Operator assume policy", assume], ["Role policy", role]]) {
  if (policy?.Version !== "2012-10-17" || !Array.isArray(policy?.Statement)) failures.push(`${label} must be a valid 2012-10-17 policy with Statement array.`);
  rejectProduction(policy, label);
}

if (trust) {
  if (trust.Statement.length !== 1) failures.push("Trust policy must contain exactly one statement.");
  const statement = trust.Statement[0];
  if (statement?.Effect !== "Allow" || !same(asArray(statement.Action), ["sts:AssumeRole"]) || statement.Principal?.AWS !== operatorUserArn) {
    failures.push(`Trust policy must allow only ${operatorUserArn} to assume the role.`);
  }
  if (statement?.Condition?.Bool?.["aws:MultiFactorAuthPresent"] !== "true") failures.push("Trust policy must require MFA for role assumption.");
  const principal = statement?.Principal?.AWS || "";
  if (principal === "*" || /:root$|terraform-(?:plan|apply)-role/i.test(principal)) failures.push("Root, wildcard, and Terraform plan/apply principals are forbidden.");
}

if (assume) {
  if (assume.Statement.length !== 1) failures.push("Operator assume policy must contain exactly one statement.");
  const statement = assume.Statement[0];
  if (statement?.Effect !== "Allow" || !same(asArray(statement.Action), ["sts:AssumeRole"]) || !same(asArray(statement.Resource), [operatorRoleArn])) {
    failures.push(`Operator assume policy must allow only sts:AssumeRole on ${operatorRoleArn}.`);
  }
}

if (role) {
  const allowedActions = new Set([
    "lambda:InvokeFunction", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition", "ecs:DescribeServices", "ecs:ListTaskDefinitions", "ecs:ListServices",
    "events:ListRules", "events:ListTargetsByRule", "logs:GetLogEvents",
  ]);
  const seenActions = new Set(role.Statement.flatMap((statement) => asArray(statement.Action)));
  for (const action of seenActions) if (!allowedActions.has(action) || action.includes("*")) failures.push(`Unapproved or wildcard action: ${action}.`);
  for (const action of allowedActions) if (!seenActions.has(action)) failures.push(`Missing required action ${action}.`);
  for (const statement of role.Statement) if (statement.Effect !== "Allow") failures.push(`${statement.Sid || "Statement"}: only explicit Allow statements are permitted.`);

  for (const forbidden of ["ecs:RunTask", "iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:UpdateService", "ecs:ExecuteCommand", "secretsmanager:GetSecretValue"]) {
    if (seenActions.has(forbidden)) failures.push(`Human operator policy must not allow ${forbidden}.`);
  }
  const invoke = requireStatement(role, "InvokeOnlyReviewedDatabaseRoleExecutorBroker");
  if (invoke && (!same(asArray(invoke.Action), ["lambda:InvokeFunction"]) || !same(asArray(invoke.Resource), [brokerFunctionArn]))) {
    failures.push("Human operator may invoke only the exact staging database-role executor broker Lambda.");
  }
  const logs = requireStatement(role, "ReadOnlyReviewedDatabaseRoleTaskLogs");
  const logStreamArn = `arn:aws:logs:eu-west-2:${accountId}:log-group:/ecs/mscqr-staging-backend:log-stream:database-role-admin/db-admin/*`;
  if (logs && (!same(asArray(logs.Action), ["logs:GetLogEvents"]) || !same(asArray(logs.Resource), [logStreamArn]))) {
    failures.push("Human operator may read only the reviewed database-role helper log streams.");
  }

  if ([...seenActions].some((action) => action.startsWith("secretsmanager:"))) failures.push("Human operator policy must not allow Secrets Manager actions.");
  rejectProduction(role, "Role policy");
}

if (!brokerRolePolicy) failures.push("Terraform broker execution-role policy is missing.");
else {
  for (const required of [
    "arn:aws:ecs:${var.aws_region}:${var.account_id}:task-definition/mscqr-staging-database-role-admin:*",
    "ArnEquals = { \"ecs:cluster\" = aws_ecs_cluster.staging.arn }",
    "aws_iam_role.database_role_admin_task.arn",
    "aws_iam_role.ecs_execution.arn",
    "StringEquals = { \"iam:PassedToService\" = \"ecs-tasks.amazonaws.com\" }",
  ]) if (!brokerRolePolicy.includes(required)) failures.push(`Terraform broker execution-role policy is missing required scope: ${required}.`);
  if (/Resource\s*=\s*"\*"/.test(brokerRolePolicy) || /secretsmanager:GetSecretValue|ecs:RegisterTaskDefinition|ecs:UpdateService|ecs:ExecuteCommand/.test(brokerRolePolicy)) {
    failures.push("Terraform broker execution role contains a wildcard or forbidden permission.");
  }
}

if (failures.length) {
  console.error("Staging database-role operator IAM lint failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("Staging database-role operator IAM lint passed.");
console.log(`Validated assumed role: ${roleName}.`);
console.log("Human operator has no RunTask or PassRole; only the exact broker Lambda is invokable.");

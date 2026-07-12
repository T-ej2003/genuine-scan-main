#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const accountId = "368992683803";
const roleName = "mscqr-staging-database-role-operator";
const operatorUserArn = `arn:aws:iam::${accountId}:user/mscqr-staging-database-role-operator-user`;
const operatorRoleArn = `arn:aws:iam::${accountId}:role/${roleName}`;
const adminTaskRoleArn = `arn:aws:iam::${accountId}:role/mscqr-staging-database-role-admin-task`;
const executionRoleArn = `arn:aws:iam::${accountId}:role/mscqr-staging-ecs-execution-role`;
const runTaskArn = `arn:aws:ecs:eu-west-2:${accountId}:task-definition/mscqr-staging-database-role-admin:*`;
const clusterArn = `arn:aws:ecs:eu-west-2:${accountId}:cluster/mscqr-staging-euw2-main`;
const secretArns = ["app", "migrator", "rls-read"].map((role) => `arn:aws:secretsmanager:eu-west-2:${accountId}:secret:mscqr/staging/database-url/${role}-*`);
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
    "ecs:RunTask", "ecs:DescribeTasks", "ecs:DescribeTaskDefinition", "ecs:DescribeServices", "ecs:ListTaskDefinitions", "ecs:ListServices",
    "events:ListRules", "events:ListTargetsByRule", "secretsmanager:DescribeSecret", "iam:PassRole",
  ]);
  const seenActions = new Set(role.Statement.flatMap((statement) => asArray(statement.Action)));
  for (const action of seenActions) if (!allowedActions.has(action) || action.includes("*")) failures.push(`Unapproved or wildcard action: ${action}.`);
  for (const action of allowedActions) if (!seenActions.has(action)) failures.push(`Missing required action ${action}.`);
  for (const statement of role.Statement) if (statement.Effect !== "Allow") failures.push(`${statement.Sid || "Statement"}: only explicit Allow statements are permitted.`);

  const runTask = requireStatement(role, "RunReviewedDisposableDatabaseRoleTask");
  if (runTask && (!same(asArray(runTask.Action), ["ecs:RunTask"]) || !same(asArray(runTask.Resource), [runTaskArn]) || runTask.Condition?.ArnEquals?.["ecs:cluster"] !== clusterArn)) {
    failures.push("ecs:RunTask must target only the reviewed database-role-admin task family on the reviewed staging cluster.");
  }
  if (asArray(runTask?.Resource).includes("*")) failures.push("Wildcard ecs:RunTask resources are forbidden.");

  const passRole = requireStatement(role, "PassOnlyReviewedDatabaseRoleTaskRoles");
  if (passRole && (!same(asArray(passRole.Action), ["iam:PassRole"]) || !same(asArray(passRole.Resource), [adminTaskRoleArn, executionRoleArn]))) {
    failures.push("iam:PassRole must target only the reviewed admin task and ECS execution roles.");
  }
  if (asArray(passRole?.Resource).some((resource) => resource === "*" || resource.includes("*"))) failures.push("Wildcard iam:PassRole resources are forbidden.");
  if (passRole?.Condition?.StringEquals?.["iam:PassedToService"] !== "ecs-tasks.amazonaws.com") failures.push("iam:PassRole requires iam:PassedToService = ecs-tasks.amazonaws.com.");

  const secrets = requireStatement(role, "DescribeReviewedStagingDatabaseRoleSecrets");
  if (secrets && (!same(asArray(secrets.Action), ["secretsmanager:DescribeSecret"]) || !same(asArray(secrets.Resource), secretArns))) {
    failures.push("secretsmanager:DescribeSecret must target only the three reviewed database-role secret patterns.");
  }
  rejectProduction(role, "Role policy");
}

if (failures.length) {
  console.error("Staging database-role operator IAM lint failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log("Staging database-role operator IAM lint passed.");
console.log(`Validated assumed role: ${roleName}.`);
console.log("RunTask and PassRole are exact-resource scoped; PassRole is ECS-tasks-only.");
